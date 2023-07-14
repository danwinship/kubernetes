/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package iptables

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lithammer/dedent"
	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	proxyutiliptables "k8s.io/kubernetes/pkg/proxy/util/iptables"
	proxyutiltest "k8s.io/kubernetes/pkg/proxy/util/testing"
	"k8s.io/kubernetes/pkg/util/async"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptablestest "k8s.io/kubernetes/pkg/util/iptables/testing"
	fakeexec "k8s.io/utils/exec/testing"
	netutils "k8s.io/utils/net"
)

// Conventions for tests using NewFakeProxier:
//
// Pod IPs:             10.0.0.0/8
// Service ClusterIPs:  172.30.0.0/16
// Node IPs:            192.168.0.0/24
// Local Node IP:       192.168.0.2
// Service ExternalIPs: 192.168.99.0/24
// LoadBalancer IPs:    1.2.3.4, 5.6.7.8, 9.10.11.12
// Non-cluster IPs:     203.0.113.0/24
// LB Source Range:     203.0.113.0/25

const testHostname = "test-hostname"
const testNodeIP = "192.168.0.2"
const testExternalClient = "203.0.113.2"
const testExternalClientBlocked = "203.0.113.130"

func NewFakeProxier(ipt utiliptables.Interface) *Proxier {
	// TODO: Call NewProxier after refactoring out the goroutine
	// invocation into a Run() method.
	ipfamily := v1.IPv4Protocol
	podCIDR := "10.0.0.0/8"
	if ipt.IsIPv6() {
		ipfamily = v1.IPv6Protocol
		podCIDR = "fd00:10::/32"
	}
	detectLocal, _ := proxyutiliptables.NewDetectLocalByCIDR(podCIDR)

	networkInterfacer := proxyutiltest.NewFakeNetwork()
	itf := net.Interface{Index: 0, MTU: 0, Name: "lo", HardwareAddr: nil, Flags: 0}
	addrs := []net.Addr{
		&net.IPNet{IP: netutils.ParseIPSloppy("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy("::1/128"), Mask: net.CIDRMask(128, 128)},
	}
	networkInterfacer.AddInterfaceAddr(&itf, addrs)
	itf1 := net.Interface{Index: 1, MTU: 0, Name: "eth0", HardwareAddr: nil, Flags: 0}
	addrs1 := []net.Addr{
		&net.IPNet{IP: netutils.ParseIPSloppy(testNodeIP), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy("192.168.99.11"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: netutils.ParseIPSloppy("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	}
	networkInterfacer.AddInterfaceAddr(&itf1, addrs1)

	p := &Proxier{
		exec:                     &fakeexec.FakeExec{},
		svcPortMap:               make(proxy.ServicePortMap),
		serviceChanges:           proxy.NewServiceChangeTracker(newServiceInfo, ipfamily, nil, nil),
		endpointsMap:             make(proxy.EndpointsMap),
		endpointsChanges:         proxy.NewEndpointChangeTracker(testHostname, newEndpointInfo, ipfamily, nil, nil),
		needFullSync:             true,
		iptables:                 ipt,
		masqueradeMark:           "0x4000",
		localDetector:            detectLocal,
		hostname:                 testHostname,
		serviceHealthServer:      healthcheck.NewFakeServiceHealthServer(),
		precomputedProbabilities: make([]string, 0, 1001),
		iptablesData:             bytes.NewBuffer(nil),
		existingFilterChainsData: bytes.NewBuffer(nil),
		filterChains:             proxyutil.LineBuffer{},
		filterRules:              proxyutil.LineBuffer{},
		natChains:                proxyutil.LineBuffer{},
		natRules:                 proxyutil.LineBuffer{},
		nodeIP:                   netutils.ParseIPSloppy(testNodeIP),
		localhostNodePorts:       true,
		nodePortAddresses:        proxyutil.NewNodePortAddresses(ipfamily, nil),
		networkInterfacer:        networkInterfacer,
	}
	p.setInitialized(true)
	p.syncRunner = async.NewBoundedFrequencyRunner("test-sync-runner", p.syncProxyRules, 0, time.Minute, 1)
	return p
}

// parseIPTablesData takes iptables-save output and returns a map of table name to array of lines.
func parseIPTablesData(ruleData string) (map[string][]string, error) {
	// Split ruleData at the "COMMIT" lines; given valid input, this will result in
	// one element for each table plus an extra empty element (since the ruleData
	// should end with a "COMMIT" line).
	rawTables := strings.Split(strings.TrimPrefix(ruleData, "\n"), "COMMIT\n")
	nTables := len(rawTables) - 1
	if nTables < 2 || rawTables[nTables] != "" {
		return nil, fmt.Errorf("bad ruleData (%d tables)\n%s", nTables, ruleData)
	}

	tables := make(map[string][]string, nTables)
	for i, table := range rawTables[:nTables] {
		lines := strings.Split(strings.Trim(table, "\n"), "\n")
		// The first line should be, eg, "*nat" or "*filter"
		if lines[0][0] != '*' {
			return nil, fmt.Errorf("bad ruleData (table %d starts with %q)", i+1, lines[0])
		}
		// add back the "COMMIT" line that got eaten by the strings.Split above
		lines = append(lines, "COMMIT")
		tables[lines[0][1:]] = lines
	}

	if tables["nat"] == nil {
		return nil, fmt.Errorf("bad ruleData (no %q table)", "nat")
	}
	if tables["filter"] == nil {
		return nil, fmt.Errorf("bad ruleData (no %q table)", "filter")
	}
	return tables, nil
}

func TestParseIPTablesData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		output map[string][]string
		error  string
	}{
		{
			name: "basic test",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-NODEPORTS - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.20.30.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.20.30.41 --dport 80 ! -s 10.0.0.0/24 -j KUBE-MARK-MASQ
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment ns1/svc1:p80 -j KUBE-SEP-SXIVWICOYRO3J4NJ
				-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
				-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				COMMIT
				`),
			output: map[string][]string{
				"filter": {
					`*filter`,
					`:KUBE-SERVICES - [0:0]`,
					`:KUBE-EXTERNAL-SERVICES - [0:0]`,
					`:KUBE-FORWARD - [0:0]`,
					`:KUBE-NODEPORTS - [0:0]`,
					`-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT`,
					`-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP`,
					`-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT`,
					`-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`,
					`COMMIT`,
				},
				"nat": {
					`*nat`,
					`:KUBE-SERVICES - [0:0]`,
					`:KUBE-NODEPORTS - [0:0]`,
					`:KUBE-POSTROUTING - [0:0]`,
					`:KUBE-MARK-MASQ - [0:0]`,
					`:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]`,
					`:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]`,
					`-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN`,
					`-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000`,
					`-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE`,
					`-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000`,
					`-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.20.30.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O`,
					`-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.20.30.41 --dport 80 ! -s 10.0.0.0/24 -j KUBE-MARK-MASQ`,
					`-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment ns1/svc1:p80 -j KUBE-SEP-SXIVWICOYRO3J4NJ`,
					`-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ`,
					`-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80`,
					`-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS`,
					`COMMIT`,
				},
			},
		},
		{
			name: "not enough tables",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				`),
			error: "bad ruleData (1 tables)",
		},
		{
			name: "trailing junk",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				junk
				`),
			error: "bad ruleData (2 tables)",
		},
		{
			name: "bad start line",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				`),
			error: `bad ruleData (table 2 starts with ":KUBE-SERVICES - [0:0]")`,
		},
		{
			name: "no nat",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*mangle
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				`),
			error: `bad ruleData (no "nat" table)`,
		},
		{
			name: "no filter",
			input: dedent.Dedent(`
				*mangle
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				`),
			error: `bad ruleData (no "filter" table)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := parseIPTablesData(tc.input)
			if err == nil {
				if tc.error != "" {
					t.Errorf("unexpectedly did not get error")
				} else {
					assert.Equal(t, tc.output, out)
				}
			} else {
				if tc.error == "" {
					t.Errorf("got unexpected error: %v", err)
				} else if !strings.HasPrefix(err.Error(), tc.error) {
					t.Errorf("got wrong error: %v (expected %q)", err, tc.error)
				}
			}
		})
	}
}

func countRules(tableName utiliptables.Table, ruleData string) int {
	dump, err := iptablestest.ParseIPTablesDump(ruleData)
	if err != nil {
		klog.ErrorS(err, "error parsing iptables rules")
		return -1
	}

	rules := 0
	table, err := dump.GetTable(tableName)
	if err != nil {
		klog.ErrorS(err, "can't find table", "table", tableName)
		return -1
	}

	for _, c := range table.Chains {
		rules += len(c.Rules)
	}
	return rules
}

// findAllMatches takes an array of lines and a pattern with one parenthesized group, and
// returns a sorted array of all of the unique matches of the parenthesized group.
func findAllMatches(lines []string, pattern string) []string {
	regex := regexp.MustCompile(pattern)
	allMatches := sets.New[string]()
	for _, line := range lines {
		match := regex.FindStringSubmatch(line)
		if len(match) == 2 {
			allMatches.Insert(match[1])
		}
	}
	return sets.List(allMatches)
}

// checkIPTablesRuleJumps checks that every `-j` in the given rules jumps to a chain
// that we created and added rules to
func checkIPTablesRuleJumps(ruleData string) error {
	tables, err := parseIPTablesData(ruleData)
	if err != nil {
		return err
	}

	for tableName, lines := range tables {
		// Find all of the lines like ":KUBE-SERVICES", indicating chains that
		// iptables-restore would create when loading the data.
		createdChains := sets.New[string](findAllMatches(lines, `^:([^ ]*)`)...)
		// Find all of the lines like "-X KUBE-SERVICES ..." indicating chains
		// that we are deleting because they are no longer used, and remove
		// those chains from createdChains.
		createdChains = createdChains.Delete(findAllMatches(lines, `-X ([^ ]*)`)...)

		// Find all of the lines like "-A KUBE-SERVICES ..." indicating chains
		// that we are adding at least one rule to.
		filledChains := sets.New[string](findAllMatches(lines, `-A ([^ ]*)`)...)

		// Find all of the chains that are jumped to by some rule so we can make
		// sure we only jump to valid chains.
		jumpedChains := sets.New[string](findAllMatches(lines, `-j ([^ ]*)`)...)
		// Ignore jumps to chains that we expect to exist even if kube-proxy
		// didn't create them itself.
		jumpedChains.Delete("ACCEPT", "REJECT", "DROP", "MARK", "RETURN", "DNAT", "SNAT", "MASQUERADE")

		// Find cases where we have "-A FOO ... -j BAR" but no ":BAR", meaning
		// that we are jumping to a chain that was not created.
		missingChains := jumpedChains.Difference(createdChains)
		missingChains = missingChains.Union(filledChains.Difference(createdChains))
		if len(missingChains) > 0 {
			return fmt.Errorf("some chains in %s are used but were not created: %v", tableName, missingChains.UnsortedList())
		}

		// Find cases where we have "-A FOO ... -j BAR", but no "-A BAR ...",
		// meaning that we are jumping to a chain that we didn't write out any
		// rules for, which is normally a bug. (Except that KUBE-SERVICES always
		// jumps to KUBE-NODEPORTS, even when there are no NodePort rules.)
		emptyChains := jumpedChains.Difference(filledChains)
		emptyChains.Delete(string(kubeNodePortsChain))
		if len(emptyChains) > 0 {
			return fmt.Errorf("some chains in %s are jumped to but have no rules: %v", tableName, emptyChains.UnsortedList())
		}

		// Find cases where we have ":BAR" but no "-A FOO ... -j BAR", meaning
		// that we are creating an empty chain but not using it for anything.
		extraChains := createdChains.Difference(jumpedChains)
		extraChains.Delete(string(kubeServicesChain), string(kubeExternalServicesChain), string(kubeNodePortsChain), string(kubePostroutingChain), string(kubeForwardChain), string(kubeMarkMasqChain), string(kubeProxyFirewallChain), string(kubeletFirewallChain))
		if len(extraChains) > 0 {
			return fmt.Errorf("some chains in %s are created but not used: %v", tableName, extraChains.UnsortedList())
		}
	}

	return nil
}

func TestCheckIPTablesRuleJumps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		error string
	}{
		{
			name: "valid",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.20.30.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.20.30.41 --dport 80 ! -s 10.0.0.0/24 -j KUBE-MARK-MASQ
				COMMIT
				`),
			error: "",
		},
		{
			name: "can't jump to chain that wasn't created",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				COMMIT
				`),
			error: "some chains in nat are used but were not created: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
		{
			name: "can't jump to chain that has no rules",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				COMMIT
				`),
			error: "some chains in nat are jumped to but have no rules: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
		{
			name: "can't add rules to a chain that wasn't created",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-SERVICES - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" ...
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				COMMIT
				`),
			error: "some chains in nat are used but were not created: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
		{
			name: "can't jump to chain that wasn't created",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				COMMIT
				`),
			error: "some chains in nat are used but were not created: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
		{
			name: "can't jump to chain that has no rules",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				COMMIT
				`),
			error: "some chains in nat are jumped to but have no rules: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
		{
			name: "can't add rules to a chain that wasn't created",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-SERVICES - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" ...
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				COMMIT
				`),
			error: "some chains in nat are used but were not created: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
		{
			name: "can't create chain and then not use it",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" ...
				COMMIT
				`),
			error: "some chains in nat are created but not used: [KUBE-SVC-XPGD46QRK7WJZT7O]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkIPTablesRuleJumps(tc.input)
			if err == nil {
				if tc.error != "" {
					t.Errorf("unexpectedly did not get error")
				}
			} else {
				if tc.error == "" {
					t.Errorf("got unexpected error: %v", err)
				} else if !strings.HasPrefix(err.Error(), tc.error) {
					t.Errorf("got wrong error: %v (expected %q)", err, tc.error)
				}
			}
		})
	}
}

// orderByCommentServiceName is a helper function that orders two IPTables rules
// based on the service name in their comment. (If either rule has no comment then the
// return value is undefined.)
func orderByCommentServiceName(rule1, rule2 *iptablestest.Rule) bool {
	if rule1.Comment == nil || rule2.Comment == nil {
		return false
	}
	name1, name2 := rule1.Comment.Value, rule2.Comment.Value

	// The service name is the comment up to the first space or colon
	i := strings.IndexAny(name1, " :")
	if i != -1 {
		name1 = name1[:i]
	}
	i = strings.IndexAny(name2, " :")
	if i != -1 {
		name2 = name2[:i]
	}

	return name1 < name2
}

// sortIPTablesRules sorts `iptables-restore` output so as to not depend on the order that
// Services get processed in, while preserving the relative ordering of related rules.
func sortIPTablesRules(ruleData string) (string, error) {
	dump, err := iptablestest.ParseIPTablesDump(ruleData)
	if err != nil {
		return "", err
	}

	// Sort tables
	sort.Slice(dump.Tables, func(i, j int) bool {
		return dump.Tables[i].Name < dump.Tables[j].Name
	})

	// Sort chains
	for t := range dump.Tables {
		table := &dump.Tables[t]
		sort.Slice(table.Chains, func(i, j int) bool {
			switch {
			case table.Chains[i].Name == kubeNodePortsChain:
				// KUBE-NODEPORTS comes before anything
				return true
			case table.Chains[j].Name == kubeNodePortsChain:
				// anything goes after KUBE-NODEPORTS
				return false
			case table.Chains[i].Name == kubeServicesChain:
				// KUBE-SERVICES comes before anything (except KUBE-NODEPORTS)
				return true
			case table.Chains[j].Name == kubeServicesChain:
				// anything (except KUBE-NODEPORTS) goes after KUBE-SERVICES
				return false
			case strings.HasPrefix(string(table.Chains[i].Name), "KUBE-") && !strings.HasPrefix(string(table.Chains[j].Name), "KUBE-"):
				// KUBE-* comes before non-KUBE-*
				return true
			case !strings.HasPrefix(string(table.Chains[i].Name), "KUBE-") && strings.HasPrefix(string(table.Chains[j].Name), "KUBE-"):
				// non-KUBE-* goes after KUBE-*
				return false
			default:
				// We have two KUBE-* chains or two non-KUBE-* chains; either
				// way they sort alphabetically
				return table.Chains[i].Name < table.Chains[j].Name
			}
		})
	}

	// Sort KUBE-NODEPORTS chains by service name
	chain, _ := dump.GetChain(utiliptables.TableFilter, kubeNodePortsChain)
	if chain != nil {
		sort.SliceStable(chain.Rules, func(i, j int) bool {
			return orderByCommentServiceName(chain.Rules[i], chain.Rules[j])
		})
	}
	chain, _ = dump.GetChain(utiliptables.TableNAT, kubeNodePortsChain)
	if chain != nil {
		sort.SliceStable(chain.Rules, func(i, j int) bool {
			return orderByCommentServiceName(chain.Rules[i], chain.Rules[j])
		})
	}

	// Sort KUBE-SERVICES chains by service name (but keeping the "must be the last
	// rule" rule in the "nat" table's KUBE-SERVICES chain last).
	chain, _ = dump.GetChain(utiliptables.TableFilter, kubeServicesChain)
	if chain != nil {
		sort.SliceStable(chain.Rules, func(i, j int) bool {
			return orderByCommentServiceName(chain.Rules[i], chain.Rules[j])
		})
	}
	chain, _ = dump.GetChain(utiliptables.TableNAT, kubeServicesChain)
	if chain != nil {
		sort.SliceStable(chain.Rules, func(i, j int) bool {
			if chain.Rules[i].Comment != nil && strings.Contains(chain.Rules[i].Comment.Value, "must be the last rule") {
				return false
			} else if chain.Rules[j].Comment != nil && strings.Contains(chain.Rules[j].Comment.Value, "must be the last rule") {
				return true
			}
			return orderByCommentServiceName(chain.Rules[i], chain.Rules[j])
		})
	}

	return dump.String(), nil
}

func TestSortIPTablesRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		output string
		error  string
	}{
		{
			name: "basic test using each match type",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j DROP
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j DROP
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m addrtype --dst-type LOCAL -m tcp -p tcp --dport 3001 -j DROP
				-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				-A KUBE-PROXY-FIREWALL -m comment --comment "ns5/svc5:p80 traffic not accepted by KUBE-FW-NUKIZ6OKUXPJNT4C" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j DROP
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-NODEPORTS - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
				:KUBE-SVC-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-EXT-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-SVL-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-FW-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-SEP-RS4RBKLTHTF2IUXJ - [0:0]
				:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
				:KUBE-SEP-OYPFS5VJICHGATKP - [0:0]
				:KUBE-SVC-4SW47YFZTEDKD3PK - [0:0]
				:KUBE-SEP-UKSFD7AGPMPPLUHC - [0:0]
				:KUBE-SEP-C6EBXVWJJZMIWKLZ - [0:0]
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment ns1/svc1:p80 -j KUBE-SEP-SXIVWICOYRO3J4NJ
				-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
				-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 external IP" -m tcp -p tcp -d 192.168.99.11 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-FW-GNZBNJ2PO5MGZ6GT
				-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment ns2/svc2:p80 -j KUBE-SEP-RS4RBKLTHTF2IUXJ
				-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -s 10.180.0.2 -j KUBE-MARK-MASQ
				-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.2:80
				-A KUBE-FW-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 loadbalancer IP" -s 203.0.113.0/25 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
				-A KUBE-FW-GNZBNJ2PO5MGZ6GT -m comment --comment "other traffic to s2/svc2:p80 will be dropped by KUBE-PROXY-FIREWALL"
				-A KUBE-NODEPORTS -m comment --comment ns2/svc2:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "Redirect pods trying to reach external loadbalancer VIP to clusterIP" -s 10.0.0.0/8 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "masquerade LOCAL traffic for ns2/svc2:p80 LB IP" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "route LOCAL traffic for ns2/svc2:p80 LB IP to service chain" -m addrtype --src-type LOCAL -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -j KUBE-SVL-GNZBNJ2PO5MGZ6GT
				-A KUBE-SVL-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 has no local endpoints" -j KUBE-MARK-DROP
				-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
				-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-NODEPORTS -m comment --comment ns3/svc3:p80 -m tcp -p tcp --dport 3002 -j KUBE-SVC-X27LE4BHSL4DOUIK
				-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment ns3/svc3:p80 -m tcp -p tcp --dport 3002 -j KUBE-MARK-MASQ
				-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment ns3/svc3:p80 -j KUBE-SEP-OYPFS5VJICHGATKP
				-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -s 10.180.0.3 -j KUBE-MARK-MASQ
				-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.3:80
				-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
				-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment ns4/svc4:p80 -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-UKSFD7AGPMPPLUHC
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment ns4/svc4:p80 -j KUBE-SEP-C6EBXVWJJZMIWKLZ
				-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -s 10.180.0.4 -j KUBE-MARK-MASQ
				-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.4:80
				-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -s 10.180.0.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.5:80
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				COMMIT
				`),
			output: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j DROP
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j DROP
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m addrtype --dst-type LOCAL -m tcp -p tcp --dport 3001 -j DROP
				-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				-A KUBE-PROXY-FIREWALL -m comment --comment "ns5/svc5:p80 traffic not accepted by KUBE-FW-NUKIZ6OKUXPJNT4C" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j DROP
				COMMIT
				*nat
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXT-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-FW-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-C6EBXVWJJZMIWKLZ - [0:0]
				:KUBE-SEP-OYPFS5VJICHGATKP - [0:0]
				:KUBE-SEP-RS4RBKLTHTF2IUXJ - [0:0]
				:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
				:KUBE-SEP-UKSFD7AGPMPPLUHC - [0:0]
				:KUBE-SVC-4SW47YFZTEDKD3PK - [0:0]
				:KUBE-SVC-GNZBNJ2PO5MGZ6GT - [0:0]
				:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
				:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
				:KUBE-SVL-GNZBNJ2PO5MGZ6GT - [0:0]
				-A KUBE-NODEPORTS -m comment --comment ns2/svc2:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
				-A KUBE-NODEPORTS -m comment --comment ns3/svc3:p80 -m tcp -p tcp --dport 3002 -j KUBE-SVC-X27LE4BHSL4DOUIK
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 external IP" -m tcp -p tcp -d 192.168.99.11 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-FW-GNZBNJ2PO5MGZ6GT
				-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
				-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
				-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "Redirect pods trying to reach external loadbalancer VIP to clusterIP" -s 10.0.0.0/8 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "masquerade LOCAL traffic for ns2/svc2:p80 LB IP" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "route LOCAL traffic for ns2/svc2:p80 LB IP to service chain" -m addrtype --src-type LOCAL -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
				-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -j KUBE-SVL-GNZBNJ2PO5MGZ6GT
				-A KUBE-FW-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 loadbalancer IP" -s 203.0.113.0/25 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
				-A KUBE-FW-GNZBNJ2PO5MGZ6GT -m comment --comment "other traffic to s2/svc2:p80 will be dropped by KUBE-PROXY-FIREWALL"
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -s 10.180.0.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.5:80
				-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -s 10.180.0.3 -j KUBE-MARK-MASQ
				-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.3:80
				-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -s 10.180.0.2 -j KUBE-MARK-MASQ
				-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.2:80
				-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
				-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
				-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -s 10.180.0.4 -j KUBE-MARK-MASQ
				-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.4:80
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment ns4/svc4:p80 -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-UKSFD7AGPMPPLUHC
				-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment ns4/svc4:p80 -j KUBE-SEP-C6EBXVWJJZMIWKLZ
				-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment ns2/svc2:p80 -j KUBE-SEP-RS4RBKLTHTF2IUXJ
				-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment ns3/svc3:p80 -m tcp -p tcp --dport 3002 -j KUBE-MARK-MASQ
				-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment ns3/svc3:p80 -j KUBE-SEP-OYPFS5VJICHGATKP
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment ns1/svc1:p80 -j KUBE-SEP-SXIVWICOYRO3J4NJ
				-A KUBE-SVL-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 has no local endpoints" -j KUBE-MARK-DROP
				COMMIT
				`),
		},
		{
			name: "extra tables",
			input: dedent.Dedent(`
				*filter
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*mangle
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-NODEPORTS - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				`),
			output: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*mangle
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FORWARD - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				`),
		},
		{
			name: "correctly match same service name in different styles of comments",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" svc2 line 1
				-A KUBE-SERVICES -m comment --comment ns2/svc2 svc2 line 2
				-A KUBE-SERVICES -m comment --comment "ns2/svc2 blah" svc2 line 3
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" svc1 line 1
				-A KUBE-SERVICES -m comment --comment ns1/svc1 svc1 line 2
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 blah" svc1 line 3
				-A KUBE-SERVICES -m comment --comment ns4/svc4 svc4 line 1
				-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" svc4 line 2
				-A KUBE-SERVICES -m comment --comment "ns4/svc4 blah" svc4 line 3
				-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" svc3 line 1
				-A KUBE-SERVICES -m comment --comment "ns3/svc3 blah" svc3 line 2
				-A KUBE-SERVICES -m comment --comment ns3/svc3 svc3 line 3
				COMMIT
				`),
			output: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" svc1 line 1
				-A KUBE-SERVICES -m comment --comment ns1/svc1 svc1 line 2
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 blah" svc1 line 3
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" svc2 line 1
				-A KUBE-SERVICES -m comment --comment ns2/svc2 svc2 line 2
				-A KUBE-SERVICES -m comment --comment "ns2/svc2 blah" svc2 line 3
				-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" svc3 line 1
				-A KUBE-SERVICES -m comment --comment "ns3/svc3 blah" svc3 line 2
				-A KUBE-SERVICES -m comment --comment ns3/svc3 svc3 line 3
				-A KUBE-SERVICES -m comment --comment ns4/svc4 svc4 line 1
				-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" svc4 line 2
				-A KUBE-SERVICES -m comment --comment "ns4/svc4 blah" svc4 line 3
				COMMIT
				`),
		},
		{
			name: "unexpected junk lines are preserved",
			input: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-SEP-RS4RBKLTHTF2IUXJ - [0:0]
				:KUBE-AAAAA - [0:0]
				:KUBE-ZZZZZ - [0:0]
				:WHY-IS-THIS-CHAIN-HERE - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" svc2 line 1
				-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.2:80
				-A KUBE-ZZZZZ -m comment --comment "mystery chain number 1"
				-A KUBE-SERVICES -m comment --comment ns2/svc2 svc2 line 2
				-A WHY-IS-THIS-CHAIN-HERE -j ACCEPT
				-A KUBE-SERVICES -m comment --comment "ns2/svc2 blah" svc2 line 3
				-A KUBE-AAAAA -m comment --comment "mystery chain number 2"
				COMMIT
				`),
			output: dedent.Dedent(`
				*filter
				COMMIT
				*nat
				:KUBE-SERVICES - [0:0]
				:KUBE-AAAAA - [0:0]
				:KUBE-SEP-RS4RBKLTHTF2IUXJ - [0:0]
				:KUBE-ZZZZZ - [0:0]
				:WHY-IS-THIS-CHAIN-HERE - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" svc2 line 1
				-A KUBE-SERVICES -m comment --comment ns2/svc2 svc2 line 2
				-A KUBE-SERVICES -m comment --comment "ns2/svc2 blah" svc2 line 3
				-A KUBE-AAAAA -m comment --comment "mystery chain number 2"
				-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.2:80
				-A KUBE-ZZZZZ -m comment --comment "mystery chain number 1"
				-A WHY-IS-THIS-CHAIN-HERE -j ACCEPT
				COMMIT
				`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := sortIPTablesRules(tc.input)
			if err == nil {
				if tc.error != "" {
					t.Errorf("unexpectedly did not get error")
				} else {
					assert.Equal(t, strings.TrimPrefix(tc.output, "\n"), out)
				}
			} else {
				if tc.error == "" {
					t.Errorf("got unexpected error: %v", err)
				} else if !strings.HasPrefix(err.Error(), tc.error) {
					t.Errorf("got wrong error: %v (expected %q)", err, tc.error)
				}
			}
		})
	}
}

// getLine returns a string containing the file and line number of the caller, if
// possible. This is useful in tests with a large number of cases - when something goes
// wrong you can find which case more easily.
func getLine() string {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return ""
	}
	return fmt.Sprintf(" (from %s:%d)", file, line)
}

// assertIPTablesRulesEqual asserts that the generated rules in result match the rules in
// expected, ignoring irrelevant ordering differences. By default this also checks the
// rules for consistency (eg, no jumps to chains that aren't defined), but that can be
// disabled by passing false for checkConsistency if you are passing a partial set of rules.
func assertIPTablesRulesEqual(t *testing.T, lineStr string, checkConsistency bool, expected, result string) {
	expected = strings.TrimLeft(expected, " \t\n")

	result, err := sortIPTablesRules(strings.TrimLeft(result, " \t\n"))
	if err != nil {
		t.Fatalf("%s", err)
	}

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("rules do not match%s:\ndiff:\n%s\nfull result:\n```\n%s```", lineStr, diff, result)
	}

	if checkConsistency {
		err = checkIPTablesRuleJumps(expected)
		if err != nil {
			t.Fatalf("%s%s", err, lineStr)
		}
	}
}

// assertIPTablesRulesNotEqual asserts that the generated rules in result DON'T match the
// rules in expected, ignoring irrelevant ordering differences.
func assertIPTablesRulesNotEqual(t *testing.T, lineStr string, expected, result string) {
	expected = strings.TrimLeft(expected, " \t\n")

	result, err := sortIPTablesRules(strings.TrimLeft(result, " \t\n"))
	if err != nil {
		t.Fatalf("%s", err)
	}

	if cmp.Equal(expected, result) {
		t.Errorf("rules do not differ%s:\nfull result:\n```\n%s```", lineStr, result)
	}

	err = checkIPTablesRuleJumps(expected)
	if err != nil {
		t.Fatalf("%s", err)
	}
	err = checkIPTablesRuleJumps(result)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

// addressMatches helps test whether an iptables rule such as "! -s 192.168.0.0/16" matches
// ipStr. address.Value is either an IP address ("1.2.3.4") or a CIDR string
// ("1.2.3.0/24").
func addressMatches(t *testing.T, address *iptablestest.IPTablesValue, ipStr string) bool {
	ip := netutils.ParseIPSloppy(ipStr)
	if ip == nil {
		t.Fatalf("Bad IP in test case: %s", ipStr)
	}

	var matches bool
	if strings.Contains(address.Value, "/") {
		_, cidr, err := netutils.ParseCIDRSloppy(address.Value)
		if err != nil {
			t.Errorf("Bad CIDR in kube-proxy output: %v", err)
		}
		matches = cidr.Contains(ip)
	} else {
		ip2 := netutils.ParseIPSloppy(address.Value)
		if ip2 == nil {
			t.Errorf("Bad IP/CIDR in kube-proxy output: %s", address.Value)
		}
		matches = ip.Equal(ip2)
	}
	return (!address.Negated && matches) || (address.Negated && !matches)
}

// iptablesTracer holds data used while virtually tracing a packet through a set of
// iptables rules
type iptablesTracer struct {
	ipt    *iptablestest.FakeIPTables
	nodeIP string
	t      *testing.T

	// matches accumulates the list of rules that were matched, for debugging purposes.
	matches []string

	// outputs accumulates the list of matched terminal rule targets (endpoint
	// IP:ports, or a special target like "REJECT") and is eventually used to generate
	// the return value of tracePacket.
	outputs []string

	// markMasq tracks whether the packet has been marked for masquerading
	markMasq bool
}

// newIPTablesTracer creates an iptablesTracer. nodeIP is the IP to treat as the local
// node IP (for determining whether rules with "--src-type LOCAL" or "--dst-type LOCAL"
// match).
func newIPTablesTracer(t *testing.T, ipt *iptablestest.FakeIPTables, nodeIP string) *iptablesTracer {
	return &iptablesTracer{
		ipt:    ipt,
		nodeIP: nodeIP,
		t:      t,
	}
}

// ruleMatches checks if the given iptables rule matches (at least probabilistically) a
// packet with the given sourceIP, protocol, destIP, and destPort.
func (tracer *iptablesTracer) ruleMatches(rule *iptablestest.Rule, sourceIP, protocol, destIP, destPort string) bool {
	// The sub-rules within an iptables rule are ANDed together, so the rule only
	// matches if all of them match. So go through the subrules, and if any of them
	// DON'T match, then fail.

	if rule.SourceAddress != nil && !addressMatches(tracer.t, rule.SourceAddress, sourceIP) {
		return false
	}
	if rule.SourceType != nil {
		addrtype := "not-matched"
		if sourceIP == tracer.nodeIP || sourceIP == "127.0.0.1" {
			addrtype = "LOCAL"
		}
		if !rule.SourceType.Matches(addrtype) {
			return false
		}
	}

	if rule.Protocol != nil && !rule.Protocol.Matches(protocol) {
		return false
	}

	if rule.DestinationAddress != nil && !addressMatches(tracer.t, rule.DestinationAddress, destIP) {
		return false
	}
	if rule.DestinationType != nil {
		addrtype := "not-matched"
		if destIP == tracer.nodeIP || destIP == "127.0.0.1" {
			addrtype = "LOCAL"
		}
		if !rule.DestinationType.Matches(addrtype) {
			return false
		}
	}
	if rule.DestinationPort != nil && !rule.DestinationPort.Matches(destPort) {
		return false
	}

	// Any rule that checks for past state/history does not match
	if rule.AffinityCheck != nil || rule.MarkCheck != nil || rule.CTStateCheck != nil {
		return false
	}

	// Anything else is assumed to match
	return true
}

// runChain runs the given packet through the rules in the given table and chain, updating
// tracer's internal state accordingly. It returns true if it hits a terminal action.
func (tracer *iptablesTracer) runChain(table utiliptables.Table, chain utiliptables.Chain, sourceIP, protocol, destIP, destPort string) bool {
	c, _ := tracer.ipt.Dump.GetChain(table, chain)
	if c == nil {
		return false
	}

	for _, rule := range c.Rules {
		if rule.Jump == nil {
			continue
		}

		if !tracer.ruleMatches(rule, sourceIP, protocol, destIP, destPort) {
			continue
		}
		// record the matched rule for debugging purposes
		tracer.matches = append(tracer.matches, rule.Raw)

		switch rule.Jump.Value {
		case "KUBE-MARK-MASQ":
			tracer.markMasq = true
			continue

		case "ACCEPT", "REJECT", "DROP":
			// (only valid in filter)
			tracer.outputs = append(tracer.outputs, rule.Jump.Value)
			return true

		case "DNAT":
			// (only valid in nat)
			tracer.outputs = append(tracer.outputs, rule.DNATDestination.Value)
			return true

		default:
			// We got a "-j KUBE-SOMETHING", so process that chain
			terminated := tracer.runChain(table, utiliptables.Chain(rule.Jump.Value), sourceIP, protocol, destIP, destPort)

			// If the subchain hit a terminal rule AND the rule that sent us
			// to that chain was non-probabilistic, then this chain terminates
			// as well. But if we went there because of a --probability rule,
			// then we want to keep accumulating further matches against this
			// chain.
			if terminated && rule.Probability == nil {
				return true
			}
		}
	}

	return false
}

// tracePacket determines what would happen to a packet with the given sourceIP, protocol,
// destIP, and destPort, given the indicated iptables ruleData. nodeIP is the local node
// IP (for rules matching "LOCAL"). (The protocol value should be lowercase as in iptables
// rules, not uppercase as in corev1.)
//
// The return values are: an array of matched rules (for debugging), the final packet
// destinations (a comma-separated list of IPs, or one of the special targets "ACCEPT",
// "DROP", or "REJECT"), and whether the packet would be masqueraded.
func tracePacket(t *testing.T, ipt *iptablestest.FakeIPTables, sourceIP, protocol, destIP, destPort, nodeIP string) ([]string, string, bool) {
	tracer := newIPTablesTracer(t, ipt, nodeIP)

	// nat:PREROUTING goes first
	tracer.runChain(utiliptables.TableNAT, utiliptables.ChainPrerouting, sourceIP, protocol, destIP, destPort)

	// After the PREROUTING rules run, pending DNATs are processed (which would affect
	// the destination IP that later rules match against).
	if len(tracer.outputs) != 0 {
		destIP = strings.Split(tracer.outputs[0], ":")[0]
	}

	// Now the filter rules get run; exactly which ones depend on whether this is an
	// inbound, outbound, or intra-host packet, which we don't know. So we just run
	// the interesting tables manually. (Theoretically this could cause conflicts in
	// the future in which case we'd have to do something more complicated.)
	tracer.runChain(utiliptables.TableFilter, kubeServicesChain, sourceIP, protocol, destIP, destPort)
	tracer.runChain(utiliptables.TableFilter, kubeExternalServicesChain, sourceIP, protocol, destIP, destPort)
	tracer.runChain(utiliptables.TableFilter, kubeNodePortsChain, sourceIP, protocol, destIP, destPort)
	tracer.runChain(utiliptables.TableFilter, kubeProxyFirewallChain, sourceIP, protocol, destIP, destPort)

	// Finally, the nat:POSTROUTING rules run, but the only interesting thing that
	// happens there is that the masquerade mark gets turned into actual masquerading.

	return tracer.matches, strings.Join(tracer.outputs, ", "), tracer.markMasq
}

type packetFlowTest struct {
	name     string
	sourceIP string
	protocol v1.Protocol
	destIP   string
	destPort int
	output   string
	masq     bool
}

func runPacketFlowTests(t *testing.T, lineStr string, ipt *iptablestest.FakeIPTables, nodeIP string, testCases []packetFlowTest) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			protocol := strings.ToLower(string(tc.protocol))
			if protocol == "" {
				protocol = "tcp"
			}
			matches, output, masq := tracePacket(t, ipt, tc.sourceIP, protocol, tc.destIP, fmt.Sprintf("%d", tc.destPort), nodeIP)
			var errors []string
			if output != tc.output {
				errors = append(errors, fmt.Sprintf("wrong output: expected %q got %q", tc.output, output))
			}
			if masq != tc.masq {
				errors = append(errors, fmt.Sprintf("wrong masq: expected %v got %v", tc.masq, masq))
			}
			if errors != nil {
				t.Errorf("Test %q of a %s packet from %s to %s:%d%s got result:\n%s\n\nBy matching:\n%s\n\n",
					tc.name, protocol, tc.sourceIP, tc.destIP, tc.destPort, lineStr, strings.Join(errors, "\n"), strings.Join(matches, "\n"))
			}
		})
	}
}

// This tests tracePackets against static data, just to make sure we match things in the
// way we expect to.
func TestTracePackets(t *testing.T) {
	rules := dedent.Dedent(`
		*filter
		:INPUT - [0:0]
		:FORWARD - [0:0]
		:OUTPUT - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A INPUT -m comment --comment kubernetes health check service ports -j KUBE-NODEPORTS
		-A INPUT -m conntrack --ctstate NEW -m comment --comment kubernetes externally-visible service portals -j KUBE-EXTERNAL-SERVICES
		-A FORWARD -m comment --comment kubernetes forwarding rules -j KUBE-FORWARD
		-A FORWARD -m conntrack --ctstate NEW -m comment --comment kubernetes service portals -j KUBE-SERVICES
		-A FORWARD -m conntrack --ctstate NEW -m comment --comment kubernetes externally-visible service portals -j KUBE-EXTERNAL-SERVICES
		-A OUTPUT -m conntrack --ctstate NEW -m comment --comment kubernetes service portals -j KUBE-SERVICES
		-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
		-A KUBE-SERVICES -m comment --comment "ns6/svc6:p80 has no endpoints" -m tcp -p tcp -d 172.30.0.46 --dport 80 -j REJECT
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j DROP
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j DROP
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m addrtype --dst-type LOCAL -m tcp -p tcp --dport 3001 -j DROP
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		-A KUBE-PROXY-FIREWALL -m comment --comment "ns5/svc5:p80 traffic not accepted by KUBE-FW-NUKIZ6OKUXPJNT4C" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j DROP
		COMMIT
		*nat
		:PREROUTING - [0:0]
		:INPUT - [0:0]
		:OUTPUT - [0:0]
		:POSTROUTING - [0:0]
		:KUBE-EXT-4SW47YFZTEDKD3PK - [0:0]
		:KUBE-EXT-GNZBNJ2PO5MGZ6GT - [0:0]
		:KUBE-EXT-NUKIZ6OKUXPJNT4C - [0:0]
		:KUBE-EXT-X27LE4BHSL4DOUIK - [0:0]
		:KUBE-FW-NUKIZ6OKUXPJNT4C - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-NODEPORTS - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-C6EBXVWJJZMIWKLZ - [0:0]
		:KUBE-SEP-I77PXRDZVX7PMWMN - [0:0]
		:KUBE-SEP-OYPFS5VJICHGATKP - [0:0]
		:KUBE-SEP-RS4RBKLTHTF2IUXJ - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SEP-UKSFD7AGPMPPLUHC - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-SVC-4SW47YFZTEDKD3PK - [0:0]
		:KUBE-SVC-GNZBNJ2PO5MGZ6GT - [0:0]
		:KUBE-SVC-NUKIZ6OKUXPJNT4C - [0:0]
		:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A PREROUTING -m comment --comment kubernetes service portals -j KUBE-SERVICES
		-A OUTPUT -m comment --comment kubernetes service portals -j KUBE-SERVICES
		-A POSTROUTING -m comment --comment kubernetes postrouting rules -j KUBE-POSTROUTING
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-NODEPORTS -m comment --comment ns2/svc2:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
		-A KUBE-NODEPORTS -m comment --comment ns3/svc3:p80 -m tcp -p tcp --dport 3003 -j KUBE-EXT-X27LE4BHSL4DOUIK
		-A KUBE-NODEPORTS -m comment --comment ns5/svc5:p80 -m tcp -p tcp --dport 3002 -j KUBE-EXT-NUKIZ6OKUXPJNT4C
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.33 --dport 80 -j KUBE-EXT-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "ns5/svc5:p80 cluster IP" -m tcp -p tcp -d 172.30.0.45 --dport 80 -j KUBE-SVC-NUKIZ6OKUXPJNT4C
		-A KUBE-SERVICES -m comment --comment "ns5/svc5:p80 loadbalancer IP" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j KUBE-FW-NUKIZ6OKUXPJNT4C
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-4SW47YFZTEDKD3PK -m comment --comment "masquerade traffic for ns4/svc4:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-4SW47YFZTEDKD3PK -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "pod traffic for ns2/svc2:p80 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
		-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "masquerade LOCAL traffic for ns2/svc2:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "route LOCAL traffic for ns2/svc2:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
		-A KUBE-EXT-NUKIZ6OKUXPJNT4C -m comment --comment "masquerade traffic for ns5/svc5:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-NUKIZ6OKUXPJNT4C -j KUBE-SVC-NUKIZ6OKUXPJNT4C
		-A KUBE-EXT-X27LE4BHSL4DOUIK -m comment --comment "masquerade traffic for ns3/svc3:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-X27LE4BHSL4DOUIK -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-FW-NUKIZ6OKUXPJNT4C -m comment --comment "ns5/svc5:p80 loadbalancer IP" -s 203.0.113.0/25 -j KUBE-EXT-NUKIZ6OKUXPJNT4C
		-A KUBE-FW-NUKIZ6OKUXPJNT4C -m comment --comment "other traffic to ns5/svc5:p80 will be dropped by KUBE-PROXY-FIREWALL"
		-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -s 10.180.0.5 -j KUBE-MARK-MASQ
		-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.5:80
		-A KUBE-SEP-I77PXRDZVX7PMWMN -m comment --comment ns5/svc5:p80 -s 10.180.0.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-I77PXRDZVX7PMWMN -m comment --comment ns5/svc5:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.3:80
		-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -s 10.180.0.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.3:80
		-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -s 10.180.0.2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.2:80
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -s 10.180.0.4 -j KUBE-MARK-MASQ
		-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.4:80
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 -> 10.180.0.4:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-UKSFD7AGPMPPLUHC
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 -> 10.180.0.5:80" -j KUBE-SEP-C6EBXVWJJZMIWKLZ
		-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 -> 10.180.0.2:80" -j KUBE-SEP-RS4RBKLTHTF2IUXJ
		-A KUBE-SVC-NUKIZ6OKUXPJNT4C -m comment --comment "ns5/svc5:p80 cluster IP" -m tcp -p tcp -d 172.30.0.45 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-NUKIZ6OKUXPJNT4C -m comment --comment "ns5/svc5:p80 -> 10.180.0.3:80" -j KUBE-SEP-I77PXRDZVX7PMWMN
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.180.0.3:80" -j KUBE-SEP-OYPFS5VJICHGATKP
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -j KUBE-SEP-SXIVWICOYRO3J4NJ
		COMMIT
		`)

	ipt := iptablestest.NewFake()
	err := ipt.RestoreAll([]byte(rules), utiliptables.NoFlushTables, utiliptables.RestoreCounters)
	if err != nil {
		t.Fatalf("Restore of test data failed: %v", err)
	}

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "no match",
			sourceIP: "10.0.0.2",
			destIP:   "10.0.0.3",
			destPort: 80,
			output:   "",
		},
		{
			name:     "single endpoint",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80",
		},
		{
			name:     "multiple endpoints",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.44",
			destPort: 80,
			output:   "10.180.0.4:80, 10.180.0.5:80",
		},
		{
			name:     "LOCAL, KUBE-MARK-MASQ",
			sourceIP: testNodeIP,
			destIP:   "192.168.99.22",
			destPort: 80,
			output:   "10.180.0.2:80",
			masq:     true,
		},
		{
			name:     "DROP",
			sourceIP: testExternalClient,
			destIP:   "192.168.99.22",
			destPort: 80,
			output:   "DROP",
		},
		{
			name:     "ACCEPT (NodePortHealthCheck)",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 30000,
			output:   "ACCEPT",
		},
		{
			name:     "REJECT",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.46",
			destPort: 80,
			output:   "REJECT",
		},
	})
}

func makeTestService(namespace, name string, svcFunc func(*v1.Service)) *v1.Service {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{},
		},
		Spec:   v1.ServiceSpec{},
		Status: v1.ServiceStatus{},
	}
	svcFunc(svc)
	return svc
}

func addTestPort(array []v1.ServicePort, name string, protocol v1.Protocol, port, nodeport int32, targetPort int) []v1.ServicePort {
	svcPort := v1.ServicePort{
		Name:       name,
		Protocol:   protocol,
		Port:       port,
		NodePort:   nodeport,
		TargetPort: intstr.FromInt(targetPort),
	}
	return append(array, svcPort)
}

func populateEndpointSlices(proxier *Proxier, allEndpointSlices ...*discovery.EndpointSlice) {
	for i := range allEndpointSlices {
		proxier.OnEndpointSliceAdd(allEndpointSlices[i])
	}
}

func makeTestEndpointSlice(namespace, name string, sliceNum int, epsFunc func(*discovery.EndpointSlice)) *discovery.EndpointSlice {
	eps := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", name, sliceNum),
			Namespace: namespace,
			Labels:    map[string]string{discovery.LabelServiceName: name},
		},
	}
	epsFunc(eps)
	return eps
}

func makeNSN(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func makeServicePortName(ns, name, port string, protocol v1.Protocol) proxy.ServicePortName {
	return proxy.ServicePortName{
		NamespacedName: makeNSN(ns, name),
		Port:           port,
		Protocol:       protocol,
	}
}

func makeServiceMap(proxier *Proxier, allServices ...*v1.Service) {
	for i := range allServices {
		proxier.OnServiceAdd(allServices[i])
	}

	proxier.mu.Lock()
	defer proxier.mu.Unlock()
	proxier.servicesSynced = true
}
