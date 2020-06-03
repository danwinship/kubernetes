// +build linux

/*
Copyright 2018 The Kubernetes Authors.

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

package kubelet

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"
	utilnet "k8s.io/utils/net"
)

func (kl *Kubelet) initNetworkUtil() {
	exec := utilexec.New()
	dualStack := utilfeature.DefaultFeatureGate.Enabled(features.IPv6DualStack)

	var iptClients []utiliptables.Interface
	// Manage IPv4 iptables rules if dual-stack is enabled, if there is no user-specified node IP,
	// or if the user-specified node IP is IPv4
	if dualStack || kl.nodeIP == nil || !utilnet.IsIPv6(kl.nodeIP) {
		iptClients = append(iptClients, utiliptables.New(exec, utiliptables.ProtocolIPv4))
	}
	// Manage IPv6 iptables rules if dual-stack is enabled, or if the user-specified node IP is IPv6
	if dualStack || (kl.nodeIP != nil && utilnet.IsIPv6(kl.nodeIP)) {
		iptClients = append(iptClients, utiliptables.New(exec, utiliptables.ProtocolIPv6))
	}

	for _, iptClient := range iptClients {
		kl.syncNetworkUtil(iptClient)
		go iptClient.Monitor(
			utiliptables.Chain("KUBE-KUBELET-CANARY"),
			[]utiliptables.Table{utiliptables.TableMangle, utiliptables.TableNAT, utiliptables.TableFilter},
			func () { kl.syncNetworkUtil(iptClient) },
			1*time.Minute, wait.NeverStop,
		)
	}
}

// syncNetworkUtil ensures the network utility are present on host.
// Network util includes:
// 1. 	In nat table, KUBE-MARK-DROP rule to mark connections for dropping
// 	Marked connection will be drop on INPUT/OUTPUT Chain in filter table
// 2. 	In nat table, KUBE-MARK-MASQ rule to mark connections for SNAT
// 	Marked connection will get SNAT on POSTROUTING Chain in nat table
func (kl *Kubelet) syncNetworkUtil(iptClient utiliptables.Interface) {
	// Setup KUBE-MARK-DROP rules
	dropMark := getIPTablesMark(kl.iptablesDropBit)
	if _, err := iptClient.EnsureChain(utiliptables.TableNAT, KubeMarkDropChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkDropChain, err)
		return
	}
	if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubeMarkDropChain, "-j", "MARK", "--set-xmark", dropMark); err != nil {
		klog.Errorf("Failed to ensure marking rule for %v: %v", KubeMarkDropChain, err)
		return
	}
	if _, err := iptClient.EnsureChain(utiliptables.TableFilter, KubeFirewallChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableFilter, KubeFirewallChain, err)
		return
	}
	if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableFilter, KubeFirewallChain,
		"-m", "comment", "--comment", "kubernetes firewall for dropping marked packets",
		"-m", "mark", "--mark", dropMark,
		"-j", "DROP"); err != nil {
		klog.Errorf("Failed to ensure rule to drop packet marked by %v in %v chain %v: %v", KubeMarkDropChain, utiliptables.TableFilter, KubeFirewallChain, err)
		return
	}

	// drop all non-local packets to localhost if they're not part of an existing
	// forwarded connection. See #90259
	if !iptClient.IsIPv6() { // ipv6 doesn't have this issue
		if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableFilter, KubeFirewallChain,
			"-m", "comment", "--comment", "block incoming localnet connections",
			"--dst", "127.0.0.0/8",
			"!", "--src", "127.0.0.0/8",
			"-m", "conntrack",
			"!", "--ctstate", "RELATED,ESTABLISHED,DNAT",
			"-j", "DROP"); err != nil {
			klog.Errorf("Failed to ensure rule to drop invalid localhost packets in %v chain %v: %v", utiliptables.TableFilter, KubeFirewallChain, err)
			return
		}
	}

	if _, err := iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, utiliptables.ChainOutput, "-j", string(KubeFirewallChain)); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableFilter, utiliptables.ChainOutput, KubeFirewallChain, err)
		return
	}
	if _, err := iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, utiliptables.ChainInput, "-j", string(KubeFirewallChain)); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableFilter, utiliptables.ChainInput, KubeFirewallChain, err)
		return
	}

	// Setup KUBE-MARK-MASQ rules
	masqueradeMark := getIPTablesMark(kl.iptablesMasqueradeBit)
	if _, err := iptClient.EnsureChain(utiliptables.TableNAT, KubeMarkMasqChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkMasqChain, err)
		return
	}
	if _, err := iptClient.EnsureChain(utiliptables.TableNAT, KubePostroutingChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubePostroutingChain, err)
		return
	}
	if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubeMarkMasqChain, "-j", "MARK", "--set-xmark", masqueradeMark); err != nil {
		klog.Errorf("Failed to ensure marking rule for %v: %v", KubeMarkMasqChain, err)
		return
	}
	if _, err := iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", "kubernetes postrouting rules", "-j", string(KubePostroutingChain)); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableNAT, utiliptables.ChainPostrouting, KubePostroutingChain, err)
		return
	}
	// Establish the masquerading rule.
	// NB: THIS MUST MATCH the corresponding code in the iptables and ipvs
	// modes of kube-proxy
	masqRule := []string{
		"-m", "comment", "--comment", "kubernetes service traffic requiring SNAT",
		"-m", "mark", "--mark", masqueradeMark,
		"-j", "MASQUERADE",
	}
	if iptClient.HasRandomFully() {
		masqRule = append(masqRule, "--random-fully")
	}
	if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubePostroutingChain, masqRule...); err != nil {
		klog.Errorf("Failed to ensure SNAT rule for packets marked by %v in %v chain %v: %v", KubeMarkMasqChain, utiliptables.TableNAT, KubePostroutingChain, err)
		return
	}
}

// getIPTablesMark returns the fwmark given the bit
func getIPTablesMark(bit int) string {
	value := 1 << uint(bit)
	return fmt.Sprintf("%#08x/%#08x", value, value)
}
