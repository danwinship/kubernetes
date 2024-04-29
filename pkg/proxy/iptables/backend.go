//go:build linux
// +build linux

/*
Copyright 2024 The Kubernetes Authors.

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
	"context"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	"k8s.io/kubernetes/pkg/proxy/util/nfacct"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

const sysctlRouteLocalnet = "net/ipv4/conf/all/route_localnet"
const sysctlNFConntrackTCPBeLiberal = "net/netfilter/nf_conntrack_tcp_be_liberal"

// Backend implements the IPTables backend
type Backend struct {
	config         *kubeproxyconfig.KubeProxyConfiguration
	nodeName       string
	nodeIPs        map[v1.IPFamily]net.IP
	recorder       events.EventRecorder
	healthzServer  *healthcheck.ProxyHealthServer
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector

	ipts   map[v1.IPFamily]utiliptables.Interface
	sysctl utilsysctl.Interface

	nfAcctCounters        sets.Set[string]
	nodePortAddresses     map[v1.IPFamily]*proxyutil.NodePortAddresses
	needConntrackDropRule bool
	masqueradeMark        string
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new IPTables proxy backend
func NewBackend(
	ctx context.Context,
	config *kubeproxyconfig.KubeProxyConfiguration,
	primaryIPFamily v1.IPFamily,
	nodeName string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
) (*Backend, error) {
	logger := klog.FromContext(ctx)

	ipts := utiliptables.NewDualStack()
	sysctl := utilsysctl.New()

	if len(ipts) == 0 {
		return nil, fmt.Errorf("iptables is not available on this host")
	} else if ipts[primaryIPFamily] == nil {
		return nil, fmt.Errorf("no iptables support for primary IP family %q", primaryIPFamily)
	} else if ipts[v1.IPv4Protocol] == nil {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv4Protocol)
	} else if ipts[v1.IPv6Protocol] == nil {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv6Protocol)
	}

	var nfAcctCounters sets.Set[string]
	if nfacctRunner, err := nfacct.New(); err == nil {
		nfAcctCounters := sets.New[string]()
		for _, name := range []string{
			metrics.IPTablesCTStateInvalidDroppedNFAcctCounter,
			metrics.LocalhostNodePortAcceptedNFAcctCounter,
		} {
			if err := nfacctRunner.Ensure(name); err == nil {
				nfAcctCounters.Insert(name)
			} else {
				logger.Error(err, "Failed to create nfacct counter; the corresponding metric will not be updated", "counter", name)
			}
		}
	} else {
		logger.Error(err, "Failed to create nfacct runner, nfacct based metrics won't be available")
	}

	nodePortAddresses := map[v1.IPFamily]*proxyutil.NodePortAddresses{
		v1.IPv4Protocol: proxyutil.NewNodePortAddresses(v1.IPv4Protocol, config.NodePortAddresses),
		v1.IPv6Protocol: proxyutil.NewNodePortAddresses(v1.IPv6Protocol, config.NodePortAddresses),
	}

	// Check to see if we need the drop rule for ctstate INVALID packets
	needConntrackDropRule := true
	if val, err := sysctl.GetSysctl(sysctlNFConntrackTCPBeLiberal); err == nil && val != 0 {
		needConntrackDropRule = false
		logger.Info("nf_conntrack_tcp_be_liberal set, not installing DROP rules for INVALID packets")
	}

	// Generate the masquerade mark to use for SNAT rules.
	masqueradeValue := 1 << uint(*config.IPTables.MasqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)
	logger.V(2).Info("Using iptables mark for masquerade", "mark", masqueradeMark)

	return &Backend{
		config:         config,
		nodeName:       nodeName,
		nodeIPs:        nodeIPs,
		recorder:       recorder,
		healthzServer:  healthzServer,
		localDetectors: localDetectors,

		ipts:   ipts,
		sysctl: sysctl,

		nfAcctCounters:        nfAcctCounters,
		nodePortAddresses:     nodePortAddresses,
		needConntrackDropRule: needConntrackDropRule,
		masqueradeMark:        masqueradeMark,
	}, nil
}

func (backend *Backend) DualStackSupported() bool {
	return len(backend.ipts) == 2
}

func (backend *Backend) PrivilegedInit(ctx context.Context) error {
	// Figure out if we need to set route_localnet to allow IPv4 localhost NodePorts.
	// https://issues.k8s.io/90259
	if backend.ipts[v1.IPv4Protocol] != nil &&
		*backend.config.IPTables.LocalhostNodePorts &&
		backend.nodePortAddresses[v1.IPv4Protocol].ContainsIPv4Loopback() {

		logger := klog.FromContext(ctx)
		logger.Info("Setting route_localnet=1 to allow node-ports on localhost; to change this either disable iptables.localhostNodePorts (--iptables-localhost-nodeports) or set nodePortAddresses (--nodeport-addresses) to filter loopback addresses")
		if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlRouteLocalnet, 1); err != nil {
			return fmt.Errorf("cannot set required sysctl for proxy: %v", err)
		}
	}

	return nil
}

func (backend *Backend) NewRunner(ctx context.Context) (*proxy.Runner, error) {
	r := proxy.NewRunner()
	for family := range backend.ipts {
		proxier, err := newProxier(
			ctx,
			family,
			backend.ipts[family],
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.Linux.MasqueradeAll,
			*backend.config.IPTables.LocalhostNodePorts,
			backend.masqueradeMark,
			backend.needConntrackDropRule,
			backend.localDetectors[family],
			backend.nodeName,
			backend.nodeIPs[family],
			backend.recorder,
			backend.healthzServer,
			backend.nodePortAddresses[family],
			backend.nfAcctCounters,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create %s proxier: %v", family, err)
		}
		r.AddProxier(family, proxier)
	}
	return r, nil
}

// CleanupLeftovers removes all iptables rules and chains created by the Backend.
// It returns true if an error was encountered. Errors are logged.
func CleanupLeftovers(ctx context.Context) (encounteredError bool) {
	ipts := utiliptables.NewDualStack()
	for _, ipt := range ipts {
		encounteredError = cleanupLeftoversForFamily(ctx, ipt) || encounteredError
	}
	return
}
