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
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"
)

// NewBackend creates a new IPTables backend
func NewBackend(
	ctx context.Context,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	localhostNodePorts bool,
	masqueradeBit int,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxierHealthServer,
	nodePortAddresses []string,
	initOnly bool,
) (*proxy.Backend, error) {
	logger := klog.FromContext(ctx)

	sysctl := utilsysctl.New()
	exec := utilexec.New()
	iptv4 := utiliptables.New(exec, utiliptables.ProtocolIPv4)
	if !iptv4.Present() {
		iptv4 = nil
	}
	iptv6 := utiliptables.New(exec, utiliptables.ProtocolIPv6)
	if !iptv6.Present() {
		iptv6 = nil
	}
	if iptv4 == nil && iptv6 == nil {
		return nil, fmt.Errorf("iptables is not available on this host")
	}

	// Figure out if we need to set route_localnet to allow IPv4 localhost NodePorts.
	// https://issues.k8s.io/90259
	if iptv4 != nil && localhostNodePorts {
		nodePortAddresses := proxyutil.NewNodePortAddresses(v1.IPv4Protocol, nodePortAddresses)
		if !nodePortAddresses.ContainsIPv4Loopback() {
			localhostNodePorts = false
		}
		if localhostNodePorts {
			logger.Info("Setting route_localnet=1 to allow node-ports on localhost; to change this either disable iptables.localhostNodePorts (--iptables-localhost-nodeports) or set nodePortAddresses (--nodeport-addresses) to filter loopback addresses")
			if err := proxyutil.EnsureSysctl(sysctl, sysctlRouteLocalnet, 1); err != nil {
				return nil, fmt.Errorf("cannot set required sysctl for proxy: %v", err)
			}
		}
	}

	if initOnly {
		return nil, nil
	}

	// Check to see if we need the drop rule for ctstate INVALID packets
	needConntrackDropRule := true
	if val, err := sysctl.GetSysctl(sysctlNFConntrackTCPBeLiberal); err == nil && val != 0 {
		needConntrackDropRule = false
	}

	// Generate the masquerade mark to use for SNAT rules.
	masqueradeValue := 1 << uint(masqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)
	logger.V(2).Info("Using iptables mark for masquerade", "mark", masqueradeMark)

	var ipv4Proxier, ipv6Proxier proxy.Proxier
	var err error

	if iptv4 != nil {
		ipv4Proxier, err = newProxier(ctx, v1.IPv4Protocol, iptv4,
			syncPeriod, minSyncPeriod, masqueradeAll, masqueradeMark,
			localhostNodePorts, needConntrackDropRule,
			localDetectors[v1.IPv4Protocol], hostname, nodeIPs[v1.IPv4Protocol],
			recorder, healthzServer, nodePortAddresses)
		if err != nil {
			return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
		}
	} else {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv4Protocol)
	}

	if iptv6 != nil {
		ipv6Proxier, err = newProxier(ctx, v1.IPv6Protocol, iptv6,
			syncPeriod, minSyncPeriod, masqueradeAll, masqueradeMark,
			false /* no localhostNodePorts for IPv6 */, needConntrackDropRule,
			localDetectors[v1.IPv6Protocol], hostname, nodeIPs[v1.IPv6Protocol],
			recorder, healthzServer, nodePortAddresses)
		if err != nil {
			return nil, fmt.Errorf("unable to create ipv6 proxier: %v", err)
		}
	} else {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv6Protocol)
	}

	return proxy.NewBackend(ipv4Proxier, ipv6Proxier), nil
}

// CleanupLeftovers removes all iptables rules and chains created by the Backend
// It returns true if an error was encountered. Errors are logged.
func CleanupLeftovers(ctx context.Context) (encounteredError bool) {
	// Clean up both IPv4 and IPv6 since the previous proxier may have run in either mode.
	execer := utilexec.New()
	ipt := utiliptables.New(execer, utiliptables.ProtocolIPv4)
	encounteredError = cleanupLeftovers(ctx, ipt) || encounteredError
	ipt = utiliptables.New(execer, utiliptables.ProtocolIPv6)
	encounteredError = cleanupLeftovers(ctx, ipt) || encounteredError
	return
}
