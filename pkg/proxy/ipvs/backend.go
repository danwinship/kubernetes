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

package ipvs

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
	utilipset "k8s.io/kubernetes/pkg/proxy/ipvs/ipset"
	utilipvs "k8s.io/kubernetes/pkg/proxy/ipvs/util"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"
)

// NewBackend returns a new IPVS backend
func NewBackend(
	ctx context.Context,
	ipt [2]utiliptables.Interface,
	ipvs utilipvs.Interface,
	ipset utilipset.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	excludeCIDRs []string,
	strictARP bool,
	tcpTimeout time.Duration,
	tcpFinTimeout time.Duration,
	udpTimeout time.Duration,
	masqueradeAll bool,
	masqueradeBit int,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxierHealthServer,
	scheduler string,
	nodePortAddresses []string,
	initOnly bool,
) (*proxy.Backend, error) {
	logger := klog.FromContext(ctx)

	iptv4 := ipt[0]
	if !iptv4.Present() {
		iptv4 = nil
	}
	iptv6 := ipt[1]
	if !iptv6.Present() {
		iptv6 = nil
	}
	if iptv4 == nil && iptv6 == nil {
		return nil, fmt.Errorf("iptables is not available on this host")
	}

	var ipv4Proxier, ipv6Proxier proxy.Proxier
	var err error

	if iptv4 != nil {
		ipv4Proxier, err = newProxier(ctx, v1.IPv4Protocol,
			iptv4, ipvs, ipset, sysctl, exec,
			syncPeriod, minSyncPeriod, filterCIDRs(false, excludeCIDRs),
			strictARP, tcpTimeout, tcpFinTimeout, udpTimeout, masqueradeAll, masqueradeBit,
			localDetectors[v1.IPv4Protocol], hostname, nodeIPs[v1.IPv4Protocol],
			recorder, healthzServer, scheduler, nodePortAddresses, initOnly)
		if err != nil {
			return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
		}
	} else {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv4Protocol)
	}

	if iptv6 != nil {
		ipv6Proxier, err = newProxier(ctx, v1.IPv6Protocol,
			iptv6, ipvs, ipset, sysctl, exec,
			syncPeriod, minSyncPeriod, filterCIDRs(true, excludeCIDRs),
			strictARP, tcpTimeout, tcpFinTimeout, udpTimeout, masqueradeAll, masqueradeBit,
			localDetectors[v1.IPv6Protocol], hostname, nodeIPs[v1.IPv6Protocol],
			recorder, healthzServer, scheduler, nodePortAddresses, initOnly)
		if err != nil {
			return nil, fmt.Errorf("unable to create ipv6 proxier: %v", err)
		}
	} else {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv6Protocol)
	}

	return proxy.NewBackend(ipv4Proxier, ipv6Proxier), nil
}
