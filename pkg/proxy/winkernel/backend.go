//go:build windows
// +build windows

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

package winkernel

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/hnslib"

	v1 "k8s.io/api/core/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
)

// NewBackend returns a new winkernel backend.
func NewBackend(
	primaryIPFamily v1.IPFamily,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxierHealthServer,
	healthzBindAddress string,
	config config.KubeProxyWinkernelConfiguration,
) (*proxy.Backend, error) {
	// Check if Kernel proxier can be used at all
	if err := canUseWinKernelProxier(); err != nil {
		return nil, err
	}

	// winkernel always supports both single-stack IPv4 and single-stack IPv6, but may
	// not support dual-stack.
	dualStackSupported := isDualStackCompatible(config.NetworkName)

	var ipv4Proxier, ipv6Proxier proxy.Proxier
	var err error

	if dualStackSupported || primaryIPFamily == v1.IPv4Protocol {
		ipv4Proxier, err = newProxier(v1.IPv4Protocol, syncPeriod, minSyncPeriod,
			hostname, nodeIPs[v1.IPv4Protocol], recorder, healthzServer,
			healthzBindAddress, config)
		if err != nil {
			return nil, fmt.Errorf("unable to create ipv4 proxier: %v, hostname: %s, nodeIP:%v", err, hostname, nodeIPs[v1.IPv4Protocol])
		}
	}
	if dualStackSupported || primaryIPFamily == v1.IPv6Protocol {
		ipv6Proxier, err = newProxier(v1.IPv6Protocol, syncPeriod, minSyncPeriod,
			hostname, nodeIPs[v1.IPv6Protocol], recorder, healthzServer,
			healthzBindAddress, config)
		if err != nil {
			return nil, fmt.Errorf("unable to create ipv6 proxier: %v, hostname: %s, nodeIP:%v", err, hostname, nodeIPs[v1.IPv6Protocol])
		}
	}
	return proxy.NewBackend(ipv4Proxier, ipv6Proxier), nil
}

func canUseWinKernelProxier() error {
	_, err := hnslib.HNSListPolicyListRequest()
	if err != nil {
		return fmt.Errorf("Windows kernel is not compatible for Kernel mode")
	}
	return nil
}

func isDualStackCompatible(networkName string) bool {
	hcnImpl := newHcnImpl()
	// First tag of hnslib that has a proper check for dual stack support is v0.8.22 due to a bug.
	if err := hcnImpl.Ipv6DualStackSupported(); err != nil {
		// Hcn *can* fail the query to grab the version of hcn itself (which this call will do internally before parsing
		// to see if dual stack is supported), but the only time this can happen, at least that can be discerned, is if the host
		// is pre-1803 and hcn didn't exist. hnslib should truthfully return a known error if this happened that we can
		// check against, and the case where 'err != this known error' would be the 'this feature isn't supported' case, as is being
		// used here. For now, seeming as how nothing before ws2019 (1809) is listed as supported for k8s we can pretty much assume
		// any error here isn't because the query failed, it's just that dualstack simply isn't supported on the host. With all
		// that in mind, just log as info and not error to let the user know we're falling back.
		klog.InfoS("This version of Windows does not support dual-stack, falling back to single-stack", "err", err.Error())
		return false
	}

	// check if network is using overlay
	hns, _ := newHostNetworkService(hcnImpl)
	networkName, err := getNetworkName(networkName)
	if err != nil {
		klog.ErrorS(err, "Unable to determine dual-stack status, falling back to single-stack")
		return false
	}
	networkInfo, err := getNetworkInfo(hns, networkName)
	if err != nil {
		klog.ErrorS(err, "Unable to determine dual-stack status, falling back to single-stack")
		return false
	}

	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.WinOverlay) && isOverlay(networkInfo) {
		// Overlay (VXLAN) networks on Windows do not support dual-stack networking today
		klog.InfoS("Winoverlay does not support dual-stack, falling back to single-stack")
		return false
	}

	return true
}
