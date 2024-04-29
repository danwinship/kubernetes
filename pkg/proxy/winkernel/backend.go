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
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/hnslib"
	"github.com/Microsoft/hnslib/hcn"

	v1 "k8s.io/api/core/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	netutils "k8s.io/utils/net"
)

// Backend implements the winkernel backend
type Backend struct {
	config          *kubeproxyconfig.KubeProxyConfiguration
	primaryIPFamily v1.IPFamily
	nodeName        string
	nodeIPs         map[v1.IPFamily]net.IP
	recorder        events.EventRecorder
	healthzServer   *healthcheck.ProxyHealthServer

	hns                HostNetworkService
	hcn                HcnService
	network            *hnsNetworkInfo
	sourceVIP          string
	hostMAC            string
	isDSR              bool
	supportedFeatures  hcn.SupportedFeatures
	healthzPort        int
	dualStackSupported bool
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new winkernel proxy backend
func NewBackend(
	ctx context.Context,
	config *kubeproxyconfig.KubeProxyConfiguration,
	primaryIPFamily v1.IPFamily,
	nodeName string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
) (*Backend, error) {
	logger := klog.FromContext(ctx)

	if err := canUseWinKernelProxier(); err != nil {
		return nil, err
	}

	hcnImpl := newHcnImpl()
	hns, supportedFeatures := newHostNetworkService(hcnImpl)

	hnsNetworkName := config.Winkernel.NetworkName
	if len(hnsNetworkName) == 0 {
		logger.V(3).Info("Flag --network-name not set, checking environment variable")
		hnsNetworkName = os.Getenv("KUBE_NETWORK")
		if len(hnsNetworkName) == 0 {
			return nil, fmt.Errorf("Environment variable KUBE_NETWORK and network-flag not initialized")
		}
	}

	logger.V(3).Info("Cleaning up old HNS policy lists")
	hcnImpl.DeleteAllHnsLoadBalancerPolicy()

	// Get HNS network information
	hnsNetworkInfo, err := getNetworkInfo(hns, hnsNetworkName)
	if err != nil {
		return nil, err
	}

	// Network could have been detected before Remote Subnet Routes are applied or
	// ManagementIP is updated. Sleep and update the network to include new information
	if isOverlay(hnsNetworkInfo) {
		time.Sleep(10 * time.Second)
		hnsNetworkInfo, err = hns.getNetworkByName(hnsNetworkName)
		if err != nil {
			return nil, fmt.Errorf("could not find HNS network %s", hnsNetworkName)
		}
	}

	logger.V(1).Info("Hns Network loaded", "hnsNetworkInfo", hnsNetworkInfo)
	isDSR := config.Winkernel.EnableDSR
	if isDSR && !utilfeature.DefaultFeatureGate.Enabled(kubefeatures.WinDSR) {
		return nil, fmt.Errorf("WinDSR feature gate not enabled")
	}

	err = hcnImpl.DsrSupported()
	if isDSR && err != nil {
		return nil, err
	}

	var sourceVIP string
	var hostMAC string
	if isOverlay(hnsNetworkInfo) {
		if !utilfeature.DefaultFeatureGate.Enabled(kubefeatures.WinOverlay) {
			return nil, fmt.Errorf("WinOverlay feature gate not enabled")
		}
		err = hcn.RemoteSubnetSupported()
		if err != nil {
			return nil, err
		}
		sourceVIP = config.Winkernel.SourceVip
		if len(sourceVIP) == 0 {
			return nil, fmt.Errorf("source-vip flag not set")
		}

		primaryIP := nodeIPs[primaryIPFamily]
		interfaces, _ := net.Interfaces() //TODO create interfaces
		for _, inter := range interfaces {
			addresses, _ := inter.Addrs()
			for _, addr := range addresses {
				addrIP, _, _ := netutils.ParseCIDRSloppy(addr.String())
				if addrIP.Equal(primaryIP) {
					logger.V(2).Info("Record Host MAC address", "addr", inter.HardwareAddr)
					hostMAC = inter.HardwareAddr.String()
				}
			}
		}
		if len(hostMAC) == 0 {
			return nil, fmt.Errorf("could not find host mac address for %s", primaryIP)
		}
	}

	var healthzPort int
	if len(config.HealthzBindAddress) > 0 {
		_, port, _ := net.SplitHostPort(config.HealthzBindAddress)
		healthzPort, _ = strconv.Atoi(port)
	}

	// winkernel always supports both single-stack IPv4 and single-stack IPv6, but may
	// not support dual-stack.
	dualStackSupported := dualStackCompatible(ctx, hcnImpl, hnsNetworkInfo)

	return &Backend{
		config:          config,
		primaryIPFamily: primaryIPFamily,
		nodeName:        nodeName,
		nodeIPs:         nodeIPs,
		recorder:        recorder,
		healthzServer:   healthzServer,

		hcn:                hcnImpl,
		hns:                hns,
		network:            hnsNetworkInfo,
		sourceVIP:          sourceVIP,
		hostMAC:            hostMAC,
		isDSR:              isDSR,
		supportedFeatures:  supportedFeatures,
		healthzPort:        healthzPort,
		dualStackSupported: dualStackSupported,
	}, nil
}

func (backend *Backend) DualStackSupported() bool {
	return backend.dualStackSupported
}

func (backend *Backend) PrivilegedInit(ctx context.Context) error {
	return nil
}

func (backend *Backend) NewRunner(ctx context.Context) (*proxy.Runner, error) {
	r := proxy.NewRunner()
	for _, family := range []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol} {
		if family != backend.primaryIPFamily && !backend.dualStackSupported {
			continue
		}

		proxier, err := newProxier(
			family,
			backend.hcn,
			backend.hns,
			backend.network,
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.nodeName,
			backend.nodeIPs[family],
			backend.recorder,
			backend.healthzServer,
			backend.healthzPort,
			backend.isDSR,
			backend.sourceVIP,
			backend.hostMAC,
			backend.supportedFeatures,
			backend.config.Winkernel,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create %s proxier: %w", family, err)
		}
		r.AddProxier(family, proxier)
	}
	return r, nil
}

// canUseWinKernelProxier returns an error if we can't use the winkernel Proxier.
func canUseWinKernelProxier() error {
	_, err := hnslib.HNSListPolicyListRequest()
	if err != nil {
		return fmt.Errorf("Windows kernel is not compatible for Kernel mode")
	}
	return nil
}

// dualStackCompatible tests if networkName supports dual stack
func dualStackCompatible(ctx context.Context, hcnImpl HcnService, networkInfo *hnsNetworkInfo) bool {
	logger := klog.FromContext(ctx)

	// First tag of hnslib that has a proper check for dual stack support is v0.8.22 due to a bug.
	if err := hcnImpl.Ipv6DualStackSupported(); err != nil {
		// Hcn *can* fail the query to grab the version of hcn itself (which this call will do internally before parsing
		// to see if dual stack is supported), but the only time this can happen, at least that can be discerned, is if the host
		// is pre-1803 and hcn didn't exist. hnslib should truthfully return a known error if this happened that we can
		// check against, and the case where 'err != this known error' would be the 'this feature isn't supported' case, as is being
		// used here. For now, seeming as how nothing before ws2019 (1809) is listed as supported for k8s we can pretty much assume
		// any error here isn't because the query failed, it's just that dualstack simply isn't supported on the host. With all
		// that in mind, just log as info and not error to let the user know we're falling back.
		logger.Info("This version of Windows does not support dual-stack, falling back to single-stack", "err", err.Error())
		return false
	}

	// check if network is using overlay
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.WinOverlay) && isOverlay(networkInfo) {
		// Overlay (VXLAN) networks on Windows do not support dual-stack networking today
		logger.Info("Winoverlay does not support dual-stack, falling back to single-stack")
		return false
	}

	return true
}

func newHostNetworkService(hcnImpl HcnService) (HostNetworkService, hcn.SupportedFeatures) {
	var h HostNetworkService
	supportedFeatures := hcnImpl.GetSupportedFeatures()
	klog.V(3).InfoS("HNS Supported features", "hnsSupportedFeatures", supportedFeatures)
	if supportedFeatures.Api.V2 {
		h = hns{
			hcn: hcnImpl,
		}
	} else {
		panic("Windows HNS Api V2 required. This version of windows does not support API V2")
	}
	return h, supportedFeatures
}

func getNetworkInfo(hns HostNetworkService, hnsNetworkName string) (*hnsNetworkInfo, error) {
	hnsNetworkInfo, err := hns.getNetworkByName(hnsNetworkName)
	for err != nil {
		klog.ErrorS(err, "Unable to find HNS Network specified, please check network name and CNI deployment", "hnsNetworkName", hnsNetworkName)
		time.Sleep(1 * time.Second)
		hnsNetworkInfo, err = hns.getNetworkByName(hnsNetworkName)
	}
	return hnsNetworkInfo, err
}

func isOverlay(hnsNetworkInfo *hnsNetworkInfo) bool {
	return strings.EqualFold(hnsNetworkInfo.networkType, NETWORK_TYPE_OVERLAY)
}
