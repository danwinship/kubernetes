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
	"os/exec"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	utilipset "k8s.io/kubernetes/pkg/proxy/ipvs/ipset"
	utilipvs "k8s.io/kubernetes/pkg/proxy/ipvs/util"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
	netutils "k8s.io/utils/net"
)

// In IPVS proxy mode, the following flags need to be set
const (
	sysctlVSConnTrack             = "net/ipv4/vs/conntrack"
	sysctlConnReuse               = "net/ipv4/vs/conn_reuse_mode"
	sysctlExpireNoDestConn        = "net/ipv4/vs/expire_nodest_conn"
	sysctlExpireQuiescentTemplate = "net/ipv4/vs/expire_quiescent_template"
	sysctlForward                 = "net/ipv4/ip_forward"
	sysctlARPIgnore               = "net/ipv4/conf/all/arp_ignore"
	sysctlARPAnnounce             = "net/ipv4/conf/all/arp_announce"
)

// Backend implements the IPVS backend
type Backend struct {
	config         *kubeproxyconfig.KubeProxyConfiguration
	nodeName       string
	nodeIPs        map[v1.IPFamily]net.IP
	recorder       events.EventRecorder
	healthzServer  *healthcheck.ProxyHealthServer
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector

	ipts   map[v1.IPFamily]utiliptables.Interface
	ipvs   utilipvs.Interface
	ipset  utilipset.Interface
	sysctl utilsysctl.Interface
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new IPVS proxy backend
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
	ipset := utilipset.New()
	ipvs := utilipvs.New()
	sysctl := utilsysctl.New()

	if err := canUseIPVSProxier(ctx, ipvs, ipset, config.IPVS.Scheduler); err != nil {
		return nil, fmt.Errorf("can't use the IPVS proxier: %v", err)
	}
	if len(ipts) == 0 {
		return nil, fmt.Errorf("iptables (required for ipvs backend) is not available on this host")
	} else if ipts[primaryIPFamily] == nil {
		return nil, fmt.Errorf("no iptables support for primary IP family %q", primaryIPFamily)
	} else if ipts[v1.IPv4Protocol] == nil {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv4Protocol)
	} else if ipts[v1.IPv6Protocol] == nil {
		logger.Info("No iptables support for family", "ipFamily", v1.IPv6Protocol)
	}

	return &Backend{
		config:         config,
		nodeName:       nodeName,
		nodeIPs:        nodeIPs,
		recorder:       recorder,
		healthzServer:  healthzServer,
		localDetectors: localDetectors,

		ipts:   ipts,
		ipvs:   ipvs,
		ipset:  ipset,
		sysctl: sysctl,
	}, nil
}

func (backend *Backend) DualStackSupported() bool {
	return len(backend.ipts) == 2
}

func (backend *Backend) PrivilegedInit(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	// Set the conntrack sysctl we need for
	if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlVSConnTrack, 1); err != nil {
		return err
	}

	kernelVersion, err := utilkernel.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}

	if kernelVersion.LessThan(version.MustParseGeneric(utilkernel.IPVSConnReuseModeMinSupportedKernelVersion)) {
		logger.Error(nil, "Can't set sysctl, kernel version doesn't satisfy minimum version requirements", "sysctl", sysctlConnReuse, "minimumKernelVersion", utilkernel.IPVSConnReuseModeMinSupportedKernelVersion)
	} else if kernelVersion.AtLeast(version.MustParseGeneric(utilkernel.IPVSConnReuseModeFixedKernelVersion)) {
		// https://github.com/kubernetes/kubernetes/issues/93297
		logger.V(2).Info("Left as-is", "sysctl", sysctlConnReuse)
	} else {
		// Set the connection reuse mode
		if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlConnReuse, 0); err != nil {
			return err
		}
	}

	// Set the expire_nodest_conn sysctl we need for
	if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlExpireNoDestConn, 1); err != nil {
		return err
	}

	// Set the expire_quiescent_template sysctl we need for
	if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlExpireQuiescentTemplate, 1); err != nil {
		return err
	}

	// Set the ip_forward sysctl we need for
	if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlForward, 1); err != nil {
		return err
	}

	if backend.config.IPVS.StrictARP {
		// Set the arp_ignore sysctl we need for
		if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlARPIgnore, 1); err != nil {
			return err
		}

		// Set the arp_announce sysctl we need for
		if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlARPAnnounce, 2); err != nil {
			return err
		}
	}

	// Configure IPVS timeouts if any one of the timeout parameters have been set.
	// This is the equivalent to running ipvsadm --set, a value of 0 indicates the
	// current system timeout should be preserved
	tcpTimeout := backend.config.IPVS.TCPTimeout.Duration
	tcpFinTimeout := backend.config.IPVS.TCPFinTimeout.Duration
	udpTimeout := backend.config.IPVS.UDPTimeout.Duration
	if tcpTimeout > 0 || tcpFinTimeout > 0 || udpTimeout > 0 {
		if err := backend.ipvs.ConfigureTimeouts(tcpTimeout, tcpFinTimeout, udpTimeout); err != nil {
			logger.Error(err, "Failed to configure IPVS timeouts")
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
			backend.ipvs,
			backend.ipset,
			backend.sysctl,
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.IPVS.ExcludeCIDRs,
			backend.config.IPVS.StrictARP,
			backend.config.IPVS.TCPTimeout.Duration,
			backend.config.IPVS.TCPFinTimeout.Duration,
			backend.config.IPVS.UDPTimeout.Duration,
			backend.config.Linux.MasqueradeAll,
			int(*backend.config.IPTables.MasqueradeBit),
			backend.localDetectors[family],
			backend.nodeName,
			backend.nodeIPs[family],
			backend.recorder,
			backend.healthzServer,
			backend.config.IPVS.Scheduler,
			backend.config.NodePortAddresses,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create %s proxier: %v", family, err)
		}
		r.AddProxier(family, proxier)
	}
	return r, nil
}

// canUseIPVSProxier checks if we can use the ipvs Proxier.
// The ipset version and the scheduler are checked. If any virtual servers (VS)
// already exist with the configured scheduler, we just return. Otherwise
// we check if a dummy VS can be configured with the configured scheduler.
// Kernel modules will be loaded automatically if necessary.
func canUseIPVSProxier(ctx context.Context, ipvs utilipvs.Interface, ipsetver IPSetVersioner, scheduler string) error {
	logger := klog.FromContext(ctx)
	// BUG: https://github.com/moby/ipvs/issues/27
	// If ipvs is not compiled into the kernel no error is returned and handle==nil.
	// This in turn causes ipvs.GetVirtualServers and ipvs.AddVirtualServer
	// to return ok (err==nil). If/when this bug is fixed parameter "ipvs" will be nil
	// if ipvs is not supported by the kernel. Until then a re-read work-around is used.
	if ipvs == nil {
		return fmt.Errorf("Ipvs not supported by the kernel")
	}

	// Check ipset version
	versionString, err := ipsetver.GetVersion()
	if err != nil {
		return fmt.Errorf("error getting ipset version, error: %v", err)
	}
	if !checkMinVersion(versionString) {
		return fmt.Errorf("ipset version: %s is less than min required version: %s", versionString, MinIPSetCheckVersion)
	}

	if scheduler == "" {
		scheduler = defaultScheduler
	}

	// If any virtual server (VS) using the scheduler exist we skip the checks.
	vservers, err := ipvs.GetVirtualServers()
	if err != nil {
		logger.Error(err, "Can't read the ipvs")
		return err
	}
	logger.V(5).Info("Virtual Servers", "count", len(vservers))
	if len(vservers) > 0 {
		// This is most likely a kube-proxy re-start. We know that ipvs works
		// and if any VS uses the configured scheduler, we are done.
		for _, vs := range vservers {
			if vs.Scheduler == scheduler {
				logger.V(5).Info("VS exist, Skipping checks")
				return nil
			}
		}
		logger.V(5).Info("No existing VS uses the configured scheduler", "scheduler", scheduler)
	}

	// Try to insert a dummy VS with the passed scheduler.
	// We should use a VIP address that is not used on the node.
	// An address "198.51.100.0" from the TEST-NET-2 rage in https://datatracker.ietf.org/doc/html/rfc5737
	// is used. These addresses are reserved for documentation. If the user is using
	// this address for a VS anyway we *will* mess up, but that would be an invalid configuration.
	// If the user have configured the address to an interface on the node (but not a VS)
	// then traffic will temporary be routed to ipvs during the probe and dropped.
	// The later case is also and invalid configuration, but the traffic impact will be minor.
	// This should not be a problem if users honors reserved addresses, but cut/paste
	// from documentation is not unheard of, so the restriction to not use the TEST-NET-2 range
	// must be documented.
	vs := utilipvs.VirtualServer{
		Address:   netutils.ParseIPSloppy("198.51.100.0"),
		Protocol:  "TCP",
		Port:      20000,
		Scheduler: scheduler,
	}
	if err := ipvs.AddVirtualServer(&vs); err != nil {
		logger.Error(err, "Could not create dummy VS", "scheduler", scheduler)
		return err
	}

	// To overcome the BUG described above we check that the VS is *really* added.
	vservers, err = ipvs.GetVirtualServers()
	if err != nil {
		logger.Error(err, "ipvs.GetVirtualServers")
		return err
	}
	logger.V(5).Info("Virtual Servers after adding dummy", "count", len(vservers))
	if len(vservers) == 0 {
		logger.Info("Dummy VS not created", "scheduler", scheduler)
		return fmt.Errorf("Ipvs not supported") // This is a BUG work-around
	}
	logger.V(5).Info("Dummy VS created", "vs", vs)

	if err := ipvs.DeleteVirtualServer(&vs); err != nil {
		logger.Error(err, "Could not delete dummy VS")
		return err
	}

	return nil
}

// CleanupLeftovers clean up all ipvs and iptables rules created by ipvs Proxier.
func CleanupLeftovers(ctx context.Context) (encounteredError bool) {
	// libipvs.New() will log errors if the "ip_vs" kernel module (or the "modprobe"
	// binary) is not available. Logging an extra error is fine if we were actually
	// trying to run the ipvs proxier, but it's confusing to see when just doing
	// best-effort cleanup (eg, when starting the nftables proxier), so we do the same
	// check libipvs does here, and bail out without calling libipvs if it fails.
	if _, err := exec.Command("modprobe", "-va", "ip_vs").CombinedOutput(); err != nil {
		return false
	}

	ipts := utiliptables.NewDualStack()
	ipsetInterface := utilipset.New()
	ipvsInterface := utilipvs.New()

	return cleanupLeftovers(ctx, ipvsInterface, ipts, ipsetInterface)
}
