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

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	utilipset "k8s.io/kubernetes/pkg/proxy/ipvs/ipset"
	utilipvs "k8s.io/kubernetes/pkg/proxy/ipvs/util"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
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
	config          *proxyconfigapi.KubeProxyConfiguration
	primaryIPFamily v1.IPFamily

	ipts  map[v1.IPFamily]utiliptables.Interface
	ipvs  utilipvs.Interface
	ipset utilipset.Interface
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeIPVS] = &Backend{}
}

// Init initializes the IPVS backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, primaryIPFamily v1.IPFamily) error {
	logger := klog.FromContext(ctx)

	if len(config.IPVS.Scheduler) == 0 {
		logger.Info("IPVS scheduler not specified. Using default.", "scheduler", defaultScheduler)
		config.IPVS.Scheduler = defaultScheduler
	}

	backend.ipvs = utilipvs.New()
	if backend.ipvs == nil {
		return fmt.Errorf("IPVS not supported by the kernel")
	}
	backend.ipset = utilipset.New()

	if err := CanUseIPVSProxier(ctx, backend.ipvs, backend.ipset, config.IPVS.Scheduler); err != nil {
		return err
	}

	iptv4 := utiliptables.New(utiliptables.ProtocolIPv4)
	errv4 := iptv4.Present()
	iptv6 := utiliptables.New(utiliptables.ProtocolIPv6)
	errv6 := iptv6.Present()

	// In some cases, the CLI tools may look like they support IPv6 even when it's
	// disabled in the kernel, so check that as well.
	if errv6 == nil {
		errv6 = utilkernel.CheckIPv6()
	}

	if errv4 != nil && errv6 != nil {
		// errv4 and errv6 are almost certainly the same underlying error
		// ("iptables isn't installed" or "kernel modules not available")
		// so it doesn't make sense to try to combine them.
		return fmt.Errorf("iptables (required for IPVS) is not available on this host: %w", errv4)
	}

	backend.ipts = map[v1.IPFamily]utiliptables.Interface{}
	if errv4 == nil {
		backend.ipts[v1.IPv4Protocol] = iptv4
	} else if primaryIPFamily == v1.IPv4Protocol {
		return fmt.Errorf("no backend support for primary IP family (%s)", primaryIPFamily)
	} else {
		logger.Info("No iptables support for family", "family", v1.IPv4Protocol, "error", errv4)
	}
	if errv6 == nil {
		backend.ipts[v1.IPv6Protocol] = iptv6
	} else if primaryIPFamily == v1.IPv6Protocol {
		return fmt.Errorf("no backend support for primary IP family (%s)", primaryIPFamily)
	} else {
		logger.Info("No iptables support for family", "family", v1.IPv6Protocol, "error", errv6)
	}

	backend.config = config
	backend.primaryIPFamily = primaryIPFamily
	return nil
}

// DualStackSupported checks if the IPVS backend supports dual-stack operation on this
// host. (Assumes Init() has been called.)
func (backend *Backend) DualStackSupported() bool {
	return len(backend.ipts) == 2
}

// PrivilegedInit performs any host initialization steps that require full root
// privileges, *if they have not already been performed*. When using `--init-only`, this
// will be called first from a privileged kube-proxy process, and then a second time from
// an unprivileged kube-proxy process; the second call must not return an error if the
// first call correctly initialized everything. (Assumes Init() has been called.)
func (backend *Backend) PrivilegedInit(ctx context.Context, initOnly bool) error {
	logger := klog.FromContext(ctx)

	sysctl := utilsysctl.New()
	if err := proxyutil.EnsureSysctl(sysctl, sysctlVSConnTrack, 1); err != nil {
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
		if err := proxyutil.EnsureSysctl(sysctl, sysctlConnReuse, 0); err != nil {
			return err
		}
	}

	if err := proxyutil.EnsureSysctl(sysctl, sysctlExpireNoDestConn, 1); err != nil {
		return err
	}
	if err := proxyutil.EnsureSysctl(sysctl, sysctlExpireQuiescentTemplate, 1); err != nil {
		return err
	}
	if err := proxyutil.EnsureSysctl(sysctl, sysctlForward, 1); err != nil {
		return err
	}

	if backend.config.IPVS.StrictARP {
		if err := proxyutil.EnsureSysctl(sysctl, sysctlARPIgnore, 1); err != nil {
			return err
		}
		if err := proxyutil.EnsureSysctl(sysctl, sysctlARPAnnounce, 2); err != nil {
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

// NewProxier creates a new IPVS proxier. (Assumes Init() has been called.)
func (backend *Backend) NewProxier(
	ctx context.Context,
	nodeName string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
) (proxy.Proxier, error) {
	var proxier proxy.Proxier
	var err error

	if len(backend.ipts) == 2 {
		proxier, err = NewDualStackProxier(
			ctx,
			backend.ipts,
			backend.ipvs,
			backend.ipset,
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.IPVS.ExcludeCIDRs,
			backend.config.Linux.MasqueradeAll,
			int(*backend.config.IPTables.MasqueradeBit),
			localDetectors,
			nodeName,
			nodeIPs,
			recorder,
			healthzServer,
			backend.config.IPVS.Scheduler,
			backend.config.NodePortAddresses,
		)
	} else {
		proxier, err = NewProxier(
			ctx,
			backend.primaryIPFamily,
			backend.ipts[backend.primaryIPFamily],
			backend.ipvs,
			backend.ipset,
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.IPVS.ExcludeCIDRs,
			backend.config.Linux.MasqueradeAll,
			int(*backend.config.IPTables.MasqueradeBit),
			localDetectors[backend.primaryIPFamily],
			nodeName,
			nodeIPs[backend.primaryIPFamily],
			recorder,
			healthzServer,
			backend.config.IPVS.Scheduler,
			backend.config.NodePortAddresses,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to create proxier: %v", err)
	}

	return proxier, nil
}

// Cleanup cleans up state left behind by a previous run of the Backend, either because
// the user is switching backends, or because they ran --cleanup. (It *does not* get
// called for a given Backend when restarting in the same mode.) If force is true, then it
// should clean up everything, unconditionally. Otherwise, it should only clean up state
// that is guaranteed to not interfere with the current backend according to config. The
// return value indicates whether any errors occurred. (Unlike the other methods, this
// *does not* require that Init() has been called.)
func (backend *Backend) Cleanup(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, force bool) bool {
	// Don't clean up our iptables rules if kube-proxy is starting in iptables mode,
	// because the ipvs and iptables backends use some of the same chain names, and we
	// don't want to accidentally clean up the iptables backend's iptables rules. (In
	// theory we could clean up just the IPVS stuff, but for historical reasons, we
	// don't bother trying.)
	if config.Mode == proxyconfigapi.ProxyModeIPTables && !force {
		return false
	}

	return CleanupLeftovers(ctx)
}
