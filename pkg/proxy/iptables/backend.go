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
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
)

const sysctlRouteLocalnet = "net/ipv4/conf/all/route_localnet"

// Backend implements the IPTables backend
type Backend struct {
	config *proxyconfigapi.KubeProxyConfiguration

	ipts map[v1.IPFamily]utiliptables.Interface
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeIPTables] = &Backend{}
}

// Init initializes the IPTables backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration) error {
	logger := klog.FromContext(ctx)

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
		return fmt.Errorf("iptables is not available on this host: %w", errv4)
	}

	backend.ipts = map[v1.IPFamily]utiliptables.Interface{}
	if errv4 == nil {
		backend.ipts[v1.IPv4Protocol] = iptv4
	} else {
		logger.Info("No iptables support for family", "family", v1.IPv4Protocol, "error", errv4)
	}
	if errv6 == nil {
		backend.ipts[v1.IPv6Protocol] = iptv6
	} else {
		logger.Info("No iptables support for family", "family", v1.IPv6Protocol, "error", errv6)
	}

	backend.config = config
	return nil
}

// CheckIPFamilySupport checks if the IPTables backend can support the given primary IP
// family on this host, and whether dual-stack operation is supported. (Assumes Init() has
// been called.)
func (backend *Backend) CheckIPFamilySupport(ctx context.Context, primaryIPFamily v1.IPFamily) (singleStackSupported, dualStackSupported bool) {
	singleStackSupported = backend.ipts[primaryIPFamily] != nil
	dualStackSupported = len(backend.ipts) == 2

	return singleStackSupported, dualStackSupported
}

// PrivilegedInit performs any host initialization steps that require full root
// privileges, *if they have not already been performed*. When using `--init-only`, this
// will be called first from a privileged kube-proxy process, and then a second time from
// an unprivileged kube-proxy process; the second call must not return an error if the
// first call correctly initialized everything. (Assumes Init() has been called.)
func (backend *Backend) PrivilegedInit(ctx context.Context, initOnly bool) error {
	// Figure out if we need to set route_localnet to allow IPv4 localhost NodePorts.
	// https://issues.k8s.io/90259
	if backend.ipts[v1.IPv4Protocol] != nil && *backend.config.IPTables.LocalhostNodePorts {
		v4NodePortAddresses := proxyutil.NewNodePortAddresses(v1.IPv4Protocol, backend.config.NodePortAddresses)
		if v4NodePortAddresses.ContainsIPv4Loopback() {
			klog.FromContext(ctx).Info("Setting route_localnet=1 to allow node-ports on localhost; to change this either disable iptables.localhostNodePorts (--iptables-localhost-nodeports) or set nodePortAddresses (--nodeport-addresses) to filter loopback addresses")
			if err := proxyutil.EnsureSysctl(utilsysctl.New(), sysctlRouteLocalnet, 1); err != nil {
				return fmt.Errorf("cannot set required sysctl for proxy: %v", err)
			}
		}
	}

	return nil
}

// NewProxier creates a new IPTables proxier. (Assumes Init() has been called.)
func (backend *Backend) NewProxier(
	ctx context.Context,
	primaryIPFamily v1.IPFamily,
	nodeName string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
) (proxy.Proxier, error) {
	var proxier proxy.Proxier
	var err error

	if len(backend.ipts) == 2 {
		// TODO this has side effects that should only happen when Run() is invoked.
		proxier, err = newDualStackProxier(
			ctx,
			backend.ipts,
			utilsysctl.New(),
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.Linux.MasqueradeAll,
			*backend.config.IPTables.LocalhostNodePorts,
			int(*backend.config.IPTables.MasqueradeBit),
			localDetectors,
			nodeName,
			nodeIPs,
			recorder,
			healthzServer,
			backend.config.NodePortAddresses,
		)
	} else {
		// TODO this has side effects that should only happen when Run() is invoked.
		proxier, err = newProxier(
			ctx,
			primaryIPFamily,
			backend.ipts[primaryIPFamily],
			utilsysctl.New(),
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.Linux.MasqueradeAll,
			*backend.config.IPTables.LocalhostNodePorts,
			int(*backend.config.IPTables.MasqueradeBit),
			localDetectors[primaryIPFamily],
			nodeName,
			nodeIPs[primaryIPFamily],
			recorder,
			healthzServer,
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
	// Don't clean up our iptables rules if kube-proxy is starting in ipvs mode,
	// because the ipvs and iptables backends use some of the same chain names, and we
	// don't want to accidentally clean up the ipvs backend's iptables rules.
	if config.Mode == proxyconfigapi.ProxyModeIPVS && !force {
		return false
	}

	return cleanupLeftovers(ctx)
}
