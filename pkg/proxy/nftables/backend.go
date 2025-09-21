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

package nftables

import (
	"context"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
	"sigs.k8s.io/knftables"
)

// Backend implements the NFTables backend
type Backend struct {
	config *proxyconfigapi.KubeProxyConfiguration

	nfts map[v1.IPFamily]knftables.Interface
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeNFTables] = &Backend{}
}

// Init initializes the NFTables backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration) error {
	logger := klog.FromContext(ctx)

	// If NodePortAddresses is unspecified, default to `--nodeport-addresses primary`
	if len(config.NodePortAddresses) == 0 {
		config.NodePortAddresses = []string{proxyconfigapi.NodePortAddressesPrimary}
	}

	backend.nfts = map[v1.IPFamily]knftables.Interface{}
	nft, err := knftables.New(knftables.IPv4Family, kubeProxyTable)
	if err == nil {
		backend.nfts[v1.IPv4Protocol] = nft
	} else {
		return fmt.Errorf("no nftables support on this host: %w", err)
	}

	err = utilkernel.CheckIPv6()
	if err == nil {
		nft, err = knftables.New(knftables.IPv6Family, kubeProxyTable)
	}
	if err == nil {
		backend.nfts[v1.IPv6Protocol] = nft
	} else {
		logger.Info("No nftables support for family", "family", v1.IPv6Protocol, "error", err)
	}

	if err = checkNFTablesSupport(); err != nil {
		return err
	}

	backend.config = config
	return nil
}

// CheckIPFamilySupport checks if the NFTables backend can support the given primary IP
// family on this host, and whether dual-stack operation is supported. (Assumes Init() has
// been called.)
func (backend *Backend) CheckIPFamilySupport(ctx context.Context, primaryIPFamily v1.IPFamily) (singleStackSupported, dualStackSupported bool) {
	singleStackSupported = backend.nfts[primaryIPFamily] != nil
	dualStackSupported = len(backend.nfts) == 2

	return singleStackSupported, dualStackSupported
}

// PrivilegedInit performs any host initialization steps that require full root
// privileges, *if they have not already been performed*. When using `--init-only`, this
// will be called first from a privileged kube-proxy process, and then a second time from
// an unprivileged kube-proxy process; the second call must not return an error if the
// first call correctly initialized everything. (Assumes Init() has been called.)
func (backend *Backend) PrivilegedInit(ctx context.Context, initOnly bool) error {
	// nftables backend needs no privileged init
	return nil
}

// NewProxier creates a new NFTables proxier. (Assumes Init() has been called.)
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

	if len(backend.nfts) == 2 {
		// TODO this has side effects that should only happen when Run() is invoked.
		proxier, err = newDualStackProxier(
			ctx,
			backend.nfts,
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.Linux.MasqueradeAll,
			int(*backend.config.NFTables.MasqueradeBit),
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
			backend.nfts[primaryIPFamily],
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.Linux.MasqueradeAll,
			int(*backend.config.NFTables.MasqueradeBit),
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
	return cleanupLeftovers(ctx)
}
