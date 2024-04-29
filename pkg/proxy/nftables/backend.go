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
	"os"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
	"sigs.k8s.io/knftables"
)

// Backend implements the NFTables backend
type Backend struct {
	config         *kubeproxyconfig.KubeProxyConfiguration
	nodeName       string
	nodeIPs        map[v1.IPFamily]net.IP
	recorder       events.EventRecorder
	healthzServer  *healthcheck.ProxyHealthServer
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector

	nfts    map[v1.IPFamily]knftables.Interface

	masqueradeMark string
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new NFTables proxy backend
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

	nft, err := getNFTablesInterface(v1.IPv4Protocol)
	if err != nil {
		return nil, fmt.Errorf("no nftables support on this host: %w", err)
	}

	nfts := map[v1.IPFamily]knftables.Interface{
		v1.IPv4Protocol: nft,
	}
	nft, err = getNFTablesInterface(v1.IPv6Protocol)
	if err == nil {
		nfts[v1.IPv6Protocol] = nft
	} else if primaryIPFamily == v1.IPv6Protocol {
			return nil, fmt.Errorf("no nftables support for primary IP family %q: %v", primaryIPFamily, err)
	} else {
		logger.Info("No nftables support for family", "ipFamily", v1.IPv6Protocol, "error", err)
	}

	// Generate the masquerade mark to use for SNAT rules.
	masqueradeValue := 1 << uint(*config.NFTables.MasqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)

	return &Backend{
		config:         config,
		nodeName:       nodeName,
		nodeIPs:        nodeIPs,
		recorder:       recorder,
		healthzServer:  healthzServer,
		localDetectors: localDetectors,

		nfts: nfts,

		masqueradeMark: masqueradeMark,
	}, nil
}

func (backend *Backend) DualStackSupported() bool {
	return len(backend.nfts) == 2
}

func (backend *Backend) PrivilegedInit(ctx context.Context) error {
	return nil
}

func (backend *Backend) NewRunner(ctx context.Context) (*proxy.Runner, error) {
	r := proxy.NewRunner()
	for family := range backend.nfts {
		proxier, err := newProxier(
			ctx,
			family,
			backend.nfts[family],
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			backend.config.Linux.MasqueradeAll,
			backend.masqueradeMark,
			backend.localDetectors[family],
			backend.nodeName,
			backend.nodeIPs[family],
			backend.recorder,
			backend.healthzServer,
			backend.config.NodePortAddresses,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create %s proxier: %v", family, err)
		}
		r.AddProxier(family, proxier)
	}
	return r, nil
}

// Create a knftables.Interface and check if we can use the nftables proxy mode on this host.
func getNFTablesInterface(ipFamily v1.IPFamily) (knftables.Interface, error) {
	var nftablesFamily knftables.Family
	if ipFamily == v1.IPv4Protocol {
		nftablesFamily = knftables.IPv4Family
	} else {
		nftablesFamily = knftables.IPv6Family
	}

	// We require (or rather, knftables.New does) that the nft binary be version 1.0.1
	// or later, because versions before that would always attempt to parse the entire
	// nft ruleset at startup, even if you were only operating on a single table.
	// That's bad, because in some cases, new versions of nft have added new rule
	// types in ways that triggered bugs in older versions of nft, causing them to
	// crash. Thus, if kube-proxy used nft < 1.0.1, it could potentially get locked
	// out of its rules because of something some other component had done in a
	// completely different table.
	nft, err := knftables.New(nftablesFamily, kubeProxyTable)
	if err != nil {
		return nil, err
	}

	// Likewise, we want to ensure that the host filesystem has nft >= 1.0.1, so that
	// it's not possible that *our* rules break *the system's* nft. (In particular, we
	// know that if kube-proxy uses nft >= 1.0.3 and the system has nft <= 0.9.8, that
	// the system nft will become completely unusable.) Unfortunately, we can't easily
	// figure out the version of nft installed on the host filesystem, so instead, we
	// check the kernel version, under the assumption that the distro will have an nft
	// binary that supports the same features as its kernel does, and so kernel 5.13
	// or later implies nft 1.0.1 or later. https://issues.k8s.io/122743
	//
	// However, we allow the user to bypass this check by setting
	// `KUBE_PROXY_NFTABLES_SKIP_KERNEL_VERSION_CHECK` to anything non-empty.
	if os.Getenv("KUBE_PROXY_NFTABLES_SKIP_KERNEL_VERSION_CHECK") == "" {
		kernelVersion, err := utilkernel.GetVersion()
		if err != nil {
			return nil, fmt.Errorf("could not check kernel version: %w", err)
		}
		if kernelVersion.LessThan(version.MustParseGeneric(utilkernel.NFTablesKubeProxyKernelVersion)) {
			return nil, fmt.Errorf("kube-proxy in nftables mode requires kernel %s or later", utilkernel.NFTablesKubeProxyKernelVersion)
		}
	}

	return nft, nil
}

// CleanupLeftovers removes all nftables rules and chains created by the Proxier
// It returns true if an error was encountered. Errors are logged.
func CleanupLeftovers(ctx context.Context) bool {
	logger := klog.FromContext(ctx)
	var encounteredError bool

	for _, family := range []knftables.Family{knftables.IPv4Family, knftables.IPv6Family} {
		nft, err := knftables.New(family, kubeProxyTable)
		if err != nil {
			continue
		}
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Table{})
		err = nft.Run(ctx, tx)
		if err != nil && !knftables.IsNotFound(err) {
			logger.Error(err, "Error cleaning up nftables rules")
			encounteredError = true
		}
	}

	return encounteredError
}
