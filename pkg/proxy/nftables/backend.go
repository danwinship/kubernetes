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

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
	"sigs.k8s.io/knftables"
)

// Backend implements the NFTables backend
type Backend struct {
	config          *proxyconfigapi.KubeProxyConfiguration
	primaryIPFamily v1.IPFamily

	nfts map[v1.IPFamily]knftables.Interface
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeNFTables] = &Backend{}
}

// Init initializes the NFTables backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, primaryIPFamily v1.IPFamily) error {
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
	} else if primaryIPFamily == v1.IPv6Protocol {
		return fmt.Errorf("no backend support for primary IP family (%s)", primaryIPFamily)
	} else {
		logger.Info("No nftables support for family", "family", v1.IPv6Protocol, "error", err)
	}

	if err = checkNFTablesSupport(); err != nil {
		return err
	}

	backend.config = config
	backend.primaryIPFamily = primaryIPFamily
	return nil
}

// DualStackSupported checks if the NFTables backend supports dual-stack operation on this
// host. (Assumes Init() has been called.)
func (backend *Backend) DualStackSupported() bool {
	return len(backend.nfts) == 2
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
