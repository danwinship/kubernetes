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

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
)

// Backend implements the NFTables backend
type Backend struct {
	config          *proxyconfigapi.KubeProxyConfiguration
	primaryIPFamily v1.IPFamily
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeNFTables] = &Backend{}
}

// Init initializes the NFTables backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, primaryIPFamily v1.IPFamily) error {
	// If NodePortAddresses is unspecified, default to `--nodeport-addresses primary`
	if len(config.NodePortAddresses) == 0 {
		config.NodePortAddresses = []string{proxyconfigapi.NodePortAddressesPrimary}
	}

	backend.config = config
	backend.primaryIPFamily = primaryIPFamily
	return nil
}
