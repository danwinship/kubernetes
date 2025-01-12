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

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
)

// Backend implements the winkernel backend
type Backend struct {
	config             *proxyconfigapi.KubeProxyConfiguration
	primaryIPFamily    v1.IPFamily
	dualStackSupported bool
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeKernelspace] = &Backend{}
}

// Init initializes the winkernel backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, primaryIPFamily v1.IPFamily) error {
	if config.Winkernel.RootHnsEndpointName == "" {
		config.Winkernel.RootHnsEndpointName = "cbr0"
	}

	if _, err := CanUseWinKernelProxier(WindowsKernelCompatTester{}); err != nil {
		return err
	}

	backend.config = config
	backend.primaryIPFamily = primaryIPFamily

	// winkernel always supports both single-stack IPv4 and single-stack IPv6,
	// but may not support dual-stack.
	compatTester := DualStackCompatTester{}
	backend.dualStackSupported = compatTester.DualStackCompatible(config.Winkernel.NetworkName)

	return nil
}

// DualStackSupported checks if the winkernel backend supports dual-stack operation on this
// host. (Assumes Init() has been called.)
func (backend *Backend) DualStackSupported() bool {
	return backend.dualStackSupported
}

// PrivilegedInit performs any host initialization steps that require full root
// privileges, *if they have not already been performed*. When using `--init-only`, this
// will be called first from a privileged kube-proxy process, and then a second time from
// an unprivileged kube-proxy process; the second call must not return an error if the
// first call correctly initialized everything. (Assumes Init() has been called.)
func (backend *Backend) PrivilegedInit(ctx context.Context, initOnly bool) error {
	if initOnly {
		return fmt.Errorf("--init-only is not implemented on Windows")
	}

	// This is still called as part of setup even when not using initOnly. In that
	// case, there is nothing to do on Windows.
	return nil
}
