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

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
)

// Backend implements the winkernel backend
type Backend struct {
	config *proxyconfigapi.KubeProxyConfiguration

	dualStackSupported bool
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeKernelspace] = &Backend{}
}

// Init initializes the winkernel backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration) error {
	if config.Winkernel.RootHnsEndpointName == "" {
		config.Winkernel.RootHnsEndpointName = "cbr0"
	}

	if _, err := CanUseWinKernelProxier(WindowsKernelCompatTester{}); err != nil {
		return err
	}

	// winkernel always supports both single-stack IPv4 and single-stack IPv6,
	// but may not support dual-stack.
	compatTester := DualStackCompatTester{}
	backend.dualStackSupported = compatTester.DualStackCompatible(config.Winkernel.NetworkName)

	backend.config = config
	return nil
}

// CheckIPFamilySupport checks if the winkernel backend can support the given primary IP
// family on this host, and whether dual-stack operation is supported. (Assumes Init() has
// been called.)
func (backend *Backend) CheckIPFamilySupport(ctx context.Context, primaryIPFamily v1.IPFamily) (singleStackSupported, dualStackSupported bool) {
	return true, backend.dualStackSupported
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

// NewProxier creates a new winkernel proxier. (Assumes Init() has been called.)
func (backend *Backend) NewProxier(
	ctx context.Context,
	primaryIPFamily v1.IPFamily,
	nodeName string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	_ map[v1.IPFamily]proxyutil.LocalTrafficDetector,
) (proxy.Proxier, error) {
	var proxier proxy.Proxier
	var err error

	if backend.dualStackSupported {
		proxier, err = NewDualStackProxier(
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			nodeName,
			nodeIPs,
			recorder,
			healthzServer,
			backend.config.HealthzBindAddress,
			backend.config.Winkernel,
		)
	} else {
		proxier, err = NewProxier(
			primaryIPFamily,
			backend.config.SyncPeriod.Duration,
			backend.config.MinSyncPeriod.Duration,
			nodeName,
			nodeIPs[primaryIPFamily],
			recorder,
			healthzServer,
			backend.config.HealthzBindAddress,
			backend.config.Winkernel,
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
	if force {
		klog.FromContext(ctx).Error(nil, "--cleanup is not implemented on Windows")
		return true
	}
	return false
}
