/*
Copyright 2015 The Kubernetes Authors.

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

package proxy

import (
	"context"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
)

// Backend represents an entire proxy backend (e.g., nftables, winkernel).
type Backend interface {
	// Init initializes the selected backend, applies backend-specific config defaults,
	// and confirms that the backend can run on this node with this config.
	Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, primaryIPFamily v1.IPFamily) error

	// DualStackSupported checks if the backend supports dual-stack operation on this
	// host. (Assumes Init() has been called.)
	DualStackSupported() bool

	// PrivilegedInit performs any host initialization steps that require full root
	// privileges, *if they have not already been performed*. When using
	// `--init-only`, this will be called first from a privileged kube-proxy process,
	// and then a second time from an unprivileged kube-proxy process; the second call
	// must not return an error if the first call correctly initialized everything.
	// (Assumes Init() has been called.)
	PrivilegedInit(ctx context.Context, initOnly bool) error

	// NewProxyRunner creates the proxy.Runner for a Backend. (Assumes Init() has been
	// called.)
	NewProxyRunner(ctx context.Context, nodeName string, nodeIPs map[v1.IPFamily]net.IP, recorder events.EventRecorder, healthzServer *healthcheck.ProxyHealthServer, localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector) (*Runner, error)

	// Cleanup cleans up state left behind by a previous run of the Backend, either
	// because the user is switching backends, or because they ran --cleanup. If force
	// is true, then it should clean up everything, unconditionally. Otherwise, it
	// should only clean up state that is guaranteed to not interfere with the current
	// backend according to config. The return value indicates whether any errors
	// occurred. (Unlike the other methods, this *does not* require that Init() has
	// been called.)
	Cleanup(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration, force bool) bool
}

// Backends gives the set of available backends
var Backends = map[proxyconfigapi.ProxyMode]Backend{}

// Proxier is the interface to a specific proxy implementation. A Backend may wrap one or
// more Proxiers.
type Proxier interface {
	// The OnService*, OnEndpointSlice*, and OnNode* methods have the same semantics
	// as in config.ServiceHandler, config.EndpointSliceHandler, and
	// config.NodeHandler, but return a bool indicating whether or not a sync is
	// needed
	OnServiceAdd(service *v1.Service) bool
	OnServiceUpdate(oldService, service *v1.Service) bool
	OnServiceDelete(service *v1.Service) bool
	OnServiceSynced()

	OnEndpointSliceAdd(endpointSlice *discoveryv1.EndpointSlice) bool
	OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discoveryv1.EndpointSlice) bool
	OnEndpointSliceDelete(endpointSlice *discoveryv1.EndpointSlice) bool
	OnEndpointSlicesSynced()

	// OnServiceCIDRsChanged is called whenever a change is observed
	// in any of the ServiceCIDRs, and provides complete list of service cidrs.
	OnServiceCIDRsChanged(cidrs []string)

	// OnTopologyChange is called whenever a change is observed in proxy
	// relevant node topology labels, and provides the observed change.
	OnTopologyChange(topologyLabels map[string]string)

	// Run starts the proxy. This is expected to run as a goroutine or as the main
	// loop of the app. It does not return.
	Run()

	// Sync immediately synchronizes the Proxier's current state to proxy rules.
	Sync() error
}

// ServicePortName carries a namespace + name + portname.  This is the unique
// identifier for a load-balanced service.
type ServicePortName struct {
	types.NamespacedName
	Port     string
	Protocol v1.Protocol
}

func (spn ServicePortName) String() string {
	return fmt.Sprintf("%s%s", spn.NamespacedName.String(), fmtPortName(spn.Port))
}

func fmtPortName(in string) string {
	if in == "" {
		return ""
	}
	return fmt.Sprintf(":%s", in)
}

// ServiceEndpoint is used to identify a service and one of its endpoint pair.
type ServiceEndpoint struct {
	Endpoint        string
	ServicePortName ServicePortName
}
