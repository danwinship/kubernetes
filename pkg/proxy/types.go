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

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/proxy/config"
)

// Backend represents an entire proxy backend (e.g., nftables, winkernel).
type Backend interface {
	// DualStackSupported is true if the Backend supports dual-stack proxying on this
	// host.
	DualStackSupported() bool

	// PrivilegedInit performs any host initialization steps that require full root
	// privileges, *if they have not already been performed*. When using
	// `--init-only`, this will be called first from a privileged kube-proxy process,
	// and then a second time from an unprivileged kube-proxy process; the second call
	// must not return an error if the first call correctly initialized everything.
	PrivilegedInit(ctx context.Context) error

	// NewRunner creates the proxy.Runner for a Backend
	NewRunner(ctx context.Context) (*Runner, error)
}

// Proxier is the interface to a specific proxy implementation. A Backend may wrap one or
// more Proxiers.
type Proxier interface {
	config.EndpointSliceHandler
	config.ServiceHandler
	config.NodeHandler
	config.ServiceCIDRHandler

	// Sync immediately synchronizes the Proxier's current state to proxy rules.
	Sync()
	// SyncLoop runs periodic work.
	// This is expected to run as a goroutine or as the main loop of the app.
	// It does not return.
	SyncLoop()
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
