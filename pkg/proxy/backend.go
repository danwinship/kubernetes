/*
Copyright 2019 The Kubernetes Authors.

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
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/klog/v2"
)

// Backend represents a proxy backend that contains IPv4 and/or IPv6 proxiers
type Backend struct {
	ipv4Proxier Proxier
	ipv6Proxier Proxier
}

// NewBackend returns a Backend. Proxier API calls will be dispatched to the Proxier
// instances depending on address family.
func NewBackend(ipv4Proxier, ipv6Proxier Proxier) *Backend {
	return &Backend{
		ipv4Proxier: ipv4Proxier,
		ipv6Proxier: ipv6Proxier,
	}
}

// SupportedFamilies returns the IP families supported by backend
func (backend *Backend) SupportedFamilies() (ipv4Supported, ipv6Supported, dualStackSupported bool) {
	ipv4Supported = backend.ipv4Proxier != nil
	ipv6Supported = backend.ipv6Proxier != nil
	dualStackSupported = ipv4Supported && ipv6Supported
	return
}

// Sync immediately synchronizes the Backend's current state to proxy rules.
func (backend *Backend) Sync() {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.Sync()
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.Sync()
	}
}

// SyncLoop runs periodic work.  This is expected to run as a
// goroutine or as the main loop of the app.  It does not return.
func (backend *Backend) SyncLoop() {
	switch {
	case backend.ipv4Proxier != nil && backend.ipv6Proxier != nil:
		go backend.ipv6Proxier.SyncLoop()
		backend.ipv4Proxier.SyncLoop()
	case backend.ipv4Proxier != nil:
		backend.ipv4Proxier.SyncLoop()
	case backend.ipv6Proxier != nil:
		backend.ipv6Proxier.SyncLoop()
	default:
		select {}
	}
}

// OnServiceAdd is called whenever creation of new service object is observed.
func (backend *Backend) OnServiceAdd(service *v1.Service) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnServiceAdd(service)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnServiceAdd(service)
	}
}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (backend *Backend) OnServiceUpdate(oldService, service *v1.Service) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnServiceUpdate(oldService, service)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnServiceUpdate(oldService, service)
	}
}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (backend *Backend) OnServiceDelete(service *v1.Service) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnServiceDelete(service)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnServiceDelete(service)
	}
}

// OnServiceSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnServiceSynced() {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnServiceSynced()
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnServiceSynced()
	}
}

// OnEndpointSliceAdd is called whenever creation of a new endpoint slice object
// is observed.
func (backend *Backend) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	switch endpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		if backend.ipv4Proxier != nil {
			backend.ipv4Proxier.OnEndpointSliceAdd(endpointSlice)
		}
	case discovery.AddressTypeIPv6:
		if backend.ipv6Proxier != nil {
			backend.ipv6Proxier.OnEndpointSliceAdd(endpointSlice)
		}
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", endpointSlice.AddressType)
	}
}

// OnEndpointSliceUpdate is called whenever modification of an existing endpoint
// slice object is observed.
func (backend *Backend) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) {
	switch newEndpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		if backend.ipv4Proxier != nil {
			backend.ipv4Proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
		}
	case discovery.AddressTypeIPv6:
		if backend.ipv6Proxier != nil {
			backend.ipv6Proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
		}
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", newEndpointSlice.AddressType)
	}
}

// OnEndpointSliceDelete is called whenever deletion of an existing endpoint slice
// object is observed.
func (backend *Backend) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	switch endpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		if backend.ipv4Proxier != nil {
			backend.ipv4Proxier.OnEndpointSliceDelete(endpointSlice)
		}
	case discovery.AddressTypeIPv6:
		if backend.ipv6Proxier != nil {
			backend.ipv6Proxier.OnEndpointSliceDelete(endpointSlice)
		}
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", endpointSlice.AddressType)
	}
}

// OnEndpointSlicesSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnEndpointSlicesSynced() {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnEndpointSlicesSynced()
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnEndpointSlicesSynced()
	}
}

// OnNodeAdd is called whenever creation of new node object is observed.
func (backend *Backend) OnNodeAdd(node *v1.Node) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnNodeAdd(node)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnNodeAdd(node)
	}
}

// OnNodeUpdate is called whenever modification of an existing
// node object is observed.
func (backend *Backend) OnNodeUpdate(oldNode, node *v1.Node) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnNodeUpdate(oldNode, node)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnNodeUpdate(oldNode, node)
	}
}

// OnNodeDelete is called whenever deletion of an existing node
// object is observed.
func (backend *Backend) OnNodeDelete(node *v1.Node) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnNodeDelete(node)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnNodeDelete(node)
	}
}

// OnNodeSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnNodeSynced() {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnNodeSynced()
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnNodeSynced()
	}
}

// OnServiceCIDRsChanged is called whenever a change is observed
// in any of the ServiceCIDRs, and provides complete list of service cidrs.
func (backend *Backend) OnServiceCIDRsChanged(cidrs []string) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnServiceCIDRsChanged(cidrs)
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnServiceCIDRsChanged(cidrs)
	}
}
