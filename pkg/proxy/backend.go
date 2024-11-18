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

type Backend struct {
	// actual, wrapped
	ipv4Proxier Proxier
	// actual, wrapped
	ipv6Proxier Proxier
}

// NewBackend returns a dual-stack "meta-proxier". Proxier API
// calls will be dispatched to the Proxier instances depending
// on address family.
func NewBackend(ipv4Proxier, ipv6Proxier Proxier) *Backend {
	return &Backend{
		ipv4Proxier: ipv4Proxier,
		ipv6Proxier: ipv6Proxier,
	}
}

// Sync immediately synchronizes the Backend's current state to
// proxy rules.
func (backend *Backend) Sync() {
	backend.ipv4Proxier.Sync()
	backend.ipv6Proxier.Sync()
}

// SyncLoop runs periodic work.  This is expected to run as a
// goroutine or as the main loop of the app.  It does not return.
func (backend *Backend) SyncLoop() {
	go backend.ipv6Proxier.SyncLoop() // Use go-routine here!
	backend.ipv4Proxier.SyncLoop()    // never returns
}

// OnServiceAdd is called whenever creation of new service object is observed.
func (backend *Backend) OnServiceAdd(service *v1.Service) {
	backend.ipv4Proxier.OnServiceAdd(service)
	backend.ipv6Proxier.OnServiceAdd(service)
}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (backend *Backend) OnServiceUpdate(oldService, service *v1.Service) {
	backend.ipv4Proxier.OnServiceUpdate(oldService, service)
	backend.ipv6Proxier.OnServiceUpdate(oldService, service)
}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (backend *Backend) OnServiceDelete(service *v1.Service) {
	backend.ipv4Proxier.OnServiceDelete(service)
	backend.ipv6Proxier.OnServiceDelete(service)
}

// OnServiceSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnServiceSynced() {
	backend.ipv4Proxier.OnServiceSynced()
	backend.ipv6Proxier.OnServiceSynced()
}

// OnEndpointSliceAdd is called whenever creation of a new endpoint slice object
// is observed.
func (backend *Backend) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	switch endpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		backend.ipv4Proxier.OnEndpointSliceAdd(endpointSlice)
	case discovery.AddressTypeIPv6:
		backend.ipv6Proxier.OnEndpointSliceAdd(endpointSlice)
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", endpointSlice.AddressType)
	}
}

// OnEndpointSliceUpdate is called whenever modification of an existing endpoint
// slice object is observed.
func (backend *Backend) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) {
	switch newEndpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		backend.ipv4Proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
	case discovery.AddressTypeIPv6:
		backend.ipv6Proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", newEndpointSlice.AddressType)
	}
}

// OnEndpointSliceDelete is called whenever deletion of an existing endpoint slice
// object is observed.
func (backend *Backend) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	switch endpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		backend.ipv4Proxier.OnEndpointSliceDelete(endpointSlice)
	case discovery.AddressTypeIPv6:
		backend.ipv6Proxier.OnEndpointSliceDelete(endpointSlice)
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", endpointSlice.AddressType)
	}
}

// OnEndpointSlicesSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnEndpointSlicesSynced() {
	backend.ipv4Proxier.OnEndpointSlicesSynced()
	backend.ipv6Proxier.OnEndpointSlicesSynced()
}

// OnNodeAdd is called whenever creation of new node object is observed.
func (backend *Backend) OnNodeAdd(node *v1.Node) {
	backend.ipv4Proxier.OnNodeAdd(node)
	backend.ipv6Proxier.OnNodeAdd(node)
}

// OnNodeUpdate is called whenever modification of an existing
// node object is observed.
func (backend *Backend) OnNodeUpdate(oldNode, node *v1.Node) {
	backend.ipv4Proxier.OnNodeUpdate(oldNode, node)
	backend.ipv6Proxier.OnNodeUpdate(oldNode, node)
}

// OnNodeDelete is called whenever deletion of an existing node
// object is observed.
func (backend *Backend) OnNodeDelete(node *v1.Node) {
	backend.ipv4Proxier.OnNodeDelete(node)
	backend.ipv6Proxier.OnNodeDelete(node)
}

// OnNodeSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnNodeSynced() {
	backend.ipv4Proxier.OnNodeSynced()
	backend.ipv6Proxier.OnNodeSynced()
}

// OnServiceCIDRsChanged is called whenever a change is observed
// in any of the ServiceCIDRs, and provides complete list of service cidrs.
func (backend *Backend) OnServiceCIDRsChanged(cidrs []string) {
	backend.ipv4Proxier.OnServiceCIDRsChanged(cidrs)
	backend.ipv6Proxier.OnServiceCIDRsChanged(cidrs)
}
