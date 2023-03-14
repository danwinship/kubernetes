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
	"context"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	v1informers "k8s.io/client-go/informers/core/v1"
	discoveryv1informers "k8s.io/client-go/informers/discovery/v1"
	networkingv1beta1informers "k8s.io/client-go/informers/networking/v1beta1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
)

// Backend represents a proxy backend that contains IPv4 and/or IPv6 proxiers
type Backend struct {
	sync.Mutex

	ipv4Proxier Proxier
	ipv6Proxier Proxier

	topologyLabels map[string]string
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

// StartInformers starts the runner's informers
func (backend *Backend) StartInformers(
	ctx context.Context,
	informerSyncPeriod time.Duration,
	serviceInformer v1informers.ServiceInformer,
	endpointSliceInformer discoveryv1informers.EndpointSliceInformer,
	serviceCIDRInformer networkingv1beta1informers.ServiceCIDRInformer,
	nodeInformer v1informers.NodeInformer,
) {
	serviceConfig := proxyconfig.NewServiceConfig(ctx, serviceInformer, informerSyncPeriod)
	serviceConfig.RegisterEventHandler(backend)
	go serviceConfig.Run(ctx.Done())

	endpointSliceConfig := proxyconfig.NewEndpointSliceConfig(ctx, endpointSliceInformer, informerSyncPeriod)
	endpointSliceConfig.RegisterEventHandler(backend)
	go endpointSliceConfig.Run(ctx.Done())

	if utilfeature.DefaultFeatureGate.Enabled(features.MultiCIDRServiceAllocator) {
		serviceCIDRConfig := proxyconfig.NewServiceCIDRConfig(ctx, serviceCIDRInformer, informerSyncPeriod)
		serviceCIDRConfig.RegisterEventHandler(backend)
		go serviceCIDRConfig.Run(ctx.Done())
	}

	nodeConfig := proxyconfig.NewNodeConfig(ctx, nodeInformer, informerSyncPeriod)
	nodeConfig.RegisterEventHandler(backend)
	go nodeConfig.Run(ctx.Done())
}

// ipv4Sync immediately synchronizes the IPv4 provider
func (backend *Backend) ipv4Sync() {
	backend.ipv4Proxier.Sync()
}

// ipv6Sync immediately synchronizes the IPv6 provider
func (backend *Backend) ipv6Sync() {
	backend.ipv6Proxier.Sync()
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
		if backend.ipv4Proxier.OnServiceAdd(service) {
			backend.ipv4Sync()
		}
	}
	if backend.ipv6Proxier != nil {
		if backend.ipv6Proxier.OnServiceAdd(service) {
			backend.ipv6Sync()
		}
	}
}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (backend *Backend) OnServiceUpdate(oldService, service *v1.Service) {
	if backend.ipv4Proxier != nil {
		if backend.ipv4Proxier.OnServiceUpdate(oldService, service) {
			backend.ipv4Sync()
		}
	}
	if backend.ipv6Proxier != nil {
		if backend.ipv6Proxier.OnServiceUpdate(oldService, service) {
			backend.ipv6Sync()
		}
	}
}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (backend *Backend) OnServiceDelete(service *v1.Service) {
	if backend.ipv4Proxier != nil {
		if backend.ipv4Proxier.OnServiceDelete(service) {
			backend.ipv4Sync()
		}
	}
	if backend.ipv6Proxier != nil {
		if backend.ipv6Proxier.OnServiceDelete(service) {
			backend.ipv6Sync()
		}
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
			if backend.ipv4Proxier.OnEndpointSliceAdd(endpointSlice) {
				backend.ipv4Sync()
			}
		}
	case discovery.AddressTypeIPv6:
		if backend.ipv6Proxier != nil {
			if backend.ipv6Proxier.OnEndpointSliceAdd(endpointSlice) {
				backend.ipv6Sync()
			}
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
			if backend.ipv4Proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice) {
				backend.ipv4Sync()
			}
		}
	case discovery.AddressTypeIPv6:
		if backend.ipv6Proxier != nil {
			if backend.ipv6Proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice) {
				backend.ipv6Sync()
			}
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
			if backend.ipv4Proxier.OnEndpointSliceDelete(endpointSlice) {
				backend.ipv4Sync()
			}
		}
	case discovery.AddressTypeIPv6:
		if backend.ipv6Proxier != nil {
			if backend.ipv6Proxier.OnEndpointSliceDelete(endpointSlice) {
				backend.ipv6Sync()
			}
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

// OnNodeAdd is called when this host's node object is created.
func (backend *Backend) OnNodeAdd(node *v1.Node) {
	backend.OnNodeUpdate(nil, node)
}

// OnNodeUpdate is called when this host's node object is updated.
func (backend *Backend) OnNodeUpdate(oldNode, node *v1.Node) {
	backend.Lock()
	defer backend.Unlock()

	// See if a topology-related label has been set, unset, or modified.
	changed := false
	for _, label := range topologyRelatedLabels {
		oldVal, oldIsSet := backend.topologyLabels[label]
		newVal, newIsSet := node.Labels[label]
		if oldIsSet != newIsSet || oldVal != newVal {
			changed = true
			break
		}
	}

	if changed {
		backend.topologyLabels = node.Labels
		if backend.ipv4Proxier != nil {
			backend.ipv4Proxier.OnTopologyChange(backend.topologyLabels)
			backend.ipv4Sync()
		}
		if backend.ipv6Proxier != nil {
			backend.ipv6Proxier.OnTopologyChange(backend.topologyLabels)
			backend.ipv6Sync()
		}
	}
}

// OnNodeUpdate is called when this host's node object is deleted.
func (backend *Backend) OnNodeDelete(node *v1.Node) {
	backend.OnNodeUpdate(node, &v1.Node{})
}

// OnNodeSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (backend *Backend) OnNodeSynced() {
}

// OnServiceCIDRsChanged is called whenever a change is observed
// in any of the ServiceCIDRs, and provides complete list of service cidrs.
func (backend *Backend) OnServiceCIDRsChanged(cidrs []string) {
	if backend.ipv4Proxier != nil {
		backend.ipv4Proxier.OnServiceCIDRsChanged(cidrs)
		backend.ipv4Sync()
	}
	if backend.ipv6Proxier != nil {
		backend.ipv6Proxier.OnServiceCIDRsChanged(cidrs)
		backend.ipv6Sync()
	}
}
