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
	v1informers "k8s.io/client-go/informers/core/v1"
	discoveryv1informers "k8s.io/client-go/informers/discovery/v1"
	networkingv1informers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/klog/v2"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
)

// Runner wraps 0 or more other proxiers. Proxier API calls will be dispatched to the
// Proxier instances depending on address family.
type Runner struct {
	lock sync.Mutex

	proxiers map[v1.IPFamily]Proxier

	topologyLabels map[string]string
}

// NewRunner returns an empty Runner
func NewRunner() *Runner {
	return &Runner{
		proxiers: make(map[v1.IPFamily]Proxier),
	}
}

// AddProxier adds proxier to the Runner
func (r *Runner) AddProxier(family v1.IPFamily, proxier Proxier) {
	r.proxiers[family] = proxier
}

// StartInformers starts the runner's informers
func (r *Runner) StartInformers(
	ctx context.Context,
	informerSyncPeriod time.Duration,
	serviceInformer v1informers.ServiceInformer,
	endpointSliceInformer discoveryv1informers.EndpointSliceInformer,
	serviceCIDRInformer networkingv1informers.ServiceCIDRInformer,
	nodeInformer v1informers.NodeInformer,
) {
	serviceConfig := proxyconfig.NewServiceConfig(ctx, serviceInformer, informerSyncPeriod)
	serviceConfig.RegisterEventHandler(r)
	go serviceConfig.Run(ctx.Done())

	endpointSliceConfig := proxyconfig.NewEndpointSliceConfig(ctx, endpointSliceInformer, informerSyncPeriod)
	endpointSliceConfig.RegisterEventHandler(r)
	go endpointSliceConfig.Run(ctx.Done())

	serviceCIDRConfig := proxyconfig.NewServiceCIDRConfig(ctx, serviceCIDRInformer, informerSyncPeriod)
	serviceCIDRConfig.RegisterEventHandler(r)
	go serviceCIDRConfig.Run(ctx.Done())

	nodeConfig := proxyconfig.NewNodeConfig(ctx, nodeInformer, informerSyncPeriod)
	nodeConfig.RegisterEventHandler(r)
	go nodeConfig.Run(ctx.Done())
}

// Sync immediately synchronizes the Proxier's current state to proxy rules.
func (r *Runner) Sync() {
	for _, proxier := range r.proxiers {
		proxier.Sync()
	}
}

// SyncLoop runs periodic work. This is expected to run as a goroutine or as the main loop
// of the app. It does not return.
func (r *Runner) SyncLoop() {
	switch {
	case r.proxiers[v1.IPv4Protocol] != nil && r.proxiers[v1.IPv6Protocol] != nil:
		go r.proxiers[v1.IPv6Protocol].SyncLoop()
		r.proxiers[v1.IPv4Protocol].SyncLoop()
	case r.proxiers[v1.IPv4Protocol] != nil:
		r.proxiers[v1.IPv4Protocol].SyncLoop()
	case r.proxiers[v1.IPv6Protocol] != nil:
		r.proxiers[v1.IPv6Protocol].SyncLoop()
	default:
		select {}
	}
}

// OnServiceAdd is called whenever creation of new service object is observed.
func (r *Runner) OnServiceAdd(service *v1.Service) {
	for _, proxier := range r.proxiers {
		proxier.OnServiceAdd(service)
	}
}

// OnServiceUpdate is called whenever modification of an existing service object is
// observed.
func (r *Runner) OnServiceUpdate(oldService, service *v1.Service) {
	for _, proxier := range r.proxiers {
		proxier.OnServiceUpdate(oldService, service)
	}
}

// OnServiceDelete is called whenever deletion of an existing service object is observed.
func (r *Runner) OnServiceDelete(service *v1.Service) {
	for _, proxier := range r.proxiers {
		proxier.OnServiceDelete(service)
	}
}

// OnServiceSynced is called once all the initial event handlers were called and the state
// is fully propagated to local cache.
func (r *Runner) OnServiceSynced() {
	for _, proxier := range r.proxiers {
		proxier.OnServiceSynced()
	}
}

// OnEndpointSliceAdd is called whenever creation of a new endpoint slice object
// is observed.
func (r *Runner) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	switch endpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		proxier := r.proxiers[v1.IPv4Protocol]
		if proxier != nil {
			proxier.OnEndpointSliceAdd(endpointSlice)
		}
	case discovery.AddressTypeIPv6:
		proxier := r.proxiers[v1.IPv6Protocol]
		if proxier != nil {
			proxier.OnEndpointSliceAdd(endpointSlice)
		}
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", endpointSlice.AddressType)
	}
}

// OnEndpointSliceUpdate is called whenever modification of an existing endpoint
// slice object is observed.
func (r *Runner) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) {
	switch newEndpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		proxier := r.proxiers[v1.IPv4Protocol]
		if proxier != nil {
			proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
		}
	case discovery.AddressTypeIPv6:
		proxier := r.proxiers[v1.IPv6Protocol]
		if proxier != nil {
			proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
		}
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", newEndpointSlice.AddressType)
	}
}

// OnEndpointSliceDelete is called whenever deletion of an existing endpoint slice
// object is observed.
func (r *Runner) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	switch endpointSlice.AddressType {
	case discovery.AddressTypeIPv4:
		proxier := r.proxiers[v1.IPv4Protocol]
		if proxier != nil {
			proxier.OnEndpointSliceDelete(endpointSlice)
		}
	case discovery.AddressTypeIPv6:
		proxier := r.proxiers[v1.IPv6Protocol]
		if proxier != nil {
			proxier.OnEndpointSliceDelete(endpointSlice)
		}
	default:
		klog.ErrorS(nil, "EndpointSlice address type not supported", "addressType", endpointSlice.AddressType)
	}
}

// OnEndpointSlicesSynced is called once all the initial event handlers were called and
// the state is fully propagated to local cache.
func (r *Runner) OnEndpointSlicesSynced() {
	for _, proxier := range r.proxiers {
		proxier.OnEndpointSlicesSynced()
	}
}

// OnNodeAdd is called when this host's node object is created.
func (r *Runner) OnNodeAdd(node *v1.Node) {
	r.onNodeLabelUpdate(node.Labels)
}

// OnNodeUpdate is called when this host's node object is updated.
func (r *Runner) OnNodeUpdate(oldNode, node *v1.Node) {
	r.onNodeLabelUpdate(node.Labels)
}

// OnNodeDelete is called when this host's node is deleted.
func (r *Runner) OnNodeDelete(node *v1.Node) {
	r.onNodeLabelUpdate(nil)
}

func (r *Runner) onNodeLabelUpdate(newLabels map[string]string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	// See if a topology-related label has been set, unset, or modified.
	changed := false
	for _, label := range topologyRelatedLabels {
		oldVal, oldIsSet := r.topologyLabels[label]
		newVal, newIsSet := newLabels[label]
		if oldIsSet && !newIsSet {
			delete(r.topologyLabels, label)
			changed = true
		} else if (!oldIsSet && newIsSet) || (oldVal != newVal) {
			r.topologyLabels[label] = newVal
			changed = true
		}
	}

	if changed {
		for _, proxier := range r.proxiers {
			proxier.OnTopologyChange(r.topologyLabels)
		}
	}
}

// OnNodeSynced is called once all the initial event handlers were called and the state is
// fully propagated to local cache.
func (r *Runner) OnNodeSynced() {
}

// OnServiceCIDRsChanged is called whenever a change is observed in any of the
// ServiceCIDRs, and provides complete list of service cidrs.
func (r *Runner) OnServiceCIDRsChanged(cidrs []string) {
	for _, proxier := range r.proxiers {
		proxier.OnServiceCIDRsChanged(cidrs)
	}
}
