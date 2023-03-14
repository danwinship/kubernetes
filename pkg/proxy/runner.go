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
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	v1informers "k8s.io/client-go/informers/core/v1"
	discoveryv1informers "k8s.io/client-go/informers/discovery/v1"
	networkingv1informers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/klog/v2"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	"k8s.io/kubernetes/pkg/proxy/runner"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
)

// Runner wraps 0 or more other proxiers. Proxier API calls will be dispatched to the
// Proxier instances depending on address family.
type Runner struct {
	proxiers map[v1.IPFamily]Proxier
	bfrs     map[v1.IPFamily]*runner.BoundedFrequencyRunner

	syncPeriod    time.Duration
	minSyncPeriod time.Duration
	healthzServer *healthcheck.ProxyHealthServer
}

// NewRunner returns an empty Runner
func NewRunner(syncPeriod time.Duration, minSyncPeriod time.Duration, healthzServer *healthcheck.ProxyHealthServer) *Runner {
	return &Runner{
		proxiers: make(map[v1.IPFamily]Proxier),
		bfrs:     make(map[v1.IPFamily]*runner.BoundedFrequencyRunner),

		syncPeriod:    syncPeriod,
		minSyncPeriod: minSyncPeriod,
		healthzServer: healthzServer,
	}
}

// AddProxier adds proxier to the Runner
func (r *Runner) AddProxier(family v1.IPFamily, proxier Proxier) {
	r.proxiers[family] = proxier
	r.bfrs[family] = runner.NewBoundedFrequencyRunner(fmt.Sprintf("proxy-%s", family), func() error { return r.syncNow(family) }, r.minSyncPeriod, r.syncPeriod, proxyutil.FullSyncPeriod)
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

	if nodeInformer != nil {
		nodeTopologyConfig := proxyconfig.NewNodeTopologyConfig(ctx, nodeInformer, informerSyncPeriod)
		nodeTopologyConfig.RegisterEventHandler(r)
		// The nodeInformer is already synced at this point because of the NodeManager so
		// it has no Run() method.
	}
}

// Run starts the main loop(s) of the Runner (in goroutines)
func (r *Runner) Run() {
	for family := range r.proxiers {
		metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(family)).SetToCurrentTime()
		go r.proxiers[family].Run()
		r.healthzServer.Updated(family)
		go r.bfrs[family].Loop(wait.NeverStop)
	}
}

// syncNow immediately synchronizes the indicated proxier
func (r *Runner) syncNow(family v1.IPFamily) error {
	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		metrics.SyncProxyRulesLatency.WithLabelValues(string(family)).Observe(metrics.SinceInSeconds(start))
		klog.V(2).InfoS("Syncing proxy rules complete", "family", family, "elapsed", time.Since(start))
	}()

	if err := r.proxiers[family].Sync(); err != nil {
		return err
	}

	r.healthzServer.Updated(family)
	metrics.SyncProxyRulesLastTimestamp.WithLabelValues(string(family)).SetToCurrentTime()
	return nil
}

// sync queues a run of the indicated proxier
func (r *Runner) sync(family v1.IPFamily) {
	r.healthzServer.QueuedUpdate(family)
	metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(family)).SetToCurrentTime()

	r.bfrs[family].Run()
}

// OnServiceAdd is called whenever creation of new service object is observed.
func (r *Runner) OnServiceAdd(service *v1.Service) {
	for family, proxier := range r.proxiers {
		if proxier.OnServiceAdd(service) {
			r.sync(family)
		}
	}
}

// OnServiceUpdate is called whenever modification of an existing service object is
// observed.
func (r *Runner) OnServiceUpdate(oldService, service *v1.Service) {
	for family, proxier := range r.proxiers {
		if proxier.OnServiceUpdate(oldService, service) {
			r.sync(family)
		}
	}
}

// OnServiceDelete is called whenever deletion of an existing service object is observed.
func (r *Runner) OnServiceDelete(service *v1.Service) {
	for family, proxier := range r.proxiers {
		if proxier.OnServiceDelete(service) {
			r.sync(family)
		}
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
		if proxier != nil && proxier.OnEndpointSliceAdd(endpointSlice) {
			r.sync(v1.IPv4Protocol)
		}
	case discovery.AddressTypeIPv6:
		proxier := r.proxiers[v1.IPv6Protocol]
		if proxier != nil && proxier.OnEndpointSliceAdd(endpointSlice) {
			r.sync(v1.IPv6Protocol)
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
		if proxier != nil && proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice) {
			r.sync(v1.IPv4Protocol)
		}
	case discovery.AddressTypeIPv6:
		proxier := r.proxiers[v1.IPv6Protocol]
		if proxier != nil && proxier.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice) {
			r.sync(v1.IPv6Protocol)
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
		if proxier != nil && proxier.OnEndpointSliceDelete(endpointSlice) {
			r.sync(v1.IPv4Protocol)
		}
	case discovery.AddressTypeIPv6:
		proxier := r.proxiers[v1.IPv6Protocol]
		if proxier != nil && proxier.OnEndpointSliceDelete(endpointSlice) {
			r.sync(v1.IPv6Protocol)
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

// OnTopologyChange is called whenever change in proxy relevant topology labels is observed.
func (r *Runner) OnTopologyChange(topologyLabels map[string]string) {
	for family, proxier := range r.proxiers {
		proxier.OnTopologyChange(topologyLabels)
		r.sync(family)
	}
}

// OnServiceCIDRsChanged is called whenever a change is observed in any of the
// ServiceCIDRs, and provides complete list of service cidrs.
func (r *Runner) OnServiceCIDRsChanged(cidrs []string) {
	for family, proxier := range r.proxiers {
		proxier.OnServiceCIDRsChanged(cidrs)
		r.sync(family)
	}
}
