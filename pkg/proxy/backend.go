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
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	v1informers "k8s.io/client-go/informers/core/v1"
	discoveryv1informers "k8s.io/client-go/informers/discovery/v1"
	networkingv1beta1informers "k8s.io/client-go/informers/networking/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	"k8s.io/kubernetes/pkg/util/async"
)

// Backend represents a proxy backend that contains IPv4 and/or IPv6 proxiers
type Backend struct {
	sync.Mutex

	ipv4Proxier Proxier
	ipv4Runner  *async.BoundedFrequencyRunner

	ipv6Proxier Proxier
	ipv6Runner  *async.BoundedFrequencyRunner

	syncPeriod    time.Duration
	minSyncPeriod time.Duration
	healthzServer *healthcheck.ProxierHealthServer

	informerWaiters []cache.InformerSynced

	topologyLabels map[string]string
}

// NewBackend returns a Backend. Proxier API calls will be dispatched to the Proxier
// instances depending on address family.
func NewBackend(
	ipv4Proxier Proxier,
	ipv6Proxier Proxier,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	healthzServer *healthcheck.ProxierHealthServer,
) *Backend {
	backend := &Backend{
		ipv4Proxier:   ipv4Proxier,
		ipv6Proxier:   ipv6Proxier,
		syncPeriod:    syncPeriod,
		minSyncPeriod: syncPeriod,
		healthzServer: healthzServer,
	}

	if ipv4Proxier != nil {
		backend.ipv4Runner = async.NewBoundedFrequencyRunner("ipv4Runner", backend.ipv4SyncNow, minSyncPeriod, time.Hour, 2)
		// Queue a sync to occur as soon as the runner's loop is started
		backend.ipv4Runner.Run()
	}
	if ipv6Proxier != nil {
		backend.ipv6Runner = async.NewBoundedFrequencyRunner("ipv6Runner", backend.ipv6SyncNow, minSyncPeriod, time.Hour, 2)
		// Queue a sync to occur as soon as the runner's loop is started
		backend.ipv6Runner.Run()
	}

	return backend
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
	backend.informerWaiters = append(backend.informerWaiters, serviceConfig.InformerSynced())

	endpointSliceConfig := proxyconfig.NewEndpointSliceConfig(ctx, endpointSliceInformer, informerSyncPeriod)
	endpointSliceConfig.RegisterEventHandler(backend)
	backend.informerWaiters = append(backend.informerWaiters, endpointSliceConfig.InformerSynced())

	if utilfeature.DefaultFeatureGate.Enabled(features.MultiCIDRServiceAllocator) {
		serviceCIDRConfig := proxyconfig.NewServiceCIDRConfig(ctx, serviceCIDRInformer, informerSyncPeriod)
		serviceCIDRConfig.RegisterEventHandler(backend)
		backend.informerWaiters = append(backend.informerWaiters, serviceCIDRConfig.InformerSynced())
	}

	nodeConfig := proxyconfig.NewNodeConfig(ctx, nodeInformer, informerSyncPeriod)
	nodeConfig.RegisterEventHandler(backend)
	backend.informerWaiters = append(backend.informerWaiters, nodeConfig.InformerSynced())
}

// Run starts the main loop of the Backend (in other goroutines)
func (backend *Backend) Run() {
	go backend.waitAndRun()
}

func (backend *Backend) waitAndRun() {
	klog.InfoS("Waiting for proxy informers to sync")
	cache.WaitForNamedCacheSync("proxy.Runner", wait.NeverStop, backend.informerWaiters...)
	klog.InfoS("Proxy informers are synced")

	if backend.ipv4Proxier != nil {
		metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(v1.IPv4Protocol)).SetToCurrentTime()
		go backend.ipv4Proxier.Run()
		backend.healthzServer.Updated(v1.IPv4Protocol)
		go backend.ipv4Runner.Loop(wait.NeverStop)
	} else if backend.ipv6Proxier != nil {
		metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(v1.IPv6Protocol)).SetToCurrentTime()
		go backend.ipv6Proxier.Run()
		backend.healthzServer.Updated(v1.IPv6Protocol)
		go backend.ipv6Runner.Loop(wait.NeverStop)
	}
}

// ipv4SyncNow immediately synchronizes the IPv4 provider
func (backend *Backend) ipv4SyncNow() {
	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		metrics.SyncProxyRulesLatency.Observe(metrics.SinceInSeconds(start))
		klog.V(2).InfoS("Syncing proxy rules complete", "elapsed", time.Since(start))
	}()

	switch backend.ipv4Proxier.Sync() {
	case SyncSuccess:
		backend.healthzServer.Updated(v1.IPv4Protocol)
		metrics.SyncProxyRulesLastTimestamp.WithLabelValues(string(v1.IPv4Protocol)).SetToCurrentTime()

	case SyncFailure:

	case SyncRetry:
		klog.InfoS("Sync failed", "retryingTime", backend.syncPeriod)
		backend.ipv4Runner.RetryAfter(backend.syncPeriod)
	}
}

// ipv4Sync queues a sync of the IPv4 provider
func (backend *Backend) ipv4Sync() {
	backend.healthzServer.QueuedUpdate(v1.IPv4Protocol)
	metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(v1.IPv4Protocol)).SetToCurrentTime()

	backend.ipv4Runner.Run()
}

// ipv6SyncNow immediately synchronizes the IPv6 provider
func (backend *Backend) ipv6SyncNow() {
	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		metrics.SyncProxyRulesLatency.Observe(metrics.SinceInSeconds(start))
		klog.V(4).InfoS("Syncing proxy rules complete", "elapsed", time.Since(start))
	}()

	switch backend.ipv6Proxier.Sync() {
	case SyncSuccess:
		backend.healthzServer.Updated(v1.IPv6Protocol)
		metrics.SyncProxyRulesLastTimestamp.WithLabelValues(string(v1.IPv6Protocol)).SetToCurrentTime()

	case SyncFailure:

	case SyncRetry:
		klog.InfoS("Sync failed", "retryingTime", backend.syncPeriod)
		backend.ipv6Runner.RetryAfter(backend.syncPeriod)
	}
}

// ipv6Sync queues a sync of the IPv4 provider
func (backend *Backend) ipv6Sync() {
	backend.healthzServer.QueuedUpdate(v1.IPv6Protocol)
	metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(v1.IPv6Protocol)).SetToCurrentTime()

	backend.ipv6Runner.Run()
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
