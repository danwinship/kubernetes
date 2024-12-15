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
	"fmt"
	"net"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
)

// NewDualStackProxier returns a new dual-stack winkernel proxier.
func NewDualStackProxier(
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxierHealthServer,
	healthzBindAddress string,
	config config.KubeProxyWinkernelConfiguration,
) (*proxy.Backend, error) {

	// Create an ipv4 instance of the single-stack proxier
	ipv4Proxier, err := NewProxier(v1.IPv4Protocol, syncPeriod, minSyncPeriod,
		hostname, nodeIPs[v1.IPv4Protocol], recorder, healthzServer,
		healthzBindAddress, config)

	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v, hostname: %s, nodeIP:%v", err, hostname, nodeIPs[v1.IPv4Protocol])
	}

	ipv6Proxier, err := NewProxier(v1.IPv6Protocol, syncPeriod, minSyncPeriod,
		hostname, nodeIPs[v1.IPv6Protocol], recorder, healthzServer,
		healthzBindAddress, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 proxier: %v, hostname: %s, nodeIP:%v", err, hostname, nodeIPs[v1.IPv6Protocol])
	}

	// Return a meta-proxier that dispatch calls between the two
	// single-stack proxier instances
	return proxy.NewBackend(ipv4Proxier, ipv6Proxier), nil
}
