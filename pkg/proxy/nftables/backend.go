//go:build linux
// +build linux

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

package nftables

import (
	"context"
	"fmt"
	"net"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
)

// NewDualStackProxier creates a new dual-stack NFTables proxier.
func NewDualStackProxier(
	ctx context.Context,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	masqueradeBit int,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxierHealthServer,
	nodePortAddresses []string,
	initOnly bool,
) (*proxy.Backend, error) {
	// Create an ipv4 instance of the single-stack proxier
	ipv4Proxier, err := NewProxier(ctx, v1.IPv4Protocol,
		syncPeriod, minSyncPeriod, masqueradeAll, masqueradeBit,
		localDetectors[v1.IPv4Protocol], hostname, nodeIPs[v1.IPv4Protocol],
		recorder, healthzServer, nodePortAddresses, initOnly)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
	}

	ipv6Proxier, err := NewProxier(ctx, v1.IPv6Protocol,
		syncPeriod, minSyncPeriod, masqueradeAll, masqueradeBit,
		localDetectors[v1.IPv6Protocol], hostname, nodeIPs[v1.IPv6Protocol],
		recorder, healthzServer, nodePortAddresses, initOnly)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 proxier: %v", err)
	}
	if initOnly {
		return nil, nil
	}
	return proxy.NewBackend(ipv4Proxier, ipv6Proxier), nil
}
