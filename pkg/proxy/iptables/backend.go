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

package iptables

import (
	"context"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

const sysctlRouteLocalnet = "net/ipv4/conf/all/route_localnet"

// Backend implements the IPTables backend
type Backend struct {
	config            *kubeproxyconfig.KubeProxyConfiguration
	hostname          string
	nodeIPs           map[v1.IPFamily]net.IP
	recorder          events.EventRecorder
	healthzServer     *healthcheck.ProxyHealthServer
	localDetectors    map[v1.IPFamily]proxyutil.LocalTrafficDetector
	nodePortAddresses map[v1.IPFamily]*proxyutil.NodePortAddresses

	ipts   map[v1.IPFamily]utiliptables.Interface
	sysctl utilsysctl.Interface
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new IPTables proxy backend
func NewBackend(
	ctx context.Context,
	config *kubeproxyconfig.KubeProxyConfiguration,
	primaryIPFamily v1.IPFamily,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector,
) (*Backend, error) {
	ipts := utiliptables.NewDualStack()
	sysctl := utilsysctl.New()

	if len(ipts) == 0 {
		return nil, fmt.Errorf("iptables is not available on this host")
	}

	nodePortAddresses := map[v1.IPFamily]*proxyutil.NodePortAddresses{
		v1.IPv4Protocol: proxyutil.NewNodePortAddresses(v1.IPv4Protocol, config.NodePortAddresses),
		v1.IPv6Protocol: proxyutil.NewNodePortAddresses(v1.IPv6Protocol, config.NodePortAddresses),
	}

	return &Backend{
		config:            config,
		hostname:          hostname,
		nodeIPs:           nodeIPs,
		recorder:          recorder,
		healthzServer:     healthzServer,
		localDetectors:    localDetectors,
		nodePortAddresses: nodePortAddresses,

		ipts:   ipts,
		sysctl: sysctl,
	}, nil
}

func (backend *Backend) PrivilegedInit(ctx context.Context) error {
	// Figure out if we need to set route_localnet to allow IPv4 localhost NodePorts.
	// https://issues.k8s.io/90259
	if backend.ipts[v1.IPv4Protocol] != nil &&
		*backend.config.IPTables.LocalhostNodePorts &&
		backend.nodePortAddresses[v1.IPv4Protocol].ContainsIPv4Loopback() {

		logger := klog.FromContext(ctx)
		logger.Info("Setting route_localnet=1 to allow node-ports on localhost; to change this either disable iptables.localhostNodePorts (--iptables-localhost-nodeports) or set nodePortAddresses (--nodeport-addresses) to filter loopback addresses")
		if err := proxyutil.EnsureSysctl(backend.sysctl, sysctlRouteLocalnet, 1); err != nil {
			return fmt.Errorf("cannot set required sysctl for proxy: %v", err)
		}
	}

	return nil
}
