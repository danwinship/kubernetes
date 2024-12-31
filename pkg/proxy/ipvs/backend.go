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

package ipvs

import (
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	utilipset "k8s.io/kubernetes/pkg/proxy/ipvs/ipset"
	utilipvs "k8s.io/kubernetes/pkg/proxy/ipvs/util"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

// Backend implements the IPVS backend
type Backend struct {
	config         *kubeproxyconfig.KubeProxyConfiguration
	hostname       string
	nodeIPs        map[v1.IPFamily]net.IP
	recorder       events.EventRecorder
	healthzServer  *healthcheck.ProxyHealthServer
	localDetectors map[v1.IPFamily]proxyutil.LocalTrafficDetector

	ipts   map[v1.IPFamily]utiliptables.Interface
	ipvs   utilipvs.Interface
	ipset  utilipset.Interface
	sysctl utilsysctl.Interface
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new IPVS proxy backend
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
	ipset := utilipset.New()
	ipvs := utilipvs.New()
	sysctl := utilsysctl.New()

	return &Backend{
		config:         config,
		hostname:       hostname,
		nodeIPs:        nodeIPs,
		recorder:       recorder,
		healthzServer:  healthzServer,
		localDetectors: localDetectors,

		ipts:   ipts,
		ipvs:   ipvs,
		ipset:  ipset,
		sysctl: sysctl,
	}, nil
}
