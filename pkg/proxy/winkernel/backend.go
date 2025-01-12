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
	"context"
	"fmt"
	"net"

	"github.com/Microsoft/hnslib"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/kubernetes/pkg/proxy"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
)

// Backend implements the winkernel backend
type Backend struct {
	config          *kubeproxyconfig.KubeProxyConfiguration
	primaryIPFamily v1.IPFamily
	hostname        string
	nodeIPs         map[v1.IPFamily]net.IP
	recorder        events.EventRecorder
	healthzServer   *healthcheck.ProxyHealthServer
}

// Backend implements proxy.Backend
var _ proxy.Backend = &Backend{}

// NewBackend creates a new winkernel proxy backend
func NewBackend(
	ctx context.Context,
	config *kubeproxyconfig.KubeProxyConfiguration,
	primaryIPFamily v1.IPFamily,
	hostname string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
) (*Backend, error) {
	if err := canUseWinKernelProxier(); err != nil {
		return nil, err
	}

	return &Backend{
		config:          config,
		primaryIPFamily: primaryIPFamily,
		hostname:        hostname,
		nodeIPs:         nodeIPs,
		recorder:        recorder,
		healthzServer:   healthzServer,
	}, nil
}

// canUseWinKernelProxier returns an error if we can't use the winkernel Proxier.
func canUseWinKernelProxier() error {
	_, err := hnslib.HNSListPolicyListRequest()
	if err != nil {
		return fmt.Errorf("Windows kernel is not compatible for Kernel mode")
	}
	return nil
}
