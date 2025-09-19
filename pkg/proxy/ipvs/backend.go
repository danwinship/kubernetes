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
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	utilipset "k8s.io/kubernetes/pkg/proxy/ipvs/ipset"
	utilipvs "k8s.io/kubernetes/pkg/proxy/ipvs/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilkernel "k8s.io/kubernetes/pkg/util/kernel"
)

// Backend implements the IPVS backend
type Backend struct {
	config *proxyconfigapi.KubeProxyConfiguration

	ipts  map[v1.IPFamily]utiliptables.Interface
	ipvs  utilipvs.Interface
	ipset utilipset.Interface
}

func init() {
	proxy.Backends[proxyconfigapi.ProxyModeIPVS] = &Backend{}
}

// Init initializes the IPVS backend, applies backend-specific config defaults, and
// confirms that the backend can run on this node with this config.
func (backend *Backend) Init(ctx context.Context, config *proxyconfigapi.KubeProxyConfiguration) error {
	logger := klog.FromContext(ctx)

	if len(config.IPVS.Scheduler) == 0 {
		logger.Info("IPVS scheduler not specified. Using default.", "scheduler", defaultScheduler)
		config.IPVS.Scheduler = defaultScheduler
	}

	backend.ipvs = utilipvs.New()
	if backend.ipvs == nil {
		return fmt.Errorf("IPVS not supported by the kernel")
	}
	backend.ipset = utilipset.New()

	if err := CanUseIPVSProxier(ctx, backend.ipvs, backend.ipset, config.IPVS.Scheduler); err != nil {
		return err
	}

	iptv4 := utiliptables.New(utiliptables.ProtocolIPv4)
	errv4 := iptv4.Present()
	iptv6 := utiliptables.New(utiliptables.ProtocolIPv6)
	errv6 := iptv6.Present()

	// In some cases, the CLI tools may look like they support IPv6 even when it's
	// disabled in the kernel, so check that as well.
	if errv6 == nil {
		errv6 = utilkernel.CheckIPv6()
	}

	if errv4 != nil && errv6 != nil {
		// errv4 and errv6 are almost certainly the same underlying error
		// ("iptables isn't installed" or "kernel modules not available")
		// so it doesn't make sense to try to combine them.
		return fmt.Errorf("iptables (required for IPVS) is not available on this host: %w", errv4)
	}

	backend.ipts = map[v1.IPFamily]utiliptables.Interface{}
	if errv4 == nil {
		backend.ipts[v1.IPv4Protocol] = iptv4
	} else {
		logger.Info("No iptables support for family", "family", v1.IPv4Protocol, "error", errv4)
	}
	if errv6 == nil {
		backend.ipts[v1.IPv6Protocol] = iptv6
	} else {
		logger.Info("No iptables support for family", "family", v1.IPv6Protocol, "error", errv6)
	}

	backend.config = config
	return nil
}

// CheckIPFamilySupport checks if the IPVS backend can support the given primary IP
// family on this host, and whether dual-stack operation is supported. (Assumes Init() has
// been called.)
func (backend *Backend) CheckIPFamilySupport(ctx context.Context, primaryIPFamily v1.IPFamily) (singleStackSupported, dualStackSupported bool) {
	singleStackSupported = backend.ipts[primaryIPFamily] != nil
	dualStackSupported = len(backend.ipts) == 2

	return singleStackSupported, dualStackSupported
}
