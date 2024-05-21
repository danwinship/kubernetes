/*
Copyright 2016 The Kubernetes Authors.

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

package service

import (
	"testing"

	v1 "k8s.io/api/core/v1"
)

func TestExternallyAccessible(t *testing.T) {
	checkExternallyAccessible := func(expect bool, service *v1.Service) {
		t.Helper()
		res := ExternallyAccessible(service)
		if res != expect {
			t.Errorf("Expected ExternallyAccessible = %v, got %v", expect, res)
		}
	}

	checkExternallyAccessible(false, &v1.Service{})
	checkExternallyAccessible(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
		},
	})
	checkExternallyAccessible(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:        v1.ServiceTypeClusterIP,
			ExternalIPs: []string{"1.2.3.4"},
		},
	})
	checkExternallyAccessible(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
		},
	})
	checkExternallyAccessible(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
		},
	})
	checkExternallyAccessible(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeExternalName,
		},
	})
	checkExternallyAccessible(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:        v1.ServiceTypeExternalName,
			ExternalIPs: []string{"1.2.3.4"},
		},
	})
}

func TestExternalPolicyLocal(t *testing.T) {
	checkExternalPolicyLocal := func(requestsOnlyLocalTraffic bool, service *v1.Service) {
		t.Helper()
		res := ExternalPolicyLocal(service)
		if res != requestsOnlyLocalTraffic {
			t.Errorf("Expected requests OnlyLocal traffic = %v, got %v",
				requestsOnlyLocalTraffic, res)
		}
	}

	checkExternalPolicyLocal(false, &v1.Service{})
	checkExternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
		},
	})
	checkExternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:        v1.ServiceTypeClusterIP,
			ExternalIPs: []string{"1.2.3.4"},
		},
	})
	checkExternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeClusterIP,
			ExternalIPs:           []string{"1.2.3.4"},
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
		},
	})
	checkExternalPolicyLocal(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeClusterIP,
			ExternalIPs:           []string{"1.2.3.4"},
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
		},
	})
	checkExternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
		},
	})
	checkExternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeNodePort,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
		},
	})
	checkExternalPolicyLocal(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeNodePort,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
		},
	})
	checkExternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
		},
	})
	checkExternalPolicyLocal(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
		},
	})
}

func TestNeedsHealthCheck(t *testing.T) {
	checkNeedsHealthCheck := func(needsHealthCheck bool, service *v1.Service) {
		t.Helper()
		res := NeedsHealthCheck(service)
		if res != needsHealthCheck {
			t.Errorf("Expected needs health check = %v, got %v",
				needsHealthCheck, res)
		}
	}

	checkNeedsHealthCheck(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
		},
	})
	checkNeedsHealthCheck(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeNodePort,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
		},
	})
	checkNeedsHealthCheck(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeNodePort,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
		},
	})
	checkNeedsHealthCheck(false, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
		},
	})
	checkNeedsHealthCheck(true, &v1.Service{
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
		},
	})
}

func TestInternalPolicyLocal(t *testing.T) {
	checkInternalPolicyLocal := func(expected bool, service *v1.Service) {
		t.Helper()
		res := InternalPolicyLocal(service)
		if res != expected {
			t.Errorf("Expected internal local traffic = %v, got %v",
				expected, res)
		}
	}

	// default InternalTrafficPolicy is nil
	checkInternalPolicyLocal(false, &v1.Service{})

	local := v1.ServiceInternalTrafficPolicyLocal
	checkInternalPolicyLocal(true, &v1.Service{
		Spec: v1.ServiceSpec{
			InternalTrafficPolicy: &local,
		},
	})

	cluster := v1.ServiceInternalTrafficPolicyCluster
	checkInternalPolicyLocal(false, &v1.Service{
		Spec: v1.ServiceSpec{
			InternalTrafficPolicy: &cluster,
		},
	})
}
