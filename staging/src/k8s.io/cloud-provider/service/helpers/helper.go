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

package helpers

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	// LoadBalancerCleanupFinalizer is the finalizer added to load balancer
	// services to ensure the Service resource is not fully deleted until
	// the correlating load balancer resources are deleted.
	LoadBalancerCleanupFinalizer = "service.kubernetes.io/load-balancer-cleanup"
)

// GetServiceHealthCheckPathPort returns the path and nodePort programmed into the Cloud LB Health Check
func GetServiceHealthCheckPathPort(service *v1.Service) (string, int32) {
	if !NeedsHealthCheck(service) {
		return "", 0
	}
	port := service.Spec.HealthCheckNodePort
	if port == 0 {
		return "", 0
	}
	return "/healthz", port
}

// RequestsOnlyLocalTraffic checks if service requests OnlyLocal traffic.
func RequestsOnlyLocalTraffic(service *v1.Service) bool {
	if service.Spec.Type != v1.ServiceTypeLoadBalancer &&
		service.Spec.Type != v1.ServiceTypeNodePort {
		return false
	}
	return service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyLocal
}

// NeedsHealthCheck checks if service needs health check.
func NeedsHealthCheck(service *v1.Service) bool {
	if service.Spec.Type != v1.ServiceTypeLoadBalancer {
		return false
	}
	return RequestsOnlyLocalTraffic(service)
}

// HasLBFinalizer checks if service contains LoadBalancerCleanupFinalizer.
func HasLBFinalizer(service *v1.Service) bool {
	for _, finalizer := range service.ObjectMeta.Finalizers {
		if finalizer == LoadBalancerCleanupFinalizer {
			return true
		}
	}
	return false
}

// LoadBalancerStatusEqual checks if load balancer status are equal
func LoadBalancerStatusEqual(l, r *v1.LoadBalancerStatus) bool {
	return apiequality.Semantic.DeepEqual(l.Ingress, r.Ingress)
}

// PatchService patches the given service's Status or ObjectMeta based on the original and
// updated ones. Change to spec will be ignored.
func PatchService(c corev1.CoreV1Interface, oldSvc, newSvc *v1.Service) (*v1.Service, error) {
	// Reset spec to make sure only patch for Status or ObjectMeta.
	newSvc.Spec = oldSvc.Spec

	patchBytes, err := getPatchBytes(oldSvc, newSvc)
	if err != nil {
		return nil, err
	}

	return c.Services(oldSvc.Namespace).Patch(context.TODO(), oldSvc.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}, "status")

}

func getPatchBytes(oldSvc, newSvc *v1.Service) ([]byte, error) {
	oldData, err := json.Marshal(oldSvc)
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal oldData for svc %s/%s: %v", oldSvc.Namespace, oldSvc.Name, err)
	}

	newData, err := json.Marshal(newSvc)
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal newData for svc %s/%s: %v", newSvc.Namespace, newSvc.Name, err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, v1.Service{})
	if err != nil {
		return nil, fmt.Errorf("failed to CreateTwoWayMergePatch for svc %s/%s: %v", oldSvc.Namespace, oldSvc.Name, err)
	}
	return patchBytes, nil

}
