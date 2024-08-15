//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

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

// Code generated by conversion-gen. DO NOT EDIT.

package v1

import (
	unsafe "unsafe"

	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	restrictedendpoints "k8s.io/kubernetes/openshift-kube-apiserver/admission/network/apis/restrictedendpoints"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*RestrictedEndpointsAdmissionConfig)(nil), (*restrictedendpoints.RestrictedEndpointsAdmissionConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1_RestrictedEndpointsAdmissionConfig_To_restrictedendpoints_RestrictedEndpointsAdmissionConfig(a.(*RestrictedEndpointsAdmissionConfig), b.(*restrictedendpoints.RestrictedEndpointsAdmissionConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*restrictedendpoints.RestrictedEndpointsAdmissionConfig)(nil), (*RestrictedEndpointsAdmissionConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_restrictedendpoints_RestrictedEndpointsAdmissionConfig_To_v1_RestrictedEndpointsAdmissionConfig(a.(*restrictedendpoints.RestrictedEndpointsAdmissionConfig), b.(*RestrictedEndpointsAdmissionConfig), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1_RestrictedEndpointsAdmissionConfig_To_restrictedendpoints_RestrictedEndpointsAdmissionConfig(in *RestrictedEndpointsAdmissionConfig, out *restrictedendpoints.RestrictedEndpointsAdmissionConfig, s conversion.Scope) error {
	out.RestrictedCIDRs = *(*[]string)(unsafe.Pointer(&in.RestrictedCIDRs))
	return nil
}

// Convert_v1_RestrictedEndpointsAdmissionConfig_To_restrictedendpoints_RestrictedEndpointsAdmissionConfig is an autogenerated conversion function.
func Convert_v1_RestrictedEndpointsAdmissionConfig_To_restrictedendpoints_RestrictedEndpointsAdmissionConfig(in *RestrictedEndpointsAdmissionConfig, out *restrictedendpoints.RestrictedEndpointsAdmissionConfig, s conversion.Scope) error {
	return autoConvert_v1_RestrictedEndpointsAdmissionConfig_To_restrictedendpoints_RestrictedEndpointsAdmissionConfig(in, out, s)
}

func autoConvert_restrictedendpoints_RestrictedEndpointsAdmissionConfig_To_v1_RestrictedEndpointsAdmissionConfig(in *restrictedendpoints.RestrictedEndpointsAdmissionConfig, out *RestrictedEndpointsAdmissionConfig, s conversion.Scope) error {
	out.RestrictedCIDRs = *(*[]string)(unsafe.Pointer(&in.RestrictedCIDRs))
	return nil
}

// Convert_restrictedendpoints_RestrictedEndpointsAdmissionConfig_To_v1_RestrictedEndpointsAdmissionConfig is an autogenerated conversion function.
func Convert_restrictedendpoints_RestrictedEndpointsAdmissionConfig_To_v1_RestrictedEndpointsAdmissionConfig(in *restrictedendpoints.RestrictedEndpointsAdmissionConfig, out *RestrictedEndpointsAdmissionConfig, s conversion.Scope) error {
	return autoConvert_restrictedendpoints_RestrictedEndpointsAdmissionConfig_To_v1_RestrictedEndpointsAdmissionConfig(in, out, s)
}
