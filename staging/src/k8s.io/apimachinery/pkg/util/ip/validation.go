/*
Copyright 2023 The Kubernetes Authors.

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

package ip

import (
	"fmt"

	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// These are here rather than in pkg/util/validation because trying to import
// pkg/apis/meta/v1 or pkg/util/ip from there creates an import loop.

// ValidateIP tests that value is a valid IP address (either IPv4 or IPv6) for a
// newly-created object. Note that when validating an Update, ValidateIP must not be
// called on values that have not changed, since pre-existing objects may have IP values
// that are not considered valid according to currently validation rules.
//
// When creating new API types, consider using the stricter ValidateCanonicalIP instead.
func ValidateIP(value string, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	if _, err := ParseIP(value); err != nil {
		allErrors = append(allErrors, field.Invalid(fldPath, value, err.Error()))
	}
	return allErrors
}

// ValidateImmutableIP validates that newVal and oldVal are the same IP, even if not
// necessarily the same string. You can use this instead of
// apivalidation.ValidateImmutableField to allow replacing a "bad" IP address with an
// equivalent good one (e.g. "1.2.3.004" -> "1.2.3.4") in an otherwise-immutable field.
func ValidateImmutableIP(newVal, oldVal string, fldPath *field.Path) field.ErrorList {
	allErrors := apivalidation.ValidateImmutableField(newVal, oldVal, fldPath)
	if len(allErrors) != 0 {
		_, oldIP, _ := ParseLegacyIP(oldVal)
		newIP, _ := ParseIP(newVal)
		if oldIP.IsValid() && newIP.IsValid() && newIP == oldIP {
			allErrors = nil
		}
	}
	return allErrors
}

// ValidateIPOfFamily tests that the argument is a valid IP address of the given family.
// Note that when validating an Update, ValidateIPOfFamily must not be called on values
// that have not changed, since pre-existing objects may have IP values that are not
// considered valid according to currently validation rules.
//
// When creating new API types, consider using the stricter ValidateCanonicalIPOfFamily
// instead.
func ValidateIPOfFamily(value string, family metav1.IPFamily, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	ip, err := ParseIP(value)
	if err != nil {
		allErrors = append(allErrors, field.Invalid(fldPath, value, err.Error()))
	} else if IPFamilyOf(ip) != family {
		allErrors = append(allErrors, field.Invalid(fldPath, value, fmt.Sprintf("must be an %s address", family)))
	}
	return allErrors
}

// ValidateCanonicalIP tests that value is a valid IP address (either IPv4 or IPv6) in
// canonical form (as with ParseCanonicalIP). Requiring IPs to be in canonical form allows
// IP-valued fields to be compared as strings, since any IP has exactly 1 canonical form.
func ValidateCanonicalIP(value string, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	if _, err := ParseCanonicalIP(value); err != nil {
		allErrors = append(allErrors, field.Invalid(fldPath, value, err.Error()))
	}
	return allErrors
}

// ValidateCanonicalIPOfFamily tests that value is a valid IP address of the given family,
// in canonical form (as with ParseCanonicalIP). Requiring IPs to be in canonical form
// allows IP-valued fields to be compared as strings, since any IP has exactly 1 canonical
// form.
func ValidateCanonicalIPOfFamily(value string, family metav1.IPFamily, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	ip, err := ParseCanonicalIP(value)
	if err != nil {
		allErrors = append(allErrors, field.Invalid(fldPath, value, err.Error()))
	} else if IPFamilyOf(ip) != family {
		allErrors = append(allErrors, field.Invalid(fldPath, value, fmt.Sprintf("must be an %s address", family)))
	}
	return allErrors
}

// ValidateCIDR tests that value is a valid CIDR string (either IPv4 or IPv6) for a
// newly-created object. Note that when validating an Update, ValidateCIDR must not be
// called on values that have not changed, since pre-existing objects may have CIDR values
// that are not considered valid according to currently validation rules.
//
// When creating new API types, consider using the stricter ValidateCanonicalCIDR instead.
func ValidateCIDR(value string, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	if _, err := ParseCIDR(value); err != nil {
		allErrors = append(allErrors, field.Invalid(fldPath, value, err.Error()))
	}
	return allErrors
}

// ValidateImmutableCIDR validates that newVal and oldVal are the same CIDR value, even if
// not necessarily the same string. You can use this instead of
// apivalidation.ValidateImmutableField to allow replacing a "bad" CIDR string with an
// equivalent good one (e.g. "1.2.3.4/24" -> "1.2.3.0/24") in an otherwise-immutable field.
func ValidateImmutableCIDR(newVal, oldVal string, fldPath *field.Path) field.ErrorList {
	allErrors := apivalidation.ValidateImmutableField(newVal, oldVal, fldPath)
	if len(allErrors) != 0 {
		_, oldCIDR, _ := ParseLegacyCIDR(oldVal)
		newCIDR, _ := ParseCIDR(newVal)
		if oldCIDR.IsValid() && newCIDR.IsValid() && newCIDR == oldCIDR {
			allErrors = nil
		}
	}
	return allErrors
}

// ValidateCanonicalCIDR tests that value is a valid CIDR string (either IPv4 or IPv6) in
// canonical form (as with ParseCanonicalCIDR). Requiring CIDR strings to be in canonical
// form allows CIDR-valued fields to be compared as strings, since any CIDR string has
// exactly 1 canonical form.
func ValidateCanonicalCIDR(value string, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	if _, err := ParseCanonicalCIDR(value); err != nil {
		allErrors = append(allErrors, field.Invalid(fldPath, value, err.Error()))
	}
	return allErrors
}
