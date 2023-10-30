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
	"net"
	"net/netip"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netutils "k8s.io/utils/net"
)

type anyIPAddress interface {
	net.IP | netip.Addr | string
}

type anyCIDRAddress interface {
	*net.IPNet | netip.Prefix | string
}

// IPFamilyOf returns the IP family of ip, or IPFamilyUnknown if ip is invalid.
// IPv6-encoded IPv4 addresses (e.g., "::ffff:1.2.3.4") are considered IPv4. ip can be a
// net.IP, a netip.Addr, or a string. String-form IPs can be in canonical or non-canonical
// format.
//
// (The return value is a metav1.IPFamily, which can also be used as a v1.IPFamily without
// needing to be typecast.)
func IPFamilyOf[T anyIPAddress](ip T) metav1.IPFamily {
	switch typedIP := interface{}(ip).(type) {
	case net.IP:
		switch {
		case typedIP.To4() != nil:
			return metav1.IPv4Protocol
		case typedIP.To16() != nil:
			return metav1.IPv6Protocol
		}
	case netip.Addr:
		switch {
		case typedIP.Is4(), typedIP.Is4In6():
			return metav1.IPv4Protocol
		case typedIP.Is6():
			return metav1.IPv6Protocol
		}
	case string:
		return IPFamilyOf(netutils.ParseIPSloppy(typedIP))
	}

	return metav1.IPFamilyUnknown
}

// IPFamilyOfCIDR returns the IP family of cidr (or IPFamilyUnknown if cidr is invalid).
// cidr can be a *net.IPNet, a netip.Prefix, or a string. String-form CIDRs can be in
// canonical or non-canonical format.
//
// (The return value is a metav1.IPFamily, which can be used as a v1.IPFamily without
// casting.)
func IPFamilyOfCIDR[T anyCIDRAddress](cidr T) metav1.IPFamily {
	switch typedCIDR := interface{}(cidr).(type) {
	case *net.IPNet:
		if typedCIDR != nil {
			return IPFamilyOf(typedCIDR.IP)
		}
	case netip.Prefix:
		return IPFamilyOf(typedCIDR.Addr())
	case string:
		_, parsed, _ := netutils.ParseCIDRSloppy(typedCIDR)
		return IPFamilyOfCIDR(parsed)
	}

	return metav1.IPFamilyUnknown
}

// IsIPv4 returns true if IPFamilyOf(ip) is IPv4 (and false if it is IPv6 or invalid).
func IsIPv4[T anyIPAddress](ip T) bool {
	return IPFamilyOf(ip) == metav1.IPv4Protocol
}

// IsIPv4CIDR returns true if IPFamilyOfCIDR(cidr) is IPv4. It returns false if cidr is
// invalid or an IPv6 CIDR.
func IsIPv4CIDR[T anyCIDRAddress](cidr T) bool {
	return IPFamilyOfCIDR(cidr) == metav1.IPv4Protocol
}

// IsIPv6 returns true if IPFamilyOf(ip) is IPv6 (and false if it is IPv4 or invalid).
func IsIPv6[T anyIPAddress](ip T) bool {
	return IPFamilyOf(ip) == metav1.IPv6Protocol
}

// IsIPv6CIDR returns true if IPFamilyOfCIDR(cidr) is IPv6. It returns false if cidr is
// invalid or an IPv4 CIDR.
func IsIPv6CIDR[T anyCIDRAddress](cidr T) bool {
	return IPFamilyOfCIDR(cidr) == metav1.IPv6Protocol
}

// IsDualStackIPs returns true if:
// - all elements of ips are valid
// - at least one IP from each family (v4 and v6) is present
func IsDualStackIPs[T anyIPAddress](ips []T) bool {
	v4Found := false
	v6Found := false
	for _, ip := range ips {
		switch IPFamilyOf(ip) {
		case metav1.IPv4Protocol:
			v4Found = true
		case metav1.IPv6Protocol:
			v6Found = true
		default:
			return false
		}
	}

	return (v4Found && v6Found)
}

// IsDualStackIPPair returns true if ips contains exactly 1 IPv4 IP and 1 IPv6 IP (in
// either order).
func IsDualStackIPPair[T anyIPAddress](ips []T) bool {
	return len(ips) == 2 && IsDualStackIPs(ips)
}

// IsDualStackCIDRs returns true if:
// - all elements of cidrs are valid
// - at least one CIDR from each family (v4 and v6) is present
func IsDualStackCIDRs[T anyCIDRAddress](cidrs []T) bool {
	v4Found := false
	v6Found := false
	for _, cidr := range cidrs {
		switch IPFamilyOfCIDR(cidr) {
		case metav1.IPv4Protocol:
			v4Found = true
		case metav1.IPv6Protocol:
			v6Found = true
		default:
			return false
		}
	}

	return (v4Found && v6Found)
}

// IsDualStackCIDRPair returns true if cidrs contains exactly 1 IPv4 CIDR and 1 IPv6 CIDR
// (in either order).
func IsDualStackCIDRPair[T anyCIDRAddress](cidrs []T) bool {
	return len(cidrs) == 2 && IsDualStackCIDRs(cidrs)
}

// OtherIPFamily returns the other ip family
func OtherIPFamily(ipFamily metav1.IPFamily) metav1.IPFamily {
	switch ipFamily {
	case metav1.IPv4Protocol:
		return metav1.IPv6Protocol
	case metav1.IPv6Protocol:
		return metav1.IPv4Protocol
	default:
		return metav1.IPFamilyUnknown
	}
}
