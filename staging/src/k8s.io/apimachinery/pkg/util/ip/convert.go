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
)

// AddrFromIP converts a net.IP to a netip.Addr. If ip is nil or invalid, it returns the
// zero netip.Addr. Use this rather than netip.AddrFromSlice(), which does not deal with
// with the semantic differences between net.IP and netip.Addr with respect to 4-byte vs
// 16-byte encoding of IPv4 addresses.
func AddrFromIP(ip net.IP) netip.Addr {
	// net.ParseIP("1.2.3.4").String() => "1.2.3.4"
	// netip.MustParseAddr("1.2.3.4").String() => "1.2.3.4"
	//
	// BUT...
	//
	// netip.AddrFromSlice(net.ParseIP("1.2.3.4")).String() => "::ffff:1.2.3.4"
	// netip.AddrFromSlice(net.ParseIP("1.2.3.4")).Is4() => false
	//
	// So if ip is an IPv4-mapped IPv6 address, we need to convert it to a 4-byte IPv4
	// address before converting to netip.Addr, to make it behave in the expected way.

	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	addr, _ := netip.AddrFromSlice([]byte(ip))
	return addr
}

// IPFromAddr converts a netip.Addr to a net.IP. If addr is the zero netip.Addr, it
// returns nil. (If addr is an IPv4 address, it is undefined whether IPFromAddr() returns
// it in the 4-byte or 16-byte form, so use `.To4()`/`.To16()` if you care.)
func IPFromAddr(addr netip.Addr) net.IP {
	// addr.AsSlice() returns: nil if addr is the zero Addr; a []byte of length 4 if
	// addr is an IPv4 address; or a []byte of length 16 if addr is an IPv6 address.
	// Any of those values can be correctly cast directly to a net.IP.
	return net.IP(addr.AsSlice())
}

// PrefixFromIPNet converts a *net.IPNet to a netip.Prefix. If ipnet is nil or invalid, it
// returns the zero netip.Prefix.
func PrefixFromIPNet(ipnet *net.IPNet) netip.Prefix {
	if ipnet == nil {
		return netip.Prefix{}
	}

	addr := AddrFromIP(ipnet.IP)
	if !addr.IsValid() {
		return netip.Prefix{}
	}

	ones, bits := ipnet.Mask.Size()
	if ones == 0 && bits == 0 {
		// non-CIDR Mask representation (eg 0x11010011)
		return netip.Prefix{}
	}
	if bits == 128 && addr.Is4() {
		// ipnet contained an IPv4-mapped IPv6 address, so we have to recompute
		// the prefix length relative to the IPv4 address rather than the IPv6
		// address.
		ones -= (128 - 32)
	}

	return netip.PrefixFrom(addr, ones)
}

// IPNetFromPrefix converts a netip.Prefix to a *net.IPNet. If prefix is the zero
// netip.Prefix or contains an IPv4-mapped IPv6 address, it returns nil.
func IPNetFromPrefix(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	bits := prefix.Bits()

	if bits == -1 || !addr.IsValid() {
		return nil
	}

	// netip.Prefix allows you to construct a prefix using an IPv4-mapped IPv6
	// address, but it has broken semantics. (It requires the prefix length to be
	// between 0 and 32, as though it was an IPv4 CIDR, but if you call .Mask() on it,
	// it applies the prefix length as though it was an IPv6 CIDR, meaning you always
	// get back `::` regardless of the input, since the top 32 bits of an IPv4-mapped
	// IPv6 address are always 0.) So we just treat that as invalid.
	if addr.Is4In6() {
		return nil
	}

	return &net.IPNet{
		IP:   IPFromAddr(addr),
		Mask: net.CIDRMask(bits, addr.BitLen()),
	}
}
