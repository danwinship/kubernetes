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

package net

import (
	"net"
	"net/netip"
	"strings"
)

// AddrFromIP converts a net.IP to a netip.Addr. Given valid input this will always
// succeed; it will return the invalid netip.Addr on nil or garbage input.
//
// Use this rather than netip.AddrFromSlice(), which does not properly take into account
// the way that net.IP can represent an IPv4 address as either a 4-byte or a 16-byte
// value.
func AddrFromIP(ip net.IP) netip.Addr {
	// Naively using netip.AddrFromSlice() gives the wrong results due to semantic
	// differences between net.IP and netip.Addr that it fails to account for:
	//
	//   ip := net.ParseIP("1.2.3.4")
	//   addr, _ := netip.AddrFromSlice(ip)
	//   addr.String()  =>  "::ffff:1.2.3.4"
	//   addr.Is4()     =>  false
	//   addr.Is6()     =>  true
	//
	// This is because net.IP normally represents IPv4 addresses internally as IPv6
	// addresses in "IPv4-mapped IPv6" form, but then hides this fact from the user:
	//
	//   ip := net.ParseIP("1.2.3.4")
	//   []byte(ip)   =>  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4}
	//   ip.String()  =>  "1.2.3.4"
	//
	// whereas netip.Addr *does not* represent IPv4 addresses that way, and considers
	// the "plain" and "IPv4-mapped IPv6" forms to be different values:
	//
	//   a1 := netip.MustParseAddr("1.2.3.4")
	//   a2 := netip.MustParseAddr("::ffff:1.2.3.4")
	//   a1.String()  =>  "1.2.3.4"
	//   a2.String()  =>  "::ffff:1.2.3.4"
	//   a1 == a2     =>  false
	//
	// In order to correctly convert an IPv4 address from net.IP to netip.Addr, you
	// need to either call .To4() on it before converting, or .Unmap() on it after
	// converting. (The latter option is slightly simpler because it's a no-op in the
	// IPv6 and error/invalid cases).
	//
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

// IPFromAddr converts a netip.Addr to a net.IP. Given valid input this will always
// succeed; it will return nil if addr is the invalid netip.Addr.
func IPFromAddr(addr netip.Addr) net.IP {
	// addr.AsSlice() returns:
	//   - a []byte of length 4 if addr is a normal IPv4 address
	//   - a []byte of length 16 if addr is an IPv6 address (including IPv4-mapped IPv6)
	//   - nil if addr is the zero Addr (which is the only other possibility)
	//
	// Any of those values can be correctly cast directly to a net.IP.
	//
	// Note that we don't do any "cleanup" equivalent to what we do in the AddrFromIP
	// case, so converting a plain IPv4 netip.Addr to net.IP gives a different result
	// than converting an IPv4-mapped IPv6 netip.Addr:
	//
	//   ip1 := netutils.IPFromAddr(netip.MustParseAddr("1.2.3.4"))
	//   []byte(ip1)  =>  []byte{1, 2, 3, 4}
	//
	//   ip2 := netutils.IPFromAddr(netip.MustParseAddr("::ffff:1.2.3.4"))
	//   []byte(ip2)  =>  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4}
	//
	// However, the net.IP API treats the two values as the same anyway:
	//
	//   ip1.String()    =>  "1.2.3.4"
	//   ip2.String()    =>  "1.2.3.4"
	//   ip2.Equal(ip1)  =>  true
	//
	// (There is no net.IP value that will String()-ify to "::ffff:1.2.3.4".)
	return net.IP(addr.AsSlice())
}

// AddrFromInterfaceAddr converts a net.Addr returned from net.InterfaceAddrs(),
// net.Interface.Addrs(), or net.Interface.MulticastAddrs() to a netip.Addr. Calling it on
// other kinds of net.Addr values (such as a net.TCPAddr) will generally fail and return
// the zero/invalid netip.Addr.
func AddrFromInterfaceAddr(ifaddr net.Addr) netip.Addr {
	return AddrFromIP(IPFromInterfaceAddr(ifaddr))
}

// IPFromInterfaceAddr converts a net.Addr returned from net.InterfaceAddrs(),
// net.Interface.Addrs(), or net.Interface.MulticastAddrs() to a net.IP. Calling it on
// other kinds of net.Addr values (such as a net.TCPAddr) will generally fail and return
// nil.
func IPFromInterfaceAddr(ifaddr net.Addr) net.IP {
	// On both Linux and Windows, the values returned from the "interface addr"
	// methods are currently *net.IPNet for unicast addresses or *net.IPAddr for
	// multicast addresses.
	if ipnet, ok := ifaddr.(*net.IPNet); ok {
		return ipnet.IP
	} else if ipaddr, ok := ifaddr.(*net.IPAddr); ok {
		return ipaddr.IP
	}

	// Try to deal with other similar types... in particular, this is needed for
	// some existing unit tests...
	addrStr := ifaddr.String()
	// If it has a subnet length (like net.IPNet) or optional zone identifier (like
	// net.IPAddr), trim that away.
	if end := strings.IndexAny(addrStr, "/%"); end != -1 {
		addrStr = addrStr[:end]
	}
	// What's left is either an IP address, or something we can't parse.
	ip, _ := ParseIP(addrStr)
	return ip
}

// PrefixFromIPNet converts a *net.IPNet to a netip.Prefix. Given valid input this will
// always succeed; it will return the invalid netip.Prefix on nil or garbage input.
func PrefixFromIPNet(ipnet *net.IPNet) netip.Prefix {
	if ipnet == nil {
		return netip.Prefix{}
	}

	addr := AddrFromIP(ipnet.IP)
	if !addr.IsValid() {
		return netip.Prefix{}
	}

	prefixLen, bits := ipnet.Mask.Size()
	if prefixLen == 0 && bits == 0 {
		// non-CIDR Mask representation; not representible as a netip.Prefix
		return netip.Prefix{}
	}
	if bits == 128 && addr.Is4() && (bits-prefixLen <= 32) {
		// In the same way that net.IP allows an IPv4 IP to be either 4 or 16
		// bytes (32 or 128 bits), *net.IPNet allows an IPv4 CIDR to have either a
		// 32-bit or a 128-bit mask. If the mask is 128 bits, we discard the
		// leftmost 96 bits.
		prefixLen -= 128 - 32
	} else if bits != addr.BitLen() {
		// invalid IPv4/IPv6 mix
		return netip.Prefix{}
	}

	return netip.PrefixFrom(addr, prefixLen)
}

// IPNetFromPrefix converts a netip.Prefix to a *net.IPNet. Given valid input this will
// always succeed; it will return nil if prefix is the invalid netip.Prefix or is
// otherwise invalid.
func IPNetFromPrefix(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if bits == -1 || !addr.IsValid() {
		return nil
	}
	addrLen := addr.BitLen()

	// (As with IPFromAddr, a plain IPv4 netip.Prefix and an equivalent IPv4-mapped
	// IPv6 netip.Prefix will get converted to distinct *net.IPNet values, but
	// *net.IPNet will treat them equivalently.)

	return &net.IPNet{
		IP:   IPFromAddr(addr),
		Mask: net.CIDRMask(bits, addrLen),
	}
}
