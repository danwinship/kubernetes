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
	"reflect"
	"testing"
)

func TestAddrFromIP_IPFromAddr(t *testing.T) {
	testCases := []struct {
		desc string
		ip   net.IP
		addr netip.Addr
	}{
		{
			desc: "IPv4 all-zeros",
			ip:   net.IPv4zero,
			addr: netip.IPv4Unspecified(),
		},
		{
			desc: "IPv6 all-zeros",
			ip:   net.IPv6zero,
			addr: netip.IPv6Unspecified(),
		},
		{
			desc: "IPv4 broadcast",
			ip:   net.IPv4bcast,
			addr: netip.AddrFrom4([4]byte{0xFF, 0xFF, 0xFF, 0xFF}),
		},
		{
			desc: "IPv4 loopback",
			ip:   net.IPv4(127, 0, 0, 1),
			addr: netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		},
		{
			desc: "IPv6 loopback",
			ip:   net.IPv6loopback,
			addr: netip.IPv6Loopback(),
		},
		{
			desc: "IPv4 1",
			ip:   net.IPv4(10, 20, 40, 40),
			addr: netip.AddrFrom4([4]byte{10, 20, 40, 40}),
		},
		{
			desc: "IPv4 2",
			ip:   net.IPv4(172, 17, 3, 0),
			addr: netip.AddrFrom4([4]byte{172, 17, 3, 0}),
		},
		{
			desc: "IPv6 1",
			ip:   net.IP{0xFD, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x0D, 0xF0, 0x0D},
			addr: netip.AddrFrom16([16]byte{0xFD, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x0D, 0xF0, 0x0D}),
		},
		{
			desc: "IPv6 2",
			ip:   net.IP{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05},
			addr: netip.AddrFrom16([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			addr := AddrFromIP(tc.ip)
			if addr != tc.addr {
				t.Errorf("AddrFromIP() expected %#v (%s) got %#v (%s)", tc.addr, tc.addr.String(), addr, addr.String())
			}

			ip := IPFromAddr(tc.addr)
			if !ip.Equal(tc.ip) {
				t.Errorf("IPFromAddr() expected %#v (%s) got %#v (%s)", tc.ip, tc.ip.String(), ip, ip.String())
			}
		})
	}

	// Special cases
	var ip net.IP
	var addr, expectedAddr netip.Addr

	// IPv4-mapped IPv6 gets converted to plain IPv4
	ip = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4}
	addr = AddrFromIP(ip)
	expectedAddr = netip.AddrFrom4([4]byte{1, 2, 3, 4})
	if addr != expectedAddr {
		t.Errorf("AddrFromIP(%s) expected %#v (%s) got %#v (%s)", ip.String(), expectedAddr, expectedAddr.String(), addr, addr.String())
	}

	// nil IP
	ip = nil
	addr = AddrFromIP(ip)
	expectedAddr = netip.Addr{}
	if addr != expectedAddr {
		t.Errorf("AddrFromIP(%s) expected %#v (%s) got %#v (%s)", ip.String(), expectedAddr, expectedAddr.String(), addr, addr.String())
	}
	ip = IPFromAddr(expectedAddr)
	if ip != nil {
		t.Errorf("IPFromAddr(%s) expected nil got %#v (%s)", expectedAddr.String(), ip, ip.String())
	}

	// invalid IP
	ip = net.IP{0x1}
	addr = AddrFromIP(ip)
	expectedAddr = netip.Addr{}
	if addr != expectedAddr {
		t.Errorf("AddrFromIP(%s) expected %#v (%s) got %#v (%s)", ip.String(), expectedAddr, expectedAddr.String(), addr, addr.String())
	}
	ip = IPFromAddr(expectedAddr)
	if ip != nil {
		t.Errorf("IPFromAddr(%s) expected nil got %#v (%s)", expectedAddr.String(), ip, ip.String())
	}
}

func TestPrefixFromIPNet_IPNetFromPrefix(t *testing.T) {
	testCases := []struct {
		desc   string
		ipnet  *net.IPNet
		prefix netip.Prefix
	}{
		{
			desc: "IPv4 CIDR 1",
			ipnet: &net.IPNet{
				IP:   net.IPv4(10, 0, 0, 0),
				Mask: net.CIDRMask(8, 32),
			},
			prefix: netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 0, 0, 0}),
				8,
			),
		},
		{
			desc: "IPv4 CIDR 2",
			ipnet: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 0),
				Mask: net.CIDRMask(16, 32),
			},
			prefix: netip.PrefixFrom(
				netip.AddrFrom4([4]byte{192, 168, 0, 0}),
				16,
			),
		},
		{
			desc: "IPv6 CIDR 1",
			ipnet: &net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(1, 128),
			},
			prefix: netip.PrefixFrom(
				netip.IPv6Unspecified(),
				1,
			),
		},
		{
			desc: "IPv6 CIDR 2",
			ipnet: &net.IPNet{
				IP:   net.IP{0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				Mask: net.CIDRMask(10, 128),
			},
			prefix: netip.PrefixFrom(
				netip.AddrFrom16([16]byte{0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
				10,
			),
		},
		{
			desc: "IPv6 CIDR 3",
			ipnet: &net.IPNet{
				IP:   net.IP{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				Mask: net.CIDRMask(32, 128),
			},
			prefix: netip.PrefixFrom(
				netip.AddrFrom16([16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
				32,
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			prefix := PrefixFromIPNet(tc.ipnet)
			if prefix != tc.prefix {
				t.Errorf("PrefixFromIPNet() expected %#v (%s) got %#v (%s)", tc.prefix, tc.prefix.String(), prefix, prefix.String())
			}

			ipnet := IPNetFromPrefix(tc.prefix)
			if !ipnet.IP.Equal(tc.ipnet.IP) || !reflect.DeepEqual(ipnet.Mask, tc.ipnet.Mask) {
				t.Errorf("IPNetFromPrefix() expected %#v (%s) got %#v (%s)", tc.ipnet, tc.ipnet.String(), ipnet, ipnet.String())
			}
		})
	}

	// Special cases
	var ipnet *net.IPNet
	var prefix, expectedPrefix netip.Prefix

	// IPv4-mapped IPv6 address in Prefix is invalid
	prefix = netip.PrefixFrom(
		netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 0}),
		24,
	)
	ipnet = IPNetFromPrefix(prefix)
	if ipnet != nil {
		t.Errorf("IPNetFromPrefix(ipv4-mapped) expected nil got %#v (%s)", ipnet, ipnet.String())
	}

	// nil IPNet
	ipnet = nil
	prefix = PrefixFromIPNet(ipnet)
	expectedPrefix = netip.Prefix{}
	if prefix != expectedPrefix {
		t.Errorf("PrefixFromIPNet(nil) expected %#v (%s) got %#v (%s)", expectedPrefix, expectedPrefix.String(), prefix, prefix.String())
	}
	ipnet = IPNetFromPrefix(expectedPrefix)
	if ipnet != nil {
		t.Errorf("IPNetFromPrefix(zero) expected nil got %#v (%s)", ipnet, ipnet.String())
	}

	// invalid IPNet
	ipnet = &net.IPNet{IP: net.IP{0x1}}
	prefix = PrefixFromIPNet(ipnet)
	expectedPrefix = netip.Prefix{}
	if prefix != expectedPrefix {
		t.Errorf("PrefixFromIPNet(invalid) expected %#v (%s) got %#v (%s)", expectedPrefix, expectedPrefix.String(), prefix, prefix.String())
	}
}
