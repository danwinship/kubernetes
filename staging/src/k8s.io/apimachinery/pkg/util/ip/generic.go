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

package ip

import (
	"net"
	"net/netip"
)

type anyparsable interface {
	net.IP | netip.Addr | *net.IPNet | netip.Prefix
}

// ParseValid is a generic version of ParseValidIP / ParseValidCIDR. In particular, you
// can also use ParseValid[net.IP]("...") to parse an IP string to a net.IP, and
// ParseValid[*net.IPNet]("...") to parse a string to parse a CIDR string to a *net.IPNet,
// in contexts where you need to use the old types.
func ParseValid[T anyparsable](str string) (result T, err error) {
	var addr netip.Addr
	var prefix netip.Prefix

	switch ptr := interface{}(&result).(type) {
	case *net.IP:
		addr, err = ParseValidIP(str)
		*ptr = IPFromAddr(addr)
	case *netip.Addr:
		addr, err = ParseValidIP(str)
		*ptr = addr
	case **net.IPNet:
		prefix, err = ParseValidCIDR(str)
		*ptr = IPNetFromPrefix(prefix)
	case *netip.Prefix:
		prefix, err = ParseValidCIDR(str)
		*ptr = prefix
	}
	return
}

// Parse is a generic version of ParseIP / ParseCIDR. In particular, you can also use
// Parse[net.IP]("...") to parse an IP string to a net.IP, and Parse[*net.IPNet]("...") to
// parse a string to parse a CIDR string to a *net.IPNet, in contexts where you need to
// use the old types.
func Parse[T anyparsable](str string) (result T, err error) {
	var addr netip.Addr
	var prefix netip.Prefix

	switch ptr := interface{}(&result).(type) {
	case *net.IP:
		addr, err = ParseIP(str)
		*ptr = IPFromAddr(addr)
	case *netip.Addr:
		addr, err = ParseIP(str)
		*ptr = addr
	case **net.IPNet:
		prefix, err = ParseCIDR(str)
		*ptr = IPNetFromPrefix(prefix)
	case *netip.Prefix:
		prefix, err = ParseCIDR(str)
		*ptr = prefix
	}
	return
}

// ParseCanonical is a generic version of ParseIPCanonical / ParseCIDRCanonical. In
// particular, you can also use ParseCanonical[net.IP]("...") to parse an IP string to a
// net.IP, and ParseCanonical[*net.IPNet]("...") to parse a string to parse a CIDR string
// to a *net.IPNet, in contexts where you need to use the old types.
func ParseCanonical[T anyparsable](str string) (result T, err error) {
	var addr netip.Addr
	var prefix netip.Prefix

	switch ptr := interface{}(&result).(type) {
	case *net.IP:
		addr, err = ParseCanonicalIP(str)
		*ptr = IPFromAddr(addr)
	case *netip.Addr:
		addr, err = ParseCanonicalIP(str)
		*ptr = addr
	case **net.IPNet:
		prefix, err = ParseCanonicalCIDR(str)
		*ptr = IPNetFromPrefix(prefix)
	case *netip.Prefix:
		prefix, err = ParseCanonicalCIDR(str)
		*ptr = prefix
	}
	return
}

// MustParse is a generic version of MustParseIP / MustParseCIDR. In particular, you can
// also use MustParse[net.IP]("...") and MustParse[*net.IPNet]("...") in contexts where
// you need to use the old types.
func MustParse[T anyparsable](str string) T {
	ret, err := Parse[T](str)
	if err != nil {
		panic(err)
	}
	return ret
}

// MustParseList is a generic version of MustParseIPs / MustParseCIDRs. In particular, you
// can also use MustParseList[net.IP]("...", ...) and MustParseList[*net.IPNet]("...",
// ...) in contexts where you need to use the old types.
func MustParseList[T anyparsable](strs ...string) []T {
	var err error

	ret := make([]T, len(strs))
	for i := range strs {
		ret[i], err = Parse[T](strs[i])
		if err != nil {
			panic(err)
		}
	}
	return ret
}
