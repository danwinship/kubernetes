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
	"net/netip"
	"strings"

	netutils "k8s.io/utils/net"
)

// ParseIP parses an IPv4 or IPv6 address, accepting most valid IP addresses, but
// rejecting irregularly-formed IPs that are likely to lead to bugs (or attacks):
//
//  1. IPv4 IPs with leading "0"s in octets (e.g. "010.002.003.004") are not allowed
//     because libc-based software will interpret the bytes as octal, whereas historically
//     `net.ParseIP` (and later `netutils.ParseIPSloppy`) interpreted them as decimal,
//     meaning different software would interpret the same string as a different IP.
//
//  2. IPv4-mapped IPv6 IPs (e.g. "::ffff:1.2.3.4") are not allowed because they may be
//     treated as IPv4 by some software and IPv6 by other software.
//
//  3. IPv6 IPs may not have a trailing zone identifier (e.g. "fe80::1234%eth0") (which
//     would be allowed by `netip.ParseAddr`) since these were not allowed by
//     `net.ParseIP` / `netutils.ParseIPSloppy`, and are therefore generally not expected
//     in Kubernetes contexts.
//
// If you are parsing an IP from an object field, command line flag, etc, that pre-dates
// Kubernetes 1.30, you should use ParseLegacyIP, since existing objects, configs, etc,
// may contain IPs that do not validate according to ParseIP.
//
// If a parse error occurs, the returned error will include ipStr in the message.
func ParseIP(ipStr string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ip, handleParseAddrError(ipStr, err)
	}
	if ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("IP address %q with zone value is not allowed", ipStr)
	}
	if ip.Is4In6() {
		return netip.Addr{}, fmt.Errorf("IPv4-mapped IPv6 address %q is not allowed", ipStr)
	}

	return ip, nil
}

// ParseLegacyIP can be used to parse an IPv4 or IPv6 address which was validated
// according to looser rules than ParseIP enforces. For instance, the Service
// `.Spec.ClusterIPs` field pre-dates the introduction of stricter IP validation, so it
// should be parsed with this function.
//
// Note that if you have an object field, command line flag, etc, containing a "legacy" IP
// value, then it is not safe to pass the raw value directly to external APIs (including
// command-line APIs) because other code may interpret the string differently than
// ParseLegacyIP does, potentially creating security issues. You should instead always
// call ParseLegacyIP on it first, then convert the returned value to a string, and pass
// that string to external APIs.
//
// Contrast ParseIP and ParseCanonicalIP.
func ParseLegacyIP(ipStr string) (netip.Addr, error) {
	ip := netutils.ParseIPSloppy(ipStr)
	if ip == nil {
		// If netutils.ParseIPSloppy() rejected it then our ParseIP is sure to
		// reject it as well (either it's invalid, or it contains an IPv6 zone).
		// So use that to get an error message.
		return ParseIP(ipStr)
	}

	return AddrFromIP(ip), nil
}

// ParseCanonicalIP parses a valid IPv4 or IPv6 address and confirms that it was in
// canonical form (i.e., the form that `.String()` would return). For IPv4, any IPv4
// address accepted by ParseIP is also canonical, but for IPv6, ParseCanonicalIP requires
// the address to be in the canonical form specified by RFC 5952. (In particular, it can
// have no leading "0"s, must use the "::" in the correct place, and must use lowercase
// letters.)
//
// ParseCanonicalIP is preferred to ParseIP for validating fields in new APIs, because
// there is exactly 1 canonical representation for any IP, meaning canonical-IP-valued
// fields can just be treated as strings when checking for equality or uniqueness.
func ParseCanonicalIP(ipStr string) (netip.Addr, error) {
	ip, err := ParseIP(ipStr)
	if err != nil {
		return ip, err
	}

	if ip.Is6() {
		canonical := ip.String()
		if ipStr != canonical {
			return netip.Addr{}, fmt.Errorf("not accepting IP address %q which is not in canonical form (%q)", ipStr, canonical)
		}
	}

	return ip, nil
}

// handleParseAddrError tries to improve on netip.ParseAddr's sometimes-unhelpful error
// messages.
func handleParseAddrError(ipStr string, err error) error {
	switch {
	case ipStr == "":
		return fmt.Errorf("IP address %q should not be empty", ipStr)
	case ipStr[0] == '[':
		return fmt.Errorf("IP address %q should not include brackets", ipStr)
	case strings.Contains(ipStr, ".") && strings.Contains(ipStr, ":"):
		return fmt.Errorf("IP address %q should not include port", ipStr)
	case strings.Contains(ipStr, "/"):
		return fmt.Errorf("expected IP address but got CIDR value %q", ipStr)
	case strings.TrimSpace(ipStr) != ipStr:
		return fmt.Errorf("IP address %q should not include whitespace", ipStr)
	default:
		return err
	}
}

type ipParser func (string) (netip.Addr, error)

// SplitIPs parses a list of IPs delimited by sep, using the provided parser (ParseIP,
// ParseLegacyIP, or ParseCanonicalIP). If ipStrList is the empty string, this will return
// an empty list of IPs.
func SplitIPs(ipStrList, sep string, parser ipParser) ([]netip.Addr, error) {
	var err error

	if ipStrList == "" {
		return []netip.Addr{}, nil
	}

	ipStrs := strings.Split(ipStrList, sep)
	ips := make([]netip.Addr, len(ipStrs))
	for i := range ipStrs {
		ips[i], err = parser(ipStrs[i])
		if err != nil {
			return nil, err
		}
	}
	return ips, nil
}

// JoinIPs joins a list of IPs, using the given separator
func JoinIPs(ips []netip.Addr, sep string) string {
	var b strings.Builder

	for i := range ips {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(ips[i].String())
	}
	return b.String()
}

// MustParseIP parses an IPv4 or IPv6 string (which must be in canonical format), and
// panics on failure. This can be used for test cases or compile-time constants.
func MustParseIP(ipStr string) netip.Addr {
	ip, err := ParseCanonicalIP(ipStr)
	if err != nil {
		panic(err)
	}
	return ip
}

// MustParseIPs parses an array of IPv4 or IPv6 strings (which must be in canonical
// format), and panics on failure. This can be used for test cases or compile-time
// constants.
func MustParseIPs(ipStrs []string) []netip.Addr {
	ips := make([]netip.Addr, len(ipStrs))
	for i := range ipStrs {
		ips[i] = MustParseIP(ipStrs[i])
	}
	return ips
}
