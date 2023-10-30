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

// ParseCIDR parses an IPv4 or IPv6 CIDR string, accepting most valid CIDR strings, but
// rejecting irregularly-formed CIDR strings that are likely to lead to bugs (or attacks):
//
//  1. CIDR strings containing IPv4 IPs with leading "0"s (e.g. "010.002.003.000/24") are
//     not allowed because libc-based software will interpret the bytes as octal, whereas
//     historically `net.ParseCIDR` (and later `netutils.ParseCIDRSloppy`) interpreted
//     them as decimal, meaning different software would interpret the same string as a
//     different CIDR value.
//
//  2. CIDR strings containing IPv6-wrapped IPv4 IPs (e.g. "::ffff:1.2.3.0/24") are not
//     allowed because they may be treated as IPv4 by some software and IPv6 by other
//     software (in fact, they are not even treated consistently between `net.IPNet` and
//     `netip.Prefix`).
//
//  3. CIDRs with non-0 bits after the prefix length (e.g. "1.2.3.4/24") are not allowed
//     because some software will treat that as an IP address with an associated subnet
//     size, while other software will just mask out the bits after the prefix length.
//
// If you are parsing a CIDR string from an object field, command line flag, etc, that
// pre-dates Kubernetes 1.30, you should use ParseLegacyCIDR, since existing objects,
// configs, etc, may contain CIDR strings that do not validate according to ParseCIDR.
//
// If a parse error occurs, the returned error will include cidrStr in the message.
func ParseCIDR(cidrStr string) (netip.Prefix, error) {
	cidr, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidr, handleParsePrefixError(cidrStr, err)
	}

	// (Unlike netip.ParseAddr, netip.ParsePrefix doesn't allow IPv6 zones, so we
	// don't have to check for that.)

	if cidr.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 address %q is not allowed", cidrStr)
	}
	if cidr != cidr.Masked() {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR value %q; should not have any bits set beyond the prefix length", cidrStr)
	}

	// ParsePrefix uses strconv.Atoi so it allows "1.2.3.0/+24". Ugh.
	// https://github.com/golang/go/issues/63850
	if strings.Contains(cidrStr, "/+") {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR value %q", cidrStr)
	}

	return cidr, nil
}

// ParseLegacyCIDR can be used to parse an IPv4 or IPv6 CIDR string which was validated
// according to looser rules than ParseCIDR enforces. For instance, the NetworkPolicy
// `IPBlock` field pre-dates the introduction of stricter CIDR validation, so it should be
// parsed with this function.
//
// Note that if you have an object field, command line flag, etc, containing a "legacy"
// CIDR value, then it is not safe to pass the raw value directly to external APIs
// (including command-line APIs) because other code may interpret the string differently
// than ParseLegacyCIDR does, potentially creating security issues. You should instead
// always call ParseLegacyCIDR on it first, mask the result, and then convert it to a
// string, and pass that string to external APIs.
//
// Contrast ParseCIDR and ParseCanonicalCIDR.
func ParseLegacyCIDR(cidrStr string) (netip.Prefix, error) {
	_, cidr, _ := netutils.ParseCIDRSloppy(cidrStr)
	if cidr == nil {
		// If netutils.ParseCIDRSloppy() rejected it then our ParseCIDR is sure to
		// reject it as well. So use that to get a (better) error message.
		return ParseCIDR(cidrStr)
	}

	return PrefixFromIPNet(cidr), nil
}

// ParseCanonicalCIDR parses a valid IPv4 or IPv6 CIDR string and confirms that it was in
// canonical form (i.e., the form that `.String()` would return). For both IPv4 and IPv6
// this means that the prefix length must not have any leading "0"s. For IPv6 this also
// means that the IP part of the string must be in the canonical form specified by RFC
// 5952. (In particular, it can have no leading "0"s, must use the "::" in the correct
// place, and must use lowercase letters.)
//
// ParseCanonicalCIDR is preferred to ParseCIDR for validating fields in new APIs, because
// there is exactly 1 canonical representation for any CIDR value, meaning
// canonical-CIDR-valued fields can just be treated as strings when checking for equality
// or uniqueness.
func ParseCanonicalCIDR(cidrStr string) (netip.Prefix, error) {
	cidr, err := ParseCIDR(cidrStr)
	if err != nil {
		return cidr, err
	}

	if cidr.Addr().Is6() {
		canonical := cidr.String()
		if cidrStr != canonical {
			return netip.Prefix{}, fmt.Errorf("not accepting CIDR string %q which is not in canonical form (%q)", cidrStr, canonical)
		}
	}

	// Check for, e.g., "1.2.3.0/024"
	if strings.Contains(cidrStr, "/0") && cidr.Bits() != 0 {
		return netip.Prefix{}, fmt.Errorf("not accepting CIDR string %q which is not in canonical form (\"%s/%d\")", cidrStr, cidr.Addr().String(), cidr.Bits())
	}

	return cidr, nil
}

// handleParsePrefixError tries to improve on netip.ParseAddr's sometimes-unhelpful error
// messages.
func handleParsePrefixError(cidrStr string, err error) error {
	switch {
	case cidrStr == "":
		return fmt.Errorf("CIDR value %q should not be empty", cidrStr)
	case strings.TrimSpace(cidrStr) != cidrStr:
		return fmt.Errorf("CIDR value %q should not include whitespace", cidrStr)
	default:
		if _, ipErr := ParseIP(cidrStr); ipErr == nil {
			return fmt.Errorf("expected CIDR value but got IP address %q", cidrStr)
		}
		return err
	}
}

type cidrParser func (string) (netip.Prefix, error)

// SplitCIDRs parses a list of CIDR strings delimited by sep, using the provided parser
// (ParseCIDR, ParseLegacyCIDR, or ParseCanonicalCIDR). If cidrStrList is the empty
// string, this will return an empty list of CIDRs.
func SplitCIDRs(cidrStrList, sep string, parser cidrParser) ([]netip.Prefix, error) {
	var err error

	if cidrStrList == "" {
		return []netip.Prefix{}, nil
	}

	cidrStrs := strings.Split(cidrStrList, sep)
	cidrs := make([]netip.Prefix, len(cidrStrs))
	for i := range cidrStrs {
		cidrs[i], err = parser(cidrStrs[i])
		if err != nil {
			return nil, err
		}
	}
	return cidrs, nil
}

// JoinCIDRs joins a list of CIDR values as strings, using the given separator
func JoinCIDRs(cidrs []netip.Prefix, sep string) string {
	var b strings.Builder

	for i := range cidrs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(cidrs[i].String())
	}
	return b.String()
}

// MustParseCIDR parses an IPv4 or IPv6 CIDR string (which must be in canonical format),
// and panics on failure. This can be used for test cases or compile-time constants.
func MustParseCIDR(cidrStr string) netip.Prefix {
	cidr, err := ParseCanonicalCIDR(cidrStr)
	if err != nil {
		panic(err)
	}
	return cidr
}

// MustParseCIDRs parses an array of IPv4 or IPv6 CIDR strings (which must be in canonical
// format), and panics on failure. This can be used for test cases or compile-time
// constants.
func MustParseCIDRs(cidrStrs []string) []netip.Prefix {
	cidrs := make([]netip.Prefix, len(cidrStrs))
	for i := range cidrStrs {
		cidrs[i] = MustParseCIDR(cidrStrs[i])
	}
	return cidrs
}
