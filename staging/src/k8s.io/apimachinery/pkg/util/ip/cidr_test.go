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
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		legacy bool
		output netip.Prefix
		err    string
	}{
		{
			name:   "ipv4",
			input:  "1.2.3.0/24",
			output: netip.MustParsePrefix("1.2.3.0/24"),
		},
		{
			name:   "ipv4 with leading 0s",
			input:  "001.002.003.000/24",
			legacy: true,
			output: netip.MustParsePrefix("1.2.3.0/24"),
		},
		{
			name:   "ipv4-in-ipv6",
			input:  "::ffff:1.2.3.0/120",
			legacy: true,
			output: netip.MustParsePrefix("1.2.3.0/24"),
		},
		{
			name:   "ipv6",
			input:  "1234:abcd::/64",
			output: netip.MustParsePrefix("1234:abcd::/64"),
		},
		{
			name:   "ipv4 with bad prefix",
			input:  "1.2.3.4/24",
			legacy: true,
			output: netip.MustParsePrefix("1.2.3.0/24"),
		},
		{
			name:   "ipv6 non-canonical 1",
			input:  "1234:abcd:0::/64",
			output: netip.MustParsePrefix("1234:abcd::/64"),
		},
		{
			name:   "ipv6 non-canonical 2",
			input:  "1234:ABCD::/64",
			output: netip.MustParsePrefix("1234:abcd::/64"),
		},
		{
			name:  "empty (invalid)",
			input: "",
			err:   "should not be empty",
		},
		{
			name:  "junk (invalid)",
			input: "blah",
			err:   "no '/'",
		},
		{
			name:  "ip (invalid)",
			input: "1.2.3.0",
			err:   "but got IP address",
		},
		{
			name:  "leading whitespace (invalid)",
			input: "  1.2.3.0/24",
			err:   "should not include whitespace",
		},
		{
			name:  "trailing whitespace (invalid)",
			input: "1.2.3.0/24\n",
			err:   "should not include whitespace",
		},
		{
			name:  "ipv6 with zone (invalid)",
			input: "1234:abcd::%eth0/64",
			err:   "IPv6 zones cannot be present in a prefix",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cidr, err := ParseCIDR(tc.input)
			if tc.legacy {
				if err == nil {
					t.Errorf("expected %q to not parse with ParseCIDR but got %q", tc.input, cidr.String())
				}
			} else if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Errorf("expected %q to return error containing %q but got %q, %v", tc.input, tc.err, cidr.String(), err)
				}
			} else if err != nil {
				t.Errorf("expected %q to parse with ParseCIDR but got %v", tc.input, err)
			} else if cidr != tc.output {
				t.Errorf("expected %q to parse to %q with ParseCIDR but got %q", tc.input, tc.output.String(), cidr.String())
			}

			cidr, err = ParseLegacyCIDR(tc.input)
			if !tc.output.IsValid() {
				if err == nil {
					t.Errorf("expected %q to not parse with ParseLegacyCIDR but got %q", tc.input, cidr.String())
				}
			} else if err != nil {
				t.Errorf("expected %q to parse with ParseLegacyCIDR but got %v", tc.input, err)
			} else {
				if cidr != tc.output {
					t.Errorf("expected %q to parse to %q with ParseLegacyCIDR but got %q", tc.input, tc.output.String(), cidr.String())
				}
			}

			cidr, err = ParseCanonicalCIDR(tc.input)
			if tc.output.String() != tc.input || tc.legacy {
				if err == nil {
					t.Errorf("expected %q to not parse with ParseCanonicalCIDR but got %q", tc.input, cidr.String())
				}
			} else if err != nil {
				t.Errorf("expected %q to parse with ParseCanonicalCIDR but got %v", tc.input, err)
			} else if cidr != tc.output {
				t.Errorf("expected %q to parse to %q with ParseCanonicalCIDR but got %q", tc.input, tc.output.String(), cidr.String())
			}
		})
	}
}

func TestParseCIDRList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		legacy bool
		output []netip.Prefix
	}{
		{
			name:   "empty",
			input:  "",
			output: []netip.Prefix{},
		},
		{
			name:  "ipv4 single",
			input: "1.2.3.0/24",
			output: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
			},
		},
		{
			name:  "ipv4 double",
			input: "1.2.3.0/24,5.6.0.0/16",
			output: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("5.6.0.0/16"),
			},
		},
		{
			name:  "ipv4 triple",
			input: "1.2.3.0/24,5.6.0.0/16,9.10.11.128/25",
			output: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("5.6.0.0/16"),
				netip.MustParsePrefix("9.10.11.128/25"),
			},
		},
		{
			name:   "ipv4 legacy",
			input:  "001.002.003.000/24",
			legacy: true,
			output: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
			},
		},
		{
			name:   "ipv4 mixed legacy",
			input:  "1.2.3.0/24,001.002.003.000/24,5.6.0.0/16",
			legacy: true,
			output: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("5.6.0.0/16"),
			},
		},
		{
			name:  "mixed IP family",
			input: "1234:abcd::/64,5.6.0.0/16",
			output: []netip.Prefix{
				netip.MustParsePrefix("1234:abcd::/64"),
				netip.MustParsePrefix("5.6.0.0/16"),
			},
		},
		{
			name:   "bad prefix",
			input:  "1.2.3.0/24,5.6.7.0/16",
			legacy: true,
			output: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("5.6.0.0/16"),
			},
		},
		{
			name:   "invalid",
			input:  "blah",
			output: nil,
		},
		{
			name:   "mixed invalid",
			input:  "1.2.3.4,blah",
			output: nil,
		},
		{
			name:   "extra commas",
			input:  "1.2.3.4,,5.6.7.8",
			output: nil,
		},
		{
			name:   "whitespace",
			input:  "1.2.3.4, 5.6.7.8",
			output: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cidrs, err := SplitCIDRs(tc.input, ",", ParseCIDR)
			if tc.output == nil || tc.legacy {
				if err == nil {
					t.Errorf("expected %q to not parse with ParseCIDRList but got %v", tc.input, cidrs)
				}
			} else if err != nil {
				t.Errorf("expected %q to parse with ParseCIDRList but got %v", tc.input, err)
			} else if !reflect.DeepEqual(cidrs, tc.output) {
				t.Errorf("expected %q to parse to %v with ParseCIDRList but got %v", tc.input, tc.output, cidrs)
			}

			cidrs, err = SplitCIDRs(tc.input, ",", ParseLegacyCIDR)
			if tc.output == nil {
				if err == nil {
					t.Errorf("expected %q to not parse with ParseLegacyCIDRList but got %q", tc.input, cidrs)
				}
			} else if err != nil {
				t.Errorf("expected %q to parse with ParseLegacyCIDRList but got %v", tc.input, err)
			} else {
				if !reflect.DeepEqual(cidrs, tc.output) {
					t.Errorf("expected %q to parse to %v with ParseLegacyCIDRList but got %v", tc.input, tc.output, cidrs)
				}
			}
		})
	}
}
