/*
Copyright 2016 The Kubernetes Authors.

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

package node

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetPreferredAddress(t *testing.T) {
	testcases := map[string]struct {
		Labels      map[string]string
		Addresses   []v1.NodeAddress
		Preferences []v1.NodeAddressType

		ExpectErr     string
		ExpectAddress string
	}{
		"no addresses": {
			ExpectErr: "no preferred addresses found; known addresses: []",
		},
		"missing address": {
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
			},
			Preferences: []v1.NodeAddressType{v1.NodeHostName},
			ExpectErr:   "no preferred addresses found; known addresses: [{InternalIP 1.2.3.4}]",
		},
		"found address": {
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.5"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.7"},
			},
			Preferences:   []v1.NodeAddressType{v1.NodeHostName, v1.NodeExternalIP},
			ExpectAddress: "1.2.3.5",
		},
		"found hostname address": {
			Labels: map[string]string{v1.LabelHostname: "label-hostname"},
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeExternalIP, Address: "1.2.3.5"},
				{Type: v1.NodeHostName, Address: "status-hostname"},
			},
			Preferences:   []v1.NodeAddressType{v1.NodeHostName, v1.NodeExternalIP},
			ExpectAddress: "status-hostname",
		},
		"label address ignored": {
			Labels: map[string]string{v1.LabelHostname: "label-hostname"},
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeExternalIP, Address: "1.2.3.5"},
			},
			Preferences:   []v1.NodeAddressType{v1.NodeHostName, v1.NodeExternalIP},
			ExpectAddress: "1.2.3.5",
		},
	}

	for k, tc := range testcases {
		node := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{Labels: tc.Labels},
			Status:     v1.NodeStatus{Addresses: tc.Addresses},
		}
		address, err := GetPreferredNodeAddress(node, tc.Preferences)
		errString := ""
		if err != nil {
			errString = err.Error()
		}
		if errString != tc.ExpectErr {
			t.Errorf("%s: expected err=%q, got %q", k, tc.ExpectErr, errString)
		}
		if address != tc.ExpectAddress {
			t.Errorf("%s: expected address=%q, got %q", k, tc.ExpectAddress, address)
		}
	}
}

func TestGetNodeHostIPs(t *testing.T) {
	testcases := []struct {
		name      string
		addresses []v1.NodeAddress

		expectIPs []net.IP
	}{
		{
			name:      "no addresses",
			expectIPs: nil,
		},
		{
			name:      "no InternalIP/ExternalIP",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeHostName, Address: "example.com"},
			},
			expectIPs: nil,
		},
		{
			name:      "IPv4-only, simple",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.5"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.7"},
			},
			expectIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name:      "IPv4-only, external-first",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeExternalIP, Address: "2.1.3.5"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.7"},
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
			},
			expectIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name:      "IPv4-only, no internal",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeExternalIP, Address: "2.1.3.5"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.7"},
			},
			expectIPs: []net.IP{net.ParseIP("2.1.3.5")},
		},
		{
			name:      "dual-stack",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.5"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.7"},
				{Type: v1.NodeInternalIP, Address: "a:b::c:d"},
				{Type: v1.NodeExternalIP, Address: "b:a::d:c"},
			},
			expectIPs: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("a:b::c:d")},
		},
		{
			name:      "dual-stack, different order",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeInternalIP, Address: "a:b::c:d"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.5"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.7"},
				{Type: v1.NodeExternalIP, Address: "b:a::d:c"},
			},
			expectIPs: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("a:b::c:d")},
		},
		{
			name:      "dual-stack, IPv6-first, no internal IPv4",
			addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "a:b::c:d"},
				{Type: v1.NodeExternalIP, Address: "b:a::d:c"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.5"},
				{Type: v1.NodeExternalIP, Address: "2.1.3.7"},
			},
			expectIPs: []net.IP{net.ParseIP("a:b::c:d"), net.ParseIP("2.1.3.5")},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func (t *testing.T) {
			node := &v1.Node{
				Status: v1.NodeStatus{Addresses: tc.addresses},
			}
			nodeIPs, err := GetNodeHostIPs(node)
			nodeIP, err2 := GetNodeHostIP(node)

			if (err == nil && err2 != nil) || (err != nil && err2 == nil) {
				t.Errorf("GetNodeHostIPs() returned error=%q but GetNodeHostIP() returned error=%q", err, err2)
			}
			if err != nil {
				if tc.expectIPs != nil {
					t.Errorf("expected %v, got error (%v)", tc.expectIPs, err)
				}
			} else if tc.expectIPs == nil {
				t.Errorf("expected error, got %v", nodeIPs)
			} else if !reflect.DeepEqual(nodeIPs, tc.expectIPs) {
				t.Errorf("expected %v, got %v", tc.expectIPs, nodeIPs)
			} else if !nodeIP.Equal(nodeIPs[0]) {
				t.Errorf("GetNodeHostIP did not return same primary (%s) as GetNodeHostIPs (%s)", nodeIP.String(), nodeIPs[0].String())
			}
		})
	}
}

func TestGetHostname(t *testing.T) {
	testCases := []struct {
		hostName         string
		expectedHostName string
		expectError      bool
	}{
		{
			hostName:    "   ",
			expectError: true,
		},
		{
			hostName:         " abc  ",
			expectedHostName: "abc",
			expectError:      false,
		},
	}

	for idx, test := range testCases {
		hostName, err := GetHostname(test.hostName)
		if err != nil && !test.expectError {
			t.Errorf("[%d]: unexpected error: %s", idx, err)
		}
		if err == nil && test.expectError {
			t.Errorf("[%d]: expected error, got none", idx)
		}
		if test.expectedHostName != hostName {
			t.Errorf("[%d]: expected output %q, got %q", idx, test.expectedHostName, hostName)
		}

	}
}

func Test_GetZoneKey(t *testing.T) {
	tests := []struct {
		name string
		node *v1.Node
		zone string
	}{
		{
			name: "has no zone or region keys",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{},
				},
			},
			zone: "",
		},
		{
			name: "has beta zone and region keys",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						v1.LabelZoneFailureDomain: "zone1",
						v1.LabelZoneRegion:        "region1",
					},
				},
			},
			zone: "region1:\x00:zone1",
		},
		{
			name: "has GA zone and region keys",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						v1.LabelZoneFailureDomainStable: "zone1",
						v1.LabelZoneRegionStable:        "region1",
					},
				},
			},
			zone: "region1:\x00:zone1",
		},
		{
			name: "has both beta and GA zone and region keys",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						v1.LabelZoneFailureDomainStable: "zone1",
						v1.LabelZoneRegionStable:        "region1",
						v1.LabelZoneFailureDomain:       "zone1",
						v1.LabelZoneRegion:              "region1",
					},
				},
			},
			zone: "region1:\x00:zone1",
		},
		{
			name: "has both beta and GA zone and region keys, beta labels take precedent",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						v1.LabelZoneFailureDomainStable: "zone1",
						v1.LabelZoneRegionStable:        "region1",
						v1.LabelZoneFailureDomain:       "zone2",
						v1.LabelZoneRegion:              "region2",
					},
				},
			},
			zone: "region2:\x00:zone2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			zone := GetZoneKey(test.node)
			if zone != test.zone {
				t.Logf("actual zone key: %q", zone)
				t.Logf("expected zone key: %q", test.zone)
				t.Errorf("unexpected zone key")
			}
		})
	}
}

func TestParseNodeIPs(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		out       []net.IP
		expectErr string
	}{
		{
			name: "unset",
			in:   "",

			out:  []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("::")},
		},
		{
			name: "any IPv4",
			in:   "ipv4",

			out:  []net.IP{net.ParseIP("0.0.0.0")},
		},
		{
			name: "any IPv6, test case-insensitivity",
			in:   "IPv6",

			out:  []net.IP{net.ParseIP("::")},
		},
		{
			name: "ipv6-primary, test whitespace",
			in:   "ipv6, ipv4",

			out:  []net.IP{net.ParseIP("::"), net.ParseIP("0.0.0.0")},
		},
		{
			name: "specific IP",
			in:   "1.2.3.4",

			out:  []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "two specific IPs",
			in:   "1.2.3.4,a:b::c:d",

			out:  []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("a:b::c:d")},
		},
		{
			name: "specific IPv4, non-specific IPv6",
			in:   "1.2.3.4,ipv6",

			out:  []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("::")},
		},

		{
			name: "invalid IP address",
			in:   "example.com",

			expectErr: "or an IP address",
		},
		{
			name: "too many IP addresses",
			in:   "1.2.3.4, 5.6.7.8, 9.10.11.12",

			expectErr: "1 or 2",
		},
		{
			name: "two IPv4 addresses",
			in:   "1.2.3.4,5.6.7.8",

			expectErr: "one IPv4 and one IPv6",
		},
		{
			name: "two IPv6 addresses, one non-specific",
			in:   "ipv6,a:b::c:d",

			expectErr: "one IPv4 and one IPv6",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nodeIPs, err := ParseNodeIPs(test.in)
			if err != nil {
				if test.expectErr == "" {
					t.Errorf("expected %v, got error %v", test.out, err)
				}
				if !strings.Contains(err.Error(), test.expectErr) {
					t.Errorf("expected error %q to contain the string %q", err, test.expectErr)
				}
			}
			if !reflect.DeepEqual(nodeIPs, test.out) {
					t.Errorf("expected %v, got %v", test.out, nodeIPs)
			}
		})
	}
}

func TestFixUpNodeAddresses(t *testing.T) {
	tests := []struct {
		name      string
		in        []v1.NodeAddress
		nodeIPs   string
		out       []v1.NodeAddress
		outIPs    []net.IP
		expectErr string
	}{
		{
			name: "simple single-stack",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "simple single-stack, optional dual-stack node-IPs",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4,ipv6",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "simple single-stack, optional dual-stack node-IPs, wrong order",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv6,ipv4",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "internal has precedence over external",
			in: []v1.NodeAddress{
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "internal has precedence over external when duplicate",
			in: []v1.NodeAddress{
				{ Type: v1.NodeExternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeExternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "internal has precedence over external when duplicate and out of order",
			in: []v1.NodeAddress{
				{ Type: v1.NodeExternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.5",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" }, // MOVED
				{ Type: v1.NodeExternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.5")},
		},
		{
			name: "explicitly request the already-default IP",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.4",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "explicitly request an alternate IP",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.5",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.5")},
		},
		{
			name: "explicit single-stack IP, missing optional primary IP",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv6,1.2.3.4",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "explicit single-stack IP, missing optional secondary IP",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.5,ipv6",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.5")},
		},
		{
			name: "no IPs of requested family",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv6",

			expectErr: "no IPs matching \"ipv6\"",
		},
		{
			name: "no match for requested IP",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.6",

			expectErr: "no IP matching \"1.2.3.6\"",
		},
		{
			name: "can't force external to become primary",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "2.1.4.3",

			expectErr: "could not rearrange",
		},
		{
			name: "dual-stack addresses, single-stack config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				// IPV6 DROPPED
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "dual-stack addresses, single explicit --node-ip",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.4",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				// IPV6 DROPPED
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4")},
		},
		{
			name: "dual-stack addresses, single-stack non-primary config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv6",
			out: []v1.NodeAddress{
				// IPV4 DROPPED
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("a:b::c:d")},
		},
		{
			name: "dual-stack addresses, single explict non-primary IP config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "a:b::c:e",
			out: []v1.NodeAddress{
				// IPV4 DROPPED
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("a:b::c:e")},
		},
		{
			name: "dual-stack addresses, dual-stack config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4,ipv6",
			out: []v1.NodeAddress{ // UNCHANGED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("a:b::c:d")},
		},
		{
			name: "dual-stack addresses, explicit/implicit config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.5,ipv6",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.5"), net.ParseIP("a:b::c:d")},
		},
		{
			name: "dual-stack addresses, implicit/explicit config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4,a:b::c:e",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("a:b::c:e")},
		},
		{
			name: "dual-stack addresses, explicit/explicit config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.4,a:b::c:e",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("a:b::c:e")},
		},
		{
			name: "dual-stack addresses, double-non-default config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.5,a:b::c:e",
			out: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" }, // MOVED
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			outIPs: []net.IP{net.ParseIP("1.2.3.5"), net.ParseIP("a:b::c:e")},
		},
		{
			name: "dual-stack addresses, implicit/unmatched config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv4,a:b::c:f",

			expectErr: "no IP matching \"a:b::c:f\"",
		},
		{
			name: "dual-stack addresses, unmatched/implicit config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.6,ipv6",

			expectErr: "no IP matching \"1.2.3.6\"",
		},
		{
			name: "dual-stack addresses, explicit/unmatched config",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "1.2.3.4,a:b::c:f",

			expectErr: "no IP matching \"a:b::c:f\"",
		},
		{
			name: "dual-stack addresses, bad external IP as first node-ip",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "2.1.4.3,ipv6",

			expectErr: "could not rearrange",
		},
		{
			name: "dual-stack addresses, bad external IP as second node-ip",
			in: []v1.NodeAddress{
				{ Type: v1.NodeInternalIP, Address: "1.2.3.4" },
				{ Type: v1.NodeInternalIP, Address: "1.2.3.5" },
				{ Type: v1.NodeExternalIP, Address: "2.1.4.3" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:d" },
				{ Type: v1.NodeInternalIP, Address: "a:b::c:e" },
				{ Type: v1.NodeHostName, Address: "example.com" },
			},
			nodeIPs: "ipv6,2.1.4.3",

			expectErr: "could not rearrange",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrs, err := FixUpNodeAddresses(test.in, test.nodeIPs)
			if err != nil {
				if test.expectErr == "" {
					t.Errorf("expected %v, got error %v", test.out, err)
				}
				if !strings.Contains(err.Error(), test.expectErr) {
					t.Errorf("expected error %q to contain the string %q", err, test.expectErr)
				}
				return
			} else if test.expectErr != "" {
				t.Errorf("expected error matching %q, got %v", test.expectErr, addrs)
			}
			if !reflect.DeepEqual(addrs, test.out) {
					t.Errorf("expected addresses %v, got %v", test.out, addrs)
			}
			nodeHostIPs, err := getNodeHostIPs(addrs)
			if !reflect.DeepEqual(nodeHostIPs, test.outIPs) {
					t.Errorf("expected ips %v, got %v", test.outIPs, nodeHostIPs)
			}
		})
	}
}
