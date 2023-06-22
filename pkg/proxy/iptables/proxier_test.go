/*
Copyright 2015 The Kubernetes Authors.

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

package iptables

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lithammer/dedent"
	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/component-base/metrics/testutil"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/conntrack"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptablestest "k8s.io/kubernetes/pkg/util/iptables/testing"
	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
	netutils "k8s.io/utils/net"
	"k8s.io/utils/pointer"
)

func TestDeleteEndpointConnections(t *testing.T) {
	const (
		UDP  = v1.ProtocolUDP
		TCP  = v1.ProtocolTCP
		SCTP = v1.ProtocolSCTP
	)

	testCases := []struct {
		description  string
		svcName      string
		svcIP        string
		svcPort      int32
		protocol     v1.Protocol
		endpoint     string // IP:port endpoint
		simulatedErr string
	}{
		{
			description: "V4 UDP",
			svcName:     "v4-udp",
			svcIP:       "172.30.1.1",
			svcPort:     80,
			protocol:    UDP,
			endpoint:    "10.240.0.3:80",
		},
		{
			description: "V4 TCP",
			svcName:     "v4-tcp",
			svcIP:       "172.30.2.2",
			svcPort:     80,
			protocol:    TCP,
			endpoint:    "10.240.0.4:80",
		},
		{
			description: "V4 SCTP",
			svcName:     "v4-sctp",
			svcIP:       "172.30.3.3",
			svcPort:     80,
			protocol:    SCTP,
			endpoint:    "10.240.0.5:80",
		},
		{
			description:  "V4 UDP, nothing to delete, benign error",
			svcName:      "v4-udp-nothing-to-delete",
			svcIP:        "172.30.4.4",
			svcPort:      80,
			protocol:     UDP,
			endpoint:     "10.240.0.6:80",
			simulatedErr: conntrack.NoConnectionToDelete,
		},
		{
			description:  "V4 UDP, unexpected error, should be glogged",
			svcName:      "v4-udp-simulated-error",
			svcIP:        "172.30.5.5",
			svcPort:      80,
			protocol:     UDP,
			endpoint:     "10.240.0.7:80",
			simulatedErr: "simulated error",
		},
		{
			description: "V6 UDP",
			svcName:     "v6-udp",
			svcIP:       "fd00:1234::20",
			svcPort:     80,
			protocol:    UDP,
			endpoint:    "[2001:db8::2]:80",
		},
		{
			description: "V6 TCP",
			svcName:     "v6-tcp",
			svcIP:       "fd00:1234::30",
			svcPort:     80,
			protocol:    TCP,
			endpoint:    "[2001:db8::3]:80",
		},
		{
			description: "V6 SCTP",
			svcName:     "v6-sctp",
			svcIP:       "fd00:1234::40",
			svcPort:     80,
			protocol:    SCTP,
			endpoint:    "[2001:db8::4]:80",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			priorGlogErrs := klog.Stats.Error.Lines()

			// Create a fake executor for the conntrack utility.
			fcmd := fakeexec.FakeCmd{}
			fexec := &fakeexec.FakeExec{
				LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
			}
			execFunc := func(cmd string, args ...string) exec.Cmd {
				return fakeexec.InitFakeCmd(&fcmd, cmd, args...)
			}

			if tc.protocol == UDP {
				cmdOutput := "1 flow entries have been deleted"
				var simErr error

				// First call outputs cmdOutput and succeeds
				fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript,
					func() ([]byte, []byte, error) { return []byte(cmdOutput), nil, nil },
				)
				fexec.CommandScript = append(fexec.CommandScript, execFunc)

				// Second call may succeed or fail
				if tc.simulatedErr != "" {
					cmdOutput = ""
					simErr = fmt.Errorf(tc.simulatedErr)
				}
				fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript,
					func() ([]byte, []byte, error) { return []byte(cmdOutput), nil, simErr },
				)
				fexec.CommandScript = append(fexec.CommandScript, execFunc)
			}

			endpointIP := proxyutil.IPPart(tc.endpoint)
			isIPv6 := netutils.IsIPv6String(endpointIP)

			var ipt utiliptables.Interface
			if isIPv6 {
				ipt = iptablestest.NewIPv6Fake()
			} else {
				ipt = iptablestest.NewFake()
			}
			fp := NewFakeProxier(ipt)
			fp.exec = fexec

			makeServiceMap(fp,
				makeTestService("ns1", tc.svcName, func(svc *v1.Service) {
					svc.Spec.ClusterIP = tc.svcIP
					svc.Spec.Ports = []v1.ServicePort{{
						Name:     "p80",
						Port:     tc.svcPort,
						Protocol: tc.protocol,
					}}
					svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
				}),
			)
			fp.svcPortMap.Update(fp.serviceChanges)

			slice := makeTestEndpointSlice("ns1", tc.svcName, 1, func(eps *discovery.EndpointSlice) {
				if isIPv6 {
					eps.AddressType = discovery.AddressTypeIPv6
				} else {
					eps.AddressType = discovery.AddressTypeIPv4
				}
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{endpointIP},
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tc.protocol,
				}}
			})

			// Add and then remove the endpoint slice
			fp.OnEndpointSliceAdd(slice)
			fp.syncProxyRules()
			fp.OnEndpointSliceDelete(slice)
			fp.syncProxyRules()

			// Check the executed conntrack command
			if tc.protocol == UDP {
				if fexec.CommandCalls != 2 {
					t.Fatalf("Expected conntrack to be executed 2 times, but got %d", fexec.CommandCalls)
				}

				// First clear conntrack entries for the clusterIP when the
				// endpoint is first added.
				expectCommand := fmt.Sprintf("conntrack -D --orig-dst %s -p udp", tc.svcIP)
				if isIPv6 {
					expectCommand += " -f ipv6"
				}
				actualCommand := strings.Join(fcmd.CombinedOutputLog[0], " ")
				if actualCommand != expectCommand {
					t.Errorf("Expected command: %s, but executed %s", expectCommand, actualCommand)
				}

				// Then clear conntrack entries for the endpoint when it is
				// deleted.
				expectCommand = fmt.Sprintf("conntrack -D --orig-dst %s --dst-nat %s -p udp", tc.svcIP, endpointIP)
				if isIPv6 {
					expectCommand += " -f ipv6"
				}
				actualCommand = strings.Join(fcmd.CombinedOutputLog[1], " ")
				if actualCommand != expectCommand {
					t.Errorf("Expected command: %s, but executed %s", expectCommand, actualCommand)
				}
			} else if fexec.CommandCalls != 0 {
				t.Fatalf("Expected conntrack to be executed 0 times, but got %d", fexec.CommandCalls)
			}

			// Check the number of new glog errors
			var expGlogErrs int64
			if tc.simulatedErr != "" && tc.simulatedErr != conntrack.NoConnectionToDelete {
				expGlogErrs = 1
			}
			glogErrs := klog.Stats.Error.Lines() - priorGlogErrs
			if glogErrs != expGlogErrs {
				t.Errorf("Expected %d glogged errors, but got %d", expGlogErrs, glogErrs)
			}
		})
	}
}

func TestComputeProbability(t *testing.T) {
	expectedProbabilities := map[int]string{
		1:      "1.0000000000",
		2:      "0.5000000000",
		10:     "0.1000000000",
		100:    "0.0100000000",
		1000:   "0.0010000000",
		10000:  "0.0001000000",
		100000: "0.0000100000",
		100001: "0.0000099999",
	}

	for num, expected := range expectedProbabilities {
		actual := computeProbability(num)
		if actual != expected {
			t.Errorf("Expected computeProbability(%d) to be %s, got: %s", num, expected, actual)
		}
	}

	prevProbability := float64(0)
	for i := 100000; i > 1; i-- {
		currProbability, err := strconv.ParseFloat(computeProbability(i), 64)
		if err != nil {
			t.Fatalf("Error parsing float probability for %d: %v", i, err)
		}
		if currProbability <= prevProbability {
			t.Fatalf("Probability unexpectedly <= to previous probability for %d: (%0.10f <= %0.10f)", i, currProbability, prevProbability)
		}
		prevProbability = currProbability
	}
}

func TestBuildServiceMapAddRemove(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	services := []*v1.Service{
		makeTestService("somewhere-else", "cluster-ip", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.55.4"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "UDP", 1235, 5321, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "sctpport", "SCTP", 1236, 6321, 0)
		}),
		makeTestService("somewhere-else", "node-port", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeNodePort
			svc.Spec.ClusterIP = "172.30.55.10"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "blahblah", "UDP", 345, 678, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "moreblahblah", "TCP", 344, 677, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "muchmoreblah", "SCTP", 343, 676, 0)
		}),
		makeTestService("somewhere", "load-balancer", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = "172.30.55.11"
			svc.Spec.LoadBalancerIP = "1.2.3.4"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "foobar", "UDP", 8675, 30061, 7000)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "baz", "UDP", 8676, 30062, 7001)
			svc.Status.LoadBalancer = v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			}
		}),
		makeTestService("somewhere", "only-local-load-balancer", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = "172.30.55.12"
			svc.Spec.LoadBalancerIP = "5.6.7.8"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "foobar2", "UDP", 8677, 30063, 7002)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "baz", "UDP", 8678, 30064, 7003)
			svc.Status.LoadBalancer = v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "5.6.7.8"},
				},
			}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
			svc.Spec.HealthCheckNodePort = 345
		}),
	}

	for i := range services {
		fp.OnServiceAdd(services[i])
	}
	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 10 {
		t.Errorf("expected service map length 10, got %v", fp.svcPortMap)
	}

	if len(result.DeletedUDPClusterIPs) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}

	// The only-local-loadbalancer ones get added
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 1 {
		t.Errorf("expected 1 healthcheck port, got %v", healthCheckNodePorts)
	} else {
		nsn := makeNSN("somewhere", "only-local-load-balancer")
		if port, found := healthCheckNodePorts[nsn]; !found || port != 345 {
			t.Errorf("expected healthcheck port [%q]=345: got %v", nsn, healthCheckNodePorts)
		}
	}

	// Remove some stuff
	// oneService is a modification of services[0] with removed first port.
	oneService := makeTestService("somewhere-else", "cluster-ip", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeClusterIP
		svc.Spec.ClusterIP = "172.30.55.4"
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "UDP", 1235, 5321, 0)
	})

	fp.OnServiceUpdate(services[0], oneService)
	fp.OnServiceDelete(services[1])
	fp.OnServiceDelete(services[2])
	fp.OnServiceDelete(services[3])

	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 1 {
		t.Errorf("expected service map length 1, got %v", fp.svcPortMap)
	}

	// All services but one were deleted. While you'd expect only the ClusterIPs
	// from the three deleted services here, we still have the ClusterIP for
	// the not-deleted service, because one of it's ServicePorts was deleted.
	expectedStaleUDPServices := []string{"172.30.55.10", "172.30.55.4", "172.30.55.11", "172.30.55.12"}
	if len(result.DeletedUDPClusterIPs) != len(expectedStaleUDPServices) {
		t.Errorf("expected stale UDP services length %d, got %v", len(expectedStaleUDPServices), result.DeletedUDPClusterIPs.UnsortedList())
	}
	for _, ip := range expectedStaleUDPServices {
		if !result.DeletedUDPClusterIPs.Has(ip) {
			t.Errorf("expected stale UDP service service %s", ip)
		}
	}

	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected 0 healthcheck ports, got %v", healthCheckNodePorts)
	}
}

func TestBuildServiceMapServiceHeadless(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	makeServiceMap(fp,
		makeTestService("somewhere-else", "headless", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = v1.ClusterIPNone
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "rpc", "UDP", 1234, 0, 0)
		}),
		makeTestService("somewhere-else", "headless-without-port", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = v1.ClusterIPNone
		}),
	)

	// Headless service should be ignored
	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 0 {
		t.Errorf("expected service map length 0, got %d", len(fp.svcPortMap))
	}

	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}

	// No proxied services, so no healthchecks
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %d", len(healthCheckNodePorts))
	}
}

func TestBuildServiceMapServiceTypeExternalName(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	makeServiceMap(fp,
		makeTestService("somewhere-else", "external-name", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeExternalName
			svc.Spec.ClusterIP = "172.30.55.4" // Should be ignored
			svc.Spec.ExternalName = "foo2.bar.com"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "blah", "UDP", 1235, 5321, 0)
		}),
	)

	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 0 {
		t.Errorf("expected service map length 0, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", result.DeletedUDPClusterIPs)
	}
	// No proxied services, so no healthchecks
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %v", healthCheckNodePorts)
	}
}

func TestBuildServiceMapServiceUpdate(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	servicev1 := makeTestService("somewhere", "some-service", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeClusterIP
		svc.Spec.ClusterIP = "172.30.55.4"
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 0)
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "TCP", 1235, 5321, 0)
	})
	servicev2 := makeTestService("somewhere", "some-service", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeLoadBalancer
		svc.Spec.ClusterIP = "172.30.55.4"
		svc.Spec.LoadBalancerIP = "1.2.3.4"
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 7002)
		svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "TCP", 1235, 5321, 7003)
		svc.Status.LoadBalancer = v1.LoadBalancerStatus{
			Ingress: []v1.LoadBalancerIngress{
				{IP: "1.2.3.4"},
			},
		}
		svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		svc.Spec.HealthCheckNodePort = 345
	})

	fp.OnServiceAdd(servicev1)

	result := fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}
	healthCheckNodePorts := fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %v", healthCheckNodePorts)
	}

	// Change service to load-balancer
	fp.OnServiceUpdate(servicev1, servicev2)
	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", result.DeletedUDPClusterIPs.UnsortedList())
	}
	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 1 {
		t.Errorf("expected healthcheck ports length 1, got %v", healthCheckNodePorts)
	}

	// No change; make sure the service map stays the same and there are
	// no health-check changes
	fp.OnServiceUpdate(servicev2, servicev2)
	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", result.DeletedUDPClusterIPs.UnsortedList())
	}
	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 1 {
		t.Errorf("expected healthcheck ports length 1, got %v", healthCheckNodePorts)
	}

	// And back to ClusterIP
	fp.OnServiceUpdate(servicev2, servicev1)
	result = fp.svcPortMap.Update(fp.serviceChanges)
	if len(fp.svcPortMap) != 2 {
		t.Errorf("expected service map length 2, got %v", fp.svcPortMap)
	}
	if len(result.DeletedUDPClusterIPs) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(result.DeletedUDPClusterIPs))
	}
	healthCheckNodePorts = fp.svcPortMap.HealthCheckNodePorts()
	if len(healthCheckNodePorts) != 0 {
		t.Errorf("expected healthcheck ports length 0, got %v", healthCheckNodePorts)
	}
}

func compareEndpointsMapsExceptChainName(t *testing.T, tci int, newMap proxy.EndpointsMap, expected map[proxy.ServicePortName][]*endpointsInfo) {
	if len(newMap) != len(expected) {
		t.Errorf("[%d] expected %d results, got %d: %v", tci, len(expected), len(newMap), newMap)
	}
	for x := range expected {
		if len(newMap[x]) != len(expected[x]) {
			t.Errorf("[%d] expected %d endpoints for %v, got %d", tci, len(expected[x]), x, len(newMap[x]))
		} else {
			for i := range expected[x] {
				newEp, ok := newMap[x][i].(*endpointsInfo)
				if !ok {
					t.Errorf("Failed to cast endpointsInfo")
					continue
				}
				if newEp.Endpoint != expected[x][i].Endpoint ||
					newEp.IsLocal != expected[x][i].IsLocal {
					t.Errorf("[%d] expected new[%v][%d] to be %v, got %v", tci, x, i, expected[x][i], newEp)
				}
			}
		}
	}
}

func TestUpdateEndpointsMap(t *testing.T) {
	var nodeName = testHostname
	udpProtocol := v1.ProtocolUDP

	emptyEndpointSlices := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, func(*discovery.EndpointSlice) {}),
	}
	subset1 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}}
	}
	subset2 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.2"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	namedPortLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
					NodeName:  &nodeName,
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11"),
					Port:     pointer.Int32(11),
					Protocol: &udpProtocol,
				}}
			}),
	}
	namedPort := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
	}
	namedPortRenamed := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11-2"),
					Port:     pointer.Int32(11),
					Protocol: &udpProtocol,
				}}
			}),
	}
	namedPortRenumbered := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11"),
					Port:     pointer.Int32(22),
					Protocol: &udpProtocol,
				}}
			}),
	}
	namedPortsLocalNoLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1,
			func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{{
					Addresses: []string{"10.1.1.1"},
				}, {
					Addresses: []string{"10.1.1.2"},
					NodeName:  &nodeName,
				}}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p11"),
					Port:     pointer.Int32(11),
					Protocol: &udpProtocol,
				}, {
					Name:     pointer.String("p12"),
					Port:     pointer.Int32(12),
					Protocol: &udpProtocol,
				}}
			}),
	}
	multipleSubsets := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
		makeTestEndpointSlice("ns1", "ep1", 2, subset2),
	}
	subsetLocal := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.2"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	multipleSubsetsWithLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
		makeTestEndpointSlice("ns1", "ep1", 2, subsetLocal),
	}
	subsetMultiplePortsLocal := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	subset3 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.3"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p13"),
			Port:     pointer.Int32(13),
			Protocol: &udpProtocol,
		}}
	}
	multipleSubsetsMultiplePortsLocal := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subsetMultiplePortsLocal),
		makeTestEndpointSlice("ns1", "ep1", 2, subset3),
	}
	subsetMultipleIPsPorts1 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
		}, {
			Addresses: []string{"10.1.1.2"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}}
	}
	subsetMultipleIPsPorts2 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.3"},
		}, {
			Addresses: []string{"10.1.1.4"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p13"),
			Port:     pointer.Int32(13),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p14"),
			Port:     pointer.Int32(14),
			Protocol: &udpProtocol,
		}}
	}
	subsetMultipleIPsPorts3 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.2.2.1"},
		}, {
			Addresses: []string{"10.2.2.2"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p21"),
			Port:     pointer.Int32(21),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p22"),
			Port:     pointer.Int32(22),
			Protocol: &udpProtocol,
		}}
	}
	multipleSubsetsIPsPorts := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subsetMultipleIPsPorts1),
		makeTestEndpointSlice("ns1", "ep1", 2, subsetMultipleIPsPorts2),
		makeTestEndpointSlice("ns2", "ep2", 1, subsetMultipleIPsPorts3),
	}
	complexSubset1 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.2.2.2"},
			NodeName:  &nodeName,
		}, {
			Addresses: []string{"10.2.2.22"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p22"),
			Port:     pointer.Int32(22),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset2 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.2.2.3"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p23"),
			Port:     pointer.Int32(23),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset3 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.4.4"},
			NodeName:  &nodeName,
		}, {
			Addresses: []string{"10.4.4.5"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p44"),
			Port:     pointer.Int32(44),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset4 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.4.6"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p45"),
			Port:     pointer.Int32(45),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset5 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.1"},
		}, {
			Addresses: []string{"10.1.1.11"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p11"),
			Port:     pointer.Int32(11),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset6 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.1.1.2"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p12"),
			Port:     pointer.Int32(12),
			Protocol: &udpProtocol,
		}, {
			Name:     pointer.String("p122"),
			Port:     pointer.Int32(122),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset7 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.3.3.3"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p33"),
			Port:     pointer.Int32(33),
			Protocol: &udpProtocol,
		}}
	}
	complexSubset8 := func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.4.4"},
			NodeName:  &nodeName,
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p44"),
			Port:     pointer.Int32(44),
			Protocol: &udpProtocol,
		}}
	}
	complexBefore := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, subset1),
		nil,
		makeTestEndpointSlice("ns2", "ep2", 1, complexSubset1),
		makeTestEndpointSlice("ns2", "ep2", 2, complexSubset2),
		nil,
		makeTestEndpointSlice("ns4", "ep4", 1, complexSubset3),
		makeTestEndpointSlice("ns4", "ep4", 2, complexSubset4),
	}
	complexAfter := []*discovery.EndpointSlice{
		makeTestEndpointSlice("ns1", "ep1", 1, complexSubset5),
		makeTestEndpointSlice("ns1", "ep1", 2, complexSubset6),
		nil,
		nil,
		makeTestEndpointSlice("ns3", "ep3", 1, complexSubset7),
		makeTestEndpointSlice("ns4", "ep4", 1, complexSubset8),
		nil,
	}

	testCases := []struct {
		// previousEndpoints and currentEndpoints are used to call appropriate
		// handlers OnEndpoints* (based on whether corresponding values are nil
		// or non-nil) and must be of equal length.
		name                           string
		previousEndpoints              []*discovery.EndpointSlice
		currentEndpoints               []*discovery.EndpointSlice
		oldEndpoints                   map[proxy.ServicePortName][]*endpointsInfo
		expectedResult                 map[proxy.ServicePortName][]*endpointsInfo
		expectedDeletedUDPEndpoints    []proxy.ServiceEndpoint
		expectedNewlyActiveUDPServices map[proxy.ServicePortName]bool
		expectedLocalEndpoints         map[types.NamespacedName]int
	}{{
		// Case[0]: nothing
		name:                           "nothing",
		oldEndpoints:                   map[proxy.ServicePortName][]*endpointsInfo{},
		expectedResult:                 map[proxy.ServicePortName][]*endpointsInfo{},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[1]: no change, named port, local
		name:              "no change, named port, local",
		previousEndpoints: namedPortLocal,
		currentEndpoints:  namedPortLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[2]: no change, multiple subsets
		name:              "no change, multiple subsets",
		previousEndpoints: multipleSubsets,
		currentEndpoints:  multipleSubsets,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[3]: no change, multiple subsets, multiple ports, local
		name:              "no change, multiple subsets, multiple ports, local",
		previousEndpoints: multipleSubsetsMultiplePortsLocal,
		currentEndpoints:  multipleSubsetsMultiplePortsLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[4]: no change, multiple endpoints, subsets, IPs, and ports
		name:              "no change, multiple endpoints, subsets, IPs, and ports",
		previousEndpoints: multipleSubsetsIPsPorts,
		currentEndpoints:  multipleSubsetsIPsPorts,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:13", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p14", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:14", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:14", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p21", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:21", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:21", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:22", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p13", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:13", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:13", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p14", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.3:14", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.4:14", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p21", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:21", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:21", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.1:22", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints:    []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 2,
			makeNSN("ns2", "ep2"): 1,
		},
	}, {
		// Case[5]: add an Endpoints
		name:              "add an Endpoints",
		previousEndpoints: []*discovery.EndpointSlice{nil},
		currentEndpoints:  namedPortLocal,
		oldEndpoints:      map[proxy.ServicePortName][]*endpointsInfo{},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[6]: remove an Endpoints
		name:              "remove an Endpoints",
		previousEndpoints: namedPortLocal,
		currentEndpoints:  []*discovery.EndpointSlice{nil},
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.1:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[7]: add an IP and port
		name:              "add an IP and port",
		previousEndpoints: namedPort,
		currentEndpoints:  namedPortsLocalNoLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[8]: remove an IP and port
		name:              "remove an IP and port",
		previousEndpoints: namedPortsLocalNoLocal,
		currentEndpoints:  namedPort,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:11", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.2:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.1.1.1:12",
			ServicePortName: makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.1.1.2:12",
			ServicePortName: makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[9]: add a subset
		name:              "add a subset",
		previousEndpoints: []*discovery.EndpointSlice{namedPort[0], nil},
		currentEndpoints:  multipleSubsetsWithLocal,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns1", "ep1"): 1,
		},
	}, {
		// Case[10]: remove a subset
		name:              "remove a subset",
		previousEndpoints: multipleSubsets,
		currentEndpoints:  []*discovery.EndpointSlice{namedPort[0], nil},
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.2:12",
			ServicePortName: makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[11]: rename a port
		name:              "rename a port",
		previousEndpoints: namedPort,
		currentEndpoints:  namedPortRenamed,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11-2", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.1:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p11-2", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{},
	}, {
		// Case[12]: renumber a port
		name:              "renumber a port",
		previousEndpoints: namedPort,
		currentEndpoints:  namedPortRenumbered,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:22", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.1.1.1:11",
			ServicePortName: makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{},
		expectedLocalEndpoints:         map[types.NamespacedName]int{},
	}, {
		// Case[13]: complex add and remove
		name:              "complex add and remove",
		previousEndpoints: complexBefore,
		currentEndpoints:  complexAfter,
		oldEndpoints: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.22:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.2:22", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns2", "ep2", "p23", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.2.2.3:23", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns4", "ep4", "p44", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.4:44", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.5:44", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns4", "ep4", "p45", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.6:45", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.11:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:12", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns1", "ep1", "p122", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.2:122", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns3", "ep3", "p33", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.3.3.3:33", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
			makeServicePortName("ns4", "ep4", "p44", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.4.4.4:44", IsLocal: true, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{{
			Endpoint:        "10.2.2.2:22",
			ServicePortName: makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.2.2.22:22",
			ServicePortName: makeServicePortName("ns2", "ep2", "p22", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.2.2.3:23",
			ServicePortName: makeServicePortName("ns2", "ep2", "p23", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.4.4.5:44",
			ServicePortName: makeServicePortName("ns4", "ep4", "p44", v1.ProtocolUDP),
		}, {
			Endpoint:        "10.4.4.6:45",
			ServicePortName: makeServicePortName("ns4", "ep4", "p45", v1.ProtocolUDP),
		}},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p12", v1.ProtocolUDP):  true,
			makeServicePortName("ns1", "ep1", "p122", v1.ProtocolUDP): true,
			makeServicePortName("ns3", "ep3", "p33", v1.ProtocolUDP):  true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{
			makeNSN("ns4", "ep4"): 1,
		},
	}, {
		// Case[14]: change from 0 endpoint address to 1 unnamed port
		name:              "change from 0 endpoint address to 1 unnamed port",
		previousEndpoints: emptyEndpointSlices,
		currentEndpoints:  namedPort,
		oldEndpoints:      map[proxy.ServicePortName][]*endpointsInfo{},
		expectedResult: map[proxy.ServicePortName][]*endpointsInfo{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): {
				{BaseEndpointInfo: &proxy.BaseEndpointInfo{Endpoint: "10.1.1.1:11", IsLocal: false, Ready: true, Serving: true, Terminating: false}},
			},
		},
		expectedDeletedUDPEndpoints: []proxy.ServiceEndpoint{},
		expectedNewlyActiveUDPServices: map[proxy.ServicePortName]bool{
			makeServicePortName("ns1", "ep1", "p11", v1.ProtocolUDP): true,
		},
		expectedLocalEndpoints: map[types.NamespacedName]int{},
	},
	}

	for tci, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ipt := iptablestest.NewFake()
			fp := NewFakeProxier(ipt)
			fp.hostname = nodeName

			// First check that after adding all previous versions of endpoints,
			// the fp.oldEndpoints is as we expect.
			for i := range tc.previousEndpoints {
				if tc.previousEndpoints[i] != nil {
					fp.OnEndpointSliceAdd(tc.previousEndpoints[i])
				}
			}
			fp.endpointsMap.Update(fp.endpointsChanges)
			compareEndpointsMapsExceptChainName(t, tci, fp.endpointsMap, tc.oldEndpoints)

			// Now let's call appropriate handlers to get to state we want to be.
			if len(tc.previousEndpoints) != len(tc.currentEndpoints) {
				t.Fatalf("[%d] different lengths of previous and current endpoints", tci)
			}

			for i := range tc.previousEndpoints {
				prev, curr := tc.previousEndpoints[i], tc.currentEndpoints[i]
				switch {
				case prev == nil:
					fp.OnEndpointSliceAdd(curr)
				case curr == nil:
					fp.OnEndpointSliceDelete(prev)
				default:
					fp.OnEndpointSliceUpdate(prev, curr)
				}
			}
			result := fp.endpointsMap.Update(fp.endpointsChanges)
			newMap := fp.endpointsMap
			compareEndpointsMapsExceptChainName(t, tci, newMap, tc.expectedResult)
			if len(result.DeletedUDPEndpoints) != len(tc.expectedDeletedUDPEndpoints) {
				t.Errorf("[%d] expected %d staleEndpoints, got %d: %v", tci, len(tc.expectedDeletedUDPEndpoints), len(result.DeletedUDPEndpoints), result.DeletedUDPEndpoints)
			}
			for _, x := range tc.expectedDeletedUDPEndpoints {
				found := false
				for _, stale := range result.DeletedUDPEndpoints {
					if stale == x {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("[%d] expected staleEndpoints[%v], but didn't find it: %v", tci, x, result.DeletedUDPEndpoints)
				}
			}
			if len(result.NewlyActiveUDPServices) != len(tc.expectedNewlyActiveUDPServices) {
				t.Errorf("[%d] expected %d staleServiceNames, got %d: %v", tci, len(tc.expectedNewlyActiveUDPServices), len(result.NewlyActiveUDPServices), result.NewlyActiveUDPServices)
			}
			for svcName := range tc.expectedNewlyActiveUDPServices {
				found := false
				for _, stale := range result.NewlyActiveUDPServices {
					if stale == svcName {
						found = true
					}
				}
				if !found {
					t.Errorf("[%d] expected staleServiceNames[%v], but didn't find it: %v", tci, svcName, result.NewlyActiveUDPServices)
				}
			}
			localReadyEndpoints := fp.endpointsMap.LocalReadyEndpoints()
			if !reflect.DeepEqual(localReadyEndpoints, tc.expectedLocalEndpoints) {
				t.Errorf("[%d] expected local endpoints %v, got %v", tci, tc.expectedLocalEndpoints, localReadyEndpoints)
			}
		})
	}
}

// TestHealthCheckNodePortWhenTerminating tests that health check node ports are not enabled when all local endpoints are terminating
func TestHealthCheckNodePortWhenTerminating(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.OnServiceSynced()
	fp.OnEndpointSlicesSynced()

	serviceName := "svc1"
	namespaceName := "ns1"

	fp.OnServiceAdd(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespaceName},
		Spec: v1.ServiceSpec{
			ClusterIP: "172.30.1.1",
			Selector:  map[string]string{"foo": "bar"},
			Ports:     []v1.ServicePort{{Name: "", TargetPort: intstr.FromInt32(80), Protocol: v1.ProtocolTCP}},
		},
	})

	endpointSlice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-1", serviceName),
			Namespace: namespaceName,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{{
			Name:     pointer.String(""),
			Port:     pointer.Int32(80),
			Protocol: &tcpProtocol,
		}},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{{
			Addresses:  []string{"10.0.1.1"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
			NodeName:   pointer.String(testHostname),
		}, {
			Addresses:  []string{"10.0.1.2"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
			NodeName:   pointer.String(testHostname),
		}, {
			Addresses:  []string{"10.0.1.3"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
			NodeName:   pointer.String(testHostname),
		}, { // not ready endpoints should be ignored
			Addresses:  []string{"10.0.1.4"},
			Conditions: discovery.EndpointConditions{Ready: pointer.Bool(false)},
			NodeName:   pointer.String(testHostname),
		}},
	}

	fp.OnEndpointSliceAdd(endpointSlice)
	_ = fp.endpointsMap.Update(fp.endpointsChanges)
	localReadyEndpoints := fp.endpointsMap.LocalReadyEndpoints()
	if len(localReadyEndpoints) != 1 {
		t.Errorf("unexpected number of local ready endpoints, expected 1 but got: %d", len(localReadyEndpoints))
	}

	// set all endpoints to terminating
	endpointSliceTerminating := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-1", serviceName),
			Namespace: namespaceName,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{{
			Name:     pointer.String(""),
			Port:     pointer.Int32(80),
			Protocol: &tcpProtocol,
		}},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{{
			Addresses: []string{"10.0.1.1"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(true),
				Terminating: pointer.Bool(false),
			},
			NodeName: pointer.String(testHostname),
		}, {
			Addresses: []string{"10.0.1.2"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(true),
				Terminating: pointer.Bool(true),
			},
			NodeName: pointer.String(testHostname),
		}, {
			Addresses: []string{"10.0.1.3"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(true),
				Terminating: pointer.Bool(true),
			},
			NodeName: pointer.String(testHostname),
		}, { // not ready endpoints should be ignored
			Addresses: []string{"10.0.1.4"},
			Conditions: discovery.EndpointConditions{
				Ready:       pointer.Bool(false),
				Serving:     pointer.Bool(false),
				Terminating: pointer.Bool(true),
			},
			NodeName: pointer.String(testHostname),
		}},
	}

	fp.OnEndpointSliceUpdate(endpointSlice, endpointSliceTerminating)
	_ = fp.endpointsMap.Update(fp.endpointsChanges)
	localReadyEndpoints = fp.endpointsMap.LocalReadyEndpoints()
	if len(localReadyEndpoints) != 0 {
		t.Errorf("unexpected number of local ready endpoints, expected 0 but got: %d", len(localReadyEndpoints))
	}
}

func TestProxierDeleteNodePortStaleUDP(t *testing.T) {
	fcmd := fakeexec.FakeCmd{}
	fexec := &fakeexec.FakeExec{
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
	}
	execFunc := func(cmd string, args ...string) exec.Cmd {
		return fakeexec.InitFakeCmd(&fcmd, cmd, args...)
	}
	cmdOutput := "1 flow entries have been deleted"
	cmdFunc := func() ([]byte, []byte, error) { return []byte(cmdOutput), nil, nil }

	// Delete ClusterIP entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)
	// Delete ExternalIP entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)
	// Delete LoadBalancerIP entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)
	// Delete NodePort entries
	fcmd.CombinedOutputScript = append(fcmd.CombinedOutputScript, cmdFunc)
	fexec.CommandScript = append(fexec.CommandScript, execFunc)

	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.exec = fexec

	svcIP := "172.30.0.41"
	extIP := "192.168.99.11"
	lbIngressIP := "1.2.3.4"
	svcPort := 80
	nodePort := 31201
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolUDP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{extIP}
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolUDP,
				NodePort: int32(nodePort),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: lbIngressIP,
			}}
		}),
	)

	fp.syncProxyRules()
	if fexec.CommandCalls != 0 {
		t.Fatalf("Created service without endpoints must not clear conntrack entries")
	}

	epIP := "10.180.0.1"
	udpProtocol := v1.ProtocolUDP
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
				Conditions: discovery.EndpointConditions{
					Ready: pointer.Bool(false),
				},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &udpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	if fexec.CommandCalls != 0 {
		t.Fatalf("Updated UDP service with not ready endpoints must not clear UDP entries")
	}

	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
				Conditions: discovery.EndpointConditions{
					Ready: pointer.Bool(true),
				},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &udpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	if fexec.CommandCalls != 4 {
		t.Fatalf("Updated UDP service with new endpoints must clear UDP entries 4 times: ClusterIP, NodePort, ExternalIP and LB")
	}

	// the order is not guaranteed so we have to compare the strings in any order
	expectedCommands := []string{
		// Delete ClusterIP Conntrack entries
		fmt.Sprintf("conntrack -D --orig-dst %s -p %s", svcIP, strings.ToLower(string((v1.ProtocolUDP)))),
		// Delete ExternalIP Conntrack entries
		fmt.Sprintf("conntrack -D --orig-dst %s -p %s", extIP, strings.ToLower(string((v1.ProtocolUDP)))),
		// Delete LoadBalancerIP Conntrack entries
		fmt.Sprintf("conntrack -D --orig-dst %s -p %s", lbIngressIP, strings.ToLower(string((v1.ProtocolUDP)))),
		// Delete NodePort Conntrack entrie
		fmt.Sprintf("conntrack -D -p %s --dport %d", strings.ToLower(string((v1.ProtocolUDP))), nodePort),
	}
	actualCommands := []string{
		strings.Join(fcmd.CombinedOutputLog[0], " "),
		strings.Join(fcmd.CombinedOutputLog[1], " "),
		strings.Join(fcmd.CombinedOutputLog[2], " "),
		strings.Join(fcmd.CombinedOutputLog[3], " "),
	}
	sort.Strings(expectedCommands)
	sort.Strings(actualCommands)

	if !reflect.DeepEqual(expectedCommands, actualCommands) {
		t.Errorf("Expected commands: %v, but executed %v", expectedCommands, actualCommands)
	}
}

func TestProxierMetricsIptablesTotalRules(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	metrics.RegisterMetrics()

	svcIP := "172.30.0.41"
	svcPort := 80
	nodePort := 31201
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(nodePort),
			}}
		}),
	)
	fp.syncProxyRules()
	iptablesData := fp.iptablesData.String()

	nFilterRulesMetric, err := testutil.GetGaugeMetricValue(metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableFilter)))
	if err != nil {
		t.Errorf("failed to get %s value, err: %v", metrics.IptablesRulesTotal.Name, err)
	}
	nFilterRules := int(nFilterRulesMetric)
	expectedFilterRules := countRules(utiliptables.TableFilter, iptablesData)

	if nFilterRules != expectedFilterRules {
		t.Fatalf("Wrong number of filter rule: expected %d got %d\n%s", expectedFilterRules, nFilterRules, iptablesData)
	}

	nNatRulesMetric, err := testutil.GetGaugeMetricValue(metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableNAT)))
	if err != nil {
		t.Errorf("failed to get %s value, err: %v", metrics.IptablesRulesTotal.Name, err)
	}
	nNatRules := int(nNatRulesMetric)
	expectedNatRules := countRules(utiliptables.TableNAT, iptablesData)

	if nNatRules != expectedNatRules {
		t.Fatalf("Wrong number of nat rules: expected %d got %d\n%s", expectedNatRules, nNatRules, iptablesData)
	}

	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.0.2"},
			}, {
				Addresses: []string{"10.0.0.5"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	iptablesData = fp.iptablesData.String()

	nFilterRulesMetric, err = testutil.GetGaugeMetricValue(metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableFilter)))
	if err != nil {
		t.Errorf("failed to get %s value, err: %v", metrics.IptablesRulesTotal.Name, err)
	}
	nFilterRules = int(nFilterRulesMetric)
	expectedFilterRules = countRules(utiliptables.TableFilter, iptablesData)

	if nFilterRules != expectedFilterRules {
		t.Fatalf("Wrong number of filter rule: expected %d got %d\n%s", expectedFilterRules, nFilterRules, iptablesData)
	}

	nNatRulesMetric, err = testutil.GetGaugeMetricValue(metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableNAT)))
	if err != nil {
		t.Errorf("failed to get %s value, err: %v", metrics.IptablesRulesTotal.Name, err)
	}
	nNatRules = int(nNatRulesMetric)
	expectedNatRules = countRules(utiliptables.TableNAT, iptablesData)

	if nNatRules != expectedNatRules {
		t.Fatalf("Wrong number of nat rules: expected %d got %d\n%s", expectedNatRules, nNatRules, iptablesData)
	}
}

func countEndpointsAndComments(iptablesData string, matchEndpoint string) (string, int, int) {
	var numEndpoints, numComments int
	var matched string
	for _, line := range strings.Split(iptablesData, "\n") {
		if strings.HasPrefix(line, "-A KUBE-SEP-") && strings.Contains(line, "-j DNAT") {
			numEndpoints++
			if strings.Contains(line, "--comment") {
				numComments++
			}
			if strings.Contains(line, matchEndpoint) {
				matched = line
			}
		}
	}
	return matched, numEndpoints, numComments
}

func TestSyncProxyRulesLargeClusterMode(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.masqueradeAll = true
	fp.syncPeriod = 30 * time.Second

	makeServiceMap(fp,
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p8080",
				Port:     8080,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		makeTestService("ns3", "svc3", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.43"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p8081",
				Port:     8081,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = make([]discovery.Endpoint, largeClusterEndpointsThreshold/2-1)
			for i := range eps.Endpoints {
				eps.Endpoints[i].Addresses = []string{fmt.Sprintf("10.0.%d.%d", i%256, i/256)}
			}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = make([]discovery.Endpoint, largeClusterEndpointsThreshold/2-1)
			for i := range eps.Endpoints {
				eps.Endpoints[i].Addresses = []string{fmt.Sprintf("10.1.%d.%d", i%256, i/256)}
			}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p8080"),
				Port:     pointer.Int32(8080),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	expectedEndpoints := 2 * (largeClusterEndpointsThreshold/2 - 1)

	firstEndpoint, numEndpoints, numComments := countEndpointsAndComments(fp.iptablesData.String(), "10.0.0.0")
	assert.Equal(t, "-A KUBE-SEP-DKGQUZGBKLTPAR56 -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.0.0:80", firstEndpoint)
	if numEndpoints != expectedEndpoints {
		t.Errorf("Found wrong number of endpoints: expected %d, got %d", expectedEndpoints, numEndpoints)
	}
	if numComments != numEndpoints {
		t.Errorf("numComments (%d) != numEndpoints (%d) when numEndpoints < threshold (%d)", numComments, numEndpoints, largeClusterEndpointsThreshold)
	}

	fp.OnEndpointSliceAdd(makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"203.0.113.4"},
		}, {
			Addresses: []string{"203.0.113.8"},
		}, {
			Addresses: []string{"203.0.113.12"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p8081"),
			Port:     pointer.Int32(8081),
			Protocol: &tcpProtocol,
		}}
	}))
	fp.syncProxyRules()

	firstEndpoint, numEndpoints, numComments = countEndpointsAndComments(fp.iptablesData.String(), "203.0.113.4")
	assert.Equal(t, "-A KUBE-SEP-RUVVH7YV3PHQBDOS -m tcp -p tcp -j DNAT --to-destination 203.0.113.4:8081", firstEndpoint)
	// syncProxyRules will only have output the endpoints for svc3, since the others
	// didn't change (and syncProxyRules doesn't automatically do a full resync when you
	// cross the largeClusterEndpointsThreshold).
	if numEndpoints != 3 {
		t.Errorf("Found wrong number of endpoints on partial resync: expected %d, got %d", 3, numEndpoints)
	}
	if numComments != 0 {
		t.Errorf("numComments (%d) != 0 after partial resync when numEndpoints (%d) > threshold (%d)", numComments, expectedEndpoints+3, largeClusterEndpointsThreshold)
	}

	// Now force a full resync and confirm that it rewrites the older services with
	// no comments as well.
	fp.forceSyncProxyRules()
	expectedEndpoints += 3

	firstEndpoint, numEndpoints, numComments = countEndpointsAndComments(fp.iptablesData.String(), "10.0.0.0")
	assert.Equal(t, "-A KUBE-SEP-DKGQUZGBKLTPAR56 -m tcp -p tcp -j DNAT --to-destination 10.0.0.0:80", firstEndpoint)
	if numEndpoints != expectedEndpoints {
		t.Errorf("Found wrong number of endpoints: expected %d, got %d", expectedEndpoints, numEndpoints)
	}
	if numComments != 0 {
		t.Errorf("numComments (%d) != 0 when numEndpoints (%d) > threshold (%d)", numComments, numEndpoints, largeClusterEndpointsThreshold)
	}

	// Now test service deletion; we have to create another service to do this though,
	// because if we deleted any of the existing services, we'd fall back out of large
	// cluster mode.
	svc4 := makeTestService("ns4", "svc4", func(svc *v1.Service) {
		svc.Spec.Type = v1.ServiceTypeClusterIP
		svc.Spec.ClusterIP = "172.30.0.44"
		svc.Spec.Ports = []v1.ServicePort{{
			Name:     "p8082",
			Port:     8082,
			Protocol: v1.ProtocolTCP,
		}}
	})
	fp.OnServiceAdd(svc4)
	fp.OnEndpointSliceAdd(makeTestEndpointSlice("ns4", "svc4", 1, func(eps *discovery.EndpointSlice) {
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{{
			Addresses: []string{"10.4.0.1"},
		}}
		eps.Ports = []discovery.EndpointPort{{
			Name:     pointer.String("p8082"),
			Port:     pointer.Int32(8082),
			Protocol: &tcpProtocol,
		}}
	}))
	fp.syncProxyRules()

	svc4Endpoint, numEndpoints, _ := countEndpointsAndComments(fp.iptablesData.String(), "10.4.0.1")
	assert.Equal(t, "-A KUBE-SEP-SU5STNODRYEWJAUF -m tcp -p tcp -j DNAT --to-destination 10.4.0.1:8082", svc4Endpoint, "svc4 endpoint was not created")
	// should only sync svc4
	if numEndpoints != 1 {
		t.Errorf("Found wrong number of endpoints after svc4 creation: expected %d, got %d", 1, numEndpoints)
	}

	// In large-cluster mode, if we delete a service, it will not re-sync its chains
	// but it will not delete them immediately either.
	fp.lastIPTablesCleanup = time.Now()
	fp.OnServiceDelete(svc4)
	fp.syncProxyRules()

	svc4Endpoint, numEndpoints, _ = countEndpointsAndComments(fp.iptablesData.String(), "10.4.0.1")
	assert.Equal(t, "", svc4Endpoint, "svc4 endpoint was still created!")
	// should only sync svc4, and shouldn't output its endpoints
	if numEndpoints != 0 {
		t.Errorf("Found wrong number of endpoints after service deletion: expected %d, got %d", 0, numEndpoints)
	}
	assert.NotContains(t, fp.iptablesData.String(), "-X ", "iptables data unexpectedly contains chain deletions")

	// But resyncing after a long-enough delay will delete the stale chains
	fp.lastIPTablesCleanup = time.Now().Add(-fp.syncPeriod).Add(-1)
	fp.syncProxyRules()

	svc4Endpoint, numEndpoints, _ = countEndpointsAndComments(fp.iptablesData.String(), "10.4.0.1")
	assert.Equal(t, "", svc4Endpoint, "svc4 endpoint was still created!")
	if numEndpoints != 0 {
		t.Errorf("Found wrong number of endpoints after delayed resync: expected %d, got %d", 0, numEndpoints)
	}
	assert.Contains(t, fp.iptablesData.String(), "-X KUBE-SVC-EBDQOQU5SJFXRIL3", "iptables data does not contain chain deletion")
	assert.Contains(t, fp.iptablesData.String(), "-X KUBE-SEP-SU5STNODRYEWJAUF", "iptables data does not contain endpoint deletions")

	// force a full sync and count
	fp.forceSyncProxyRules()
	_, numEndpoints, _ = countEndpointsAndComments(fp.iptablesData.String(), "10.0.0.0")
	if numEndpoints != expectedEndpoints {
		t.Errorf("Found wrong number of endpoints: expected %d, got %d", expectedEndpoints, numEndpoints)
	}
}

// Test calling syncProxyRules() multiple times with various changes
func TestSyncProxyRulesRepeated(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	metrics.RegisterMetrics()

	// Create initial state
	var svc2 *v1.Service

	makeServiceMap(fp,
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc2 = svc
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p8080",
				Port:     8080,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.1.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.2.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p8080"),
				Port:     pointer.Int32(8080),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SNQ3ZNILQDEJNDQO - [0:0]
		:KUBE-SEP-UHEGFW77JX3KXTOV - [0:0]
		:KUBE-SVC-2VJB64SDSIJUP5T6 - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p8080 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 8080 -j KUBE-SVC-2VJB64SDSIJUP5T6
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SNQ3ZNILQDEJNDQO -m comment --comment ns1/svc1:p80 -s 10.0.1.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SNQ3ZNILQDEJNDQO -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.1.1:80
		-A KUBE-SEP-UHEGFW77JX3KXTOV -m comment --comment ns2/svc2:p8080 -s 10.0.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-UHEGFW77JX3KXTOV -m comment --comment ns2/svc2:p8080 -m tcp -p tcp -j DNAT --to-destination 10.0.2.1:8080
		-A KUBE-SVC-2VJB64SDSIJUP5T6 -m comment --comment "ns2/svc2:p8080 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 8080 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-2VJB64SDSIJUP5T6 -m comment --comment "ns2/svc2:p8080 -> 10.0.2.1:8080" -j KUBE-SEP-UHEGFW77JX3KXTOV
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.0.1.1:80" -j KUBE-SEP-SNQ3ZNILQDEJNDQO
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	// Add a new service and its endpoints. (This will only sync the SVC and SEP rules
	// for the new service, not the existing ones.)
	makeServiceMap(fp,
		makeTestService("ns3", "svc3", func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.43"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)
	var eps3 *discovery.EndpointSlice
	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
			eps3 = eps
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.3.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
	)
	fp.syncProxyRules()

	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-BSWRHOQ77KEXZLNL - [0:0]
		:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p8080 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 8080 -j KUBE-SVC-2VJB64SDSIJUP5T6
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-BSWRHOQ77KEXZLNL -m comment --comment ns3/svc3:p80 -s 10.0.3.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-BSWRHOQ77KEXZLNL -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.3.1:80
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.0.3.1:80" -j KUBE-SEP-BSWRHOQ77KEXZLNL
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	// Delete a service. (Won't update the other services.)
	fp.OnServiceDelete(svc2)
	fp.syncProxyRules()

	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-UHEGFW77JX3KXTOV - [0:0]
		:KUBE-SVC-2VJB64SDSIJUP5T6 - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-X KUBE-SEP-UHEGFW77JX3KXTOV
		-X KUBE-SVC-2VJB64SDSIJUP5T6
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	// Add a service, sync, then add its endpoints. (The first sync will be a no-op other
	// than adding the REJECT rule. The second sync will create the new service.)
	var svc4 *v1.Service
	makeServiceMap(fp,
		makeTestService("ns4", "svc4", func(svc *v1.Service) {
			svc4 = svc
			svc.Spec.Type = v1.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.30.0.44"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
	)
	fp.syncProxyRules()
	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 has no endpoints" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j REJECT
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns4", "svc4", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.0.4.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
	)
	fp.syncProxyRules()
	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-AYCN5HPXMIRJNJXU - [0:0]
		:KUBE-SVC-4SW47YFZTEDKD3PK - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-AYCN5HPXMIRJNJXU -m comment --comment ns4/svc4:p80 -s 10.0.4.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-AYCN5HPXMIRJNJXU -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.4.1:80
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 -> 10.0.4.1:80" -j KUBE-SEP-AYCN5HPXMIRJNJXU
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	// Change an endpoint of an existing service. This will cause its SVC and SEP
	// chains to be rewritten.
	eps3update := eps3.DeepCopy()
	eps3update.Endpoints[0].Addresses[0] = "10.0.3.2"
	fp.OnEndpointSliceUpdate(eps3, eps3update)
	fp.syncProxyRules()

	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-BSWRHOQ77KEXZLNL - [0:0]
		:KUBE-SEP-DKCFIS26GWF2WLWC - [0:0]
		:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-DKCFIS26GWF2WLWC -m comment --comment ns3/svc3:p80 -s 10.0.3.2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-DKCFIS26GWF2WLWC -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.3.2:80
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.0.3.2:80" -j KUBE-SEP-DKCFIS26GWF2WLWC
		-X KUBE-SEP-BSWRHOQ77KEXZLNL
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	// Add an endpoint to a service. This will cause its SVC and SEP chains to be rewritten.
	eps3update2 := eps3update.DeepCopy()
	eps3update2.Endpoints = append(eps3update2.Endpoints, discovery.Endpoint{Addresses: []string{"10.0.3.3"}})
	fp.OnEndpointSliceUpdate(eps3update, eps3update2)
	fp.syncProxyRules()

	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-DKCFIS26GWF2WLWC - [0:0]
		:KUBE-SEP-JVVZVJ7BSEPPRNBS - [0:0]
		:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-DKCFIS26GWF2WLWC -m comment --comment ns3/svc3:p80 -s 10.0.3.2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-DKCFIS26GWF2WLWC -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.3.2:80
		-A KUBE-SEP-JVVZVJ7BSEPPRNBS -m comment --comment ns3/svc3:p80 -s 10.0.3.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-JVVZVJ7BSEPPRNBS -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.3.3:80
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.0.3.2:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-DKCFIS26GWF2WLWC
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.0.3.3:80" -j KUBE-SEP-JVVZVJ7BSEPPRNBS
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	// Sync with no new changes... This will not rewrite any SVC or SEP chains
	fp.syncProxyRules()

	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())

	// Now force a partial resync error and ensure that it recovers correctly
	if fp.needFullSync {
		t.Fatalf("Proxier unexpectedly already needs a full sync?")
	}
	prFailures, err := testutil.GetCounterMetricValue(metrics.IptablesPartialRestoreFailuresTotal)
	if err != nil {
		t.Fatalf("Could not get partial restore failures metric: %v", err)
	}
	if prFailures != 0.0 {
		t.Errorf("Already did a partial resync? Something failed earlier!")
	}

	// Add a rule jumping from svc3's service chain to svc4's endpoint, then try to
	// delete svc4. This will fail because the partial resync won't rewrite svc3's
	// rules and so the partial restore would leave a dangling jump from there to
	// svc4's endpoint. The proxier will then queue a full resync in response to the
	// partial resync failure, and the full resync will succeed (since it will rewrite
	// svc3's rules as well).
	//
	// This is an absurd scenario, but it has to be; partial resync failures are
	// supposed to be impossible; if we knew of any non-absurd scenario that would
	// cause such a failure, then that would be a bug and we would fix it.
	if _, err := fp.iptables.ChainExists(utiliptables.TableNAT, utiliptables.Chain("KUBE-SEP-AYCN5HPXMIRJNJXU")); err != nil {
		t.Fatalf("svc4's endpoint chain unexpected already does not exist!")
	}
	if _, err := fp.iptables.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.Chain("KUBE-SVC-X27LE4BHSL4DOUIK"), "-j", "KUBE-SEP-AYCN5HPXMIRJNJXU"); err != nil {
		t.Fatalf("Could not add bad iptables rule: %v", err)
	}

	fp.OnServiceDelete(svc4)
	fp.syncProxyRules()

	if _, err := fp.iptables.ChainExists(utiliptables.TableNAT, utiliptables.Chain("KUBE-SEP-AYCN5HPXMIRJNJXU")); err != nil {
		t.Errorf("svc4's endpoint chain was successfully deleted despite dangling references!")
	}
	if !fp.needFullSync {
		t.Errorf("Proxier did not fail on previous partial resync?")
	}
	updatedPRFailures, err := testutil.GetCounterMetricValue(metrics.IptablesPartialRestoreFailuresTotal)
	if err != nil {
		t.Errorf("Could not get partial restore failures metric: %v", err)
	}
	if updatedPRFailures != prFailures+1.0 {
		t.Errorf("Partial restore failures metric was not incremented after failed partial resync (expected %.02f, got %.02f)", prFailures+1.0, updatedPRFailures)
	}

	// On retry we should do a full resync, which should succeed (and delete svc4)
	fp.syncProxyRules()

	expected = dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-AYCN5HPXMIRJNJXU - [0:0]
		:KUBE-SEP-DKCFIS26GWF2WLWC - [0:0]
		:KUBE-SEP-JVVZVJ7BSEPPRNBS - [0:0]
		:KUBE-SEP-SNQ3ZNILQDEJNDQO - [0:0]
		:KUBE-SVC-4SW47YFZTEDKD3PK - [0:0]
		:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-DKCFIS26GWF2WLWC -m comment --comment ns3/svc3:p80 -s 10.0.3.2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-DKCFIS26GWF2WLWC -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.3.2:80
		-A KUBE-SEP-JVVZVJ7BSEPPRNBS -m comment --comment ns3/svc3:p80 -s 10.0.3.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-JVVZVJ7BSEPPRNBS -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.3.3:80
		-A KUBE-SEP-SNQ3ZNILQDEJNDQO -m comment --comment ns1/svc1:p80 -s 10.0.1.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SNQ3ZNILQDEJNDQO -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.0.1.1:80
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.0.3.2:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-DKCFIS26GWF2WLWC
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.0.3.3:80" -j KUBE-SEP-JVVZVJ7BSEPPRNBS
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.0.1.1:80" -j KUBE-SEP-SNQ3ZNILQDEJNDQO
		-X KUBE-SEP-AYCN5HPXMIRJNJXU
		-X KUBE-SVC-4SW47YFZTEDKD3PK
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), false, expected, fp.iptablesData.String())
}

func TestNoEndpointsMetric(t *testing.T) {
	type endpoint struct {
		ip       string
		hostname string
	}

	internalTrafficPolicyLocal := v1.ServiceInternalTrafficPolicyLocal
	externalTrafficPolicyLocal := v1.ServiceExternalTrafficPolicyLocal

	metrics.RegisterMetrics()
	testCases := []struct {
		name                                                string
		internalTrafficPolicy                               *v1.ServiceInternalTrafficPolicy
		externalTrafficPolicy                               v1.ServiceExternalTrafficPolicy
		endpoints                                           []endpoint
		expectedSyncProxyRulesNoLocalEndpointsTotalInternal int
		expectedSyncProxyRulesNoLocalEndpointsTotalExternal int
	}{
		{
			name:                  "internalTrafficPolicy is set and there are local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
		},
		{
			name:                  "externalTrafficPolicy is set and there are local endpoints",
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
		},
		{
			name:                  "both policies are set and there are local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
		},
		{
			name:                  "internalTrafficPolicy is set and there are no local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectedSyncProxyRulesNoLocalEndpointsTotalInternal: 1,
		},
		{
			name:                  "externalTrafficPolicy is set and there are no local endpoints",
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectedSyncProxyRulesNoLocalEndpointsTotalExternal: 1,
		},
		{
			name:                  "both policies are set and there are no local endpoints",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectedSyncProxyRulesNoLocalEndpointsTotalInternal: 1,
			expectedSyncProxyRulesNoLocalEndpointsTotalExternal: 1,
		},
		{
			name:                  "both policies are set and there are no endpoints at all",
			internalTrafficPolicy: &internalTrafficPolicyLocal,
			externalTrafficPolicy: externalTrafficPolicyLocal,
			endpoints:             []endpoint{},
			expectedSyncProxyRulesNoLocalEndpointsTotalInternal: 0,
			expectedSyncProxyRulesNoLocalEndpointsTotalExternal: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ipt := iptablestest.NewFake()
			fp := NewFakeProxier(ipt)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			serviceName := "svc1"
			namespaceName := "ns1"

			svc := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespaceName},
				Spec: v1.ServiceSpec{
					ClusterIP: "172.30.1.1",
					Selector:  map[string]string{"foo": "bar"},
					Ports:     []v1.ServicePort{{Name: "", Port: 80, Protocol: v1.ProtocolTCP, NodePort: 123}},
				},
			}
			if tc.internalTrafficPolicy != nil {
				svc.Spec.InternalTrafficPolicy = tc.internalTrafficPolicy
			}
			if tc.externalTrafficPolicy != "" {
				svc.Spec.Type = v1.ServiceTypeNodePort
				svc.Spec.ExternalTrafficPolicy = tc.externalTrafficPolicy
			}

			fp.OnServiceAdd(svc)

			endpointSlice := &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", serviceName),
					Namespace: namespaceName,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
			}
			for _, ep := range tc.endpoints {
				endpointSlice.Endpoints = append(endpointSlice.Endpoints, discovery.Endpoint{
					Addresses:  []string{ep.ip},
					Conditions: discovery.EndpointConditions{Ready: pointer.Bool(true)},
					NodeName:   pointer.String(ep.hostname),
				})
			}

			fp.OnEndpointSliceAdd(endpointSlice)
			fp.syncProxyRules()
			syncProxyRulesNoLocalEndpointsTotalInternal, err := testutil.GetGaugeMetricValue(metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("internal"))
			if err != nil {
				t.Errorf("failed to get %s value, err: %v", metrics.SyncProxyRulesNoLocalEndpointsTotal.Name, err)
			}

			if tc.expectedSyncProxyRulesNoLocalEndpointsTotalInternal != int(syncProxyRulesNoLocalEndpointsTotalInternal) {
				t.Errorf("sync_proxy_rules_no_endpoints_total metric mismatch(internal): got=%d, expected %d", int(syncProxyRulesNoLocalEndpointsTotalInternal), tc.expectedSyncProxyRulesNoLocalEndpointsTotalInternal)
			}

			syncProxyRulesNoLocalEndpointsTotalExternal, err := testutil.GetGaugeMetricValue(metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("external"))
			if err != nil {
				t.Errorf("failed to get %s value(external), err: %v", metrics.SyncProxyRulesNoLocalEndpointsTotal.Name, err)
			}

			if tc.expectedSyncProxyRulesNoLocalEndpointsTotalExternal != int(syncProxyRulesNoLocalEndpointsTotalExternal) {
				t.Errorf("sync_proxy_rules_no_endpoints_total metric mismatch(internal): got=%d, expected %d", int(syncProxyRulesNoLocalEndpointsTotalExternal), tc.expectedSyncProxyRulesNoLocalEndpointsTotalExternal)
			}
		})
	}
}
