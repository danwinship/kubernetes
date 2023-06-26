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
	"testing"

	"github.com/lithammer/dedent"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/component-base/metrics/testutil"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	proxyutiliptables "k8s.io/kubernetes/pkg/proxy/util/iptables"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptablestest "k8s.io/kubernetes/pkg/util/iptables/testing"
	"k8s.io/utils/pointer"
)

// TODO(thockin): add *more* tests for syncProxyRules() or break it down further and test the pieces.

// (Note that we don't use UDP ports in any of the tests here, because if you create UDP
// services you have to deal with setting up the FakeExec correctly for the conntrack
// cleanup calls.)
var tcpProtocol = v1.ProtocolTCP
var sctpProtocol = v1.ProtocolSCTP

// TestOverallIPTablesRulesWithMultipleServices creates 4 types of services: ClusterIP,
// LoadBalancer, ExternalIP and NodePort and verifies if the NAT table rules created
// are exactly the same as what is expected. This test provides an overall view of how
// the NAT table rules look like with the different jumps.
func TestOverallIPTablesRulesWithMultipleServices(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	metrics.RegisterMetrics()

	makeServiceMap(fp,
		// create ClusterIP service
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		// create LoadBalancer service with Local traffic policy
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
				NodePort: 3001,
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: "1.2.3.4",
			}}
			svc.Spec.ExternalIPs = []string{"192.168.99.22"}
			svc.Spec.HealthCheckNodePort = 30000
		}),
		// create NodePort service
		makeTestService("ns3", "svc3", func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = "172.30.0.43"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
				NodePort: 3003,
			}}
		}),
		// create ExternalIP service
		makeTestService("ns4", "svc4", func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = "172.30.0.44"
			svc.Spec.ExternalIPs = []string{"192.168.99.33"}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       "p80",
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt32(80),
			}}
		}),
		// create LoadBalancer service with Cluster traffic policy and source ranges
		makeTestService("ns5", "svc5", func(svc *v1.Service) {
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyCluster
			svc.Spec.ClusterIP = "172.30.0.45"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: v1.ProtocolTCP,
				NodePort: 3002,
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: "5.6.7.8",
			}}
			svc.Spec.HealthCheckNodePort = 30000
			// Extra whitespace to ensure that invalid value will not result
			// in a crash, for backward compatibility.
			svc.Spec.LoadBalancerSourceRanges = []string{" 203.0.113.0/25"}
		}),
		// create ClusterIP service with no endpoints
		makeTestService("ns6", "svc6", func(svc *v1.Service) {
			svc.Spec.Type = "ClusterIP"
			svc.Spec.ClusterIP = "172.30.0.46"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       "p80",
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt32(80),
			}}
		}),
	)
	populateEndpointSlices(fp,
		// create ClusterIP service endpoints
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.1"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create Local LoadBalancer endpoints. Note that since we aren't setting
		// its NodeName, this endpoint will be considered non-local and ignored.
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.2"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create NodePort service endpoints
		makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.3"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create ExternalIP service endpoints
		makeTestEndpointSlice("ns4", "svc4", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.4"},
			}, {
				Addresses: []string{"10.180.0.5"},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		// create Cluster LoadBalancer endpoints
		makeTestEndpointSlice("ns5", "svc5", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.3"},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("p80"),
				Port:     pointer.Int32(80),
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
		-A KUBE-NODEPORTS -m comment --comment "ns2/svc2:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
		-A KUBE-SERVICES -m comment --comment "ns6/svc6:p80 has no endpoints" -m tcp -p tcp -d 172.30.0.46 --dport 80 -j REJECT
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j DROP
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j DROP
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns2/svc2:p80 has no local endpoints" -m addrtype --dst-type LOCAL -m tcp -p tcp --dport 3001 -j DROP
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		-A KUBE-PROXY-FIREWALL -m comment --comment "ns5/svc5:p80 traffic not accepted by KUBE-FW-NUKIZ6OKUXPJNT4C" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j DROP
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-4SW47YFZTEDKD3PK - [0:0]
		:KUBE-EXT-GNZBNJ2PO5MGZ6GT - [0:0]
		:KUBE-EXT-NUKIZ6OKUXPJNT4C - [0:0]
		:KUBE-EXT-X27LE4BHSL4DOUIK - [0:0]
		:KUBE-FW-NUKIZ6OKUXPJNT4C - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-C6EBXVWJJZMIWKLZ - [0:0]
		:KUBE-SEP-I77PXRDZVX7PMWMN - [0:0]
		:KUBE-SEP-OYPFS5VJICHGATKP - [0:0]
		:KUBE-SEP-RS4RBKLTHTF2IUXJ - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SEP-UKSFD7AGPMPPLUHC - [0:0]
		:KUBE-SVC-4SW47YFZTEDKD3PK - [0:0]
		:KUBE-SVC-GNZBNJ2PO5MGZ6GT - [0:0]
		:KUBE-SVC-NUKIZ6OKUXPJNT4C - [0:0]
		:KUBE-SVC-X27LE4BHSL4DOUIK - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns2/svc2:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
		-A KUBE-NODEPORTS -m comment --comment ns3/svc3:p80 -m tcp -p tcp --dport 3003 -j KUBE-EXT-X27LE4BHSL4DOUIK
		-A KUBE-NODEPORTS -m comment --comment ns5/svc5:p80 -m tcp -p tcp --dport 3002 -j KUBE-EXT-NUKIZ6OKUXPJNT4C
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
		-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
		-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.33 --dport 80 -j KUBE-EXT-4SW47YFZTEDKD3PK
		-A KUBE-SERVICES -m comment --comment "ns5/svc5:p80 cluster IP" -m tcp -p tcp -d 172.30.0.45 --dport 80 -j KUBE-SVC-NUKIZ6OKUXPJNT4C
		-A KUBE-SERVICES -m comment --comment "ns5/svc5:p80 loadbalancer IP" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j KUBE-FW-NUKIZ6OKUXPJNT4C
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-4SW47YFZTEDKD3PK -m comment --comment "masquerade traffic for ns4/svc4:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-4SW47YFZTEDKD3PK -j KUBE-SVC-4SW47YFZTEDKD3PK
		-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "pod traffic for ns2/svc2:p80 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
		-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "masquerade LOCAL traffic for ns2/svc2:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-GNZBNJ2PO5MGZ6GT -m comment --comment "route LOCAL traffic for ns2/svc2:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
		-A KUBE-EXT-NUKIZ6OKUXPJNT4C -m comment --comment "masquerade traffic for ns5/svc5:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-NUKIZ6OKUXPJNT4C -j KUBE-SVC-NUKIZ6OKUXPJNT4C
		-A KUBE-EXT-X27LE4BHSL4DOUIK -m comment --comment "masquerade traffic for ns3/svc3:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-X27LE4BHSL4DOUIK -j KUBE-SVC-X27LE4BHSL4DOUIK
		-A KUBE-FW-NUKIZ6OKUXPJNT4C -m comment --comment "ns5/svc5:p80 loadbalancer IP" -s 203.0.113.0/25 -j KUBE-EXT-NUKIZ6OKUXPJNT4C
		-A KUBE-FW-NUKIZ6OKUXPJNT4C -m comment --comment "other traffic to ns5/svc5:p80 will be dropped by KUBE-PROXY-FIREWALL"
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -s 10.180.0.5 -j KUBE-MARK-MASQ
		-A KUBE-SEP-C6EBXVWJJZMIWKLZ -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.5:80
		-A KUBE-SEP-I77PXRDZVX7PMWMN -m comment --comment ns5/svc5:p80 -s 10.180.0.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-I77PXRDZVX7PMWMN -m comment --comment ns5/svc5:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.3:80
		-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -s 10.180.0.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-OYPFS5VJICHGATKP -m comment --comment ns3/svc3:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.3:80
		-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -s 10.180.0.2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-RS4RBKLTHTF2IUXJ -m comment --comment ns2/svc2:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.2:80
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -s 10.180.0.4 -j KUBE-MARK-MASQ
		-A KUBE-SEP-UKSFD7AGPMPPLUHC -m comment --comment ns4/svc4:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.4:80
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 -> 10.180.0.4:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-UKSFD7AGPMPPLUHC
		-A KUBE-SVC-4SW47YFZTEDKD3PK -m comment --comment "ns4/svc4:p80 -> 10.180.0.5:80" -j KUBE-SEP-C6EBXVWJJZMIWKLZ
		-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-GNZBNJ2PO5MGZ6GT -m comment --comment "ns2/svc2:p80 -> 10.180.0.2:80" -j KUBE-SEP-RS4RBKLTHTF2IUXJ
		-A KUBE-SVC-NUKIZ6OKUXPJNT4C -m comment --comment "ns5/svc5:p80 cluster IP" -m tcp -p tcp -d 172.30.0.45 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-NUKIZ6OKUXPJNT4C -m comment --comment "ns5/svc5:p80 -> 10.180.0.3:80" -j KUBE-SEP-I77PXRDZVX7PMWMN
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-X27LE4BHSL4DOUIK -m comment --comment "ns3/svc3:p80 -> 10.180.0.3:80" -j KUBE-SEP-OYPFS5VJICHGATKP
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -j KUBE-SEP-SXIVWICOYRO3J4NJ
		COMMIT
		`)

	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	natRulesMetric, err := testutil.GetGaugeMetricValue(metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableNAT)))
	if err != nil {
		t.Errorf("failed to get %s value, err: %v", metrics.IptablesRulesTotal.Name, err)
	}
	nNatRules := int(natRulesMetric)

	expectedNatRules := countRules(utiliptables.TableNAT, fp.iptablesData.String())

	if nNatRules != expectedNatRules {
		t.Fatalf("Wrong number of nat rules: expected %d received %d", expectedNatRules, nNatRules)
	}
}

// TestNoEndpointsReject tests that a service with no endpoints rejects connections to
// its ClusterIP, ExternalIPs, NodePort, and LoadBalancer IP.
func TestNoEndpointsReject(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcExternalIPs := "192.168.99.11"
	svcLBIP := "1.2.3.4"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Protocol: v1.ProtocolTCP,
				Port:     int32(svcPort),
				NodePort: int32(svcNodePort),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: svcLBIP,
			}}
		}),
	)
	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "pod to cluster IP with no endpoints",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   "REJECT",
		},
		{
			name:     "external to external IP with no endpoints",
			sourceIP: testExternalClient,
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   "REJECT",
		},
		{
			name:     "pod to NodePort with no endpoints",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   "REJECT",
		},
		{
			name:     "external to NodePort with no endpoints",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   "REJECT",
		},
		{
			name:     "pod to LoadBalancer IP with no endpoints",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   "REJECT",
		},
		{
			name:     "external to LoadBalancer IP with no endpoints",
			sourceIP: testExternalClient,
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   "REJECT",
		},
	})
}

// TestClusterIPGeneral tests various basic features of a ClusterIP service
func TestClusterIPGeneral(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	makeServiceMap(fp,
		makeTestService("ns1", "svc1", func(svc *v1.Service) {
			svc.Spec.ClusterIP = "172.30.0.41"
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     "http",
				Port:     80,
				Protocol: v1.ProtocolTCP,
			}}
		}),
		makeTestService("ns2", "svc2", func(svc *v1.Service) {
			svc.Spec.ClusterIP = "172.30.0.42"
			svc.Spec.Ports = []v1.ServicePort{
				{
					Name:     "http",
					Port:     80,
					Protocol: v1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       443,
					Protocol:   v1.ProtocolTCP,
					TargetPort: intstr.FromInt32(8443),
				},
				{
					// Of course this should really be UDP, but if we
					// create a service with UDP ports, the Proxier will
					// try to do conntrack cleanup and we'd have to set
					// the FakeExec up to be able to deal with that...
					Name:     "dns-sctp",
					Port:     53,
					Protocol: v1.ProtocolSCTP,
				},
				{
					Name:     "dns-tcp",
					Port:     53,
					Protocol: v1.ProtocolTCP,
					// We use TargetPort on TCP but not SCTP to help
					// disambiguate the output.
					TargetPort: intstr.FromInt32(5353),
				},
			}
		}),
	)

	populateEndpointSlices(fp,
		makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{"10.180.0.1"},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String("http"),
				Port:     pointer.Int32(80),
				Protocol: &tcpProtocol,
			}}
		}),
		makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{
				{
					Addresses: []string{"10.180.0.1"},
					NodeName:  pointer.String(testHostname),
				},
				{
					Addresses: []string{"10.180.2.1"},
					NodeName:  pointer.String("host2"),
				},
			}
			eps.Ports = []discovery.EndpointPort{
				{
					Name:     pointer.String("http"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				},
				{
					Name:     pointer.String("https"),
					Port:     pointer.Int32(8443),
					Protocol: &tcpProtocol,
				},
				{
					Name:     pointer.String("dns-sctp"),
					Port:     pointer.Int32(53),
					Protocol: &sctpProtocol,
				},
				{
					Name:     pointer.String("dns-tcp"),
					Port:     pointer.Int32(5353),
					Protocol: &tcpProtocol,
				},
			}
		}),
	)

	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "simple clusterIP",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80",
			masq:     false,
		},
		{
			name:     "hairpin to cluster IP",
			sourceIP: "10.180.0.1",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80",
			masq:     true,
		},
		{
			name:     "clusterIP with multiple endpoints",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.42",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.2.1:80",
			masq:     false,
		},
		{
			name:     "clusterIP with TargetPort",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.42",
			destPort: 443,
			output:   "10.180.0.1:8443, 10.180.2.1:8443",
			masq:     false,
		},
		{
			name:     "clusterIP with TCP and SCTP on same port (TCP)",
			sourceIP: "10.180.0.2",
			protocol: v1.ProtocolTCP,
			destIP:   "172.30.0.42",
			destPort: 53,
			output:   "10.180.0.1:5353, 10.180.2.1:5353",
			masq:     false,
		},
		{
			name:     "clusterIP with TCP and SCTP on same port (SCTP)",
			sourceIP: "10.180.0.2",
			protocol: v1.ProtocolSCTP,
			destIP:   "172.30.0.42",
			destPort: 53,
			output:   "10.180.0.1:53, 10.180.2.1:53",
			masq:     false,
		},
		{
			name:     "TCP-only port does not match UDP traffic",
			sourceIP: "10.180.0.2",
			protocol: v1.ProtocolUDP,
			destIP:   "172.30.0.42",
			destPort: 80,
			output:   "",
		},
		{
			name:     "svc1 does not accept svc2's ports",
			sourceIP: "10.180.0.2",
			destIP:   "172.30.0.41",
			destPort: 443,
			output:   "",
		},
	})
}

func TestLoadBalancer(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcLBIP1 := "1.2.3.4"
	svcLBIP2 := "5.6.7.8"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "LoadBalancer"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
				{IP: svcLBIP1},
				{IP: svcLBIP2},
			}
			svc.Spec.LoadBalancerSourceRanges = []string{
				"192.168.0.0/24",

				// Regression test that excess whitespace gets ignored
				" 203.0.113.0/25",
			}
		}),
	)

	epIP := "10.180.0.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
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
		-A KUBE-PROXY-FIREWALL -m comment --comment "ns1/svc1:p80 traffic not accepted by KUBE-FW-XPGD46QRK7WJZT7O" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j DROP
		-A KUBE-PROXY-FIREWALL -m comment --comment "ns1/svc1:p80 traffic not accepted by KUBE-FW-XPGD46QRK7WJZT7O" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j DROP
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-FW-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-FW-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 loadbalancer IP" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j KUBE-FW-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade traffic for ns1/svc1:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-FW-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 loadbalancer IP" -s 192.168.0.0/24 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-FW-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 loadbalancer IP" -s 203.0.113.0/25 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-FW-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 loadbalancer IP" -s 1.2.3.4 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-FW-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 loadbalancer IP" -s 5.6.7.8 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-FW-XPGD46QRK7WJZT7O -m comment --comment "other traffic to ns1/svc1:p80 will be dropped by KUBE-PROXY-FIREWALL"
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -j KUBE-SEP-SXIVWICOYRO3J4NJ
		COMMIT
		`)

	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "pod to cluster IP",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     false,
		},
		{
			name:     "external to nodePort",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "nodePort bypasses LoadBalancerSourceRanges",
			sourceIP: testExternalClientBlocked,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "accepted external to LB1",
			sourceIP: testExternalClient,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "accepted external to LB2",
			sourceIP: testExternalClient,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "blocked external to LB1",
			sourceIP: testExternalClientBlocked,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "blocked external to LB2",
			sourceIP: testExternalClientBlocked,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "pod to LB1 (blocked by LoadBalancerSourceRanges)",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "pod to LB2 (blocked by LoadBalancerSourceRanges)",
			sourceIP: "10.0.0.2",
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   "DROP",
		},
		{
			name:     "node to LB1 (allowed by LoadBalancerSourceRanges)",
			sourceIP: testNodeIP,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "node to LB2 (allowed by LoadBalancerSourceRanges)",
			sourceIP: testNodeIP,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},

		// The LB rules assume that when you connect from a node to a LB IP, that
		// something external to kube-proxy will cause the connection to be
		// SNATted to the LB IP, so if the LoadBalancerSourceRanges include the
		// node IP, then we add a rule allowing traffic from the LB IP as well...
		{
			name:     "same node to LB1, SNATted to LB1 (implicitly allowed)",
			sourceIP: svcLBIP1,
			destIP:   svcLBIP1,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "same node to LB2, SNATted to LB2 (implicitly allowed)",
			sourceIP: svcLBIP2,
			destIP:   svcLBIP2,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
	})
}

func TestNodePort(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
		}),
	)

	epIP := "10.180.0.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP},
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
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
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade traffic for ns1/svc1:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -j KUBE-SEP-SXIVWICOYRO3J4NJ
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "pod to cluster IP",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     false,
		},
		{
			name:     "external to nodePort",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "node to nodePort",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
		{
			name:     "localhost to nodePort gets masqueraded",
			sourceIP: "127.0.0.1",
			destIP:   "127.0.0.1",
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP, svcPort),
			masq:     true,
		},
	})
}

func TestHealthCheckNodePort(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.nodePortAddresses = proxyutil.NewNodePortAddresses(v1.IPv4Protocol, []string{"127.0.0.0/8"})

	svcIP := "172.30.0.42"
	svcPort := 80
	svcNodePort := 3001
	svcHealthCheckNodePort := 30000
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	svc := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
		svc.Spec.Type = "LoadBalancer"
		svc.Spec.ClusterIP = svcIP
		svc.Spec.Ports = []v1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: v1.ProtocolTCP,
			NodePort: int32(svcNodePort),
		}}
		svc.Spec.HealthCheckNodePort = int32(svcHealthCheckNodePort)
		svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
	})
	makeServiceMap(fp, svc)
	fp.syncProxyRules()

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FIREWALL - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-NODEPORTS -m comment --comment "ns1/svc1:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 has no endpoints" -m tcp -p tcp -d 172.30.0.42 --dport 80 -j REJECT
		-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns1/svc1:p80 has no endpoints" -m addrtype --dst-type LOCAL -m tcp -p tcp --dport 3001 -j REJECT
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
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -d 127.0.0.1 -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		COMMIT
		`)

	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "firewall accepts HealthCheckNodePort",
			sourceIP: "1.2.3.4",
			destIP:   testNodeIP,
			destPort: svcHealthCheckNodePort,
			output:   "ACCEPT",
			masq:     false,
		},
	})

	fp.OnServiceDelete(svc)
	fp.syncProxyRules()

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "HealthCheckNodePort no longer has any rule",
			sourceIP: "1.2.3.4",
			destIP:   testNodeIP,
			destPort: svcHealthCheckNodePort,
			output:   "",
		},
	})
}

func TestMasqueradeRule(t *testing.T) {
	for _, testcase := range []bool{false, true} {
		ipt := iptablestest.NewFake().SetHasRandomFully(testcase)
		fp := NewFakeProxier(ipt)
		fp.syncProxyRules()

		expectedFmt := dedent.Dedent(`
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
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE%s
		COMMIT
		`)
		var expected string
		if testcase {
			expected = fmt.Sprintf(expectedFmt, " --random-fully")
		} else {
			expected = fmt.Sprintf(expectedFmt, "")
		}
		assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())
	}
}

// TestExternalTrafficPolicyLocal tests that non-local traffic to an externally-facing IP
// does not get masqueraded, and only gets delivered to the local endpoint, when using
// Local traffic policy.
func TestExternalTrafficPolicyLocal(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)

	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcHealthCheckNodePort := 30000
	svcExternalIPs := "192.168.99.11"
	svcLBIP := "1.2.3.4"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.HealthCheckNodePort = int32(svcHealthCheckNodePort)
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
				IP: svcLBIP,
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "10.180.0.1"
	epIP2 := "10.180.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
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
		-A KUBE-NODEPORTS -m comment --comment "ns1/svc1:p80 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
		-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SEP-ZX7GRIZKSNUQ3LAJ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 external IP" -m tcp -p tcp -d 192.168.99.11 --dport 80 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "pod traffic for ns1/svc1:p80 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -s 10.180.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-SXIVWICOYRO3J4NJ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "pod to cluster IP hits both endpoints",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to external IP hits only local endpoint, unmasqueraded",
			sourceIP: testExternalClient,
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to LB IP hits only local endpoint, unmasqueraded",
			sourceIP: testExternalClient,
			destIP:   svcLBIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to NodePort hits only local endpoint, unmasqueraded",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
	})
}

// TestNonLocalExternalIPs tests if we add the masquerade rule into svcChain in order to
// SNAT packets to external IPs if externalTrafficPolicy is cluster and the traffic is NOT Local.
func TestNonLocalExternalIPs(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcIP := "172.30.0.41"
	svcPort := 80
	svcExternalIPs := "192.168.99.11"
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.ClusterIP = svcIP
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
			svc.Spec.Ports = []v1.ServicePort{{
				Name:       svcPortName.Port,
				Port:       int32(svcPort),
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(svcPort),
			}}
		}),
	)
	epIP1 := "10.180.0.1"
	epIP2 := "10.180.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
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
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SEP-ZX7GRIZKSNUQ3LAJ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 external IP" -m tcp -p tcp -d 192.168.99.11 --dport 80 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade traffic for ns1/svc1:p80 external destinations" -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -s 10.180.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-SXIVWICOYRO3J4NJ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		COMMIT
		`)
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())

	runPacketFlowTests(t, getLine(), ipt, testNodeIP, []packetFlowTest{
		{
			name:     "pod to cluster IP",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to external IP",
			sourceIP: testExternalClient,
			destIP:   svcExternalIPs,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     true,
		},
	})
}

func TestEnableLocalhostNodePortsIPv4(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
	fp.localhostNodePorts = true

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
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-6KG6DFHVBKBK53RU - [0:0]
		:KUBE-SEP-KDGX2M2ONE25PSWH - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 30001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.69.0.10 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-6KG6DFHVBKBK53RU -m comment --comment ns1/svc1:p80 -s 10.244.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-6KG6DFHVBKBK53RU -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.244.0.1:80
		-A KUBE-SEP-KDGX2M2ONE25PSWH -m comment --comment ns1/svc1:p80 -s 10.244.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-KDGX2M2ONE25PSWH -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.244.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-6KG6DFHVBKBK53RU
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.2.1:80" -j KUBE-SEP-KDGX2M2ONE25PSWH
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.2.1:80" -j KUBE-SEP-KDGX2M2ONE25PSWH
		COMMIT
		`)
	svcIP := "10.69.0.10"
	svcPort := 80
	svcNodePort := 30001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "10.244.0.1"
	epIP2 := "10.244.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())
}

func TestDisableLocalhostNodePortsIPv4(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
	fp.localhostNodePorts = false

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-6KG6DFHVBKBK53RU - [0:0]
		:KUBE-SEP-KDGX2M2ONE25PSWH - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 30001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.69.0.10 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL ! -d 127.0.0.0/8 -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-6KG6DFHVBKBK53RU -m comment --comment ns1/svc1:p80 -s 10.244.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-6KG6DFHVBKBK53RU -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.244.0.1:80
		-A KUBE-SEP-KDGX2M2ONE25PSWH -m comment --comment ns1/svc1:p80 -s 10.244.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-KDGX2M2ONE25PSWH -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.244.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-6KG6DFHVBKBK53RU
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.2.1:80" -j KUBE-SEP-KDGX2M2ONE25PSWH
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.2.1:80" -j KUBE-SEP-KDGX2M2ONE25PSWH
		COMMIT
		`)
	svcIP := "10.69.0.10"
	svcPort := 80
	svcNodePort := 30001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "10.244.0.1"
	epIP2 := "10.244.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())
}

func TestDisableLocalhostNodePortsIPv4WithNodeAddress(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
	fp.localhostNodePorts = false
	fp.networkInterfacer.InterfaceAddrs()
	fp.nodePortAddresses = proxyutil.NewNodePortAddresses(v1.IPv4Protocol, []string{"127.0.0.0/8"})

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-6KG6DFHVBKBK53RU - [0:0]
		:KUBE-SEP-KDGX2M2ONE25PSWH - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 30001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 10.69.0.10 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-6KG6DFHVBKBK53RU -m comment --comment ns1/svc1:p80 -s 10.244.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-6KG6DFHVBKBK53RU -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.244.0.1:80
		-A KUBE-SEP-KDGX2M2ONE25PSWH -m comment --comment ns1/svc1:p80 -s 10.244.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-KDGX2M2ONE25PSWH -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.244.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-6KG6DFHVBKBK53RU
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.2.1:80" -j KUBE-SEP-KDGX2M2ONE25PSWH
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.244.2.1:80" -j KUBE-SEP-KDGX2M2ONE25PSWH
		COMMIT
	`)
	svcIP := "10.69.0.10"
	svcPort := 80
	svcNodePort := 30001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "10.244.0.1"
	epIP2 := "10.244.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())
}

func TestEnableLocalhostNodePortsIPv6(t *testing.T) {
	ipt := iptablestest.NewIPv6Fake()
	fp := NewFakeProxier(ipt)
	fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
	fp.localhostNodePorts = true

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-LIGRYQQLSZN4UWQ5 - [0:0]
		:KUBE-SEP-XJJ5QXWGJG344QDZ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 30001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d fd00:ab34::20 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL ! -d ::1/128 -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-LIGRYQQLSZN4UWQ5 -m comment --comment ns1/svc1:p80 -s ff06::c1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-LIGRYQQLSZN4UWQ5 -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination [ff06::c1]:80
		-A KUBE-SEP-XJJ5QXWGJG344QDZ -m comment --comment ns1/svc1:p80 -s ff06::c2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-XJJ5QXWGJG344QDZ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination [ff06::c2]:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> [ff06::c1]:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-LIGRYQQLSZN4UWQ5
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> [ff06::c2]:80" -j KUBE-SEP-XJJ5QXWGJG344QDZ
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> [ff06::c2]:80" -j KUBE-SEP-XJJ5QXWGJG344QDZ
		COMMIT
	`)
	svcIP := "fd00:ab34::20"
	svcPort := 80
	svcNodePort := 30001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "ff06::c1"
	epIP2 := "ff06::c2"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv6
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())
}

func TestDisableLocalhostNodePortsIPv6(t *testing.T) {
	ipt := iptablestest.NewIPv6Fake()
	fp := NewFakeProxier(ipt)
	fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
	fp.localhostNodePorts = false

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-LIGRYQQLSZN4UWQ5 - [0:0]
		:KUBE-SEP-XJJ5QXWGJG344QDZ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 30001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d fd00:ab34::20 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL ! -d ::1/128 -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-LIGRYQQLSZN4UWQ5 -m comment --comment ns1/svc1:p80 -s ff06::c1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-LIGRYQQLSZN4UWQ5 -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination [ff06::c1]:80
		-A KUBE-SEP-XJJ5QXWGJG344QDZ -m comment --comment ns1/svc1:p80 -s ff06::c2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-XJJ5QXWGJG344QDZ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination [ff06::c2]:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> [ff06::c1]:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-LIGRYQQLSZN4UWQ5
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> [ff06::c2]:80" -j KUBE-SEP-XJJ5QXWGJG344QDZ
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> [ff06::c2]:80" -j KUBE-SEP-XJJ5QXWGJG344QDZ
		COMMIT
	`)
	svcIP := "fd00:ab34::20"
	svcPort := 80
	svcNodePort := 30001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "ff06::c1"
	epIP2 := "ff06::c2"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv6
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()
	assertIPTablesRulesEqual(t, getLine(), true, expected, fp.iptablesData.String())
}

func TestOnlyLocalNodePortsNoClusterCIDR(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
	fp.nodePortAddresses = proxyutil.NewNodePortAddresses(v1.IPv4Protocol, []string{"192.168.0.0/24", "2001:db8::/64"})
	fp.localhostNodePorts = false

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SEP-ZX7GRIZKSNUQ3LAJ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -d 192.168.0.2 -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -s 10.180.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-SXIVWICOYRO3J4NJ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		COMMIT
		`)
	onlyLocalNodePorts(t, fp, ipt, expected, getLine())
}

func TestOnlyLocalNodePorts(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	fp.nodePortAddresses = proxyutil.NewNodePortAddresses(v1.IPv4Protocol, []string{"192.168.0.0/24", "2001:db8::/64"})
	fp.localhostNodePorts = false

	expected := dedent.Dedent(`
		*filter
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXTERNAL-SERVICES - [0:0]
		:KUBE-FORWARD - [0:0]
		:KUBE-PROXY-FIREWALL - [0:0]
		-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
		-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		COMMIT
		*nat
		:KUBE-NODEPORTS - [0:0]
		:KUBE-SERVICES - [0:0]
		:KUBE-EXT-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-MARK-MASQ - [0:0]
		:KUBE-POSTROUTING - [0:0]
		:KUBE-SEP-SXIVWICOYRO3J4NJ - [0:0]
		:KUBE-SEP-ZX7GRIZKSNUQ3LAJ - [0:0]
		:KUBE-SVC-XPGD46QRK7WJZT7O - [0:0]
		:KUBE-SVL-XPGD46QRK7WJZT7O - [0:0]
		-A KUBE-NODEPORTS -m comment --comment ns1/svc1:p80 -m tcp -p tcp --dport 3001 -j KUBE-EXT-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -d 192.168.0.2 -j KUBE-NODEPORTS
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "pod traffic for ns1/svc1:p80 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "masquerade LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
		-A KUBE-EXT-XPGD46QRK7WJZT7O -m comment --comment "route LOCAL traffic for ns1/svc1:p80 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-XPGD46QRK7WJZT7O
		-A KUBE-EXT-XPGD46QRK7WJZT7O -j KUBE-SVL-XPGD46QRK7WJZT7O
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -s 10.180.0.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-SXIVWICOYRO3J4NJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.0.1:80
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -s 10.180.2.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-ZX7GRIZKSNUQ3LAJ -m comment --comment ns1/svc1:p80 -m tcp -p tcp -j DNAT --to-destination 10.180.2.1:80
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.0.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-SXIVWICOYRO3J4NJ
		-A KUBE-SVC-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		-A KUBE-SVL-XPGD46QRK7WJZT7O -m comment --comment "ns1/svc1:p80 -> 10.180.2.1:80" -j KUBE-SEP-ZX7GRIZKSNUQ3LAJ
		COMMIT
		`)
	onlyLocalNodePorts(t, fp, ipt, expected, getLine())
}

func onlyLocalNodePorts(t *testing.T, fp *Proxier, ipt *iptablestest.FakeIPTables, expected, line string) {
	svcIP := "172.30.0.41"
	svcPort := 80
	svcNodePort := 3001
	svcPortName := proxy.ServicePortName{
		NamespacedName: makeNSN("ns1", "svc1"),
		Port:           "p80",
		Protocol:       v1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *v1.Service) {
			svc.Spec.Type = "NodePort"
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []v1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: v1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
		}),
	)

	epIP1 := "10.180.0.1"
	epIP2 := "10.180.2.1"
	populateEndpointSlices(fp,
		makeTestEndpointSlice(svcPortName.Namespace, svcPortName.Name, 1, func(eps *discovery.EndpointSlice) {
			eps.AddressType = discovery.AddressTypeIPv4
			eps.Endpoints = []discovery.Endpoint{{
				Addresses: []string{epIP1},
				NodeName:  nil,
			}, {
				Addresses: []string{epIP2},
				NodeName:  pointer.String(testHostname),
			}}
			eps.Ports = []discovery.EndpointPort{{
				Name:     pointer.String(svcPortName.Port),
				Port:     pointer.Int32(int32(svcPort)),
				Protocol: &tcpProtocol,
			}}
		}),
	)

	fp.syncProxyRules()

	assertIPTablesRulesEqual(t, line, true, expected, fp.iptablesData.String())

	runPacketFlowTests(t, line, ipt, testNodeIP, []packetFlowTest{
		{
			name:     "pod to cluster IP hit both endpoints",
			sourceIP: "10.0.0.2",
			destIP:   svcIP,
			destPort: svcPort,
			output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "external to NodePort hits only local endpoint",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: svcNodePort,
			output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
			masq:     false,
		},
		{
			name:     "pod to localhost doesn't work because localhost is not in nodePortAddresses",
			sourceIP: "10.0.0.2",
			destIP:   "127.0.0.1",
			destPort: svcNodePort,
			output:   "",
		},
	})

	if fp.localDetector.IsImplemented() {
		// pod-to-NodePort is treated as internal traffic, so we see both endpoints
		runPacketFlowTests(t, line, ipt, testNodeIP, []packetFlowTest{
			{
				name:     "pod to NodePort hits both endpoints",
				sourceIP: "10.0.0.2",
				destIP:   testNodeIP,
				destPort: svcNodePort,
				output:   fmt.Sprintf("%s:%d, %s:%d", epIP1, svcPort, epIP2, svcPort),
				masq:     false,
			},
		})
	} else {
		// pod-to-NodePort is (incorrectly) treated as external traffic
		// when there is no LocalTrafficDetector.
		runPacketFlowTests(t, line, ipt, testNodeIP, []packetFlowTest{
			{
				name:     "pod to NodePort hits only local endpoint",
				sourceIP: "10.0.0.2",
				destIP:   testNodeIP,
				destPort: svcNodePort,
				output:   fmt.Sprintf("%s:%d", epIP2, svcPort),
				masq:     false,
			},
		})
	}
}

// This test ensures that the iptables proxier supports translating Endpoints to
// iptables output when internalTrafficPolicy is specified
func TestInternalTrafficPolicyE2E(t *testing.T) {
	type endpoint struct {
		ip       string
		hostname string
	}

	cluster := v1.ServiceInternalTrafficPolicyCluster
	local := v1.ServiceInternalTrafficPolicyLocal

	clusterExpectedIPTables := dedent.Dedent(`
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
		:KUBE-SEP-3JOIVZTXZZRGORX4 - [0:0]
		:KUBE-SEP-IO5XOSKPAXIFQXAJ - [0:0]
		:KUBE-SEP-XGJFVO3L2O5SRFNT - [0:0]
		:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
		-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
		-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
		-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
		-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
		-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
		-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
		-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -s 10.0.1.1 -j KUBE-MARK-MASQ
		-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -m tcp -p tcp -j DNAT --to-destination 10.0.1.1:80
		-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -s 10.0.1.2 -j KUBE-MARK-MASQ
		-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -m tcp -p tcp -j DNAT --to-destination 10.0.1.2:80
		-A KUBE-SEP-XGJFVO3L2O5SRFNT -m comment --comment ns1/svc1 -s 10.0.1.3 -j KUBE-MARK-MASQ
		-A KUBE-SEP-XGJFVO3L2O5SRFNT -m comment --comment ns1/svc1 -m tcp -p tcp -j DNAT --to-destination 10.0.1.3:80
		-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
		-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m statistic --mode random --probability 0.3333333333 -j KUBE-SEP-3JOIVZTXZZRGORX4
		-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-IO5XOSKPAXIFQXAJ
		-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.3:80" -j KUBE-SEP-XGJFVO3L2O5SRFNT
		COMMIT
		`)

	testCases := []struct {
		name                      string
		line                      string
		internalTrafficPolicy     *v1.ServiceInternalTrafficPolicy
		endpoints                 []endpoint
		expectEndpointRule        bool
		expectedIPTablesWithSlice string
		flowTests                 []packetFlowTest
	}{
		{
			name:                  "internalTrafficPolicy is cluster",
			line:                  getLine(),
			internalTrafficPolicy: &cluster,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectEndpointRule:        true,
			expectedIPTablesWithSlice: clusterExpectedIPTables,
			flowTests: []packetFlowTest{
				{
					name:     "pod to ClusterIP hits all endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.3:80",
					masq:     false,
				},
			},
		},
		{
			name:                  "internalTrafficPolicy is local and there are local endpoints",
			line:                  getLine(),
			internalTrafficPolicy: &local,
			endpoints: []endpoint{
				{"10.0.1.1", testHostname},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectEndpointRule: true,
			expectedIPTablesWithSlice: dedent.Dedent(`
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
				:KUBE-SEP-3JOIVZTXZZRGORX4 - [0:0]
				:KUBE-SVL-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVL-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -s 10.0.1.1 -j KUBE-MARK-MASQ
				-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -m tcp -p tcp -j DNAT --to-destination 10.0.1.1:80
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -j KUBE-SEP-3JOIVZTXZZRGORX4
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to ClusterIP hits only local endpoint",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80",
					masq:     false,
				},
			},
		},
		{
			name:                  "internalTrafficPolicy is local and there are no local endpoints",
			line:                  getLine(),
			internalTrafficPolicy: &local,
			endpoints: []endpoint{
				{"10.0.1.1", "host0"},
				{"10.0.1.2", "host1"},
				{"10.0.1.3", "host2"},
			},
			expectEndpointRule: false,
			expectedIPTablesWithSlice: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 has no local endpoints" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j DROP
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
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "no endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "DROP",
				},
			},
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
					Ports:     []v1.ServicePort{{Name: "", Port: 80, Protocol: v1.ProtocolTCP}},
				},
			}
			if tc.internalTrafficPolicy != nil {
				svc.Spec.InternalTrafficPolicy = tc.internalTrafficPolicy
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
			assertIPTablesRulesEqual(t, tc.line, true, tc.expectedIPTablesWithSlice, fp.iptablesData.String())
			runPacketFlowTests(t, tc.line, ipt, testNodeIP, tc.flowTests)

			fp.OnEndpointSliceDelete(endpointSlice)
			fp.syncProxyRules()
			if tc.expectEndpointRule {
				fp.OnEndpointSliceDelete(endpointSlice)
				fp.syncProxyRules()
				assertIPTablesRulesNotEqual(t, tc.line, tc.expectedIPTablesWithSlice, fp.iptablesData.String())
			}
			runPacketFlowTests(t, tc.line, ipt, testNodeIP, []packetFlowTest{
				{
					name:     "endpoints deleted",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
			})
		})
	}
}

// TestTerminatingEndpointsTrafficPolicyLocal tests that when there are local ready and
// ready + terminating endpoints, only the ready endpoints are used.
func TestTerminatingEndpointsTrafficPolicyLocal(t *testing.T) {
	timeout := v1.DefaultClientIPServiceAffinitySeconds
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Spec: v1.ServiceSpec{
			ClusterIP:             "172.30.1.1",
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
			Selector:              map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{
				{
					Name:       "",
					TargetPort: intstr.FromInt32(80),
					Port:       80,
					Protocol:   v1.ProtocolTCP,
				},
			},
			HealthCheckNodePort: 30000,
			SessionAffinity:     v1.ServiceAffinityClientIP,
			SessionAffinityConfig: &v1.SessionAffinityConfig{
				ClientIP: &v1.ClientIPConfig{
					TimeoutSeconds: &timeout,
				},
			},
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}

	testcases := []struct {
		name              string
		line              string
		endpointslice     *discovery.EndpointSlice
		expectedIPTables  string
		noUsableEndpoints bool
		flowTests         []packetFlowTest
	}{
		{
			name: "ready endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"10.0.1.1"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since there are ready non-terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since there are ready non-terminating endpoints
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since it's not local
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			expectedIPTables: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns1/svc1 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXT-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-3JOIVZTXZZRGORX4 - [0:0]
				:KUBE-SEP-EQCHZ7S2PJ72OHAY - [0:0]
				:KUBE-SEP-IO5XOSKPAXIFQXAJ - [0:0]
				:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-SVL-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "pod traffic for ns1/svc1 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "masquerade LOCAL traffic for ns1/svc1 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "route LOCAL traffic for ns1/svc1 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -j KUBE-SVL-AQI2S6QIMU7PVVRP
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -s 10.0.1.1 -j KUBE-MARK-MASQ
				-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-3JOIVZTXZZRGORX4 --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.1:80
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -s 10.0.1.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.5:80
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -s 10.0.1.2 -j KUBE-MARK-MASQ
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.2:80
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m recent --name KUBE-SEP-3JOIVZTXZZRGORX4 --rcheck --seconds 10800 --reap -j KUBE-SEP-3JOIVZTXZZRGORX4
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --rcheck --seconds 10800 --reap -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --rcheck --seconds 10800 --reap -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m statistic --mode random --probability 0.3333333333 -j KUBE-SEP-3JOIVZTXZZRGORX4
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m recent --name KUBE-SEP-3JOIVZTXZZRGORX4 --rcheck --seconds 10800 --reap -j KUBE-SEP-3JOIVZTXZZRGORX4
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --rcheck --seconds 10800 --reap -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-3JOIVZTXZZRGORX4
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80",
					masq:     false,
				},
			},
		},
		{
			name: "only terminating endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should not be used since it is both terminating and not ready.
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored for external since it's not local
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			expectedIPTables: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns1/svc1 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXT-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-EQCHZ7S2PJ72OHAY - [0:0]
				:KUBE-SEP-IO5XOSKPAXIFQXAJ - [0:0]
				:KUBE-SEP-XGJFVO3L2O5SRFNT - [0:0]
				:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-SVL-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "pod traffic for ns1/svc1 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "masquerade LOCAL traffic for ns1/svc1 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "route LOCAL traffic for ns1/svc1 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -j KUBE-SVL-AQI2S6QIMU7PVVRP
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -s 10.0.1.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.5:80
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -s 10.0.1.2 -j KUBE-MARK-MASQ
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.2:80
				-A KUBE-SEP-XGJFVO3L2O5SRFNT -m comment --comment ns1/svc1 -s 10.0.1.3 -j KUBE-MARK-MASQ
				-A KUBE-SEP-XGJFVO3L2O5SRFNT -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-XGJFVO3L2O5SRFNT --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.3:80
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --rcheck --seconds 10800 --reap -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --rcheck --seconds 10800 --reap -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.3:80" -m recent --name KUBE-SEP-XGJFVO3L2O5SRFNT --rcheck --seconds 10800 --reap -j KUBE-SEP-XGJFVO3L2O5SRFNT
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVL-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.3:80" -j KUBE-SEP-XGJFVO3L2O5SRFNT
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.2:80, 10.0.1.3:80",
					masq:     false,
				},
			},
		},
		{
			name: "terminating endpoints on remote node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// this endpoint won't be used because it's not local,
						// but it will prevent a REJECT rule from being created
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			expectedIPTables: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns1/svc1 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns1/svc1 has no local endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j DROP
				-A KUBE-FIREWALL -m comment --comment "block incoming localnet connections" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
				-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
				-A KUBE-FORWARD -m comment --comment "kubernetes forwarding conntrack rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
				COMMIT
				*nat
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXT-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-EQCHZ7S2PJ72OHAY - [0:0]
				:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "pod traffic for ns1/svc1 external destinations" -s 10.0.0.0/8 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "masquerade LOCAL traffic for ns1/svc1 external destinations" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "route LOCAL traffic for ns1/svc1 external destinations" -m addrtype --src-type LOCAL -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -s 10.0.1.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.5:80
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --rcheck --seconds 10800 --reap -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.5:80",
				},
				{
					name:     "external to LB, no locally-usable endpoints",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "DROP",
				},
			},
		},
		{
			name: "no usable endpoints on any node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// Local but not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// Remote and not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			noUsableEndpoints: true,
			expectedIPTables: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-NODEPORTS -m comment --comment "ns1/svc1 health check node port" -m tcp -p tcp --dport 30000 -j ACCEPT
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 has no endpoints" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j REJECT
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns1/svc1 has no endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j REJECT
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
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP, no usable endpoints",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB, no usable endpoints",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			ipt := iptablestest.NewFake()
			fp := NewFakeProxier(ipt)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			fp.OnServiceAdd(service)

			fp.OnEndpointSliceAdd(testcase.endpointslice)
			fp.syncProxyRules()
			assertIPTablesRulesEqual(t, testcase.line, true, testcase.expectedIPTables, fp.iptablesData.String())
			runPacketFlowTests(t, testcase.line, ipt, testNodeIP, testcase.flowTests)

			fp.OnEndpointSliceDelete(testcase.endpointslice)
			fp.syncProxyRules()
			if testcase.noUsableEndpoints {
				// Deleting the EndpointSlice should have had no effect
				assertIPTablesRulesEqual(t, testcase.line, true, testcase.expectedIPTables, fp.iptablesData.String())
			} else {
				assertIPTablesRulesNotEqual(t, testcase.line, testcase.expectedIPTables, fp.iptablesData.String())
			}
			runPacketFlowTests(t, testcase.line, ipt, testNodeIP, []packetFlowTest{
				{
					name:     "pod to clusterIP after endpoints deleted",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB after endpoints deleted",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			})
		})
	}
}

// TestTerminatingEndpointsTrafficPolicyCluster tests that when there are cluster-wide
// ready and ready + terminating endpoints, only the ready endpoints are used.
func TestTerminatingEndpointsTrafficPolicyCluster(t *testing.T) {
	timeout := v1.DefaultClientIPServiceAffinitySeconds
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Spec: v1.ServiceSpec{
			ClusterIP:             "172.30.1.1",
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyCluster,
			Selector:              map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{
				{
					Name:       "",
					TargetPort: intstr.FromInt32(80),
					Port:       80,
					Protocol:   v1.ProtocolTCP,
				},
			},
			HealthCheckNodePort: 30000,
			SessionAffinity:     v1.ServiceAffinityClientIP,
			SessionAffinityConfig: &v1.SessionAffinityConfig{
				ClientIP: &v1.ClientIPConfig{
					TimeoutSeconds: &timeout,
				},
			},
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}

	testcases := []struct {
		name              string
		line              string
		endpointslice     *discovery.EndpointSlice
		expectedIPTables  string
		noUsableEndpoints bool
		flowTests         []packetFlowTest
	}{
		{
			name: "ready endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"10.0.1.1"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be ignored since there are ready non-terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
					{
						// this endpoint should be ignored since it is not "serving"
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
					{
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(true),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(false),
						},
						NodeName: pointer.String("another-host"),
					},
				},
			},
			expectedIPTables: dedent.Dedent(`
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
				:KUBE-EXT-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-3JOIVZTXZZRGORX4 - [0:0]
				:KUBE-SEP-EQCHZ7S2PJ72OHAY - [0:0]
				:KUBE-SEP-IO5XOSKPAXIFQXAJ - [0:0]
				:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "masquerade traffic for ns1/svc1 external destinations" -j KUBE-MARK-MASQ
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -s 10.0.1.1 -j KUBE-MARK-MASQ
				-A KUBE-SEP-3JOIVZTXZZRGORX4 -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-3JOIVZTXZZRGORX4 --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.1:80
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -s 10.0.1.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.5:80
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -s 10.0.1.2 -j KUBE-MARK-MASQ
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.2:80
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m recent --name KUBE-SEP-3JOIVZTXZZRGORX4 --rcheck --seconds 10800 --reap -j KUBE-SEP-3JOIVZTXZZRGORX4
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --rcheck --seconds 10800 --reap -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --rcheck --seconds 10800 --reap -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.1:80" -m statistic --mode random --probability 0.3333333333 -j KUBE-SEP-3JOIVZTXZZRGORX4
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.1:80, 10.0.1.2:80, 10.0.1.5:80",
					masq:     true,
				},
			},
		},
		{
			name: "only terminating endpoints exist",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.2"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.3"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// this endpoint should not be used since it is both terminating and not ready.
						Addresses: []string{"10.0.1.4"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
					{
						// this endpoint should be used since there are only ready terminating endpoints
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("another-host"),
					},
				},
			},
			expectedIPTables: dedent.Dedent(`
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
				:KUBE-EXT-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-EQCHZ7S2PJ72OHAY - [0:0]
				:KUBE-SEP-IO5XOSKPAXIFQXAJ - [0:0]
				:KUBE-SEP-XGJFVO3L2O5SRFNT - [0:0]
				:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "masquerade traffic for ns1/svc1 external destinations" -j KUBE-MARK-MASQ
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -s 10.0.1.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.5:80
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -s 10.0.1.2 -j KUBE-MARK-MASQ
				-A KUBE-SEP-IO5XOSKPAXIFQXAJ -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.2:80
				-A KUBE-SEP-XGJFVO3L2O5SRFNT -m comment --comment ns1/svc1 -s 10.0.1.3 -j KUBE-MARK-MASQ
				-A KUBE-SEP-XGJFVO3L2O5SRFNT -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-XGJFVO3L2O5SRFNT --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.3:80
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m recent --name KUBE-SEP-IO5XOSKPAXIFQXAJ --rcheck --seconds 10800 --reap -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.3:80" -m recent --name KUBE-SEP-XGJFVO3L2O5SRFNT --rcheck --seconds 10800 --reap -j KUBE-SEP-XGJFVO3L2O5SRFNT
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --rcheck --seconds 10800 --reap -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.2:80" -m statistic --mode random --probability 0.3333333333 -j KUBE-SEP-IO5XOSKPAXIFQXAJ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.3:80" -m statistic --mode random --probability 0.5000000000 -j KUBE-SEP-XGJFVO3L2O5SRFNT
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.2:80, 10.0.1.3:80, 10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.2:80, 10.0.1.3:80, 10.0.1.5:80",
					masq:     true,
				},
			},
		},
		{
			name: "terminating endpoints on remote node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(true),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			expectedIPTables: dedent.Dedent(`
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
				:KUBE-EXT-AQI2S6QIMU7PVVRP - [0:0]
				:KUBE-MARK-MASQ - [0:0]
				:KUBE-POSTROUTING - [0:0]
				:KUBE-SEP-EQCHZ7S2PJ72OHAY - [0:0]
				:KUBE-SVC-AQI2S6QIMU7PVVRP - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-AQI2S6QIMU7PVVRP
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -m comment --comment "masquerade traffic for ns1/svc1 external destinations" -j KUBE-MARK-MASQ
				-A KUBE-EXT-AQI2S6QIMU7PVVRP -j KUBE-SVC-AQI2S6QIMU7PVVRP
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -s 10.0.1.5 -j KUBE-MARK-MASQ
				-A KUBE-SEP-EQCHZ7S2PJ72OHAY -m comment --comment ns1/svc1 -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --set -m tcp -p tcp -j DNAT --to-destination 10.0.1.5:80
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 cluster IP" -m tcp -p tcp -d 172.30.1.1 --dport 80 ! -s 10.0.0.0/8 -j KUBE-MARK-MASQ
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -m recent --name KUBE-SEP-EQCHZ7S2PJ72OHAY --rcheck --seconds 10800 --reap -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				-A KUBE-SVC-AQI2S6QIMU7PVVRP -m comment --comment "ns1/svc1 -> 10.0.1.5:80" -j KUBE-SEP-EQCHZ7S2PJ72OHAY
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "10.0.1.5:80",
					masq:     false,
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "10.0.1.5:80",
					masq:     true,
				},
			},
		},
		{
			name: "no usable endpoints on any node",
			line: getLine(),
			endpointslice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-1", "svc1"),
					Namespace: "ns1",
					Labels:    map[string]string{discovery.LabelServiceName: "svc1"},
				},
				Ports: []discovery.EndpointPort{{
					Name:     pointer.String(""),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						// Local, not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String(testHostname),
					},
					{
						// Remote, not ready or serving
						Addresses: []string{"10.0.1.5"},
						Conditions: discovery.EndpointConditions{
							Ready:       pointer.Bool(false),
							Serving:     pointer.Bool(false),
							Terminating: pointer.Bool(true),
						},
						NodeName: pointer.String("host-1"),
					},
				},
			},
			noUsableEndpoints: true,
			expectedIPTables: dedent.Dedent(`
				*filter
				:KUBE-NODEPORTS - [0:0]
				:KUBE-SERVICES - [0:0]
				:KUBE-EXTERNAL-SERVICES - [0:0]
				:KUBE-FIREWALL - [0:0]
				:KUBE-FORWARD - [0:0]
				:KUBE-PROXY-FIREWALL - [0:0]
				-A KUBE-SERVICES -m comment --comment "ns1/svc1 has no endpoints" -m tcp -p tcp -d 172.30.1.1 --dport 80 -j REJECT
				-A KUBE-EXTERNAL-SERVICES -m comment --comment "ns1/svc1 has no endpoints" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j REJECT
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
				-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
				-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000
				-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
				-A KUBE-POSTROUTING -j MARK --xor-mark 0x4000
				-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE
				COMMIT
				`),
			flowTests: []packetFlowTest{
				{
					name:     "pod to clusterIP",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {

			ipt := iptablestest.NewFake()
			fp := NewFakeProxier(ipt)
			fp.OnServiceSynced()
			fp.OnEndpointSlicesSynced()

			fp.OnServiceAdd(service)

			fp.OnEndpointSliceAdd(testcase.endpointslice)
			fp.syncProxyRules()
			assertIPTablesRulesEqual(t, testcase.line, true, testcase.expectedIPTables, fp.iptablesData.String())
			runPacketFlowTests(t, testcase.line, ipt, testNodeIP, testcase.flowTests)

			fp.OnEndpointSliceDelete(testcase.endpointslice)
			fp.syncProxyRules()
			if testcase.noUsableEndpoints {
				// Deleting the EndpointSlice should have had no effect
				assertIPTablesRulesEqual(t, testcase.line, true, testcase.expectedIPTables, fp.iptablesData.String())
			} else {
				assertIPTablesRulesNotEqual(t, testcase.line, testcase.expectedIPTables, fp.iptablesData.String())
			}
			runPacketFlowTests(t, testcase.line, ipt, testNodeIP, []packetFlowTest{
				{
					name:     "pod to clusterIP after endpoints deleted",
					sourceIP: "10.0.0.2",
					destIP:   "172.30.1.1",
					destPort: 80,
					output:   "REJECT",
				},
				{
					name:     "external to LB after endpoints deleted",
					sourceIP: testExternalClient,
					destIP:   "1.2.3.4",
					destPort: 80,
					output:   "REJECT",
				},
			})
		})
	}
}

func TestInternalExternalMasquerade(t *testing.T) {
	// (Put the test setup code in an internal function so we can have it here at the
	// top, before the test cases that will be run against it.)
	setupTest := func(fp *Proxier) {
		local := v1.ServiceInternalTrafficPolicyLocal

		makeServiceMap(fp,
			makeTestService("ns1", "svc1", func(svc *v1.Service) {
				svc.Spec.Type = "LoadBalancer"
				svc.Spec.ClusterIP = "172.30.0.41"
				svc.Spec.Ports = []v1.ServicePort{{
					Name:     "p80",
					Port:     80,
					Protocol: v1.ProtocolTCP,
					NodePort: int32(3001),
				}}
				svc.Spec.HealthCheckNodePort = 30001
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
					IP: "1.2.3.4",
				}}
			}),
			makeTestService("ns2", "svc2", func(svc *v1.Service) {
				svc.Spec.Type = "LoadBalancer"
				svc.Spec.ClusterIP = "172.30.0.42"
				svc.Spec.Ports = []v1.ServicePort{{
					Name:     "p80",
					Port:     80,
					Protocol: v1.ProtocolTCP,
					NodePort: int32(3002),
				}}
				svc.Spec.HealthCheckNodePort = 30002
				svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
					IP: "5.6.7.8",
				}}
			}),
			makeTestService("ns3", "svc3", func(svc *v1.Service) {
				svc.Spec.Type = "LoadBalancer"
				svc.Spec.ClusterIP = "172.30.0.43"
				svc.Spec.Ports = []v1.ServicePort{{
					Name:     "p80",
					Port:     80,
					Protocol: v1.ProtocolTCP,
					NodePort: int32(3003),
				}}
				svc.Spec.HealthCheckNodePort = 30003
				svc.Spec.InternalTrafficPolicy = &local
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{
					IP: "9.10.11.12",
				}}
			}),
		)

		populateEndpointSlices(fp,
			makeTestEndpointSlice("ns1", "svc1", 1, func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{
					{
						Addresses: []string{"10.180.0.1"},
						NodeName:  pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.180.1.1"},
						NodeName:  pointer.String("remote"),
					},
				}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}}
			}),
			makeTestEndpointSlice("ns2", "svc2", 1, func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{
					{
						Addresses: []string{"10.180.0.2"},
						NodeName:  pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.180.1.2"},
						NodeName:  pointer.String("remote"),
					},
				}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}}
			}),
			makeTestEndpointSlice("ns3", "svc3", 1, func(eps *discovery.EndpointSlice) {
				eps.AddressType = discovery.AddressTypeIPv4
				eps.Endpoints = []discovery.Endpoint{
					{
						Addresses: []string{"10.180.0.3"},
						NodeName:  pointer.String(testHostname),
					},
					{
						Addresses: []string{"10.180.1.3"},
						NodeName:  pointer.String("remote"),
					},
				}
				eps.Ports = []discovery.EndpointPort{{
					Name:     pointer.String("p80"),
					Port:     pointer.Int32(80),
					Protocol: &tcpProtocol,
				}}
			}),
		)

		fp.syncProxyRules()
	}

	// We use the same flowTests for all of the testCases. The "output" and "masq"
	// values here represent the normal case (working localDetector, no masqueradeAll)
	flowTests := []packetFlowTest{
		{
			name:     "pod to ClusterIP",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     false,
		},
		{
			name:     "pod to NodePort",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "pod to LB",
			sourceIP: "10.0.0.2",
			destIP:   "1.2.3.4",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "node to ClusterIP",
			sourceIP: testNodeIP,
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "node to NodePort",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "localhost to NodePort",
			sourceIP: "127.0.0.1",
			destIP:   "127.0.0.1",
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "node to LB",
			sourceIP: testNodeIP,
			destIP:   "1.2.3.4",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "external to ClusterIP",
			sourceIP: testExternalClient,
			destIP:   "172.30.0.41",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "external to NodePort",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: 3001,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "external to LB",
			sourceIP: testExternalClient,
			destIP:   "1.2.3.4",
			destPort: 80,
			output:   "10.180.0.1:80, 10.180.1.1:80",
			masq:     true,
		},
		{
			name:     "pod to ClusterIP with eTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.42",
			destPort: 80,

			// externalTrafficPolicy does not apply to ClusterIP traffic, so same
			// as "Pod to ClusterIP"
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   false,
		},
		{
			name:     "pod to NodePort with eTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: 3002,

			// See the comment below in the "pod to LB with eTP:Local" case.
			// It doesn't actually make sense to short-circuit here, since if
			// you connect directly to a NodePort from outside the cluster,
			// you only get the local endpoints. But it's simpler for us and
			// slightly more convenient for users to have this case get
			// short-circuited too.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   false,
		},
		{
			name:     "pod to LB with eTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "5.6.7.8",
			destPort: 80,

			// The short-circuit rule is supposed to make this behave the same
			// way it would if the packet actually went out to the LB and then
			// came back into the cluster. So it gets routed to all endpoints,
			// not just local ones. In reality, if the packet actually left
			// the cluster, it would have to get masqueraded, but since we can
			// avoid doing that in the short-circuit case, and not masquerading
			// is more useful, we avoid masquerading.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   false,
		},
		{
			name:     "node to ClusterIP with eTP:Local",
			sourceIP: testNodeIP,
			destIP:   "172.30.0.42",
			destPort: 80,

			// externalTrafficPolicy does not apply to ClusterIP traffic, so same
			// as "node to ClusterIP"
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "node to NodePort with eTP:Local",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 3001,

			// The traffic gets short-circuited, ignoring externalTrafficPolicy, so
			// same as "node to NodePort" above.
			output: "10.180.0.1:80, 10.180.1.1:80",
			masq:   true,
		},
		{
			name:     "localhost to NodePort with eTP:Local",
			sourceIP: "127.0.0.1",
			destIP:   "127.0.0.1",
			destPort: 3002,

			// The traffic gets short-circuited, ignoring externalTrafficPolicy, so
			// same as "localhost to NodePort" above.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "node to LB with eTP:Local",
			sourceIP: testNodeIP,
			destIP:   "5.6.7.8",
			destPort: 80,

			// The traffic gets short-circuited, ignoring externalTrafficPolicy, so
			// same as "node to LB" above.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "external to ClusterIP with eTP:Local",
			sourceIP: testExternalClient,
			destIP:   "172.30.0.42",
			destPort: 80,

			// externalTrafficPolicy does not apply to ClusterIP traffic, so same
			// as "external to ClusterIP" above.
			output: "10.180.0.2:80, 10.180.1.2:80",
			masq:   true,
		},
		{
			name:     "external to NodePort with eTP:Local",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: 3002,

			// externalTrafficPolicy applies; only the local endpoint is
			// selected, and we don't masquerade.
			output: "10.180.0.2:80",
			masq:   false,
		},
		{
			name:     "external to LB with eTP:Local",
			sourceIP: testExternalClient,
			destIP:   "5.6.7.8",
			destPort: 80,

			// externalTrafficPolicy applies; only the local endpoint is
			// selected, and we don't masquerade.
			output: "10.180.0.2:80",
			masq:   false,
		},
		{
			name:     "pod to ClusterIP with iTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "172.30.0.43",
			destPort: 80,

			// internalTrafficPolicy applies; only the local endpoint is
			// selected.
			output: "10.180.0.3:80",
			masq:   false,
		},
		{
			name:     "pod to NodePort with iTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   testNodeIP,
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "pod to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "pod to LB with iTP:Local",
			sourceIP: "10.0.0.2",
			destIP:   "9.10.11.12",
			destPort: 80,

			// internalTrafficPolicy does not apply to LoadBalancer traffic, so
			// same as "pod to LB" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "node to ClusterIP with iTP:Local",
			sourceIP: testNodeIP,
			destIP:   "172.30.0.43",
			destPort: 80,

			// internalTrafficPolicy applies; only the local endpoint is selected.
			// Traffic is masqueraded as in the "node to ClusterIP" case because
			// internalTrafficPolicy does not affect masquerading.
			output: "10.180.0.3:80",
			masq:   true,
		},
		{
			name:     "node to NodePort with iTP:Local",
			sourceIP: testNodeIP,
			destIP:   testNodeIP,
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "node to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "localhost to NodePort with iTP:Local",
			sourceIP: "127.0.0.1",
			destIP:   "127.0.0.1",
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "localhost to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "node to LB with iTP:Local",
			sourceIP: testNodeIP,
			destIP:   "9.10.11.12",
			destPort: 80,

			// internalTrafficPolicy does not apply to LoadBalancer traffic, so
			// same as "node to LB" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "external to ClusterIP with iTP:Local",
			sourceIP: testExternalClient,
			destIP:   "172.30.0.43",
			destPort: 80,

			// internalTrafficPolicy applies; only the local endpoint is selected.
			// Traffic is masqueraded as in the "external to ClusterIP" case
			// because internalTrafficPolicy does not affect masquerading.
			output: "10.180.0.3:80",
			masq:   true,
		},
		{
			name:     "external to NodePort with iTP:Local",
			sourceIP: testExternalClient,
			destIP:   testNodeIP,
			destPort: 3003,

			// internalTrafficPolicy does not apply to NodePort traffic, so same as
			// "external to NodePort" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
		{
			name:     "external to LB with iTP:Local",
			sourceIP: testExternalClient,
			destIP:   "9.10.11.12",
			destPort: 80,

			// internalTrafficPolicy does not apply to LoadBalancer traffic, so
			// same as "external to LB" above.
			output: "10.180.0.3:80, 10.180.1.3:80",
			masq:   true,
		},
	}

	type packetFlowTestOverride struct {
		output *string
		masq   *bool
	}

	testCases := []struct {
		name          string
		line          string
		masqueradeAll bool
		localDetector bool
		overrides     map[string]packetFlowTestOverride
	}{
		{
			name:          "base",
			line:          getLine(),
			masqueradeAll: false,
			localDetector: true,
			overrides:     nil,
		},
		{
			name:          "no LocalTrafficDetector",
			line:          getLine(),
			masqueradeAll: false,
			localDetector: false,
			overrides: map[string]packetFlowTestOverride{
				// With no LocalTrafficDetector, all traffic to a
				// ClusterIP is assumed to be from a pod, and thus to not
				// require masquerading.
				"node to ClusterIP": {
					masq: pointer.Bool(false),
				},
				"node to ClusterIP with eTP:Local": {
					masq: pointer.Bool(false),
				},
				"node to ClusterIP with iTP:Local": {
					masq: pointer.Bool(false),
				},
				"external to ClusterIP": {
					masq: pointer.Bool(false),
				},
				"external to ClusterIP with eTP:Local": {
					masq: pointer.Bool(false),
				},
				"external to ClusterIP with iTP:Local": {
					masq: pointer.Bool(false),
				},

				// And there's no eTP:Local short-circuit for pod traffic,
				// so pods get only the local endpoints.
				"pod to NodePort with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
				"pod to LB with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
			},
		},
		{
			name:          "masqueradeAll",
			line:          getLine(),
			masqueradeAll: true,
			localDetector: true,
			overrides: map[string]packetFlowTestOverride{
				// All "to ClusterIP" traffic gets masqueraded when using
				// --masquerade-all.
				"pod to ClusterIP": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with eTP:Local": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with iTP:Local": {
					masq: pointer.Bool(true),
				},
			},
		},
		{
			name:          "masqueradeAll, no LocalTrafficDetector",
			line:          getLine(),
			masqueradeAll: true,
			localDetector: false,
			overrides: map[string]packetFlowTestOverride{
				// As in "masqueradeAll"
				"pod to ClusterIP": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with eTP:Local": {
					masq: pointer.Bool(true),
				},
				"pod to ClusterIP with iTP:Local": {
					masq: pointer.Bool(true),
				},

				// As in "no LocalTrafficDetector"
				"pod to NodePort with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
				"pod to LB with eTP:Local": {
					output: pointer.String("10.180.0.2:80"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ipt := iptablestest.NewFake()
			fp := NewFakeProxier(ipt)
			fp.masqueradeAll = tc.masqueradeAll
			if !tc.localDetector {
				fp.localDetector = proxyutiliptables.NewNoOpLocalDetector()
			}
			setupTest(fp)

			// Merge base flowTests with per-test-case overrides
			tcFlowTests := make([]packetFlowTest, len(flowTests))
			overridesApplied := 0
			for i := range flowTests {
				tcFlowTests[i] = flowTests[i]
				if overrides, set := tc.overrides[flowTests[i].name]; set {
					overridesApplied++
					if overrides.masq != nil {
						if tcFlowTests[i].masq == *overrides.masq {
							t.Errorf("%q override value for masq is same as base value", flowTests[i].name)
						}
						tcFlowTests[i].masq = *overrides.masq
					}
					if overrides.output != nil {
						if tcFlowTests[i].output == *overrides.output {
							t.Errorf("%q override value for output is same as base value", flowTests[i].name)
						}
						tcFlowTests[i].output = *overrides.output
					}
				}
			}
			if overridesApplied != len(tc.overrides) {
				t.Errorf("%d overrides did not match any test case name!", len(tc.overrides)-overridesApplied)
			}
			runPacketFlowTests(t, tc.line, ipt, testNodeIP, tcFlowTests)
		})
	}
}
