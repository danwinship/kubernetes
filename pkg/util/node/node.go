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

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	utilnet "k8s.io/utils/net"
)

const (
	// NodeUnreachablePodReason is the reason on a pod when its state cannot be confirmed as kubelet is unresponsive
	// on the node it is (was) running.
	NodeUnreachablePodReason = "NodeLost"
	// NodeUnreachablePodMessage is the message on a pod when its state cannot be confirmed as kubelet is unresponsive
	// on the node it is (was) running.
	NodeUnreachablePodMessage = "Node %v which was running pod %v is unresponsive"
)

// GetHostname returns OS's hostname if 'hostnameOverride' is empty; otherwise, return 'hostnameOverride'.
func GetHostname(hostnameOverride string) (string, error) {
	hostName := hostnameOverride
	if len(hostName) == 0 {
		nodeName, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("couldn't determine hostname: %v", err)
		}
		hostName = nodeName
	}

	// Trim whitespaces first to avoid getting an empty hostname
	// For linux, the hostname is read from file /proc/sys/kernel/hostname directly
	hostName = strings.TrimSpace(hostName)
	if len(hostName) == 0 {
		return "", fmt.Errorf("empty hostname is invalid")
	}
	return strings.ToLower(hostName), nil
}

// NoMatchError is a typed implementation of the error interface. It indicates a failure to get a matching Node.
type NoMatchError struct {
	addresses []v1.NodeAddress
}

// Error is the implementation of the conventional interface for
// representing an error condition, with the nil value representing no error.
func (e *NoMatchError) Error() string {
	return fmt.Sprintf("no preferred addresses found; known addresses: %v", e.addresses)
}

// GetPreferredNodeAddress returns the address of the provided node, using the provided preference order.
// If none of the preferred address types are found, an error is returned.
func GetPreferredNodeAddress(node *v1.Node, preferredAddressTypes []v1.NodeAddressType) (string, error) {
	for _, addressType := range preferredAddressTypes {
		for _, address := range node.Status.Addresses {
			if address.Type == addressType {
				return address.Address, nil
			}
		}
	}
	return "", &NoMatchError{addresses: node.Status.Addresses}
}

// getNodeHostIPs is used internally; it is just GetNodeHostIPs with different arguments
func getNodeHostIPs(addresses []v1.NodeAddress) ([]net.IP, error) {
	allIPs := make([]net.IP, 0, len(addresses))
	for _, addr := range addresses {
		if addr.Type == v1.NodeInternalIP {
			ip := net.ParseIP(addr.Address)
			if ip != nil {
				allIPs = append(allIPs, ip)
			}
		}
	}
	for _, addr := range addresses {
		if addr.Type == v1.NodeExternalIP {
			ip := net.ParseIP(addr.Address)
			if ip != nil {
				allIPs = append(allIPs, ip)
			}
		}
	}

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("host IP unknown; known addresses: %v", addresses)
	}
	nodeIPs := []net.IP{allIPs[0]}
	for _, ip := range allIPs {
		if utilnet.IsIPv6(ip) != utilnet.IsIPv6(nodeIPs[0]) {
			nodeIPs = append(nodeIPs, ip)
			break
		}
	}
	return nodeIPs, nil
}

// GetNodeHostIPs returns the provided node's "primary" and "secondary" IPs; this will
// always return at least one IP (or an error), which is the same as would be returned by
// GetNodeHostIP. If the node is dual stack, it will also return a second IP of the other
// address family.
func GetNodeHostIPs(node *v1.Node) ([]net.IP, error) {
	return getNodeHostIPs(node.Status.Addresses)
}

// GetNodeHostIP returns the provided node's "primary" IP
func GetNodeHostIP(node *v1.Node) (net.IP, error) {
	ips, err := GetNodeHostIPs(node)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

// GetNodeIP returns an IP for node with the provided hostname
// If required, wait for the node to be defined.
func GetNodeIP(client clientset.Interface, hostname string) net.IP {
	var nodeIP net.IP
	backoff := wait.Backoff{
		Steps:    6,
		Duration: 1 * time.Second,
		Factor:   2.0,
		Jitter:   0.2,
	}

	err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(context.TODO(), hostname, metav1.GetOptions{})
		if err != nil {
			klog.Errorf("Failed to retrieve node info: %v", err)
			return false, nil
		}
		nodeIP, err = GetNodeHostIP(node)
		if err != nil {
			klog.Errorf("Failed to retrieve node IP: %v", err)
			return false, err
		}
		return true, nil
	})
	if err == nil {
		klog.Infof("Successfully retrieved node IP: %v", nodeIP)
	}
	return nodeIP
}

// GetZoneKey is a helper function that builds a string identifier that is unique per failure-zone;
// it returns empty-string for no zone.
// Since there are currently two separate zone keys:
//   * "failure-domain.beta.kubernetes.io/zone"
//   * "topology.kubernetes.io/zone"
// GetZoneKey will first check failure-domain.beta.kubernetes.io/zone and if not exists, will then check
// topology.kubernetes.io/zone
func GetZoneKey(node *v1.Node) string {
	labels := node.Labels
	if labels == nil {
		return ""
	}

	// TODO: prefer stable labels for zone in v1.18
	zone, ok := labels[v1.LabelZoneFailureDomain]
	if !ok {
		zone, _ = labels[v1.LabelZoneFailureDomainStable]
	}

	// TODO: prefer stable labels for region in v1.18
	region, ok := labels[v1.LabelZoneRegion]
	if !ok {
		region, _ = labels[v1.LabelZoneRegionStable]
	}

	if region == "" && zone == "" {
		return ""
	}

	// We include the null character just in case region or failureDomain has a colon
	// (We do assume there's no null characters in a region or failureDomain)
	// As a nice side-benefit, the null character is not printed by fmt.Print or glog
	return region + ":\x00:" + zone
}

type nodeForConditionPatch struct {
	Status nodeStatusForPatch `json:"status"`
}

type nodeStatusForPatch struct {
	Conditions []v1.NodeCondition `json:"conditions"`
}

// SetNodeCondition updates specific node condition with patch operation.
func SetNodeCondition(c clientset.Interface, node types.NodeName, condition v1.NodeCondition) error {
	generatePatch := func(condition v1.NodeCondition) ([]byte, error) {
		patch := nodeForConditionPatch{
			Status: nodeStatusForPatch{
				Conditions: []v1.NodeCondition{
					condition,
				},
			},
		}
		patchBytes, err := json.Marshal(&patch)
		if err != nil {
			return nil, err
		}
		return patchBytes, nil
	}
	condition.LastHeartbeatTime = metav1.NewTime(time.Now())
	patch, err := generatePatch(condition)
	if err != nil {
		return nil
	}
	_, err = c.CoreV1().Nodes().PatchStatus(context.TODO(), string(node), patch)
	return err
}

type nodeForCIDRMergePatch struct {
	Spec nodeSpecForMergePatch `json:"spec"`
}

type nodeSpecForMergePatch struct {
	PodCIDR  string   `json:"podCIDR"`
	PodCIDRs []string `json:"podCIDRs,omitempty"`
}

// PatchNodeCIDR patches the specified node's CIDR to the given value.
func PatchNodeCIDR(c clientset.Interface, node types.NodeName, cidr string) error {
	patch := nodeForCIDRMergePatch{
		Spec: nodeSpecForMergePatch{
			PodCIDR: cidr,
		},
	}
	patchBytes, err := json.Marshal(&patch)
	if err != nil {
		return fmt.Errorf("failed to json.Marshal CIDR: %v", err)
	}

	if _, err := c.CoreV1().Nodes().Patch(context.TODO(), string(node), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("failed to patch node CIDR: %v", err)
	}
	return nil
}

// PatchNodeCIDRs patches the specified node.CIDR=cidrs[0] and node.CIDRs to the given value.
func PatchNodeCIDRs(c clientset.Interface, node types.NodeName, cidrs []string) error {
	// set the pod cidrs list and set the old pod cidr field
	patch := nodeForCIDRMergePatch{
		Spec: nodeSpecForMergePatch{
			PodCIDR:  cidrs[0],
			PodCIDRs: cidrs,
		},
	}

	patchBytes, err := json.Marshal(&patch)
	if err != nil {
		return fmt.Errorf("failed to json.Marshal CIDR: %v", err)
	}
	klog.V(4).Infof("cidrs patch bytes are:%s", string(patchBytes))
	if _, err := c.CoreV1().Nodes().Patch(context.TODO(), string(node), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("failed to patch node CIDR: %v", err)
	}
	return nil
}

// PatchNodeStatus patches node status.
func PatchNodeStatus(c v1core.CoreV1Interface, nodeName types.NodeName, oldNode *v1.Node, newNode *v1.Node) (*v1.Node, []byte, error) {
	patchBytes, err := preparePatchBytesforNodeStatus(nodeName, oldNode, newNode)
	if err != nil {
		return nil, nil, err
	}

	updatedNode, err := c.Nodes().Patch(context.TODO(), string(nodeName), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}, "status")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to patch status %q for node %q: %v", patchBytes, nodeName, err)
	}
	return updatedNode, patchBytes, nil
}

func preparePatchBytesforNodeStatus(nodeName types.NodeName, oldNode *v1.Node, newNode *v1.Node) ([]byte, error) {
	oldData, err := json.Marshal(oldNode)
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal oldData for node %q: %v", nodeName, err)
	}

	// NodeStatus.Addresses is incorrectly annotated as patchStrategy=merge, which
	// will cause strategicpatch.CreateTwoWayMergePatch to create an incorrect patch
	// if it changed.
	manuallyPatchAddresses := (len(oldNode.Status.Addresses) > 0) && !equality.Semantic.DeepEqual(oldNode.Status.Addresses, newNode.Status.Addresses)

	// Reset spec to make sure only patch for Status or ObjectMeta is generated.
	// Note that we don't reset ObjectMeta here, because:
	// 1. This aligns with Nodes().UpdateStatus().
	// 2. Some component does use this to update node annotations.
	diffNode := newNode.DeepCopy()
	diffNode.Spec = oldNode.Spec
	if manuallyPatchAddresses {
		diffNode.Status.Addresses = oldNode.Status.Addresses
	}
	newData, err := json.Marshal(diffNode)
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal newData for node %q: %v", nodeName, err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, v1.Node{})
	if err != nil {
		return nil, fmt.Errorf("failed to CreateTwoWayMergePatch for node %q: %v", nodeName, err)
	}
	if manuallyPatchAddresses {
		patchBytes, err = fixupPatchForNodeStatusAddresses(patchBytes, newNode.Status.Addresses)
		if err != nil {
			return nil, fmt.Errorf("failed to fix up NodeAddresses in patch for node %q: %v", nodeName, err)
		}
	}

	return patchBytes, nil
}

// fixupPatchForNodeStatusAddresses adds a replace-strategy patch for Status.Addresses to
// the existing patch
func fixupPatchForNodeStatusAddresses(patchBytes []byte, addresses []v1.NodeAddress) ([]byte, error) {
	// Given patchBytes='{"status": {"conditions": [ ... ], "phase": ...}}' and
	// addresses=[{"type": "InternalIP", "address": "10.0.0.1"}], we need to generate:
	//
	//   {
	//     "status": {
	//       "conditions": [ ... ],
	//       "phase": ...,
	//       "addresses": [
	//         {
	//           "type": "InternalIP",
	//           "address": "10.0.0.1"
	//         },
	//         {
	//           "$patch": "replace"
	//         }
	//       ]
	//     }
	//   }

	var patchMap map[string]interface{}
	if err := json.Unmarshal(patchBytes, &patchMap); err != nil {
		return nil, err
	}

	addrBytes, err := json.Marshal(addresses)
	if err != nil {
		return nil, err
	}
	var addrArray []interface{}
	if err := json.Unmarshal(addrBytes, &addrArray); err != nil {
		return nil, err
	}
	addrArray = append(addrArray, map[string]interface{}{"$patch": "replace"})

	status := patchMap["status"]
	if status == nil {
		status = map[string]interface{}{}
		patchMap["status"] = status
	}
	statusMap, ok := status.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected data in patch")
	}
	statusMap["addresses"] = addrArray

	return json.Marshal(patchMap)
}

// ParseNodeIPs parses the kubelet --node-ips argument or the corresponding Node
// annotation. rawNodeIPs should consist of one or two elements, where each element is
// either an IP address or the string "ipv4" or "ipv6". If it contains two elements, one
// must be IPv4 and the other IPv6. In the returned array, the strings "ipv4" and "ipv6"
// are replaced with the corresponding unspecified IP address for that family.
func ParseNodeIPs(rawNodeIPs string) ([]net.IP, error) {
	if rawNodeIPs == "" {
		return []net.IP{net.IPv4zero, net.IPv6zero}, nil
	}

	var nodeIPs []net.IP
	var haveIPv4, haveIPv6 bool
	for _, nodeIP := range strings.Split(rawNodeIPs, ",") {
		var ip net.IP
		nodeIP = strings.TrimSpace(nodeIP)
		if strings.ToLower(nodeIP) == "ipv4" {
			ip = net.IPv4zero
			haveIPv4 = true
		} else if strings.ToLower(nodeIP) == "ipv6" {
			ip = net.IPv6zero
			haveIPv6 = true
		} else {
			ip = net.ParseIP(nodeIP)
			if ip == nil {
				return nil, fmt.Errorf("bad --node-ips value %q; should be %q, %q, or an IP address", nodeIP, "ipv4", "ipv6")
			}
			if utilnet.IsIPv6(ip) {
				haveIPv6 = true
			} else {
				haveIPv4 = true
			}
		}
		nodeIPs = append(nodeIPs, ip)
	}

	if len(nodeIPs) > 2 {
		return nil, fmt.Errorf("bad --node-ips value %q; should be 1 or 2 values", rawNodeIPs)
	} else if len(nodeIPs) == 2 && !(haveIPv4 && haveIPv6) {
		return nil, fmt.Errorf("bad --node-ips value %q; should have one IPv4 and one IPv6 value", rawNodeIPs)
	}

	return nodeIPs, nil
}

// ipMatches returns true if actualIP matches requestedIP (a single element of the parsed --node-ips value)
func ipMatches(actualIP, requestedIP net.IP) bool {
	if requestedIP.IsUnspecified() {
		return utilnet.IsIPv6(requestedIP) == utilnet.IsIPv6(actualIP)
	} else {
		return actualIP.Equal(requestedIP)
	}
}

// ipsMatch returns true if actualIPs matches requestedIPs (the parsed --node-ips value)
func ipsMatch(actualNodeIPs, requestedNodeIPs []net.IP) bool {
	switch {
	case len(actualNodeIPs) == len(requestedNodeIPs):
		// Each actual node IP must match the corresponding requested node IP.
		for n := range actualNodeIPs {
			if !ipMatches(actualNodeIPs[n], requestedNodeIPs[n]) {
				return false
			}
		}
		return true

	case len(actualNodeIPs) == 1 && len(requestedNodeIPs) == 2:
		// The actual node IP must match one of the requested node IPs, and the other
		// requested node IP must be unspecified. (eg, actual=1.2.3.4 requested=ipv4,ipv6)
		if ipMatches(actualNodeIPs[0], requestedNodeIPs[0]) && requestedNodeIPs[1].IsUnspecified() {
			return true
		}
		if requestedNodeIPs[0].IsUnspecified() && ipMatches(actualNodeIPs[0], requestedNodeIPs[1]) {
			return true
		}
		return false

	default:
		return false
	}
}

// FixUpNodeAddresses is the function used by kubelet and external cloud providers to
// filter and sort the raw list of node addresses based on the provided --node-ips
// argument before setting it on Node.Status.Addresses, ensuring that:
//
//   - If nodeIPs has only 1 element then the returned list will not contain any
//     addresses of the opposite family.
//
//   - The returned list does not contain any syntactically incorrect InternalIP or
//     ExternalIP addresses.
//
//   - If nodeIPs specifies particular IP address or address family preferences,
//     the returned list will be sorted in a way such that GetNodeHostIPs() will
//     return addresses satisfying those preferences.
//
// If it is not possible to make nodeAddresses reflect the preferences in nodeIPs, an
// error will be returned.
func FixUpNodeAddresses(nodeAddresses []v1.NodeAddress, nodeIPs string) ([]v1.NodeAddress, error) {
	requestedNodeIPs, err := ParseNodeIPs(nodeIPs)
	if err != nil {
		return nil, err
	}

	// If nodeIPs is a single element then we need to drop IPs of the non-matching family from
	// nodeAddresses.
	var dropIPv4, dropIPv6 bool
	if len(requestedNodeIPs) == 1 {
		dropIPv4 = utilnet.IsIPv6(requestedNodeIPs[0])
		dropIPv6 = !dropIPv4
	}

	// bestMatch is the best match in result for each requestedNodeIP
	var bestMatch [2]*v1.NodeAddress

	// Filter/sanitize/inspect nodeAddresses
	result := make([]v1.NodeAddress, 0, len(nodeAddresses))
	for _, addr := range nodeAddresses {
		if addr.Type != v1.NodeInternalIP && addr.Type != v1.NodeExternalIP {
			result = append(result, addr)
			continue
		}

		ip := net.ParseIP(addr.Address)
		if ip == nil {
			klog.Warningf("Ignoring invalid IP address %q from cloud provider", addr.Address)
			continue
		}
		isIPv6 := utilnet.IsIPv6(ip)
		if (isIPv6 && dropIPv6) || (!isIPv6 && dropIPv4) {
			continue
		}

		result = append(result, addr)

		for n := range requestedNodeIPs {
			if bestMatch[n] == nil || (bestMatch[n].Type == v1.NodeExternalIP && addr.Type == v1.NodeInternalIP) {
				if ipMatches(ip, requestedNodeIPs[n]) {
					copy := addr
					bestMatch[n] = &copy
				}
			}
		}
	}

	// Bail out if there are no matches at all, or no matches for a required IP
	if bestMatch[0] == nil && !requestedNodeIPs[0].IsUnspecified() {
		return nil, fmt.Errorf("node has no IP matching %q", requestedNodeIPs[0].String())
	} else if bestMatch[1] == nil && len(requestedNodeIPs) == 2 && !requestedNodeIPs[1].IsUnspecified() {
		return nil, fmt.Errorf("node has no IP matching %q", requestedNodeIPs[1].String())
	} else if bestMatch[0] == nil && bestMatch[1] == nil {
		return nil, fmt.Errorf("node has no IPs matching %q", nodeIPs)
	}

	// See if we already have a valid configuration
	actualNodeIPs, _ := getNodeHostIPs(result)
	if ipsMatch(actualNodeIPs, requestedNodeIPs) {
		return result, nil
	}

	// Sort with bestMatch[0] first (if it's set), then bestMatch[1] (if it's set), then
	// everything else in the existing order.
	sort.SliceStable(result, func(i, j int) bool {
		// bestMatch[0] is less than everything else
		if bestMatch[0] != nil {
			if result[i] == *bestMatch[0] {
				return true
			} else if result[j] == *bestMatch[0] {
				return false
			}
		}
		// bestMatch[1] is less than everything that isn't bestMatch[0]
		if bestMatch[1] != nil {
			if result[i] == *bestMatch[1] {
				return true
			} else if result[j] == *bestMatch[1] {
				return false
			}
		}
		// everything else is unordered/stable
		return false
	})

	actualNodeIPs, _ = getNodeHostIPs(result)
	if !ipsMatch(actualNodeIPs, requestedNodeIPs) {
		return nil, fmt.Errorf("could not rearrange node IPs to match %q", nodeIPs)
	}

	return result, nil
}
