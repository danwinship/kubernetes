/*
Copyright 2017 The Kubernetes Authors.

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

package validation

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	componentbaseconfig "k8s.io/component-base/config"
	logsapi "k8s.io/component-base/logs/api/v1"
	"k8s.io/component-base/metrics"
	apivalidation "k8s.io/kubernetes/pkg/apis/core/validation"
	"k8s.io/kubernetes/pkg/features"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	netutils "k8s.io/utils/net"
)

// Validate validates the configuration of kube-proxy
func Validate(config *kubeproxyconfig.KubeProxyConfiguration) field.ErrorList {
	allErrs := field.ErrorList{}

	newPath := field.NewPath("KubeProxyConfiguration")

	effectiveFeatures := utilfeature.DefaultFeatureGate.DeepCopy()
	if err := effectiveFeatures.SetFromMap(config.FeatureGates); err != nil {
		allErrs = append(allErrs, field.Invalid(newPath.Child("featureGates"), config.FeatureGates, err.Error()))
	}

	allErrs = append(allErrs, validateKubeProxyIPTablesConfiguration(config.IPTables, newPath.Child("KubeProxyIPTablesConfiguration"))...)
	switch config.Mode {
	case kubeproxyconfig.ProxyModeIPVS:
		allErrs = append(allErrs, validateKubeProxyIPVSConfiguration(config.IPVS, newPath.Child("KubeProxyIPVSConfiguration"))...)
	case kubeproxyconfig.ProxyModeNFTables:
		allErrs = append(allErrs, validateKubeProxyNFTablesConfiguration(config.NFTables, newPath.Child("KubeProxyNFTablesConfiguration"))...)
	}
	allErrs = append(allErrs, validateKubeProxyConntrackConfiguration(config.Conntrack, newPath.Child("KubeProxyConntrackConfiguration"))...)
	allErrs = append(allErrs, validateProxyMode(config.Mode, newPath.Child("Mode"))...)
	allErrs = append(allErrs, validateClientConnectionConfiguration(config.ClientConnection, newPath.Child("ClientConnection"))...)

	if config.OOMScoreAdj != nil && (*config.OOMScoreAdj < -1000 || *config.OOMScoreAdj > 1000) {
		allErrs = append(allErrs, field.Invalid(newPath.Child("OOMScoreAdj"), *config.OOMScoreAdj, "must be within the range [-1000, 1000]"))
	}

	if config.ConfigSyncPeriod.Duration <= 0 {
		allErrs = append(allErrs, field.Invalid(newPath.Child("ConfigSyncPeriod"), config.ConfigSyncPeriod, "must be greater than 0"))
	}

	for _, msg := range validation.IsValidIP(config.BindAddress) {
		allErrs = append(allErrs, field.Invalid(newPath.Child("BindAddress"), config.BindAddress, msg))
	}

	if config.HealthzBindAddress != "" {
		allErrs = append(allErrs, validateHostPort(config.HealthzBindAddress, newPath.Child("HealthzBindAddress"))...)
	}
	allErrs = append(allErrs, validateHostPort(config.MetricsBindAddress, newPath.Child("MetricsBindAddress"))...)

	if config.ClusterCIDR != "" {
		cidrs := strings.Split(config.ClusterCIDR, ",")
		switch {
		case len(cidrs) > 2:
			allErrs = append(allErrs, field.Invalid(newPath.Child("ClusterCIDR"), config.ClusterCIDR, "only one CIDR allowed or a valid DualStack CIDR (e.g. 10.100.0.0/16,fde4:8dba:82e1::/48)"))
		// if DualStack and two cidrs validate if there is at least one of each IP family
		case len(cidrs) == 2:
			isDual, err := netutils.IsDualStackCIDRStrings(cidrs)
			if err != nil || !isDual {
				allErrs = append(allErrs, field.Invalid(newPath.Child("ClusterCIDR"), config.ClusterCIDR, "must be a valid DualStack CIDR (e.g. 10.100.0.0/16,fde4:8dba:82e1::/48)"))
			}
		// if we are here means that len(cidrs) == 1, we need to validate it
		default:
			for _, msg := range validation.IsValidCIDR(config.ClusterCIDR) {
				allErrs = append(allErrs, field.Invalid(newPath.Child("ClusterCIDR"), config.ClusterCIDR, msg)
			}
		}
	}

	if _, err := utilnet.ParsePortRange(config.PortRange); err != nil {
		allErrs = append(allErrs, field.Invalid(newPath.Child("PortRange"), config.PortRange, "must be a valid port range (e.g. 300-2000)"))
	}

	allErrs = append(allErrs, validateKubeProxyNodePortAddress(config.NodePortAddresses, newPath.Child("NodePortAddresses"))...)
	allErrs = append(allErrs, validateShowHiddenMetricsVersion(config.ShowHiddenMetricsForVersion, newPath.Child("ShowHiddenMetricsForVersion"))...)

	allErrs = append(allErrs, validateDetectLocalMode(config.DetectLocalMode, newPath.Child("DetectLocalMode"))...)
	if config.DetectLocalMode == kubeproxyconfig.LocalModeBridgeInterface {
		allErrs = append(allErrs, validateInterface(config.DetectLocal.BridgeInterface, newPath.Child("InterfaceName"))...)
	}
	if config.DetectLocalMode == kubeproxyconfig.LocalModeInterfaceNamePrefix {
		allErrs = append(allErrs, validateInterface(config.DetectLocal.InterfaceNamePrefix, newPath.Child("InterfacePrefix"))...)
	}
	allErrs = append(allErrs, logsapi.Validate(&config.Logging, effectiveFeatures, newPath.Child("logging"))...)

	return allErrs
}

func validateKubeProxyIPTablesConfiguration(config kubeproxyconfig.KubeProxyIPTablesConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if config.MasqueradeBit != nil && (*config.MasqueradeBit < 0 || *config.MasqueradeBit > 31) {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("MasqueradeBit"), config.MasqueradeBit, "must be within the range [0, 31]"))
	}

	if config.SyncPeriod.Duration <= 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("SyncPeriod"), config.SyncPeriod, "must be greater than 0"))
	}

	if config.MinSyncPeriod.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("MinSyncPeriod"), config.MinSyncPeriod, "must be greater than or equal to 0"))
	}

	if config.MinSyncPeriod.Duration > config.SyncPeriod.Duration {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("SyncPeriod"), config.MinSyncPeriod, fmt.Sprintf("must be greater than or equal to %s", fldPath.Child("MinSyncPeriod").String())))
	}

	return allErrs
}

func validateKubeProxyIPVSConfiguration(config kubeproxyconfig.KubeProxyIPVSConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if config.SyncPeriod.Duration <= 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("SyncPeriod"), config.SyncPeriod, "must be greater than 0"))
	}

	if config.MinSyncPeriod.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("MinSyncPeriod"), config.MinSyncPeriod, "must be greater than or equal to 0"))
	}

	if config.MinSyncPeriod.Duration > config.SyncPeriod.Duration {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("SyncPeriod"), config.MinSyncPeriod, fmt.Sprintf("must be greater than or equal to %s", fldPath.Child("MinSyncPeriod").String())))
	}

	allErrs = append(allErrs, validateIPVSTimeout(config, fldPath)...)
	allErrs = append(allErrs, validateIPVSExcludeCIDRs(config.ExcludeCIDRs, fldPath.Child("ExcludeCidrs"))...)

	return allErrs
}

func validateKubeProxyNFTablesConfiguration(config kubeproxyconfig.KubeProxyNFTablesConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if config.MasqueradeBit != nil && (*config.MasqueradeBit < 0 || *config.MasqueradeBit > 31) {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("MasqueradeBit"), config.MasqueradeBit, "must be within the range [0, 31]"))
	}

	if config.SyncPeriod.Duration <= 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("SyncPeriod"), config.SyncPeriod, "must be greater than 0"))
	}

	if config.MinSyncPeriod.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("MinSyncPeriod"), config.MinSyncPeriod, "must be greater than or equal to 0"))
	}

	if config.MinSyncPeriod.Duration > config.SyncPeriod.Duration {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("SyncPeriod"), config.MinSyncPeriod, fmt.Sprintf("must be greater than or equal to %s", fldPath.Child("MinSyncPeriod").String())))
	}

	return allErrs
}

func validateKubeProxyConntrackConfiguration(config kubeproxyconfig.KubeProxyConntrackConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if config.MaxPerCore != nil && *config.MaxPerCore < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("MaxPerCore"), config.MaxPerCore, "must be greater than or equal to 0"))
	}

	if config.Min != nil && *config.Min < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("Min"), config.Min, "must be greater than or equal to 0"))
	}

	// config.TCPEstablishedTimeout has a default value, so can't be nil.
	if config.TCPEstablishedTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("TCPEstablishedTimeout"), config.TCPEstablishedTimeout, "must be greater than or equal to 0"))
	}

	// config.TCPCloseWaitTimeout has a default value, so can't be nil.
	if config.TCPCloseWaitTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("TCPCloseWaitTimeout"), config.TCPCloseWaitTimeout, "must be greater than or equal to 0"))
	}

	if config.UDPTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("UDPTimeout"), config.UDPTimeout, "must be greater than or equal to 0"))
	}

	if config.UDPStreamTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("UDPStreamTimeout"), config.UDPStreamTimeout, "must be greater than or equal to 0"))
	}

	return allErrs
}

func validateProxyMode(mode kubeproxyconfig.ProxyMode, fldPath *field.Path) field.ErrorList {
	if runtime.GOOS == "windows" {
		return validateProxyModeWindows(mode, fldPath)
	}

	return validateProxyModeLinux(mode, fldPath)
}

func validateProxyModeLinux(mode kubeproxyconfig.ProxyMode, fldPath *field.Path) field.ErrorList {
	validModes := sets.New[string](
		string(kubeproxyconfig.ProxyModeIPTables),
		string(kubeproxyconfig.ProxyModeIPVS),
	)

	if utilfeature.DefaultFeatureGate.Enabled(features.NFTablesProxyMode) {
		validModes.Insert(string(kubeproxyconfig.ProxyModeNFTables))
	}

	if mode == "" || validModes.Has(string(mode)) {
		return nil
	}

	errMsg := fmt.Sprintf("must be %s or blank (blank means the best-available proxy [currently iptables])", strings.Join(sets.List(validModes), ", "))
	return field.ErrorList{field.Invalid(fldPath.Child("ProxyMode"), string(mode), errMsg)}
}

func validateProxyModeWindows(mode kubeproxyconfig.ProxyMode, fldPath *field.Path) field.ErrorList {
	validModes := sets.New[string](
		string(kubeproxyconfig.ProxyModeKernelspace),
	)

	if mode == "" || validModes.Has(string(mode)) {
		return nil
	}

	errMsg := fmt.Sprintf("must be %s or blank (blank means the most-available proxy [currently 'kernelspace'])", strings.Join(sets.List(validModes), ", "))
	return field.ErrorList{field.Invalid(fldPath.Child("ProxyMode"), string(mode), errMsg)}
}

func validateDetectLocalMode(mode kubeproxyconfig.LocalMode, fldPath *field.Path) field.ErrorList {
	validModes := []string{
		string(kubeproxyconfig.LocalModeClusterCIDR),
		string(kubeproxyconfig.LocalModeNodeCIDR),
		string(kubeproxyconfig.LocalModeBridgeInterface),
		string(kubeproxyconfig.LocalModeInterfaceNamePrefix),
		"",
	}

	if sets.New(validModes...).Has(string(mode)) {
		return nil
	}

	return field.ErrorList{field.NotSupported(fldPath, string(mode), validModes)}
}

func validateClientConnectionConfiguration(config componentbaseconfig.ClientConnectionConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	allErrs = append(allErrs, apivalidation.ValidateNonnegativeField(int64(config.Burst), fldPath.Child("Burst"))...)
	return allErrs
}

func validateHostPort(input string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	hostIP, port, err := net.SplitHostPort(input)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, input, "must be IP:port"))
		return allErrs
	}

	for _, msg := range validation.IsValidIP(hostIP) {
		allErrs = append(allErrs, field.Invalid(fldPath, hostIP, msg)
	}

	if p, err := strconv.Atoi(port); err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, port, "must be a valid port"))
	} else if p < 1 || p > 65535 {
		allErrs = append(allErrs, field.Invalid(fldPath, port, "must be a valid port"))
	}

	return allErrs
}

func validateKubeProxyNodePortAddress(nodePortAddresses []string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i := range nodePortAddresses {
		for _, msg := range validation.IsValidCIDR(nodePortAddresses[i]) {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i), nodePortAddresses[i], msg))
		}
	}

	return allErrs
}

func validateIPVSTimeout(config kubeproxyconfig.KubeProxyIPVSConfiguration, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if config.TCPTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("TCPTimeout"), config.TCPTimeout, "must be greater than or equal to 0"))
	}

	if config.TCPFinTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("TCPFinTimeout"), config.TCPFinTimeout, "must be greater than or equal to 0"))
	}

	if config.UDPTimeout.Duration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("UDPTimeout"), config.UDPTimeout, "must be greater than or equal to 0"))
	}

	return allErrs
}

func validateIPVSExcludeCIDRs(excludeCIDRs []string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i := range excludeCIDRs {
		for _, msg := range validation.IsValidCIDR(excludeCIDRs[i]) {
			allErrs = append(allErrs, field.Invalid(fldPath.Index(i), excludeCIDRs[i], msg))
		}
	}
	return allErrs
}

func validateShowHiddenMetricsVersion(version string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	errs := metrics.ValidateShowHiddenMetricsVersion(version)
	for _, e := range errs {
		allErrs = append(allErrs, field.Invalid(fldPath, version, e.Error()))
	}

	return allErrs
}

func validateInterface(iface string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if len(iface) == 0 {
		allErrs = append(allErrs, field.Invalid(fldPath, iface, "must not be empty"))
	}
	return allErrs
}
