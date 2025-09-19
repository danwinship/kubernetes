/*
Copyright 2025 The Kubernetes Authors.

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

package kernel

import (
	"fmt"
	"os"
)

// CheckIPv6 checks that IPv6 is enabled at the kernel level. This does not imply that
// IPv6 is actually in use on the host, or that the host has IPv6 routing, but if this
// returns an error then it is likely that attempts to configure IPv6 addresses, routing,
// or iptables/nftables rules will fail.
func CheckIPv6() error {
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		return fmt.Errorf("no kernel support for IPv6")
	}
	return nil
}
