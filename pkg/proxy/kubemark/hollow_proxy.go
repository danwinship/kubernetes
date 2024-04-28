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

package kubemark

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/events"
	proxyapp "k8s.io/kubernetes/cmd/kube-proxy/app"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/utils/ptr"
)

type HollowProxy struct {
	ProxyServer *proxyapp.ProxyServer
}

func NewHollowProxy(
	nodeName string,
	client clientset.Interface,
	eventClient v1core.EventsGetter,
	broadcaster events.EventBroadcaster,
	recorder events.EventRecorder,
) *HollowProxy {
	return &HollowProxy{
		ProxyServer: &proxyapp.ProxyServer{
			Config: &proxyconfigapi.KubeProxyConfiguration{
				Mode:             proxyconfigapi.ProxyMode("fake"),
				ConfigSyncPeriod: metav1.Duration{Duration: 30 * time.Second},
				Linux: proxyconfigapi.KubeProxyLinuxConfiguration{
					OOMScoreAdj: ptr.To[int32](0),
				},
			},

			Client:      client,
			Backend:     proxy.NewBackend(nil, nil),
			Broadcaster: broadcaster,
			Recorder:    recorder,
			NodeRef: &v1.ObjectReference{
				Kind:      "Node",
				Name:      nodeName,
				UID:       types.UID(nodeName),
				Namespace: "",
			},
		},
	}
}

func (hp *HollowProxy) Run() error {

	if err := hp.ProxyServer.Run(context.TODO()); err != nil {
		return fmt.Errorf("Error while running proxy: %w", err)
	}
	return nil
}
