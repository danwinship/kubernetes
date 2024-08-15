// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/openshift/client-go/network/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// DNSNameResolvers returns a DNSNameResolverInformer.
	DNSNameResolvers() DNSNameResolverInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// DNSNameResolvers returns a DNSNameResolverInformer.
func (v *version) DNSNameResolvers() DNSNameResolverInformer {
	return &dNSNameResolverInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
