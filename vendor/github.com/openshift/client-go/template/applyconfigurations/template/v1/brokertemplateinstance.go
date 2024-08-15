// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	apitemplatev1 "github.com/openshift/api/template/v1"
	internal "github.com/openshift/client-go/template/applyconfigurations/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	managedfields "k8s.io/apimachinery/pkg/util/managedfields"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// BrokerTemplateInstanceApplyConfiguration represents a declarative configuration of the BrokerTemplateInstance type for use
// with apply.
type BrokerTemplateInstanceApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Spec                             *BrokerTemplateInstanceSpecApplyConfiguration `json:"spec,omitempty"`
}

// BrokerTemplateInstance constructs a declarative configuration of the BrokerTemplateInstance type for use with
// apply.
func BrokerTemplateInstance(name string) *BrokerTemplateInstanceApplyConfiguration {
	b := &BrokerTemplateInstanceApplyConfiguration{}
	b.WithName(name)
	b.WithKind("BrokerTemplateInstance")
	b.WithAPIVersion("template.openshift.io/v1")
	return b
}

// ExtractBrokerTemplateInstance extracts the applied configuration owned by fieldManager from
// brokerTemplateInstance. If no managedFields are found in brokerTemplateInstance for fieldManager, a
// BrokerTemplateInstanceApplyConfiguration is returned with only the Name, Namespace (if applicable),
// APIVersion and Kind populated. It is possible that no managed fields were found for because other
// field managers have taken ownership of all the fields previously owned by fieldManager, or because
// the fieldManager never owned fields any fields.
// brokerTemplateInstance must be a unmodified BrokerTemplateInstance API object that was retrieved from the Kubernetes API.
// ExtractBrokerTemplateInstance provides a way to perform a extract/modify-in-place/apply workflow.
// Note that an extracted apply configuration will contain fewer fields than what the fieldManager previously
// applied if another fieldManager has updated or force applied any of the previously applied fields.
// Experimental!
func ExtractBrokerTemplateInstance(brokerTemplateInstance *apitemplatev1.BrokerTemplateInstance, fieldManager string) (*BrokerTemplateInstanceApplyConfiguration, error) {
	return extractBrokerTemplateInstance(brokerTemplateInstance, fieldManager, "")
}

// ExtractBrokerTemplateInstanceStatus is the same as ExtractBrokerTemplateInstance except
// that it extracts the status subresource applied configuration.
// Experimental!
func ExtractBrokerTemplateInstanceStatus(brokerTemplateInstance *apitemplatev1.BrokerTemplateInstance, fieldManager string) (*BrokerTemplateInstanceApplyConfiguration, error) {
	return extractBrokerTemplateInstance(brokerTemplateInstance, fieldManager, "status")
}

func extractBrokerTemplateInstance(brokerTemplateInstance *apitemplatev1.BrokerTemplateInstance, fieldManager string, subresource string) (*BrokerTemplateInstanceApplyConfiguration, error) {
	b := &BrokerTemplateInstanceApplyConfiguration{}
	err := managedfields.ExtractInto(brokerTemplateInstance, internal.Parser().Type("com.github.openshift.api.template.v1.BrokerTemplateInstance"), fieldManager, b, subresource)
	if err != nil {
		return nil, err
	}
	b.WithName(brokerTemplateInstance.Name)

	b.WithKind("BrokerTemplateInstance")
	b.WithAPIVersion("template.openshift.io/v1")
	return b, nil
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithKind(value string) *BrokerTemplateInstanceApplyConfiguration {
	b.Kind = &value
	return b
}

// WithAPIVersion sets the APIVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the APIVersion field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithAPIVersion(value string) *BrokerTemplateInstanceApplyConfiguration {
	b.APIVersion = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithName(value string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Name = &value
	return b
}

// WithGenerateName sets the GenerateName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GenerateName field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithGenerateName(value string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.GenerateName = &value
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithNamespace(value string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Namespace = &value
	return b
}

// WithUID sets the UID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UID field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithUID(value types.UID) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.UID = &value
	return b
}

// WithResourceVersion sets the ResourceVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceVersion field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithResourceVersion(value string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.ResourceVersion = &value
	return b
}

// WithGeneration sets the Generation field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Generation field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithGeneration(value int64) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Generation = &value
	return b
}

// WithCreationTimestamp sets the CreationTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CreationTimestamp field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithCreationTimestamp(value metav1.Time) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.CreationTimestamp = &value
	return b
}

// WithDeletionTimestamp sets the DeletionTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionTimestamp field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithDeletionTimestamp(value metav1.Time) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionTimestamp = &value
	return b
}

// WithDeletionGracePeriodSeconds sets the DeletionGracePeriodSeconds field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionGracePeriodSeconds field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithDeletionGracePeriodSeconds(value int64) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionGracePeriodSeconds = &value
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *BrokerTemplateInstanceApplyConfiguration) WithLabels(entries map[string]string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *BrokerTemplateInstanceApplyConfiguration) WithAnnotations(entries map[string]string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithOwnerReferences adds the given value to the OwnerReferences field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the OwnerReferences field.
func (b *BrokerTemplateInstanceApplyConfiguration) WithOwnerReferences(values ...*v1.OwnerReferenceApplyConfiguration) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithOwnerReferences")
		}
		b.OwnerReferences = append(b.OwnerReferences, *values[i])
	}
	return b
}

// WithFinalizers adds the given value to the Finalizers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Finalizers field.
func (b *BrokerTemplateInstanceApplyConfiguration) WithFinalizers(values ...string) *BrokerTemplateInstanceApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		b.Finalizers = append(b.Finalizers, values[i])
	}
	return b
}

func (b *BrokerTemplateInstanceApplyConfiguration) ensureObjectMetaApplyConfigurationExists() {
	if b.ObjectMetaApplyConfiguration == nil {
		b.ObjectMetaApplyConfiguration = &v1.ObjectMetaApplyConfiguration{}
	}
}

// WithSpec sets the Spec field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Spec field is set to the value of the last call.
func (b *BrokerTemplateInstanceApplyConfiguration) WithSpec(value *BrokerTemplateInstanceSpecApplyConfiguration) *BrokerTemplateInstanceApplyConfiguration {
	b.Spec = value
	return b
}

// GetName retrieves the value of the Name field in the declarative configuration.
func (b *BrokerTemplateInstanceApplyConfiguration) GetName() *string {
	b.ensureObjectMetaApplyConfigurationExists()
	return b.Name
}
