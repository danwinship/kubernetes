package servicecidr

import (
	"context"
	"fmt"
	"io"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/apis/networking"
	"k8s.io/kubernetes/pkg/controlplane/controller/defaultservicecidr"
)

const ServiceCIDRPluginName = "network.openshift.io/ServiceCIDRAdmission"

func RegisterServiceCIDR(plugins *admission.Plugins) {
	plugins.Register(ServiceCIDRPluginName,
		func(config io.Reader) (admission.Interface, error) {
			return NewServiceCIDRAdmission(), nil
		})
}

type serviceCIDRAdmission struct {
	*admission.Handler
}

var _ = admission.ValidationInterface(&serviceCIDRAdmission{})

// NewServiceCIDRAdmission creates a new ServiceCIDR admission plugin.
func NewServiceCIDRAdmission() *serviceCIDRAdmission {
	return &serviceCIDRAdmission{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}

// Validate determines if the ServiceCIDR object should be admitted
func (r *serviceCIDRAdmission) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if a.GetResource().GroupResource() != networking.Resource("servicecidrs") {
		return nil
	}

	if a.GetName() == defaultservicecidr.DefaultServiceCIDRName {
		// We want to allow kube-apiserver to create this. Validation will
		// prevent anyone from modifying the CIDRs after it is created.
		return nil
	}

	// Block any additional ServiceCIDRs
	return admission.NewForbidden(a, fmt.Errorf("additional ServiceCIDRs are not supported in this cluster"))
}
