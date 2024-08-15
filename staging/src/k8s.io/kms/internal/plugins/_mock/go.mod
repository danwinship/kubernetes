module k8s.io/kms/plugins/mock

go 1.22.0

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	k8s.io/kms v0.0.0-00010101000000-000000000000
)

require (
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/grpc v1.65.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace k8s.io/kms => ../../../../kms

replace github.com/onsi/ginkgo/v2 => github.com/openshift/onsi-ginkgo/v2 v2.6.1-0.20240806135314-3946b2b7b2a8

replace github.com/openshift/api => github.com/atiratree/api v0.0.0-20240815160400-5b5d653b3369

replace github.com/openshift/apiserver-library-go => github.com/atiratree/apiserver-library-go v0.0.0-20240819192945-8e75bf27542f

replace github.com/openshift/client-go => github.com/atiratree/client-go v0.0.0-20240815161612-1bc9a0b37591

replace github.com/openshift/library-go => github.com/atiratree/library-go v0.0.0-20240815162203-33cdeb72a6e9
