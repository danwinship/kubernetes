// Code generated by applyconfiguration-gen. DO NOT EDIT.

package internal

import (
	"fmt"
	"sync"

	typed "sigs.k8s.io/structured-merge-diff/v4/typed"
)

func Parser() *typed.Parser {
	parserOnce.Do(func() {
		var err error
		parser, err = typed.NewParser(schemaYAML)
		if err != nil {
			panic(fmt.Sprintf("Failed to parse schema: %v", err))
		}
	})
	return parser
}

var parserOnce sync.Once
var parser *typed.Parser
var schemaYAML = typed.YAMLObject(`types:
- name: com.github.openshift.api.quota.v1.ClusterResourceQuota
  map:
    fields:
    - name: apiVersion
      type:
        scalar: string
    - name: kind
      type:
        scalar: string
    - name: metadata
      type:
        namedType: io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta
      default: {}
    - name: spec
      type:
        namedType: com.github.openshift.api.quota.v1.ClusterResourceQuotaSpec
      default: {}
    - name: status
      type:
        namedType: com.github.openshift.api.quota.v1.ClusterResourceQuotaStatus
      default: {}
- name: com.github.openshift.api.quota.v1.ClusterResourceQuotaSelector
  map:
    fields:
    - name: annotations
      type:
        map:
          elementType:
            scalar: string
    - name: labels
      type:
        namedType: io.k8s.apimachinery.pkg.apis.meta.v1.LabelSelector
- name: com.github.openshift.api.quota.v1.ClusterResourceQuotaSpec
  map:
    fields:
    - name: quota
      type:
        namedType: io.k8s.api.core.v1.ResourceQuotaSpec
      default: {}
    - name: selector
      type:
        namedType: com.github.openshift.api.quota.v1.ClusterResourceQuotaSelector
      default: {}
- name: com.github.openshift.api.quota.v1.ClusterResourceQuotaStatus
  map:
    fields:
    - name: namespaces
      type:
        list:
          elementType:
            namedType: com.github.openshift.api.quota.v1.ResourceQuotaStatusByNamespace
          elementRelationship: atomic
    - name: total
      type:
        namedType: io.k8s.api.core.v1.ResourceQuotaStatus
      default: {}
- name: com.github.openshift.api.quota.v1.ResourceQuotaStatusByNamespace
  map:
    fields:
    - name: namespace
      type:
        scalar: string
      default: ""
    - name: status
      type:
        namedType: io.k8s.api.core.v1.ResourceQuotaStatus
      default: {}
- name: io.k8s.api.core.v1.ResourceQuotaSpec
  map:
    fields:
    - name: hard
      type:
        map:
          elementType:
            namedType: io.k8s.apimachinery.pkg.api.resource.Quantity
    - name: scopeSelector
      type:
        namedType: io.k8s.api.core.v1.ScopeSelector
    - name: scopes
      type:
        list:
          elementType:
            scalar: string
          elementRelationship: atomic
- name: io.k8s.api.core.v1.ResourceQuotaStatus
  map:
    fields:
    - name: hard
      type:
        map:
          elementType:
            namedType: io.k8s.apimachinery.pkg.api.resource.Quantity
    - name: used
      type:
        map:
          elementType:
            namedType: io.k8s.apimachinery.pkg.api.resource.Quantity
- name: io.k8s.api.core.v1.ScopeSelector
  map:
    fields:
    - name: matchExpressions
      type:
        list:
          elementType:
            namedType: io.k8s.api.core.v1.ScopedResourceSelectorRequirement
          elementRelationship: atomic
    elementRelationship: atomic
- name: io.k8s.api.core.v1.ScopedResourceSelectorRequirement
  map:
    fields:
    - name: operator
      type:
        scalar: string
      default: ""
    - name: scopeName
      type:
        scalar: string
      default: ""
    - name: values
      type:
        list:
          elementType:
            scalar: string
          elementRelationship: atomic
- name: io.k8s.apimachinery.pkg.api.resource.Quantity
  scalar: untyped
- name: io.k8s.apimachinery.pkg.apis.meta.v1.FieldsV1
  map:
    elementType:
      scalar: untyped
      list:
        elementType:
          namedType: __untyped_atomic_
        elementRelationship: atomic
      map:
        elementType:
          namedType: __untyped_deduced_
        elementRelationship: separable
- name: io.k8s.apimachinery.pkg.apis.meta.v1.LabelSelector
  map:
    fields:
    - name: matchExpressions
      type:
        list:
          elementType:
            namedType: io.k8s.apimachinery.pkg.apis.meta.v1.LabelSelectorRequirement
          elementRelationship: atomic
    - name: matchLabels
      type:
        map:
          elementType:
            scalar: string
    elementRelationship: atomic
- name: io.k8s.apimachinery.pkg.apis.meta.v1.LabelSelectorRequirement
  map:
    fields:
    - name: key
      type:
        scalar: string
      default: ""
    - name: operator
      type:
        scalar: string
      default: ""
    - name: values
      type:
        list:
          elementType:
            scalar: string
          elementRelationship: atomic
- name: io.k8s.apimachinery.pkg.apis.meta.v1.ManagedFieldsEntry
  map:
    fields:
    - name: apiVersion
      type:
        scalar: string
    - name: fieldsType
      type:
        scalar: string
    - name: fieldsV1
      type:
        namedType: io.k8s.apimachinery.pkg.apis.meta.v1.FieldsV1
    - name: manager
      type:
        scalar: string
    - name: operation
      type:
        scalar: string
    - name: subresource
      type:
        scalar: string
    - name: time
      type:
        namedType: io.k8s.apimachinery.pkg.apis.meta.v1.Time
- name: io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta
  map:
    fields:
    - name: annotations
      type:
        map:
          elementType:
            scalar: string
    - name: creationTimestamp
      type:
        namedType: io.k8s.apimachinery.pkg.apis.meta.v1.Time
    - name: deletionGracePeriodSeconds
      type:
        scalar: numeric
    - name: deletionTimestamp
      type:
        namedType: io.k8s.apimachinery.pkg.apis.meta.v1.Time
    - name: finalizers
      type:
        list:
          elementType:
            scalar: string
          elementRelationship: associative
    - name: generateName
      type:
        scalar: string
    - name: generation
      type:
        scalar: numeric
    - name: labels
      type:
        map:
          elementType:
            scalar: string
    - name: managedFields
      type:
        list:
          elementType:
            namedType: io.k8s.apimachinery.pkg.apis.meta.v1.ManagedFieldsEntry
          elementRelationship: atomic
    - name: name
      type:
        scalar: string
    - name: namespace
      type:
        scalar: string
    - name: ownerReferences
      type:
        list:
          elementType:
            namedType: io.k8s.apimachinery.pkg.apis.meta.v1.OwnerReference
          elementRelationship: associative
          keys:
          - uid
    - name: resourceVersion
      type:
        scalar: string
    - name: selfLink
      type:
        scalar: string
    - name: uid
      type:
        scalar: string
- name: io.k8s.apimachinery.pkg.apis.meta.v1.OwnerReference
  map:
    fields:
    - name: apiVersion
      type:
        scalar: string
      default: ""
    - name: blockOwnerDeletion
      type:
        scalar: boolean
    - name: controller
      type:
        scalar: boolean
    - name: kind
      type:
        scalar: string
      default: ""
    - name: name
      type:
        scalar: string
      default: ""
    - name: uid
      type:
        scalar: string
      default: ""
    elementRelationship: atomic
- name: io.k8s.apimachinery.pkg.apis.meta.v1.Time
  scalar: untyped
- name: __untyped_atomic_
  scalar: untyped
  list:
    elementType:
      namedType: __untyped_atomic_
    elementRelationship: atomic
  map:
    elementType:
      namedType: __untyped_atomic_
    elementRelationship: atomic
- name: __untyped_deduced_
  scalar: untyped
  list:
    elementType:
      namedType: __untyped_atomic_
    elementRelationship: atomic
  map:
    elementType:
      namedType: __untyped_deduced_
    elementRelationship: separable
`)
