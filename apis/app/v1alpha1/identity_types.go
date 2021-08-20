/*
Copyright 2020-2021 The UnDistro authors

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

package v1alpha1

import (
	"github.com/getupio-undistro/undistro/pkg/meta"
	supervisoridpv1aplha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FederationDomain struct {
	Issuer        string `json:"issuer,omitempty"`
	TLSSecretName string `json:"tlsSecretName,omitempty"`
}

type OIDCProviderName string

const (
	Gitlab OIDCProviderName = "gitlab"
	Google OIDCProviderName = "google"
	Azure  OIDCProviderName = "azure"
)

// IdentitySpec defines the desired state of Identity
type IdentitySpec struct {
	// Pause Identity reconciliation
	Paused bool `json:"paused,omitempty"`

	// OIDCIdentityProvider describes the configuration of an upstream OpenID Connect identity provider.
	OIDCIdentityProvider supervisoridpv1aplha1.OIDCIdentityProvider `json:"oidcProvider,omitempty"`

	// ClusterName is the name of the cluster to which this identity belongs
	ClusterName string `json:"clusterName,omitempty"`

	// Local activate local authenticator with user and password
	Local bool `json:"local,omitempty"`
}

// IdentityStatus defines the observed state of Identity
type IdentityStatus struct {
	// ObservedGeneration is the last observed generation.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

//+genclient
//+kubebuilder:object:root=true
//+kubebuilder:resource:shortName=id
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Cluster Name",type="string",JSONPath=".spec.ClusterName",description="shows the cluster that the identity belongs"
//+kubebuilder:printcolumn:name="Paused",type="string",JSONPath=".spec.Paused",description="shows if the identity object is paused"
//+kubebuilder:printcolumn:name="Local",type="string",JSONPath=".spec.Local",description=""
//+kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// Identity is the Schema for the identities API
type Identity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IdentitySpec   `json:"spec,omitempty"`
	Status IdentityStatus `json:"status,omitempty"`
}

// IdentityPaused registers a paused reconciliation of the given Cluster.
func IdentityPaused(i Identity) *Identity {
	meta.SetResourceCondition(&i, meta.ReadyCondition, metav1.ConditionTrue, meta.ReconciliationPausedReason, meta.ReconciliationPausedReason)
	return &i
}

func (i *Identity) GetStatusConditions() *[]metav1.Condition {
	return &i.Status.Conditions
}

//+kubebuilder:object:root=true

// IdentityList contains a list of Identity
type IdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Identity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Identity{}, &IdentityList{})
}
