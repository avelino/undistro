// +build !ignore_autogenerated

/*
Copyright 2020 Getup Cloud. All rights reserved.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BootstrapProvider) DeepCopyInto(out *BootstrapProvider) {
	*out = *in
	if in.Version != nil {
		in, out := &in.Version, &out.Version
		*out = new(string)
		**out = **in
	}
	if in.File != nil {
		in, out := &in.File, &out.File
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BootstrapProvider.
func (in *BootstrapProvider) DeepCopy() *BootstrapProvider {
	if in == nil {
		return nil
	}
	out := new(BootstrapProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ChartFileSelector) DeepCopyInto(out *ChartFileSelector) {
	*out = *in
	if in.Optional != nil {
		in, out := &in.Optional, &out.Optional
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ChartFileSelector.
func (in *ChartFileSelector) DeepCopy() *ChartFileSelector {
	if in == nil {
		return nil
	}
	out := new(ChartFileSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ChartSource) DeepCopyInto(out *ChartSource) {
	*out = *in
	out.RepoChartSource = in.RepoChartSource
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ChartSource.
func (in *ChartSource) DeepCopy() *ChartSource {
	if in == nil {
		return nil
	}
	out := new(ChartSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Cluster) DeepCopyInto(out *Cluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Cluster.
func (in *Cluster) DeepCopy() *Cluster {
	if in == nil {
		return nil
	}
	out := new(Cluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Cluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterList) DeepCopyInto(out *ClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Cluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterList.
func (in *ClusterList) DeepCopy() *ClusterList {
	if in == nil {
		return nil
	}
	out := new(ClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterSpec) DeepCopyInto(out *ClusterSpec) {
	*out = *in
	if in.Template != nil {
		in, out := &in.Template, &out.Template
		*out = new(string)
		**out = **in
	}
	in.InfrastructureProvider.DeepCopyInto(&out.InfrastructureProvider)
	if in.BootstrapProvider != nil {
		in, out := &in.BootstrapProvider, &out.BootstrapProvider
		*out = new(BootstrapProvider)
		(*in).DeepCopyInto(*out)
	}
	if in.ControlPlaneProvider != nil {
		in, out := &in.ControlPlaneProvider, &out.ControlPlaneProvider
		*out = new(ControlPlaneProvider)
		(*in).DeepCopyInto(*out)
	}
	in.ControlPlaneNode.DeepCopyInto(&out.ControlPlaneNode)
	in.WorkerNode.DeepCopyInto(&out.WorkerNode)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterSpec.
func (in *ClusterSpec) DeepCopy() *ClusterSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterStatus) DeepCopyInto(out *ClusterStatus) {
	*out = *in
	if in.InstalledComponents != nil {
		in, out := &in.InstalledComponents, &out.InstalledComponents
		*out = make([]InstalledComponent, len(*in))
		copy(*out, *in)
	}
	if in.ClusterAPIRef != nil {
		in, out := &in.ClusterAPIRef, &out.ClusterAPIRef
		*out = new(v1.ObjectReference)
		**out = **in
	}
	in.ControlPlaneNode.DeepCopyInto(&out.ControlPlaneNode)
	in.WorkerNode.DeepCopyInto(&out.WorkerNode)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterStatus.
func (in *ClusterStatus) DeepCopy() *ClusterStatus {
	if in == nil {
		return nil
	}
	out := new(ClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConfigMapKeySelector) DeepCopyInto(out *ConfigMapKeySelector) {
	*out = *in
	out.LocalObjectReference = in.LocalObjectReference
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConfigMapKeySelector.
func (in *ConfigMapKeySelector) DeepCopy() *ConfigMapKeySelector {
	if in == nil {
		return nil
	}
	out := new(ConfigMapKeySelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ControlPlaneProvider) DeepCopyInto(out *ControlPlaneProvider) {
	*out = *in
	if in.Version != nil {
		in, out := &in.Version, &out.Version
		*out = new(string)
		**out = **in
	}
	if in.File != nil {
		in, out := &in.File, &out.File
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ControlPlaneProvider.
func (in *ControlPlaneProvider) DeepCopy() *ControlPlaneProvider {
	if in == nil {
		return nil
	}
	out := new(ControlPlaneProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalSourceSelector) DeepCopyInto(out *ExternalSourceSelector) {
	*out = *in
	if in.Optional != nil {
		in, out := &in.Optional, &out.Optional
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalSourceSelector.
func (in *ExternalSourceSelector) DeepCopy() *ExternalSourceSelector {
	if in == nil {
		return nil
	}
	out := new(ExternalSourceSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HelmRelease) DeepCopyInto(out *HelmRelease) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HelmRelease.
func (in *HelmRelease) DeepCopy() *HelmRelease {
	if in == nil {
		return nil
	}
	out := new(HelmRelease)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HelmRelease) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HelmReleaseList) DeepCopyInto(out *HelmReleaseList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]HelmRelease, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HelmReleaseList.
func (in *HelmReleaseList) DeepCopy() *HelmReleaseList {
	if in == nil {
		return nil
	}
	out := new(HelmReleaseList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HelmReleaseList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HelmReleaseSpec) DeepCopyInto(out *HelmReleaseSpec) {
	*out = *in
	out.ChartSource = in.ChartSource
	if in.MaxHistory != nil {
		in, out := &in.MaxHistory, &out.MaxHistory
		*out = new(int)
		**out = **in
	}
	if in.ValuesFrom != nil {
		in, out := &in.ValuesFrom, &out.ValuesFrom
		*out = make([]ValuesFromSource, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(int64)
		**out = **in
	}
	if in.ResetValues != nil {
		in, out := &in.ResetValues, &out.ResetValues
		*out = new(bool)
		**out = **in
	}
	if in.Wait != nil {
		in, out := &in.Wait, &out.Wait
		*out = new(bool)
		**out = **in
	}
	in.Rollback.DeepCopyInto(&out.Rollback)
	in.Test.DeepCopyInto(&out.Test)
	if in.Values != nil {
		in, out := &in.Values, &out.Values
		*out = new(apiextensionsv1.JSON)
		(*in).DeepCopyInto(*out)
	}
	if in.BeforeApplyObjects != nil {
		in, out := &in.BeforeApplyObjects, &out.BeforeApplyObjects
		*out = make([]apiextensionsv1.JSON, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.AfterApplyObjects != nil {
		in, out := &in.AfterApplyObjects, &out.AfterApplyObjects
		*out = make([]apiextensionsv1.JSON, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HelmReleaseSpec.
func (in *HelmReleaseSpec) DeepCopy() *HelmReleaseSpec {
	if in == nil {
		return nil
	}
	out := new(HelmReleaseSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HelmReleaseStatus) DeepCopyInto(out *HelmReleaseStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HelmReleaseStatus.
func (in *HelmReleaseStatus) DeepCopy() *HelmReleaseStatus {
	if in == nil {
		return nil
	}
	out := new(HelmReleaseStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InfrastructureProvider) DeepCopyInto(out *InfrastructureProvider) {
	*out = *in
	if in.Version != nil {
		in, out := &in.Version, &out.Version
		*out = new(string)
		**out = **in
	}
	if in.File != nil {
		in, out := &in.File, &out.File
		*out = new(string)
		**out = **in
	}
	if in.Env != nil {
		in, out := &in.Env, &out.Env
		*out = make([]v1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InfrastructureProvider.
func (in *InfrastructureProvider) DeepCopy() *InfrastructureProvider {
	if in == nil {
		return nil
	}
	out := new(InfrastructureProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstalledComponent) DeepCopyInto(out *InstalledComponent) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstalledComponent.
func (in *InstalledComponent) DeepCopy() *InstalledComponent {
	if in == nil {
		return nil
	}
	out := new(InstalledComponent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LocalObjectReference) DeepCopyInto(out *LocalObjectReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalObjectReference.
func (in *LocalObjectReference) DeepCopy() *LocalObjectReference {
	if in == nil {
		return nil
	}
	out := new(LocalObjectReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Metadata) DeepCopyInto(out *Metadata) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.ReleaseSeries != nil {
		in, out := &in.ReleaseSeries, &out.ReleaseSeries
		*out = make([]ReleaseSeries, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Metadata.
func (in *Metadata) DeepCopy() *Metadata {
	if in == nil {
		return nil
	}
	out := new(Metadata)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Metadata) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Node) DeepCopyInto(out *Node) {
	*out = *in
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Node.
func (in *Node) DeepCopy() *Node {
	if in == nil {
		return nil
	}
	out := new(Node)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ObjectReference) DeepCopyInto(out *ObjectReference) {
	*out = *in
	out.LocalObjectReference = in.LocalObjectReference
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ObjectReference.
func (in *ObjectReference) DeepCopy() *ObjectReference {
	if in == nil {
		return nil
	}
	out := new(ObjectReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OptionalConfigMapKeySelector) DeepCopyInto(out *OptionalConfigMapKeySelector) {
	*out = *in
	out.ConfigMapKeySelector = in.ConfigMapKeySelector
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OptionalConfigMapKeySelector.
func (in *OptionalConfigMapKeySelector) DeepCopy() *OptionalConfigMapKeySelector {
	if in == nil {
		return nil
	}
	out := new(OptionalConfigMapKeySelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OptionalSecretKeySelector) DeepCopyInto(out *OptionalSecretKeySelector) {
	*out = *in
	out.SecretKeySelector = in.SecretKeySelector
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OptionalSecretKeySelector.
func (in *OptionalSecretKeySelector) DeepCopy() *OptionalSecretKeySelector {
	if in == nil {
		return nil
	}
	out := new(OptionalSecretKeySelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Provider) DeepCopyInto(out *Provider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Provider.
func (in *Provider) DeepCopy() *Provider {
	if in == nil {
		return nil
	}
	out := new(Provider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Provider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderList) DeepCopyInto(out *ProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Provider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderList.
func (in *ProviderList) DeepCopy() *ProviderList {
	if in == nil {
		return nil
	}
	out := new(ProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReleaseSeries) DeepCopyInto(out *ReleaseSeries) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReleaseSeries.
func (in *ReleaseSeries) DeepCopy() *ReleaseSeries {
	if in == nil {
		return nil
	}
	out := new(ReleaseSeries)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RepoChartSource) DeepCopyInto(out *RepoChartSource) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RepoChartSource.
func (in *RepoChartSource) DeepCopy() *RepoChartSource {
	if in == nil {
		return nil
	}
	out := new(RepoChartSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Rollback) DeepCopyInto(out *Rollback) {
	*out = *in
	if in.MaxRetries != nil {
		in, out := &in.MaxRetries, &out.MaxRetries
		*out = new(int64)
		**out = **in
	}
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(int64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Rollback.
func (in *Rollback) DeepCopy() *Rollback {
	if in == nil {
		return nil
	}
	out := new(Rollback)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretKeySelector) DeepCopyInto(out *SecretKeySelector) {
	*out = *in
	out.LocalObjectReference = in.LocalObjectReference
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretKeySelector.
func (in *SecretKeySelector) DeepCopy() *SecretKeySelector {
	if in == nil {
		return nil
	}
	out := new(SecretKeySelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Test) DeepCopyInto(out *Test) {
	*out = *in
	if in.IgnoreFailures != nil {
		in, out := &in.IgnoreFailures, &out.IgnoreFailures
		*out = new(bool)
		**out = **in
	}
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(int64)
		**out = **in
	}
	if in.Cleanup != nil {
		in, out := &in.Cleanup, &out.Cleanup
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Test.
func (in *Test) DeepCopy() *Test {
	if in == nil {
		return nil
	}
	out := new(Test)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ValuesFromSource) DeepCopyInto(out *ValuesFromSource) {
	*out = *in
	if in.ConfigMapKeyRef != nil {
		in, out := &in.ConfigMapKeyRef, &out.ConfigMapKeyRef
		*out = new(OptionalConfigMapKeySelector)
		**out = **in
	}
	if in.SecretKeyRef != nil {
		in, out := &in.SecretKeyRef, &out.SecretKeyRef
		*out = new(OptionalSecretKeySelector)
		**out = **in
	}
	if in.ExternalSourceRef != nil {
		in, out := &in.ExternalSourceRef, &out.ExternalSourceRef
		*out = new(ExternalSourceSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ChartFileRef != nil {
		in, out := &in.ChartFileRef, &out.ChartFileRef
		*out = new(ChartFileSelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ValuesFromSource.
func (in *ValuesFromSource) DeepCopy() *ValuesFromSource {
	if in == nil {
		return nil
	}
	out := new(ValuesFromSource)
	in.DeepCopyInto(out)
	return out
}
