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

package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	"github.com/getupio-undistro/undistro/pkg/cloud"
	"github.com/getupio-undistro/undistro/pkg/fs"
	"github.com/getupio-undistro/undistro/pkg/kube"
	"github.com/getupio-undistro/undistro/pkg/meta"
	"github.com/getupio-undistro/undistro/pkg/retry"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/template"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/uuid"
	capi "sigs.k8s.io/cluster-api/api/v1alpha4"
	capicp "sigs.k8s.io/cluster-api/controlplane/kubeadm/api/v1alpha4"
	capiexp "sigs.k8s.io/cluster-api/exp/api/v1alpha4"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ClusterReconciler reconciles a Cluster object
type ClusterReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=*,resources=*,verbs=*

func (r *ClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cl := appv1alpha1.Cluster{}
	if err := r.Get(ctx, req.NamespacedName, &cl); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log := r.Log.WithValues("cluster", req.NamespacedName, "infra", cl.Spec.InfrastructureProvider.Name, "flavor", cl.Spec.InfrastructureProvider.Flavor)
	// Initialize the patch helper.
	patchHelper, err := patch.NewHelper(&cl, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	defer func() {
		var patchOpts []patch.Option
		if err == nil {
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})
		}
		patchErr := patchHelper.Patch(ctx, &cl, patchOpts...)
		if patchErr != nil {
			err = kerrors.NewAggregate([]error{patchErr, err})
		}
	}()
	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&cl, meta.Finalizer) {
		controllerutil.AddFinalizer(&cl, meta.Finalizer)
		return ctrl.Result{}, nil
	}
	if cl.Spec.Paused {
		log.Info("Reconciliation is paused for this object")
		cl = appv1alpha1.ClusterPaused(cl)
		return ctrl.Result{}, nil
	}

	capiCluster := capi.Cluster{}
	err = r.Get(ctx, client.ObjectKeyFromObject(&cl), &capiCluster)
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}
	if !cl.DeletionTimestamp.IsZero() {
		log.Info("Deleting")
		cl = appv1alpha1.ClusterDeleting(cl)
		return r.reconcileDelete(ctx, cl)
	}
	cl, result, err := r.reconcile(ctx, log, cl, capiCluster)
	return result, err
}

func (r *ClusterReconciler) templateVariables(ctx context.Context, c client.Client, cl *appv1alpha1.Cluster) (map[string]interface{}, error) {
	vars := make(map[string]interface{})
	v := make(map[string]interface{})
	err := template.SetVariablesFromEnvVar(ctx, template.VariablesInput{
		ClientSet:      r.Client,
		NamespacedName: client.ObjectKeyFromObject(cl),
		Variables:      v,
		EnvVars:        cl.Spec.InfrastructureProvider.Env,
	})
	if err != nil {
		return nil, err
	}
	vars["Cluster"] = cl
	vars["ENV"] = v
	acc, err := cloud.GetAccount(ctx, c, cl)
	if err != nil {
		return nil, err
	}
	vars["Account"] = acc
	validDiff := true
	labels := cl.GetLabels()
	_, moved := labels[meta.LabelUndistroMoved]
	if moved && !cl.Spec.InfrastructureProvider.IsManaged() && cl.Status.LastUsedUID == "" {
		validDiff = false
		cp := capicp.KubeadmControlPlane{}
		err := r.Get(ctx, client.ObjectKeyFromObject(cl), &cp)
		if client.IgnoreNotFound(err) != nil {
			return nil, err
		}
		if !apierrors.IsNotFound(err) {
			split := strings.Split(cp.Spec.MachineTemplate.InfrastructureRef.Name, "-")
			cl.Status.LastUsedUID = split[len(split)-1]
		}
	}
	if r.hasDiff(cl) && validDiff {
		cl.Status.LastUsedUID = string(uuid.NewUUID())
	}
	return vars, nil
}

func (r *ClusterReconciler) getBastionIP(ctx context.Context, cl appv1alpha1.Cluster, capiCluster capi.Cluster) (string, error) {
	ref := capiCluster.Spec.InfrastructureRef
	if ref != nil {
		key := client.ObjectKey{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		}
		o := unstructured.Unstructured{}
		o.SetGroupVersionKind(ref.GroupVersionKind())
		err := r.Get(ctx, key, &o)
		if err != nil {
			return "", client.IgnoreNotFound(err)
		}
		ip, _, err := unstructured.NestedString(o.Object, "status", "bastion", "publicIp")
		if err != nil {
			return "", err
		}
		return ip, nil
	}
	return "", nil
}

func (r *ClusterReconciler) reconcile(ctx context.Context, log logr.Logger, cl appv1alpha1.Cluster, capiCluster capi.Cluster) (appv1alpha1.Cluster, ctrl.Result, error) {
	cl.Status.TotalWorkerPools = int32(len(cl.Spec.Workers))
	cl.Status.TotalWorkerReplicas = 0
	for _, w := range cl.Spec.Workers {
		cl.Status.TotalWorkerReplicas += *w.Replicas
	}
	// we need to install calico in managed flavors too for network policy support
	err := r.reconcileCNI(ctx, &cl)
	if err != nil {
		meta.SetResourceCondition(&cl, meta.CNIInstalledCondition, metav1.ConditionFalse, meta.CNIInstalledFailedReason, err.Error())
		return cl, ctrl.Result{}, err
	}

	if cl.Spec.Bastion != nil {
		if *cl.Spec.Bastion.Enabled && cl.Status.BastionPublicIP == "" {
			cl.Status.BastionPublicIP, err = r.getBastionIP(ctx, cl, capiCluster)
			if err != nil {
				return appv1alpha1.ClusterNotReady(cl, meta.WaitProvisionReason, err.Error()), ctrl.Result{Requeue: true}, nil
			}
		}
	}
	err = cloud.ReconcileLaunchTemplate(ctx, r.Client, &cl)
	if err != nil {
		return appv1alpha1.ClusterNotReady(cl, meta.ReconcileLaunchTemplateFailed, err.Error()), ctrl.Result{}, err
	}
	err = cloud.ReconcileNetwork(ctx, r.Client, &cl, &capiCluster)
	if err != nil {
		return appv1alpha1.ClusterNotReady(cl, meta.ReconcileNetworkFailed, err.Error()), ctrl.Result{}, err
	}
	if r.hasDiff(&cl) {
		vars, err := r.templateVariables(ctx, r.Client, &cl)
		if err != nil {
			return appv1alpha1.ClusterNotReady(cl, meta.TemplateAppliedFailed, err.Error()), ctrl.Result{}, err
		}

		objs, err := template.GetObjs(fs.FS, "clustertemplates", cl.GetTemplate(), vars)
		if err != nil {
			return appv1alpha1.ClusterNotReady(cl, meta.TemplateAppliedFailed, err.Error()), ctrl.Result{}, err
		}
		for _, o := range objs {
			if o.GetAPIVersion() == capi.GroupVersion.String() && o.GetKind() == "Cluster" {
				err = ctrl.SetControllerReference(&cl, &o, scheme.Scheme)
				if err != nil {
					return cl, ctrl.Result{}, err
				}
			}
			err = retry.WithExponentialBackoff(retry.NewBackoff(), func() error {
				labels := o.GetLabels()
				if labels == nil {
					labels = make(map[string]string)
				}
				labels[meta.LabelUndistro] = ""
				labels[meta.LabelUndistroClusterName] = cl.Name
				labels[capi.ClusterLabelName] = cl.Name
				o.SetLabels(labels)
				_, err = util.CreateOrUpdate(ctx, r.Client, &o)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return cl, ctrl.Result{}, err
			}
		}
	}
	cl.Status.KubernetesVersion = cl.Spec.KubernetesVersion
	cl.Status.ControlPlane = *cl.Spec.ControlPlane
	cl.Status.Workers = cl.Spec.Workers
	cl.Status.BastionConfig = cl.Spec.Bastion
	if capiCluster.Status.ControlPlaneReady && capiCluster.Status.InfrastructureReady {
		cl = appv1alpha1.ClusterReady(cl)
		if cl.Status.ConciergeInfo == nil {
			cl, err = r.reconcileConciergeEndpoint(ctx, cl)
			if err != nil {
				return cl, ctrl.Result{}, err
			}
		}
		return cl, ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}
	return appv1alpha1.ClusterNotReady(cl, meta.WaitProvisionReason, "wait cluster to be provisioned"), ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *ClusterReconciler) reconcileConciergeEndpoint(ctx context.Context, cl appv1alpha1.Cluster) (appv1alpha1.Cluster, error) {
	cfg, err := kube.NewClusterConfig(ctx, r.Client, cl.Name, cl.GetNamespace())
	if err != nil {
		return cl, err
	}
	info, err := kube.ConciergeInfoFromConfig(ctx, cfg)
	if err != nil {
		return cl, kube.IgnoreConciergeNotInstalled(err)
	}
	cl.Status.ConciergeInfo = info
	return cl, nil
}

func (r *ClusterReconciler) hasDiff(cl *appv1alpha1.Cluster) bool {
	if cl.Spec.KubernetesVersion != cl.Status.KubernetesVersion {
		return true
	}
	if !cl.Spec.InfrastructureProvider.IsManaged() && cl.Spec.ControlPlane != nil {
		if *cl.Spec.ControlPlane.Replicas != *cl.Status.ControlPlane.Replicas {
			return true
		}
		if cl.Spec.ControlPlane.MachineType != cl.Status.ControlPlane.MachineType {
			return true
		}
	}
	return false
}

func (r *ClusterReconciler) reconcileCNI(ctx context.Context, cl *appv1alpha1.Cluster) error {
	const (
		cniCalicoName = "calico"
		calicoVersion = "3.19.1"
	)

	v, err := cloud.CalicoValues(cl.Spec.InfrastructureProvider.Flavor)
	if err != nil {
		return err
	}
	key := client.ObjectKey{
		Name:      cniCalicoName,
		Namespace: cl.GetNamespace(),
	}
	hr := appv1alpha1.HelmRelease{}
	err = r.Get(ctx, key, &hr)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		hr = appv1alpha1.HelmRelease{
			TypeMeta: metav1.TypeMeta{
				APIVersion: appv1alpha1.GroupVersion.String(),
				Kind:       "HelmRelease",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%s", cniCalicoName, cl.Name),
				Namespace: cl.GetNamespace(),
			},
			Spec: appv1alpha1.HelmReleaseSpec{
				TargetNamespace: "kube-system",
				ReleaseName:     cniCalicoName,
				Values:          &apiextensionsv1.JSON{Raw: v},
				ClusterName:     fmt.Sprintf("%s/%s", cl.GetNamespace(), cl.Name),
				Chart: appv1alpha1.ChartSource{
					RepoChartSource: appv1alpha1.RepoChartSource{
						RepoURL: undistro.DefaultRepo,
						Name:    cniCalicoName,
						Version: calicoVersion,
					},
				},
			},
		}
		err = ctrl.SetControllerReference(cl, &hr, r.Scheme)
		if err != nil {
			return err
		}
	}
	if hr.Annotations == nil {
		hr.Annotations = make(map[string]string)
	}
	hr.Annotations[meta.CNIAnnotation] = cniCalicoName
	_, err = util.CreateOrUpdate(ctx, r.Client, &hr)
	if err != nil {
		return err
	}
	if meta.InReadyCondition(hr.Status.Conditions) {
		meta.SetResourceCondition(cl, meta.CNIInstalledCondition, metav1.ConditionTrue, meta.CNIInstalledSuccessReason, "calico installed")
	}
	return nil
}

func (r *ClusterReconciler) reconcileDelete(ctx context.Context, cl appv1alpha1.Cluster) (ctrl.Result, error) {
	capiCluster := capi.Cluster{}
	err := r.Get(ctx, client.ObjectKeyFromObject(&cl), &capiCluster)
	if apierrors.IsNotFound(err) {
		controllerutil.RemoveFinalizer(&cl, meta.Finalizer)
		_, err = util.CreateOrUpdate(ctx, r.Client, &cl)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	err = r.Delete(ctx, &capiCluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	for i := range cl.Spec.Workers {
		key := client.ObjectKey{
			Name:      fmt.Sprintf("%s-mp-%d", cl.Name, i),
			Namespace: cl.GetNamespace(),
		}
		mp := capiexp.MachinePool{}
		err = r.Get(ctx, key, &mp)
		if err != nil {
			if client.IgnoreNotFound(err) != nil {
				return ctrl.Result{}, err
			}
			continue
		}
		err = r.Delete(ctx, &mp)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	err = r.removeDeps(ctx, cl)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

func (r *ClusterReconciler) removeDeps(ctx context.Context, cl appv1alpha1.Cluster) error {
	hrClusterName := fmt.Sprintf("%s/%s", cl.GetNamespace(), cl.Name)
	hrList := appv1alpha1.HelmReleaseList{}
	err := r.List(ctx, &hrList)
	if err != nil {
		return err
	}
	for _, item := range hrList.Items {
		if item.Spec.ClusterName == hrClusterName {
			err = r.Delete(ctx, &item)
			if err != nil {
				return err
			}
		}
	}
	policies := appv1alpha1.DefaultPoliciesList{}
	err = r.List(ctx, &policies, client.InNamespace(cl.GetNamespace()))
	if err != nil {
		return err
	}
	for _, item := range policies.Items {
		if item.Spec.ClusterName == cl.Name {
			err = r.Delete(ctx, &item)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *ClusterReconciler) capiToUndistro(o client.Object) []ctrl.Request {
	capiCluster := o.(*capi.Cluster).DeepCopy()
	if capiCluster.Status.Phase == "" {
		return nil
	}
	return []ctrl.Request{
		{
			NamespacedName: client.ObjectKeyFromObject(capiCluster),
		},
	}
}

func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appv1alpha1.Cluster{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 10}).
		Watches(
			&source.Kind{
				Type: &capi.Cluster{},
			},
			handler.EnqueueRequestsFromMapFunc(r.capiToUndistro),
		).
		Complete(r)
}
