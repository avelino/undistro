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

package metadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	metadatav1alpha1 "github.com/getupio-undistro/undistro/apis/metadata/v1alpha1"
	"github.com/getupio-undistro/undistro/pkg/cloud"
	"github.com/getupio-undistro/undistro/pkg/meta"
	"github.com/getupio-undistro/undistro/pkg/retry"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/util"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var baseURL = "https://undistro.io/resources/metadata"

// ProviderReconciler reconciles a provider object
type ProviderReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

func (r *ProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	p := metadatav1alpha1.Provider{}
	if err := r.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log := r.Log.WithValues("provider", req.NamespacedName)
	// Initialize the patch helper.
	patchHelper, err := patch.NewHelper(&p, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	defer func() {
		var patchOpts []patch.Option
		if err == nil {
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})
		}
		patchErr := patchHelper.Patch(ctx, &p, patchOpts...)
		if patchErr != nil {
			err = kerrors.NewAggregate([]error{patchErr, err})
		}
	}()
	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&p, meta.Finalizer) {
		controllerutil.AddFinalizer(&p, meta.Finalizer)
		return ctrl.Result{}, nil
	}

	if p.Spec.Paused {
		log.Info("Reconciliation is paused for this object")
		p = metadatav1alpha1.UpdatePaused(p)
		return ctrl.Result{}, nil
	}
	if !p.DeletionTimestamp.IsZero() {
		log.Info("Deleting provider metadata")
		p = metadatav1alpha1.ProviderDeleting(p)
		return r.reconcileDelete(ctx, p)
	}
	p, result, err := r.reconcile(ctx, log, p)
	return result, err
}

func (r *ProviderReconciler) reconcile(ctx context.Context, log logr.Logger, p metadatav1alpha1.Provider) (metadatav1alpha1.Provider, ctrl.Result, error) {
	log.Info("Reconciling provider metadata")
	hrList := appv1alpha1.HelmReleaseList{}
	err := r.List(ctx, &hrList, client.MatchingLabels{meta.LabelProvider: p.Name})
	if err != nil {
		log.V(2).Info("failed to list HelmReleases", "error", err)
	}
	for _, hr := range hrList.Items {
		p.Status.ChartName = hr.Spec.Chart.Name
		p.Status.ChartVersion = hr.Spec.Chart.Version
	}
	p.Status.RegionNames = cloud.RegionNames(p)
	if p.Spec.AutoFetch {
		u, err := url.Parse(baseURL)
		if err != nil {
			p = metadatav1alpha1.ProviderNotReady(p, meta.URLInvalidReason, err.Error())
			return p, ctrl.Result{}, err
		}
		u.Path = path.Join(u.Path, fmt.Sprintf("%s.yaml", p.Name))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			p = metadatav1alpha1.ProviderNotReady(p, meta.URLInvalidReason, err.Error())
			return p, ctrl.Result{}, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			p = metadatav1alpha1.ProviderNotReady(p, meta.URLInvalidReason, err.Error())
			return p, ctrl.Result{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			byt, err := io.ReadAll(resp.Body)
			if err != nil {
				return p, ctrl.Result{}, err
			}
			objs, err := util.ToUnstructured(byt)
			if err != nil {
				return p, ctrl.Result{}, err
			}
			for _, o := range objs {
				_, err = util.CreateOrUpdate(ctx, r.Client, &o)
				if err != nil {
					return p, ctrl.Result{}, err
				}
			}
			p = metadatav1alpha1.ProviderReady(p)
			return p, ctrl.Result{RequeueAfter: 24 * time.Hour}, nil
		}
	}
	log.Info("Reconciling provider flavors metadata")
	p, err = r.execMetadataFunc(ctx, p, cloud.GetFlavors(p))
	if err != nil {
		return p, ctrl.Result{}, err
	}
	log.Info("Reconciling provider machines metadata")
	p, err = r.execMetadataFunc(ctx, p, cloud.GetMachineMetadata(p))
	if err != nil {
		return p, ctrl.Result{}, err
	}
	p = metadatav1alpha1.ProviderReady(p)
	return p, ctrl.Result{RequeueAfter: 24 * time.Hour}, nil
}

func (r *ProviderReconciler) execMetadataFunc(ctx context.Context, p metadatav1alpha1.Provider, f cloud.MetadataFunc) (metadatav1alpha1.Provider, error) {
	if f != nil {
		objs, err := f(ctx, p)
		if err != nil {
			p = metadatav1alpha1.ProviderNotReady(p, meta.ArtifactFailedReason, err.Error())
			return p, err
		}
		for _, o := range objs {
			err = retry.WithExponentialBackoff(retry.NewBackoff(), func() error {
				err = ctrl.SetControllerReference(&p, o, scheme.Scheme)
				if err != nil {
					return err
				}
				_, err = util.CreateOrUpdate(ctx, r.Client, o)
				return err
			})
			if err != nil {
				p = metadatav1alpha1.ProviderNotReady(p, meta.ArtifactFailedReason, err.Error())
				return p, err
			}
		}
	}
	return p, nil
}

func (r *ProviderReconciler) reconcileDelete(ctx context.Context, p metadatav1alpha1.Provider) (ctrl.Result, error) {
	controllerutil.RemoveFinalizer(&p, meta.Finalizer)
	_, err := util.CreateOrUpdate(ctx, r.Client, &p)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&metadatav1alpha1.Provider{}).
		Complete(r)
}
