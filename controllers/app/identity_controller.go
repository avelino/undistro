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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	conciergev1aplha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	supervisorconfigv1aplha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisoridpv1aplha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	"github.com/getupio-undistro/undistro/pkg/kube"
	"github.com/getupio-undistro/undistro/pkg/meta"
	"github.com/getupio-undistro/undistro/pkg/retry"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
)

const (
	requeueAfter    = time.Minute * 2
	identityManager = "pinniped"
)

type PinnipedComponent string

const (
	concierge  PinnipedComponent = "concierge"
	supervisor PinnipedComponent = "supervisor"
)

// IdentityReconciler reconciles a Identity object
type IdentityReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string
	Log       logr.Logger
	Audience  string
}

// +kubebuilder:rbac:groups=*,resources=*,verbs=*

func (r *IdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	// Fetch the Identity instance.
	instance := &appv1alpha1.Identity{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		} else {
			return ctrl.Result{}, err
		}
	}

	// Initialize the patch helper.
	patchHelper, err := patch.NewHelper(instance, r.Client)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "failed to init patch helper")
	}
	defer func() {
		var patchOpts []patch.Option
		if err == nil {
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})
		}
		patchErr := patchHelper.Patch(ctx, instance, patchOpts...)
		if patchErr != nil {
			err = kerrors.NewAggregate([]error{patchErr, err})
			r.Log.Info("failed to Patch identity")
		}
	}()

	r.Log.Info("Checking paused")
	if instance.Spec.Paused {
		r.Log.Info("Reconciliation is paused for this object")
		instance = appv1alpha1.IdentityPaused(*instance)
		return ctrl.Result{}, nil
	}
	r.Log.Info("Checking object age")
	if instance.Generation < instance.Status.ObservedGeneration {
		r.Log.Info("Skipping this old version of reconciled object")
		return ctrl.Result{}, nil
	}
	r.Log.Info("Checking if the Pinniped components are installed")
	if err := r.reconcile(ctx, req, *instance); err != nil {
		r.Log.Info(err.Error())
		return ctrl.Result{}, err
	}

	elapsed := time.Since(start)
	msg := fmt.Sprintf("Queueing after %s", elapsed.String())
	r.Log.Info(msg)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// reconcile ensures that Pinniped is installed
func (r *IdentityReconciler) reconcile(ctx context.Context, req ctrl.Request, i appv1alpha1.Identity) error {
	cl := &appv1alpha1.Cluster{}
	clusterClient := r.Client
	key := client.ObjectKey{
		Name:      i.Spec.ClusterName,
		Namespace: i.GetNamespace(),
	}
	err := r.Get(ctx, key, cl)
	if client.IgnoreNotFound(err) != nil {
		r.Log.Info(err.Error())
		return err
	}

	err = r.reconcileComponentInstallation(ctx, req, cl, i, concierge, undistro.Namespace)
	if err != nil {
		r.Log.Info(err.Error())
		return err
	}
	fedo := make(map[string]interface{})
	if util.IsMgmtCluster(i.Spec.ClusterName) {
		r.Log.Info("Installing Pinniped components in cluster ", "cluster-name", i.Spec.ClusterName)
		r.Log.Info("Installing components in management cluster")
		cl.Name = "management"
		cl.Namespace = undistro.Namespace
		// install supervisor
		err = r.reconcileComponentInstallation(ctx, req, cl, i, supervisor, undistro.Namespace)
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
		o, err := getFromConfigMap(
			ctx, clusterClient, "identity-config", undistro.Namespace, "federationdomain.yaml", fedo)
		fedo = o.(map[string]interface{})
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
		err = r.reconcileFederationDomain(ctx, fedo)
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
		err = r.reconcileOIDCProvider(ctx)
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
	} else {
		clusterClient, err = kube.NewClusterClient(ctx, r.Client, i.Spec.ClusterName, cl.GetNamespace())
		if err != nil {
			r.Log.Info(err.Error())
			return err
		}
	}

	err = r.reconcileJWTAuthenticator(ctx, clusterClient, fedo["issuer"].(string))
	if err != nil {
		r.Log.Info(err.Error())
		return err
	}
	return err
}

func (r *IdentityReconciler) reconcileFederationDomain(ctx context.Context, federationDomainCfg map[string]interface{}) error {
	r.Log.Info("Reconciling Federation Domain")

	spec := supervisorconfigv1aplha1.FederationDomainSpec{}
	spec.Issuer = federationDomainCfg["issuer"].(string)
	isLocal, err := util.IsLocalCluster(ctx, r.Client)
	if err != nil {
		return err
	}
	if isLocal {
		msg := fmt.Sprintf("%v", federationDomainCfg)
		r.Log.Info(msg)
		spec.TLS = &supervisorconfigv1aplha1.FederationDomainTLSSpec{
			SecretName: federationDomainCfg["tlsSecretName"].(string),
		}
	}
	fedo := &supervisorconfigv1aplha1.FederationDomain{
		TypeMeta: metav1.TypeMeta{
			Kind:       "FederationDomain",
			APIVersion: supervisorconfigv1aplha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "undistro-federationdomain",
			Namespace: undistro.Namespace,
		},
		Spec: spec,
	}
	_, err = util.CreateOrUpdate(ctx, r.Client, fedo)
	if err != nil {
		return err
	}
	return nil
}

func (r *IdentityReconciler) reconcileOIDCProvider(ctx context.Context) error {
	r.Log.Info("Reconciling OIDC Provider")
	// get oidc related configmap
	tmp := make(map[string]interface{})
	o, err := getFromConfigMap(
		ctx, r.Client, "identity-config", undistro.Namespace, "oidcprovider.yaml", tmp)
	if err != nil {
		r.Log.Info(err.Error())
		return err
	}
	tmp = o.(map[string]interface{})
	name := tmp["issuer"].(map[string]interface{})["name"].(string)
	fmtName := fmt.Sprintf("undistro-%s-idp", name)
	spec := supervisoridpv1aplha1.OIDCIdentityProviderSpec{}
	spec.Client = supervisoridpv1aplha1.OIDCClient{
		SecretName: "idp-credentials",
	}
	switch strings.ToLower(name) {
	case string(appv1alpha1.Google):
		spec.Issuer = "https://accounts.google.com"
		spec.AuthorizationConfig = supervisoridpv1aplha1.OIDCAuthorizationConfig{
			AdditionalScopes: []string{"email", "profile"},
		}
		spec.Claims = supervisoridpv1aplha1.OIDCClaims{}
	case string(appv1alpha1.Azure):
		// Todo get tenant id from config file
		tenantID := "<tenant-id>"
		spec.Issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
		spec.AuthorizationConfig = supervisoridpv1aplha1.OIDCAuthorizationConfig{
			AdditionalScopes: []string{"email", "profile"},
		}
		spec.Claims = supervisoridpv1aplha1.OIDCClaims{}
	case string(appv1alpha1.Gitlab):
		spec.Issuer = "https://gitlab.com"
		spec.Claims = supervisoridpv1aplha1.OIDCClaims{
			Username: "nickname",
			Groups:   "groups",
		}
	}
	oidcProvider := &supervisoridpv1aplha1.OIDCIdentityProvider{
		TypeMeta: metav1.TypeMeta{
			Kind:       "OIDCIdentityProvider",
			APIVersion: supervisoridpv1aplha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmtName,
			Namespace: undistro.Namespace,
		},
		Spec: spec,
	}
	_, err = util.CreateOrUpdate(ctx, r.Client, oidcProvider)
	if err != nil {
		r.Log.Info(err.Error())
		return err
	}
	return nil
}

func (r *IdentityReconciler) reconcileJWTAuthenticator(ctx context.Context, c client.Client, issuer string) (err error) {
	local, err := util.IsLocalCluster(ctx, c)
	if err != nil {
		return
	}

	const caSecretName = "ca-secret"
	const caName = "ca.crt"
	jwtAuth := conciergev1aplha1.JWTAuthenticator{
		TypeMeta: metav1.TypeMeta{
			Kind:       "JWTAuthenticator",
			APIVersion: conciergev1aplha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "supervisor-jwt-authenticator",
			Namespace: undistro.Namespace,
		},
		Spec: conciergev1aplha1.JWTAuthenticatorSpec{
			Issuer:   issuer,
			Audience: r.Audience,
		},
	}
	if local {
		secretByt, err := util.GetCaFromSecret(ctx, c, caSecretName, caName, undistro.Namespace)
		if err != nil {
			return err
		}
		secretData := base64.StdEncoding.EncodeToString(secretByt)
		jwtAuth.Spec.TLS = &conciergev1aplha1.TLSSpec{
			CertificateAuthorityData: secretData,
		}

	}
	_, err = util.CreateOrUpdate(ctx, c, &jwtAuth)
	if err != nil {
		return
	}
	return
}

func (r *IdentityReconciler) reconcileComponentInstallation(
	ctx context.Context,
	req ctrl.Request,
	cl *appv1alpha1.Cluster,
	i appv1alpha1.Identity,
	pc PinnipedComponent,
	targetNs string,
) (err error) {
	release := appv1alpha1.HelmRelease{}
	msg := fmt.Sprintf("Checking if %s is installed", pc)
	r.Log.Info(msg)
	err = r.Get(ctx, req.NamespacedName, &release)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		release, err = prepareHR(pc, targetNs, cl.GetNamespace(), "0.10.0", i)
		if err != nil {
			return err
		}
		msg = fmt.Sprintf("Installing %s component: %s", identityManager, pc)
		r.Log.Info(msg)
		if err := installComponent(ctx, r.Client, release, cl); err != nil {
			return err
		}
	}
	return
}

func getFromConfigMap(ctx context.Context, c client.Client, name, ns, dataField string, o interface{}) (interface{}, error) {
	// retrieve the config map for update
	cmKey := client.ObjectKey{
		Name:      name,
		Namespace: ns,
	}
	cm := corev1.ConfigMap{}
	err := c.Get(ctx, cmKey, &cm)
	if err != nil {
		return o, err
	}
	// convert data for more simply manipulation
	f := cm.Data[dataField]
	fede := strings.ReplaceAll(f, "|", "")
	byt := []byte(fede)
	err = yaml.Unmarshal(byt, &o)
	if err != nil {
		return o, err
	}
	return o, nil
}

// installComponent installs some chart in a such cluster
func installComponent(ctx context.Context, c client.Client, hr appv1alpha1.HelmRelease, cl *appv1alpha1.Cluster) error {
	msg := fmt.Sprintf("%s installation", hr.Name)
	if meta.InReadyCondition(hr.Status.Conditions) {
		meta.SetResourceCondition(cl, meta.ReadyCondition, metav1.ConditionTrue, meta.InstallSucceededReason, msg)
	}
	err := retry.WithExponentialBackoff(retry.NewBackoff(), func() error {
		_, e := util.CreateOrUpdate(ctx, c, &hr)
		return e
	})
	return err
}

// prepareHR fills the Helm Release fields for the given component
func prepareHR(pc PinnipedComponent, targetNs, clusterNs, version string, i appv1alpha1.Identity) (appv1alpha1.HelmRelease, error) {
	chartName := fmt.Sprintf("%s-%s", "pinniped", pc)
	vMap := map[string]interface{}{
		"metadata": map[string]interface{}{
			"namespace": undistro.Namespace,
		},
	}
	byt, err := json.Marshal(vMap)
	if err != nil {
		return appv1alpha1.HelmRelease{}, err
	}
	values := apiextensionsv1.JSON{
		Raw: byt,
	}
	hr := &appv1alpha1.HelmRelease{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appv1alpha1.GroupVersion.String(),
			Kind:       "HelmRelease",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      chartName,
			Namespace: clusterNs,
		},
		Spec: appv1alpha1.HelmReleaseSpec{
			ReleaseName:     chartName,
			TargetNamespace: targetNs,
			ClusterName:     i.GetClusterName(),
			Values:          &values,
			Chart: appv1alpha1.ChartSource{
				RepoChartSource: appv1alpha1.RepoChartSource{
					RepoURL: undistro.DefaultRepo,
					Name:    chartName,
					Version: version,
				},
			},
		},
	}
	return *hr, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appv1alpha1.Identity{}).
		Complete(r)
}
