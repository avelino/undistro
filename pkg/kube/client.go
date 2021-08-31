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

package kube

import (
	"context"
	"fmt"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	pinnipedcmd "github.com/getupio-undistro/undistro/third_party/pinniped/pinniped/cmd"
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

 var ErrConciergeNotInstalled = errors.New("concierge not installed")

 func IgnoreConciergeNotInstalled(err error) error {
	 if err != ErrConciergeNotInstalled {
		 return err
	 }
	 return nil
 }

func ConciergeInfoFromConfig(ctx context.Context, cfg *rest.Config) (*appv1alpha1.ConciergeInfo, error){
	pinnipedClient, err := pinnipedcmd.GetRealConciergeClientsetFromConfig(cfg, "pinniped.dev")
	if err != nil {
		return nil, ErrConciergeNotInstalled
	}
	credentialIssuers, err := pinnipedClient.ConfigV1alpha1().CredentialIssuers().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, ErrConciergeNotInstalled
	}
	if len(credentialIssuers.Items) != 1 {
		return nil, errors.New("unable to discover concierge endpoint: credentialIssuer is 0 or more than 1")
	}
	credentialIssuer := credentialIssuers.Items[0]
	for _, s := range credentialIssuer.Status.Strategies {
		if s.Status != configv1alpha1.SuccessStrategyStatus {
			continue
		}
		if s.Frontend == nil {
			continue
		}
		switch s.Frontend.Type {
		case configv1alpha1.ImpersonationProxyFrontendType:
			info := appv1alpha1.ConciergeInfo{
				Endpoint: s.Frontend.ImpersonationProxyInfo.Endpoint,
				CABundle: s.Frontend.ImpersonationProxyInfo.CertificateAuthorityData,
			}
			return &info, nil
		case configv1alpha1.TokenCredentialRequestAPIFrontendType:
			info := appv1alpha1.ConciergeInfo{
				Endpoint: s.Frontend.TokenCredentialRequestAPIInfo.Server,
				CABundle: s.Frontend.TokenCredentialRequestAPIInfo.CertificateAuthorityData,
			}
			return &info, nil
		default:
			continue
		}
	}
	return nil, ErrConciergeNotInstalled
}

func NewClusterClient(ctx context.Context, c client.Client, name, namespace string) (client.Client, error) {
	cfg, err := NewClusterConfig(ctx, c, name, namespace)
	if err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{
		Scheme: scheme.Scheme,
	})
}

func NewClusterConfig(ctx context.Context, c client.Client, name, namespace string) (*rest.Config, error) {
	key := client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}
	byt, err := GetInternalKubeconfig(ctx, c, key)
	if err != nil {
		return nil, err
	}
	getter := NewMemoryRESTClientGetter(byt, namespace)
	cfg, err := getter.ToRESTConfig()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func NewInClusterRESTClientGetter(cfg *rest.Config, namespace string) genericclioptions.RESTClientGetter {
	flags := genericclioptions.NewConfigFlags(false)
	flags.APIServer = &cfg.Host
	flags.BearerToken = &cfg.BearerToken
	flags.CAFile = &cfg.CAFile
	flags.Namespace = &namespace
	return flags
}

// MemoryRESTClientGetter is an implementation of the genericclioptions.RESTClientGetter,
// capable of working with an in-memory kubeconfig file.
type MemoryRESTClientGetter struct {
	kubeConfig []byte
	namespace  string
}

func NewMemoryRESTClientGetter(kubeConfig []byte, namespace string) genericclioptions.RESTClientGetter {
	return &MemoryRESTClientGetter{
		kubeConfig: kubeConfig,
		namespace:  namespace,
	}
}

func (c *MemoryRESTClientGetter) ToRESTConfig() (*rest.Config, error) {
	return clientcmd.RESTConfigFromKubeConfig(c.kubeConfig)
}

func (c *MemoryRESTClientGetter) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	config, err := c.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	// The more groups you have, the more discovery requests you need to make.
	// given 25 groups (our groups + a few custom resources) with one-ish version each, discovery needs to make 50 requests
	// double it just so we don't end up here again for a while.  This config is only used for discovery.
	config.Burst = 100

	discoveryClient, _ := discovery.NewDiscoveryClientForConfig(config)
	return memory.NewMemCacheClient(discoveryClient), nil
}

func (c *MemoryRESTClientGetter) ToRESTMapper() (meta.RESTMapper, error) {
	discoveryClient, err := c.ToDiscoveryClient()
	if err != nil {
		return nil, err
	}

	mapper := restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient)
	expander := restmapper.NewShortcutExpander(mapper, discoveryClient)
	return expander, nil
}

func (c *MemoryRESTClientGetter) ToRawKubeConfigLoader() clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	// use the standard defaults for this client command
	// DEPRECATED: remove and replace with something more accurate
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig

	overrides := &clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}
	overrides.Context.Namespace = c.namespace

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
}

// Purpose is the name to append to the secret generated for a cluster.
type Purpose string

const (
	// KubeconfigDataName is the key used to store a Kubeconfig in the secret's data field.
	KubeconfigDataName = "value"
	// Kubeconfig is the secret name suffix storing the Cluster Kubeconfig.
	Kubeconfig = Purpose("kubeconfig")
)

func GetInternalKubeconfig(ctx context.Context, c client.Reader, cluster client.ObjectKey) ([]byte, error) {
	out, err := getSecret(ctx, c, cluster, Kubeconfig)
	if err != nil {
		return nil, err
	}
	return toKubeconfigBytes(out)
}

// Get retrieves the specified Secret (if any) from the given
// cluster name and namespace.
func getSecret(ctx context.Context, c client.Reader, cluster client.ObjectKey, purpose Purpose) (*corev1.Secret, error) {
	return getFromNamespacedName(ctx, c, cluster, purpose)
}

// GetFromNamespacedName retrieves the specified Secret (if any) from the given
// cluster name and namespace.
func getFromNamespacedName(ctx context.Context, c client.Reader, clusterName client.ObjectKey, purpose Purpose) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: clusterName.Namespace,
		Name:      name(clusterName.Name, purpose),
	}

	if err := c.Get(ctx, secretKey, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Name returns the name of the secret for a cluster.
func name(cluster string, suffix Purpose) string {
	return fmt.Sprintf("%s-%s", cluster, suffix)
}

func toKubeconfigBytes(out *corev1.Secret) ([]byte, error) {
	data, ok := out.Data[KubeconfigDataName]
	if !ok {
		return nil, errors.Errorf("missing key %q in secret data", KubeconfigDataName)
	}
	return data, nil
}
