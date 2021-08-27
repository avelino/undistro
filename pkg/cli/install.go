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
package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	metadatav1alpha1 "github.com/getupio-undistro/undistro/apis/metadata/v1alpha1"
	"github.com/getupio-undistro/undistro/pkg/capi"
	"github.com/getupio-undistro/undistro/pkg/certmanager"
	undistrofs "github.com/getupio-undistro/undistro/pkg/fs"
	"github.com/getupio-undistro/undistro/pkg/helm"
	"github.com/getupio-undistro/undistro/pkg/internalautohttps"
	"github.com/getupio-undistro/undistro/pkg/kube"
	"github.com/getupio-undistro/undistro/pkg/meta"
	"github.com/getupio-undistro/undistro/pkg/retry"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	"github.com/getupio-undistro/undistro/pkg/version"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	knet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"sigs.k8s.io/cluster-api/util/kubeconfig"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

var (
	getters = getter.Providers{
		getter.Provider{
			Schemes: []string{"http", "https"},
			New:     getter.NewHTTPGetter,
		},
	}
)

const (
	undistroRepo  = undistro.DefaultRepo
	ns            = undistro.Namespace
	cfgSecretName = "undistro-config"
)

var providersInfo = map[string]metadatav1alpha1.ProviderInfo{
	"metallb": {
		Category: metadatav1alpha1.ProviderCore,
	},
	"cert-manager": {
		Category: metadatav1alpha1.ProviderCore,
	},
	"cluster-api": {
		Category: metadatav1alpha1.ProviderCore,
	},
	"undistro": {
		Category:   metadatav1alpha1.ProviderCore,
		SecretName: cfgSecretName,
	},
	"ingress-nginx": {
		Category: metadatav1alpha1.ProviderCore,
	},
	"undistro-aws": {
		Category:   metadatav1alpha1.ProviderInfra,
		SecretName: "undistro-aws-config",
	},
}

type InstallOptions struct {
	ConfigPath  string
	ClusterName string
	genericclioptions.IOStreams
}

func NewInstallOptions(streams genericclioptions.IOStreams) *InstallOptions {
	return &InstallOptions{
		IOStreams: streams,
	}
}

func (o *InstallOptions) Complete(f *ConfigFlags, cmd *cobra.Command, args []string) error {
	o.ConfigPath = *f.ConfigFile
	switch len(args) {
	case 0:
		// do nothing
	case 1:
		o.ClusterName = args[0]
	default:
		return cmdutil.UsageErrorf(cmd, "%s", "too many arguments")
	}
	return nil
}

func (o *InstallOptions) Validate() error {
	if o.ConfigPath != "" {
		_, err := os.Stat(o.ConfigPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *InstallOptions) installChart(restGetter genericclioptions.RESTClientGetter, chartName string, overrideValuesMap map[string]interface{}) (*appv1alpha1.HelmRelease, error) {
	overrideValues := &apiextensionsv1.JSON{}
	if overrideValuesMap == nil {
		overrideValuesMap = make(map[string]interface{})
	}
	if len(overrideValuesMap) > 0 {
		byt, err := json.Marshal(overrideValuesMap)
		if err != nil {
			return nil, err
		}
		overrideValues.Raw = byt
	}
	var (
		file  fs.File
		found bool
	)
	err := fs.WalkDir(undistrofs.ChartFS, "chart", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if found {
			return nil
		}

		if d.IsDir() {
			return nil
		}
		file, err = undistrofs.ChartFS.Open(path)
		if err != nil {
			return err
		}
		name := filepath.Base(path)
		name = util.ChartNameByFile(name)
		if name == chartName {
			found = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	chart, err := loader.LoadArchive(file)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(o.IOStreams.Out, "Installing %s version %s\n", chart.Name(), chart.AppVersion())
	for _, dep := range chart.Dependencies() {
		fmt.Fprintf(o.IOStreams.Out, "Installing %s version %s\n", dep.Name(), dep.AppVersion())
	}
	wait := true
	forceUpgrade := true
	reset := false
	history := 0
	_, dev := os.LookupEnv("DEV_ENV")
	label := strings.TrimPrefix(chartName, "undistro-")
	hr := appv1alpha1.HelmRelease{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appv1alpha1.GroupVersion.String(),
			Kind:       "HelmRelease",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      chartName,
			Namespace: ns,
			Labels: map[string]string{
				meta.LabelProvider: label,
			},
		},
		Spec: appv1alpha1.HelmReleaseSpec{
			Paused: dev,
			Chart: appv1alpha1.ChartSource{
				RepoChartSource: appv1alpha1.RepoChartSource{
					RepoURL: undistroRepo,
					Name:    chartName,
					Version: chart.Metadata.Version,
				},
			},
			ReleaseName:     chartName,
			TargetNamespace: ns,
			Values:          overrideValues,
			Wait:            &wait,
			MaxHistory:      &history,
			ResetValues:     &reset,
			ForceUpgrade:    &forceUpgrade,
			Timeout: &metav1.Duration{
				Duration: 5 * time.Minute,
			},
		},
	}
	err = retry.WithExponentialBackoff(retry.NewBackoff(), func() error {
		runner, err := helm.NewRunner(restGetter, ns, log.Log)
		if err != nil {
			return err
		}
		m := make(map[string]interface{})
		if overrideValues.Raw != nil {
			err = json.Unmarshal(overrideValues.Raw, &m)
			if err != nil {
				return err
			}
		}
		chart.Values = util.MergeMaps(chart.Values, m)
		rel, _ := runner.ObserveLastRelease(hr)
		if rel == nil {
			_, err = runner.Install(hr, chart, chart.Values)
			if err != nil {
				return err
			}
		} else if rel.Info.Status == release.StatusDeployed {
			_, err = runner.Upgrade(hr, chart, chart.Values)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return &hr, err
}

func (o *InstallOptions) checkEnabledList(ctx context.Context, c client.Client, cfg map[string]interface{}) []string {
	p := []string{"cert-manager", "cluster-api", "undistro", "ingress-nginx"}
	isLocal, err := util.IsLocalCluster(ctx, c)
	if err != nil {
		return nil
	}
	if isLocal {
		p = []string{"metallb", "cert-manager", "cluster-api", "undistro", "ingress-nginx"}
	}

	for k := range cfg {
		_, ok := providersInfo[k]
		if !ok {
			continue
		}
		item, ok := cfg[k].(map[string]interface{})
		if !ok {
			continue
		}
		v, ok := item["enabled"]
		if !ok {
			continue
		}
		enabled, ok := v.(bool)
		if !ok {
			continue
		}
		if !enabled {
			continue
		}
		if !util.ContainsStringInSlice(p, k) {
			p = append(p, k)
		}
	}
	return p
}

func (o *InstallOptions) applyMetadata(ctx context.Context, c client.Client, providers ...string) error {
	for k, v := range providersInfo {
		o := metadatav1alpha1.Provider{
			TypeMeta: metav1.TypeMeta{
				APIVersion: metadatav1alpha1.GroupVersion.String(),
				Kind:       "Provider",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: strings.TrimPrefix(k, "undistro-"),
			},
			Spec: metadatav1alpha1.ProviderSpec{
				Paused:          !util.ContainsStringInSlice(providers, k),
				AutoFetch:       true,
				UnDistroVersion: version.Get().GitVersion,
				Category:        v.Category,
			},
		}
		if v.SecretName != "" {
			o.Spec.SecretRef = &corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Secret",
				Name:       v.SecretName,
				Namespace:  ns,
			}
		}
		_, err := util.CreateOrUpdate(ctx, c, &o)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *InstallOptions) installCore(ctx context.Context, c client.Client, restGetter genericclioptions.RESTClientGetter, cfg map[string]interface{}, charts ...string) ([]appv1alpha1.HelmRelease, error) {
	var depsMap = map[string]string{
		"cert-manager": certmanager.TestResources,
		"cluster-api":  capi.TestResources,
		"undistro":     undistro.TestResources,
	}
	globalValue, hasGlobal := cfg["global"]
	hrs := make([]appv1alpha1.HelmRelease, len(charts))
	n := corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: ns,
		},
	}
	_, err := util.CreateOrUpdate(ctx, c, &n)
	if err != nil {
		return nil, err
	}
	for i, chart := range charts {
		values := defaultValues(ctx, c, chart)
		cfgValues, ok := cfg[chart]
		if !ok {
			cfgValues = make(map[string]interface{})
		}
		vMap, ok := cfgValues.(map[string]interface{})
		if ok {
			if hasGlobal {
				vMap["global"] = globalValue
			}
			values = util.MergeMaps(vMap, values)
		}
		hr, err := o.installChart(restGetter, chart, values)
		if err != nil {
			return nil, err
		}
		testRes := depsMap[chart]
		if testRes != "" {
			objs, err := util.ToUnstructured([]byte(testRes))
			if err != nil {
				return nil, err
			}
			for _, o := range objs {
				err = retry.WithExponentialBackoff(retry.NewBackoff(), func() error {
					_, err = util.CreateOrUpdate(ctx, c, &o)
					return err
				})
			}
		}
		if chart == "undistro" {
			isLocal, ok := values["local"].(bool)
			if ok && isLocal {
				fmt.Fprintf(o.IOStreams.Out, "Installing local certificates\n")
				err = internalautohttps.InstallLocalCert(ctx, c)
				if err != nil {
					return nil, err
				}
			}
		}
		hrs[i] = *hr
	}
	return hrs, nil
}

func validateSupervisorConfig(ctx context.Context, c client.Client, out io.Writer) error {
	// is required to use the local IP for the Pinniped Federation Domain Issuer
	ip, err := knet.ChooseHostInterface()
	if err != nil {
		return err
	}
	issuer := fmt.Sprintf("https://%s/auth", ip.String())
	// retrieve the config map for update
	cmKey := client.ObjectKey{
		Name:      "identity-config",
		Namespace: undistro.Namespace,
	}
	cm := corev1.ConfigMap{}
	err = c.Get(ctx, cmKey, &cm)
	if err != nil {
		return err
	}
	// edit configmap issuer address
	f := cm.Data["federationdomain.yaml"]
	fede := strings.ReplaceAll(f, "|", "")
	fedeDomain := make(map[string]interface{})
	byt := []byte(fede)
	err = yaml.Unmarshal(byt, &fedeDomain)
	if err != nil {
		return err
	}
	fedeDomain["issuer"] = issuer
	b, err := yaml.Marshal(fedeDomain)
	if err != nil {
		return err
	}
	cm.Data["federationdomain.yaml"] = string(b)
	cm.TypeMeta = metav1.TypeMeta{
		Kind:       "ConfigMap",
		APIVersion: corev1.SchemeGroupVersion.String(),
	}
	// update the configmap
	_, err = util.CreateOrUpdate(ctx, c, &cm)
	if err != nil {
		return err
	}
	return nil
}

func validateKindConfig(ctx context.Context, c client.Client, out io.Writer) error {
	// get kind container ip for metallb configuration
	kindContainerName := "kind-control-plane"
	cmd := exec.Command(
		"docker",
		"inspect", "-f", "'{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}'", kindContainerName,
	)
	b := bytes.Buffer{}
	cmd.Stdout = &b
	err := cmd.Run()
	if err != nil {
		fmt.Fprintln(out, "error getting kind container IP", err.Error())
	}
	containerIP := strings.TrimSpace(strings.ReplaceAll(b.String(), "'", ""))
	// format container IP
	containerIPFmt := fmt.Sprintf("%s-%s", containerIP, containerIP)
	// retrieve metallb configmap
	cmKey := client.ObjectKey{
		Name:      "metallb-config",
		Namespace: undistro.Namespace,
	}
	cm := corev1.ConfigMap{}
	err = c.Get(ctx, cmKey, &cm)
	if err != nil {
		return err
	}

	// get the address-pools field and unmarshal it
	metallbConfig := cm.Data["config"]
	byt := []byte(metallbConfig)
	type AddressPools struct {
		Name      string   `json:"name,omitempty"`
		Protocol  string   `json:"protocol,omitempty"`
		Addresses []string `json:"addresses,omitempty"`
	}
	type addressPoolsYaml struct {
		AddressPools []AddressPools `json:"address-pools,omitempty"`
	}
	var ayaml addressPoolsYaml
	err = yaml.Unmarshal(byt, &ayaml)
	if err != nil {
		return err
	}
	ayaml.AddressPools[0].Addresses = []string{containerIPFmt}
	by, err := yaml.Marshal(ayaml)
	if err != nil {
		return err
	}
	cm.Data["config"] = string(by)
	// update the configmap
	cm.TypeMeta = metav1.TypeMeta{
		Kind:       "ConfigMap",
		APIVersion: corev1.SchemeGroupVersion.String(),
	}
	_, err = util.CreateOrUpdate(ctx, c, &cm)
	if err != nil {
		return err
	}

	cmd = exec.Command(
		"kubectl",
		"-n", "undistro-system",
		"rollout", "restart", "deployment", "metallb-controller",
	)
	err = cmd.Run()
	if err != nil {
		return err
	}
	// call undistro rollout to update metallb config
	return nil
}

func (o *InstallOptions) validateLocalEnvironment(ctx context.Context, c client.Client) error {
	isLocal, err := util.IsLocalCluster(ctx, c)
	if err != nil {
		return err
	}
	if isLocal {
		fmt.Fprintln(o.IOStreams.Out, "Cluster is local. Preparing environment...")
		err = validateSupervisorConfig(ctx, c, o.IOStreams.Out)
		if err != nil {
			return err
		}
		err = validateKindConfig(ctx, c, o.IOStreams.Out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *InstallOptions) RunInstall(f cmdutil.Factory, cmd *cobra.Command) error {
	restCfg, err := f.ToRESTConfig()
	if err != nil {
		return err
	}
	c, err := client.New(restCfg, client.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return err
	}
	restGetter := kube.NewInClusterRESTClientGetter(restCfg, ns)
	if !util.IsMgmtCluster(o.ClusterName) {
		byt, err := kubeconfig.FromSecret(cmd.Context(), c, util.ObjectKeyFromString(o.ClusterName))
		if err != nil {
			return err
		}
		restGetter = kube.NewMemoryRESTClientGetter(byt, ns)
		restCfg, err = restGetter.ToRESTConfig()
		if err != nil {
			return err
		}
		c, err = client.New(restCfg, client.Options{
			Scheme: scheme.Scheme,
		})
		if err != nil {
			return err
		}
	}
	cfg := make(map[string]interface{})
	if o.ConfigPath != "" {
		byt, err := os.ReadFile(o.ConfigPath)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(byt, &cfg)
		if err != nil {
			return err
		}
	}
	providers := o.checkEnabledList(cmd.Context(), c, cfg)
	if providers == nil {
		return errors.New("is required to install at least one provider")
	}
	hrs, err := o.installCore(cmd.Context(), c, restGetter, cfg, providers...)
	if err != nil {
		return err
	}
	err = o.validateLocalEnvironment(cmd.Context(), c)
	if err != nil {
		return err
	}
	fmt.Fprintln(o.IOStreams.Out, "Applying metadata...")
	err = o.applyMetadata(cmd.Context(), c, providers...)
	if err != nil {
		return err
	}
	fmt.Fprint(o.IOStreams.Out, "Waiting all components to be ready")
	deadline := time.Now().Add(10 * time.Minute)
	ctx, cancel := context.WithDeadline(cmd.Context(), deadline)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprint(o.ErrOut, "\n\n")
			return ctx.Err()
		default:
			ready := true
			runner, err := helm.NewRunner(restGetter, ns, log.Log)
			if err != nil {
				return err
			}
			var addrs []string
			for _, hr := range hrs {
				if hr.Name == "undistro" {
					type undistroCfg struct {
						Ingress struct {
							IpAddresses []string `json:"ipAddresses,omitempty"`
							Hosts       []string `json:"hosts,omitempty"`
						} `json:"ingress,omitempty"`
					}
					unCfg := undistroCfg{}
					err = json.Unmarshal(hr.Spec.Values.Raw, &unCfg)
					if err != nil {
						return err
					}
					addrs = append(unCfg.Ingress.IpAddresses, unCfg.Ingress.Hosts...)
				}
				_, err = util.CreateOrUpdate(ctx, c, &hr)
				if err != nil {
					ready = false
					continue
				}
				rel, err := runner.Status(hr)
				if err != nil {
					return err
				}
				if rel.Info.Status != release.StatusDeployed {
					ready = false
					continue
				}
			}
			if ready {
				guiUrl := fmt.Sprintf("https://%s", addrs[0])
				msg := fmt.Sprintf("\n\nManagement cluster is ready to use. \nUI is available at %s\n", guiUrl)
				fmt.Fprintln(o.IOStreams.Out, msg)
				return nil
			}
			fmt.Fprint(o.IOStreams.Out, ".")
			<-time.After(15 * time.Second)
		}
	}
}

func NewCmdInstall(f *ConfigFlags, streams genericclioptions.IOStreams) *cobra.Command {
	o := NewInstallOptions(streams)
	cmd := &cobra.Command{
		Use:                   "install [cluster namespace/cluster name]",
		DisableFlagsInUseLine: true,
		Short:                 "Install UnDistro",
		Long: LongDesc(`Install UnDistro.
		If cluster argument exists UnDistro will be installed in this remote cluster.
		If config file exists UnDistro will be installed using file's configurations`),
		Example: Examples(`
		# Install UnDistro in local cluster
		undistro install
		# Install UnDistro in remote cluster
		undistro install undistro-production/cool-product-cluster
		# Install UnDistro with configuration file
		undistro --config undistro-config.yaml install undistro-production/cool-product-cluster
		`),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Validate())
			err := o.RunInstall(cmdutil.NewFactory(f), cmd)
			if err != nil {
				fmt.Fprintf(o.ErrOut, "error: %v\n", err)
			}
		},
	}
	return cmd
}
