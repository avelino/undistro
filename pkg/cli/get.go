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
	"github.com/getupio-undistro/undistro/pkg/kube"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	pinnipedcmd "github.com/getupio-undistro/undistro/third_party/pinniped/pinniped/cmd"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/kubectl/pkg/cmd/get"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type KubeconfigOptions struct {
	genericclioptions.IOStreams
	Namespace      string
	ClusterName    string
	Admin          bool
	Kubeconfigdeps pinnipedcmd.KubeconfigDeps
}

func (k *KubeconfigOptions) addFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&k.Admin, "admin", k.Admin, "Get admin kubeconfig")
}

func NewKubeconfigOptions(streams genericclioptions.IOStreams, deps pinnipedcmd.KubeconfigDeps) *KubeconfigOptions {
	var kubeOpts = &KubeconfigOptions{
		IOStreams:      streams,
		Kubeconfigdeps: deps,
	}
	return kubeOpts
}

func (o *KubeconfigOptions) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	var err error
	o.Namespace, _, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}
	if len(args) != 1 && o.Admin {
		return errors.New("required 1 argument")
	}
	o.ClusterName = args[0]
	return nil
}

func (o *KubeconfigOptions) RunGetKubeconfig(f cmdutil.Factory, cmd *cobra.Command, params pinnipedcmd.GetKubeconfigParams) error {
	cfg, err := f.ToRESTConfig()
	if err != nil {
		return errors.Errorf("unable to get kubeconfig: %v", err)
	}
	c, err := client.New(cfg, client.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return errors.Errorf("unable to create client: %v", err)
	}
	var byt []byte
	if o.Admin {
		byt, err = kube.GetInternalKubeconfig(cmd.Context(), c, client.ObjectKey{
			Namespace: o.Namespace,
			Name:      o.ClusterName,
		})
		if err != nil {
			return errors.Errorf("unable to get kubeconfig: %v", err)
		}
		_, err = o.IOStreams.Out.Write(byt)
		if err != nil {
			return errors.Errorf("unable to get kubeconfig: %v", err)
		}
	} else {
		err = pinnipedcmd.RunGetKubeconfig(cmd.Context(), o.IOStreams.Out, o.Kubeconfigdeps, params)
		if err != nil {
			return errors.Errorf("unable to get kubeconfig: %v", err)
		}
	}
	return nil
}

func NewCmdKubeconfig(f cmdutil.Factory, streams genericclioptions.IOStreams) *cobra.Command {
	o := NewKubeconfigOptions(streams, pinnipedcmd.KubeconfigRealDeps())
	cmd := &cobra.Command{
		Use:                   "kubeconfig [cluster name]",
		DisableFlagsInUseLine: true,
		Short:                 "Get kubeconfig of a cluster",
		Long:                  LongDesc(`Get kubeconfig of a cluster created or imported by UnDistro.`),
		Example: Examples(`		
		# Get kubeconfig of a cluster in default namespace
		undistro get kubeconfig cool-cluster
		# Get kubeconfig of a cluster in others namespace
		undistro get kubeconfig cool-cluster -n cool-namespace
		`),
	}
	cmd, flags := pinnipedcmd.SetupPinnipedCommand(cmd)
	fn := func(cmd *cobra.Command, args []string) {
		cmdutil.CheckErr(o.Complete(f, cmd, args))
		cmdutil.CheckErr(o.RunGetKubeconfig(f, cmd, flags))
	}
	cmd.Run = fn
	o.addFlags(cmd.Flags())
	return cmd
}

func NewCmdGet(f cmdutil.Factory, streams genericclioptions.IOStreams) *cobra.Command {
	cmd := get.NewCmdGet("undistro", f, streams)
	cmd.AddCommand(NewCmdKubeconfig(f, streams))
	return cmd
}
