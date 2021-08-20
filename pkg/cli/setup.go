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
	"context"
	"fmt"
	"os/exec"

	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type SetupOptions struct {
	genericclioptions.IOStreams
	Tool string
	Name string
}

func NewSetupOptions(streams genericclioptions.IOStreams) *SetupOptions {
	return &SetupOptions{
		IOStreams: streams,
	}
}

func (o *SetupOptions) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.Name, "name", o.Name, "name of the cluster (default: undistro)")
}

func (o *SetupOptions) Complete(args []string) error {
	o.Tool = args[0]
	if o.Tool != "kind" {
		return errors.Errorf("unknown tool: %s", o.Tool)
	}
	if o.Name == "" {
		o.Name = undistro.LocalCluster
	}
	return nil
}

func (o *SetupOptions) RunSetup(cmd *cobra.Command) error {
	c := o.getCmd(cmd.Context())
	if c == nil {
		return errors.Errorf("unknown tool: %s", o.Tool)
	}
	c.Stdin = o.IOStreams.In
	c.Stderr = o.IOStreams.ErrOut
	c.Stdout = o.IOStreams.Out
	return c.Run()
}

func (o *SetupOptions) getCmd(ctx context.Context) *exec.Cmd {
	var script string
	switch o.Tool {
	case "kind":
		script = fmt.Sprintf(undistro.KindCmdCreate, o.Name)
	default:
		return nil
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	return cmd
}

func NewCmdSetup(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewSetupOptions(streams)
	cmd := &cobra.Command{
		Use:                   "setup [tool]",
		DisableFlagsInUseLine: true,
		Short:                 "Setup a tool",
		Long:                  LongDesc(`Setup a tool`),
		Example: Examples(`
		undistro setup kind --name undistro-cluster
		`),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(args))
			cmdutil.CheckErr(o.RunSetup(cmd))
		},
	}
	o.AddFlags(cmd.Flags())
	return cmd
}
