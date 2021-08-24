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
	"flag"

	"github.com/getupio-undistro/undistro/pkg/meta"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	jsoniter "github.com/json-iterator/go"
	"github.com/spf13/pflag"
	knet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type ConfigFlags struct {
	ConfigFile *string
	*genericclioptions.ConfigFlags
}

// NewConfigFlags returns ConfigFlags with default values set
func NewConfigFlags() *ConfigFlags {
	return &ConfigFlags{
		ConfigFile:  stringptr(""),
		ConfigFlags: genericclioptions.NewConfigFlags(true),
	}
}

func (f *ConfigFlags) AddFlags(flags *pflag.FlagSet, goflags *flag.FlagSet) {
	klog.InitFlags(goflags)
	flags.AddGoFlagSet(goflags)
	if f.ConfigFile != nil {
		flags.StringVar(f.ConfigFile, "config", *f.ConfigFile, "Path to undistro configuration (default is `$HOME/.undistro/undistro.yaml`)")
	}
	f.ConfigFlags.AddFlags(flags)
}

func stringptr(s string) *string {
	return &s
}

func defaultValues(ctx context.Context, c client.Client, name string) map[string]interface{} {
	isKind, _ := util.IsLocalCluster(ctx, c)
	ip, _ := knet.ChooseHostInterface()
	switch name {
	case "undistro":
		if ip.String() != "" && isKind {
			return map[string]interface{}{
				"local": true,
				"ingress": map[string]interface{}{
					"ipAddresses": []string{
						ip.String(),
					},
				},
			}
		}
		if ip.String() == "" && isKind {
			return map[string]interface{}{
				"local": true,
			}
		}
	case "ingress-nginx":
		if isKind {
			return map[string]interface{}{
				"controller": map[string]interface{}{
					"service": map[string]interface{}{
						"annotations": map[string]interface{}{
							"metallb.universe.tf/address-pool": "default",
						},
						"externalTrafficPolicy": "Local",
					},
					"tolerations": []map[string]interface{}{
						{
							"effect":   "NoSchedule",
							"key":      meta.LabelK8sMaster,
							"operator": "Equal",
						},
					},
					"extraArgs": map[string]interface{}{
						"default-ssl-certificate": undistro.Namespace + "/undistro-ingress-cert",
					},
					"admissionWebhooks": map[string]interface{}{
						"enabled": false,
					},
				},
			}
		}
		return map[string]interface{}{
			"controller": map[string]interface{}{
				"extraArgs": map[string]interface{}{
					"default-ssl-certificate": undistro.Namespace + "/undistro-ingress-cert",
				},
				"admissionWebhooks": map[string]interface{}{
					"enabled": false,
				},
			},
		}

	}
	return make(map[string]interface{})
}
