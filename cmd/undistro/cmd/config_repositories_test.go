/*
Copyright 2020 Getup Cloud. All rights reserved.
*/

package cmd

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func Test_runGetRepositories(t *testing.T) {
	t.Run("prints output", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir, err := ioutil.TempDir("", "cc")
		g.Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		path := filepath.Join(tmpDir, "undistro.yaml")
		g.Expect(ioutil.WriteFile(path, []byte(template), 0600)).To(Succeed())

		buf := bytes.NewBufferString("")

		for _, val := range RepositoriesOutputs {
			cro.output = val
			g.Expect(runGetRepositories(path, buf)).To(Succeed())
			out, err := ioutil.ReadAll(buf)
			g.Expect(err).ToNot(HaveOccurred())
			if val == RepositoriesOutputText {
				g.Expect(string(out)).To(Equal(expectedOutputText))
			} else if val == RepositoriesOutputYaml {
				g.Expect(string(out)).To(Equal(expectedOutputYaml))
			}
		}
	})

	t.Run("returns error for bad cfgFile path", func(t *testing.T) {
		g := NewWithT(t)
		buf := bytes.NewBufferString("")
		g.Expect(runGetRepositories("do-not-exist", buf)).ToNot(Succeed())
	})

	t.Run("returns error for nil writer", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(runGetRepositories("do-exist", nil)).ToNot(Succeed())
	})

	t.Run("returns error for bad template", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir, err := ioutil.TempDir("", "cc")
		g.Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		path := filepath.Join(tmpDir, "undistro.yaml")
		g.Expect(ioutil.WriteFile(path, []byte("providers: foobar"), 0600)).To(Succeed())

		buf := bytes.NewBufferString("")
		g.Expect(runGetRepositories(path, buf)).ToNot(Succeed())
	})
}

var template = `---
providers:
  # add a custom provider
  - name: "my-infra-provider"
    url: "/home/.undistro/overrides/infrastructure-docker/latest/infrastructure-components.yaml"
    type: "InfrastructureProvider"
  # add a custom provider
  - name: "another-provider"
    url: "./bootstrap-components.yaml"
    type: "BootstrapProvider"
  # bad url
  - name: "aws"
    url: "my-aws-infrastructure-components.yaml"
    type: "InfrastructureProvider"
  # override a pre-defined provider
  - name: "cluster-api"
    url: "https://github.com/myorg/myforkofclusterapi/releases/latest/core_components.yaml"
    type: "CoreProvider"
`

var expectedOutputText = `NAME                TYPE                     URL                                                                                          FILE
cluster-api         CoreProvider             https://github.com/myorg/myforkofclusterapi/releases/latest/                                 core_components.yaml
undistro            UndistroProvider         https://github.com/getupcloud/undistro/releases/latest/                                      core-components.yaml
another-provider    BootstrapProvider        ./                                                                                           bootstrap-components.yaml
eks                 BootstrapProvider        https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/latest/                 eks-bootstrap-components.yaml
kubeadm             BootstrapProvider        https://github.com/kubernetes-sigs/cluster-api/releases/latest/                              bootstrap-components.yaml
talos               BootstrapProvider        https://github.com/talos-systems/cluster-api-bootstrap-provider-talos/releases/latest/       bootstrap-components.yaml
eks                 ControlPlaneProvider     https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/latest/                 eks-controlplane-components.yaml
kubeadm             ControlPlaneProvider     https://github.com/kubernetes-sigs/cluster-api/releases/latest/                              control-plane-components.yaml
talos               ControlPlaneProvider     https://github.com/talos-systems/cluster-api-control-plane-provider-talos/releases/latest/   control-plane-components.yaml
aws                 InfrastructureProvider                                                                                                my-aws-infrastructure-components.yaml
azure               InfrastructureProvider   https://github.com/kubernetes-sigs/cluster-api-provider-azure/releases/latest/               infrastructure-components.yaml
metal3              InfrastructureProvider   https://github.com/metal3-io/cluster-api-provider-metal3/releases/latest/                    infrastructure-components.yaml
my-infra-provider   InfrastructureProvider   /home/.undistro/overrides/infrastructure-docker/latest/                                      infrastructure-components.yaml
openstack           InfrastructureProvider   https://github.com/kubernetes-sigs/cluster-api-provider-openstack/releases/latest/           infrastructure-components.yaml
packet              InfrastructureProvider   https://github.com/kubernetes-sigs/cluster-api-provider-packet/releases/latest/              infrastructure-components.yaml
vsphere             InfrastructureProvider   https://github.com/kubernetes-sigs/cluster-api-provider-vsphere/releases/latest/             infrastructure-components.yaml
`

var expectedOutputYaml = `- File: core_components.yaml
  Name: cluster-api
  ProviderType: CoreProvider
  URL: https://github.com/myorg/myforkofclusterapi/releases/latest/
- File: core-components.yaml
  Name: undistro
  ProviderType: UndistroProvider
  URL: https://github.com/getupcloud/undistro/releases/latest/
- File: bootstrap-components.yaml
  Name: another-provider
  ProviderType: BootstrapProvider
  URL: ./
- File: eks-bootstrap-components.yaml
  Name: eks
  ProviderType: BootstrapProvider
  URL: https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/latest/
- File: bootstrap-components.yaml
  Name: kubeadm
  ProviderType: BootstrapProvider
  URL: https://github.com/kubernetes-sigs/cluster-api/releases/latest/
- File: bootstrap-components.yaml
  Name: talos
  ProviderType: BootstrapProvider
  URL: https://github.com/talos-systems/cluster-api-bootstrap-provider-talos/releases/latest/
- File: eks-controlplane-components.yaml
  Name: eks
  ProviderType: ControlPlaneProvider
  URL: https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/latest/
- File: control-plane-components.yaml
  Name: kubeadm
  ProviderType: ControlPlaneProvider
  URL: https://github.com/kubernetes-sigs/cluster-api/releases/latest/
- File: control-plane-components.yaml
  Name: talos
  ProviderType: ControlPlaneProvider
  URL: https://github.com/talos-systems/cluster-api-control-plane-provider-talos/releases/latest/
- File: my-aws-infrastructure-components.yaml
  Name: aws
  ProviderType: InfrastructureProvider
  URL: ""
- File: infrastructure-components.yaml
  Name: azure
  ProviderType: InfrastructureProvider
  URL: https://github.com/kubernetes-sigs/cluster-api-provider-azure/releases/latest/
- File: infrastructure-components.yaml
  Name: metal3
  ProviderType: InfrastructureProvider
  URL: https://github.com/metal3-io/cluster-api-provider-metal3/releases/latest/
- File: infrastructure-components.yaml
  Name: my-infra-provider
  ProviderType: InfrastructureProvider
  URL: /home/.undistro/overrides/infrastructure-docker/latest/
- File: infrastructure-components.yaml
  Name: openstack
  ProviderType: InfrastructureProvider
  URL: https://github.com/kubernetes-sigs/cluster-api-provider-openstack/releases/latest/
- File: infrastructure-components.yaml
  Name: packet
  ProviderType: InfrastructureProvider
  URL: https://github.com/kubernetes-sigs/cluster-api-provider-packet/releases/latest/
- File: infrastructure-components.yaml
  Name: vsphere
  ProviderType: InfrastructureProvider
  URL: https://github.com/kubernetes-sigs/cluster-api-provider-vsphere/releases/latest/
`
