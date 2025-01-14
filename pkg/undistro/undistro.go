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
package undistro

const (
	Namespace   = "undistro-system"
	DefaultRepo = "https://registry.undistro.io/chartrepo/library"
)

const LocalCluster = "undistro"

var KindCmdDestroy = `kind delete cluster --name "%s"`

var KindCmdCreate = `cat <<EOF | kind create cluster --name "%s" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerPort: 6443
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
EOF`

var TestResources = `---
apiVersion: v1
kind: Namespace
metadata:
  name: undistro-test
---
apiVersion: app.undistro.io/v1alpha1
kind: Cluster
metadata:
  name: undistro-test
  namespace: undistro-test
spec:
  paused: true
  kubernetesVersion: v1.18.2
  controlPlane:
    replicas: 3
    machineType: t3.large
  workers:
    - replicas: 3
      machineType: t3.large
  infrastructureProvider:
    name: aws
    sshKey: undistro
    region: us-east1
    flavor: ec2`
