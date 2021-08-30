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
package e2e_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/cluster-api/test/framework/exec"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Helm Release", func() {
	It("Should apply helm release", func() {
		cmd := exec.NewCommand(
			exec.WithCommand("undistro"),
			exec.WithArgs("apply", "-f", "./testdata/k8s-dash.yaml"),
		)
		out, _, err := cmd.Run(context.Background())
		Expect(err).ToNot(HaveOccurred())
		fmt.Println(string(out))
		Eventually(func() []corev1.Pod {
			pods := corev1.PodList{}
			err = k8sClient.List(context.Background(), &pods, client.InNamespace("k8s-dash"))
			if err != nil {
				fmt.Println(err)
				return pods.Items
			}
			return pods.Items
		}, 120*time.Minute, 2*time.Minute).Should(HaveLen(1))
		fmt.Println("RBAC")
		Eventually(func() error {
			rb := rbacv1.ClusterRoleBinding{}
			key := client.ObjectKey{
				Name: "dashboard-access",
			}
			return k8sClient.Get(context.Background(), key, &rb)
		}, 10*time.Minute, 1*time.Minute).Should(BeNil())
		Eventually(func() error {
			sa := corev1.ServiceAccount{}
			key := client.ObjectKey{
				Name:      "undistro-quickstart-dash",
				Namespace: "k8s-dash",
			}
			return k8sClient.Get(context.Background(), key, &sa)
		}, 10*time.Minute, 1*time.Minute).Should(BeNil())
	}, float64(240*time.Minute))

	It("Should upgrade helm release", func() {
		cmd := exec.NewCommand(
			exec.WithCommand("undistro"),
			exec.WithArgs("apply", "-f", "./testdata/k8s-dash-upgrade.yaml"),
		)
		out, _, err := cmd.Run(context.Background())
		Expect(err).ToNot(HaveOccurred())
		fmt.Println(string(out))
		Eventually(func() []corev1.Pod {
			pods := corev1.PodList{}
			err = k8sClient.List(context.Background(), &pods, client.InNamespace("k8s-dash"))
			if err != nil {
				fmt.Println(err)
				return pods.Items
			}
			return pods.Items
		}, 120*time.Minute, 2*time.Minute).Should(HaveLen(1))
		fmt.Println("RBAC Upgrade")
		Eventually(func() error {
			rb := rbacv1.ClusterRoleBinding{}
			key := client.ObjectKey{
				Name: "dashboard-access",
			}
			return k8sClient.Get(context.Background(), key, &rb)
		}, 10*time.Minute, 1*time.Minute).Should(BeNil())
		Eventually(func() error {
			sa := corev1.ServiceAccount{}
			key := client.ObjectKey{
				Name:      "undistro-quickstart-dash",
				Namespace: "k8s-dash",
			}
			return k8sClient.Get(context.Background(), key, &sa)
		}, 10*time.Minute, 1*time.Minute).Should(BeNil())
		Eventually(func() []networkingv1.Ingress {
			ingresses := networkingv1.IngressList{}
			err = k8sClient.List(context.Background(), &ingresses, client.InNamespace("k8s-dash"))
			if err != nil {
				fmt.Println(err)
				return ingresses.Items
			}
			return ingresses.Items
		}, 120*time.Minute, 2*time.Minute).Should(HaveLen(1))
	}, float64(240*time.Minute))
})
