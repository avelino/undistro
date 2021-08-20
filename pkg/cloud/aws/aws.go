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
package aws

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	metadatav1alpha1 "github.com/getupio-undistro/undistro/apis/metadata/v1alpha1"
	"github.com/getupio-undistro/undistro/pkg/cloud/aws/cloudformation"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	capi "sigs.k8s.io/cluster-api/api/v1alpha4"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultAWSRegion       = "us-east-1"
	name                   = "undistro-aws-config"
	namespace              = "undistro-system"
	key                    = "credentials"
	eksTool                = "aws-iam-authenticator"
	awsCredentialsTemplate = `[default]
aws_access_key_id = {{ .AccessKeyID }}
aws_secret_access_key = {{ .SecretAccessKey }}
region = {{ .Region }}
{{if .SessionToken }}
aws_session_token = {{ .SessionToken }}
{{end}}`
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

//go:embed instancetypes.json
var instanceTypes []byte

var Regions = []string{
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-south-1",
	"ap-southeast-1",
	"ap-northeast-2",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"sa-east-1",
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
}

var flavors = map[string][]string{
	appv1alpha1.EC2.String(): {
		"v1.19.12", "v1.19.13", "v1.20.8", "1.20.9", "v1.21.2", "v1.21.3",
	},
	appv1alpha1.EKS.String(): {
		"v1.19.8", "v1.20.7", "v1.21.2",
	},
}

func GetFlavors(_ context.Context, p metadatav1alpha1.Provider) ([]client.Object, error) {
	ref := &corev1.ObjectReference{
		APIVersion: p.APIVersion,
		Kind:       p.Kind,
		Name:       p.Name,
		Namespace:  p.Namespace,
	}
	typeMeta := metav1.TypeMeta{
		APIVersion: metadatav1alpha1.GroupVersion.String(),
		Kind:       "Flavor",
	}
	objs := make([]client.Object, len(flavors))
	index := 0
	for k, v := range flavors {
		o := metadatav1alpha1.Flavor{
			TypeMeta: typeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name: k,
			},
			Spec: metadatav1alpha1.FlavorSpec{
				ProviderRef:          ref,
				SupportedK8sVersions: v,
			},
		}
		objs[index] = &o
		index++
	}
	return objs, nil
}

func GetMachineMetadata(_ context.Context, p metadatav1alpha1.Provider) ([]client.Object, error) {
	ref := &corev1.ObjectReference{
		APIVersion: p.APIVersion,
		Kind:       p.Kind,
		Name:       p.Name,
		Namespace:  p.Namespace,
	}
	typeMeta := metav1.TypeMeta{
		APIVersion: metadatav1alpha1.GroupVersion.String(),
		Kind:       "AWSMachine",
	}
	specs := make([]metadatav1alpha1.AWSMachineSpec, 0)
	err := json.Unmarshal(instanceTypes, &specs)
	if err != nil {
		return nil, err
	}
	objs := make([]client.Object, len(specs))
	for i, spec := range specs {
		o := metadatav1alpha1.AWSMachine{
			TypeMeta: typeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name: spec.InstanceType,
			},
			Spec: spec,
		}
		o.Spec.ProviderRef = ref
		objs[i] = &o
	}
	return objs, nil
}

func kindByFlavor(flavor string) string {
	switch flavor {
	case "ec2":
		return "AWSMachinePool"
	case "eks":
		return "AWSManagedMachinePool"
	}
	return ""
}

func launchTemplateRef(ctx context.Context, u unstructured.Unstructured) (appv1alpha1.LaunchTemplateReference, error) {
	var (
		ref     appv1alpha1.LaunchTemplateReference
		version int64
		ok      bool
		err     error
	)
	switch u.GetKind() {
	case "AWSMachinePool":
		ref.ID, ok, err = unstructured.NestedString(u.Object, "spec", "awsLaunchTemplate", "id")
		if !ok || err != nil {
			return ref, err
		}
		version, ok, err = unstructured.NestedInt64(u.Object, "spec", "awsLaunchTemplate", "versionNumber")
		if !ok || err != nil {
			return ref, err
		}
		ref.Version = strconv.Itoa(int(version))
	}
	return ref, nil
}

func ReconcileLaunchTemplate(ctx context.Context, r client.Client, cl *appv1alpha1.Cluster) error {
	for i := range cl.Spec.Workers {
		if !cl.Spec.InfrastructureProvider.IsManaged() {
			key := client.ObjectKey{
				Name:      fmt.Sprintf("%s-mp-%d", cl.Name, i),
				Namespace: cl.GetNamespace(),
			}
			u := unstructured.Unstructured{}
			u.SetAPIVersion("infrastructure.cluster.x-k8s.io/v1alpha4")
			u.SetKind(kindByFlavor(cl.Spec.InfrastructureProvider.Flavor))
			err := r.Get(ctx, key, &u)
			if err != nil {
				return client.IgnoreNotFound(err)
			}
			ref, err := launchTemplateRef(ctx, u)
			if err != nil {
				return err
			}
			cl.Spec.Workers[i].LaunchTemplateReference = ref
		}
	}
	return nil
}

func ReconcileNetwork(ctx context.Context, r client.Client, cl *appv1alpha1.Cluster, capiCluster *capi.Cluster) error {
	u := unstructured.Unstructured{}
	key := client.ObjectKey{}
	if cl.Spec.InfrastructureProvider.IsManaged() {
		u.SetGroupVersionKind(capiCluster.Spec.ControlPlaneRef.GroupVersionKind())
		key = client.ObjectKey{
			Name:      capiCluster.Spec.ControlPlaneRef.Name,
			Namespace: capiCluster.Spec.ControlPlaneRef.Namespace,
		}
	} else {
		u.SetGroupVersionKind(capiCluster.Spec.InfrastructureRef.GroupVersionKind())
		key = client.ObjectKey{
			Name:      capiCluster.Spec.InfrastructureRef.Name,
			Namespace: capiCluster.Spec.InfrastructureRef.Namespace,
		}
	}
	err := r.Get(ctx, key, &u)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	return clusterNetwork(ctx, cl, u)
}

func clusterNetwork(ctx context.Context, cl *appv1alpha1.Cluster, u unstructured.Unstructured) error {
	host, ok, err := unstructured.NestedString(u.Object, "spec", "controlPlaneEndpoint", "host")
	if err != nil {
		return err
	}
	if ok && host != "" {
		cl.Spec.ControlPlane.Endpoint.Host = host
	}
	port, ok, err := unstructured.NestedInt64(u.Object, "spec", "controlPlaneEndpoint", "port")
	if err != nil {
		return err
	}
	if ok && port != 0 {
		cl.Spec.ControlPlane.Endpoint.Port = int32(port)
	}
	vpc, ok, err := unstructured.NestedMap(u.Object, "spec", "networkSpec", "vpc")
	if err != nil {
		return err
	}
	if ok {
		id, ok := vpc["id"]
		if ok {
			cl.Spec.Network.VPC.ID = id.(string)
		}
		cidr, ok := vpc["cidrBlock"]
		if ok {
			cl.Spec.Network.VPC.CIDRBlock = cidr.(string)
		}
	}
	subnets, ok, err := unstructured.NestedSlice(u.Object, "spec", "networkSpec", "subnets")
	if err != nil {
		return err
	}
	if ok {
		for _, s := range subnets {
			subnet, ok := s.(map[string]interface{})
			if !ok {
				return errors.Errorf("unable to reconcile subnets for cluster %s/%s", cl.Namespace, cl.Name)
			}
			n := appv1alpha1.NetworkSpec{
				ID:        subnet["id"].(string),
				CIDRBlock: subnet["cidrBlock"].(string),
				IsPublic:  subnet["isPublic"].(bool),
			}
			cl.Spec.Network.Subnets = append(cl.Spec.Network.Subnets, n)
		}
		cl.Spec.Network.Subnets = removeDuplicateNetwork(cl.Spec.Network.Subnets)
	}
	return nil
}

func removeDuplicateNetwork(n []appv1alpha1.NetworkSpec) []appv1alpha1.NetworkSpec {
	nMap := make(map[appv1alpha1.NetworkSpec]struct{})
	for _, t := range n {
		nMap[t] = struct{}{}
	}
	res := make([]appv1alpha1.NetworkSpec, 0)
	for k := range nMap {
		res = append(res, k)
	}
	return res
}

type AwsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

func (c AwsCredentials) renderAWSDefaultProfile() (string, error) {
	tmpl, err := template.New("AWS Credentials").Parse(awsCredentialsTemplate)
	if err != nil {
		return "", err
	}
	var credsFileStr bytes.Buffer
	err = tmpl.Execute(&credsFileStr, c)
	if err != nil {
		return "", err
	}
	return credsFileStr.String(), nil
}

func (c AwsCredentials) setBase64EncodedAWSDefaultProfile(ctx context.Context, cl client.Client, secret *corev1.Secret) error {
	profile, err := c.renderAWSDefaultProfile()
	if err != nil {
		return err
	}
	secret.Data[key] = []byte(profile)
	err = cl.Update(ctx, secret)
	if err != nil {
		return err
	}
	return nil
}

// Init providers
func Init(ctx context.Context, c client.Client) error {
	cred, secret, err := Credentials(ctx, c)
	if err != nil {
		return err
	}
	err = cred.setBase64EncodedAWSDefaultProfile(ctx, c, secret)
	if err != nil {
		return err
	}
	err = reconcileCloudformation(cred)
	if err != nil {
		return err
	}
	return nil
}

func reconcileCloudformation(cred AwsCredentials) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(cred.Region),
		Credentials: credentials.NewStaticCredentials(
			cred.AccessKeyID,
			cred.SecretAccessKey,
			cred.SessionToken,
		),
	})
	if err != nil {
		return err
	}
	cfnSvc := cloudformation.NewService(cfn.New(sess))
	return cfnSvc.ReconcileBootstrapStack(cloudformation.Template)
}

func Credentials(ctx context.Context, c client.Client) (AwsCredentials, *corev1.Secret, error) {
	secret := corev1.Secret{}
	nm := client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}
	err := c.Get(ctx, nm, &secret)
	if err != nil {
		return AwsCredentials{}, nil, err
	}
	cred, err := credentialsFromSecret(&secret)
	if err != nil {
		return AwsCredentials{}, nil, err
	}
	return cred, &secret, nil
}

func credentialsFromSecret(s *corev1.Secret) (AwsCredentials, error) {
	cred := AwsCredentials{
		AccessKeyID:     getData(s, "accessKeyID"),
		SecretAccessKey: getData(s, "secretAccessKey"),
		Region:          getData(s, "region"),
		SessionToken:    getData(s, "sessionToken"),
	}
	if cred.Region == "" {
		cred.Region = DefaultAWSRegion
	}
	return cred, nil
}

func getData(secret *corev1.Secret, key string) string {
	b, ok := secret.Data[key]
	if !ok {
		return ""
	}
	return string(b)
}

type Account struct {
	stsClient stsiface.STSAPI
	out       *sts.GetCallerIdentityOutput
}

func NewAccount(ctx context.Context, c client.Client) (*Account, error) {
	cred, _, err := Credentials(ctx, c)
	if err != nil {
		return nil, err
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(cred.Region),
		Credentials: credentials.NewStaticCredentials(
			cred.AccessKeyID,
			cred.SecretAccessKey,
			cred.SessionToken,
		),
	})
	if err != nil {
		return nil, err
	}
	stsClient := sts.New(sess)
	out, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	return &Account{
		stsClient: stsClient,
		out:       out,
	}, nil
}

func (a *Account) GetID() string {
	return aws.StringValue(a.out.Account)
}

func (a *Account) GetUsername() string {
	return aws.StringValue(a.out.Arn)
}

func (a *Account) IsRoot() bool {
	return strings.HasSuffix(a.GetUsername(), "root")
}

func InstallTools(ctx context.Context, streams genericclioptions.IOStreams) error {
	_, err := exec.LookPath(eksTool)
	if err == nil {
		fmt.Fprintf(streams.Out, "%s already installed\n", eksTool)
		return nil
	}
	addr := fmt.Sprintf("https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/%s/%s/aws-iam-authenticator", runtime.GOOS, runtime.GOARCH)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return err
	}

	f, err := os.Create(eksTool)
	if err != nil {
		return err
	}
	f.Chmod(0755)
	defer f.Close()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		f.Close()
		os.RemoveAll(eksTool)
		return errors.Errorf("unable to download %s: %v", eksTool, http.StatusText(resp.StatusCode))
	}
	_, err = exec.LookPath(eksTool)
	if err != nil {
		fmt.Fprintf(streams.Out, "PLEASE ADD %s IN YOUR $PATH\n", eksTool)
	}
	return nil
}
