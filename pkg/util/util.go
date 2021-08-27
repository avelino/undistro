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
package util

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"github.com/getupio-undistro/undistro/pkg/retry"
	"io"
	"math"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/release"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	apiyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var chartNameRegex *regexp.Regexp

func init() {
	chartNameRegex = regexp.MustCompile("[a-z]+-?[a-z]{2,}")
}

// MergeMaps merges map b into given map a and returns the result.
// It allows overwrites of map values with flat values, and vice versa.
// This is copied from https://github.com/helm/helm/blob/v3.3.0/pkg/cli/values/options.go#L88,
// as the public chartutil.CoalesceTables function does not allow
// overwriting maps with flat values.
func MergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = MergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

// ValuesChecksum calculates and returns the SHA1 checksum for the
// given chartutil.Values.
func ValuesChecksum(values chartutil.Values) string {
	var (
		s   []byte
		err error
	)
	if len(values) != 0 {
		s, err = json.Marshal(values.AsMap())
		if err != nil {
			klog.Error(err)
		}
	}
	return fmt.Sprintf("%x", sha1.Sum(s))
}

// ReleaseRevision returns the revision of the given release.Release.
func ReleaseRevision(rel *release.Release) int {
	if rel == nil {
		return 0
	}
	return rel.Version
}

func CreateOrUpdate(ctx context.Context, r client.Client, o client.Object) (bool, error) {
	uo, ok := o.(*unstructured.Unstructured)
	if !ok {
		u := unstructured.Unstructured{}
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
		if err != nil {
			return false, err
		}
		u.Object = m
		uo = &u
	}
	old := unstructured.Unstructured{}
	old.SetGroupVersionKind(uo.GroupVersionKind())
	nm := client.ObjectKey{
		Name:      o.GetName(),
		Namespace: o.GetNamespace(),
	}
	err := r.Get(ctx, nm, &old)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return false, err
		}
		err = r.Create(ctx, uo)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	uo.SetResourceVersion(old.GetResourceVersion())

	mf := client.MergeFrom(&old)

	byt, err := mf.Data(uo)
	if err != nil {
		return false, err
	}

	err = r.Patch(ctx, uo, mf)
	if err != nil {
		return false, err
	}
	return len(byt) > 0, nil
}

// ToUnstructured takes a YAML and converts it to a list of Unstructured objects
func ToUnstructured(rawyaml []byte) ([]unstructured.Unstructured, error) {
	var ret []unstructured.Unstructured

	reader := apiyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(rawyaml)))
	count := 1
	for {
		// Read one YAML document at a time, until io.EOF is returned
		b, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, errors.Wrapf(err, "failed to read yaml")
		}
		if len(b) == 0 {
			break
		}

		var m map[string]interface{}
		if err := yaml.Unmarshal(b, &m); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal the %s yaml document: %q", Ordinalize(count), string(b))
		}

		var u unstructured.Unstructured
		u.SetUnstructuredContent(m)

		// Ignore empty objects.
		// Empty objects are generated if there are weird things in manifest files like e.g. two --- in a row without a yaml doc in the middle
		if u.Object == nil {
			continue
		}

		ret = append(ret, u)
		count++
	}

	return ret, nil
}

// Ordinalize takes an int and returns the ordinalized version of it.
// Eg. 1 --> 1st, 103 --> 103rd
func Ordinalize(n int) string {
	m := map[int]string{
		0: "th",
		1: "st",
		2: "nd",
		3: "rd",
		4: "th",
		5: "th",
		6: "th",
		7: "th",
		8: "th",
		9: "th",
	}

	an := int(math.Abs(float64(n)))
	if an < 10 {
		return fmt.Sprintf("%d%s", n, m[an])
	}
	return fmt.Sprintf("%d%s", n, m[an%10])
}

func ContainsStringInSlice(ss []string, str string) bool {
	for _, s := range ss {
		if s == str {
			return true
		}
	}
	return false
}

func ObjectKeyFromString(str string) client.ObjectKey {
	c := client.ObjectKey{}
	split := strings.Split(str, "/")
	if len(split) == 2 {
		c.Name = split[1]
		c.Namespace = split[0]
	} else {
		c.Name = split[0]
		c.Namespace = "default"
	}
	return c
}

func RemoveDuplicateTaints(taints []corev1.Taint) []corev1.Taint {
	taintMap := make(map[corev1.Taint]struct{})
	for _, t := range taints {
		taintMap[t] = struct{}{}
	}
	res := make([]corev1.Taint, 0)
	for k := range taintMap {
		res = append(res, k)
	}
	sort.Slice(res[:], func(i, j int) bool {
		return res[i].Key < res[j].Key
	})
	return res
}

func IsLocalCluster(ctx context.Context, c client.Client) (bool, error) {
	nodes := corev1.NodeList{}
	err := c.List(ctx, &nodes)
	if err != nil {
		return false, err
	}
	for _, node := range nodes.Items {
		for _, image := range node.Status.Images {
			for _, name := range image.Names {
				if strings.Contains(name, "kindnet") || strings.Contains(name, "minikube") {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func ChartNameByFile(name string) string {
	// just support `chart-name` format
	// `chart-name-test` format will fail
	return chartNameRegex.FindString(name)
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return stringWithCharset(length, charset)
}

func GetCaFromSecret(ctx context.Context, c client.Client, secretName, dataField, ns string) (crt []byte, err error) {
	objKey := client.ObjectKey{
		Namespace: ns,
		Name:      secretName,
	}
	secret := corev1.Secret{}
	err = retry.WithExponentialBackoff(retry.NewBackoff(), func() error {
		err = c.Get(ctx, objKey, &secret)
		if err != nil {
			return errors.Errorf("unable to get CA secret %s: %v", secretName, err)
		}
		return nil
	})
	if err != nil {
		return
	}
	return secret.Data[dataField], nil
}

func IsMgmtCluster(clusterName string) bool {
	return clusterName == ""
}

func GetFromConfigMap(ctx context.Context, c client.Client, name, ns, dataField string, o interface{}) (interface{}, error) {
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
