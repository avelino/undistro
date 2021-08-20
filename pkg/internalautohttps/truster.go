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

package internalautohttps

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"

	"github.com/pkg/errors"
	"github.com/smallstep/truststore"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func InstallLocalCert(ctx context.Context, c client.Client) (err error) {
	const caSecretName = "ca-secret"
	const caName = "ca.crt"
	crtByt, err := util.GetCaFromSecret(ctx, c, caSecretName, caName, undistro.Namespace)
	if err != nil {
		return errors.Errorf("unable to get certificate %s: %v\n", caSecretName, err)
	}

	block, _ := pem.Decode(crtByt)
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Errorf("unable to parse certificate %s: %v\n", caSecretName, err)
	}

	if !trusted(rootCert) {
		err = truststore.Install(rootCert,
			truststore.WithFirefox(),
			truststore.WithJava(),
		)
		if err != nil {
			return errors.Errorf("unable to install certificate%s: %v\n", caSecretName, err)
		}
	}
	return nil
}

func trusted(cert *x509.Certificate) bool {
	chains, err := cert.Verify(x509.VerifyOptions{})
	return len(chains) > 0 && err == nil
}
