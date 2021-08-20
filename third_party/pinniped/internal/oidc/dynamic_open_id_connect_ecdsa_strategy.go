// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"reflect"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"

	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/constable"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/oidc/jwks"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/plog"
)

// dynamicOpenIDConnectECDSAStrategy is an openid.OpenIDConnectTokenStrategy that can dynamically
// load a signing key to issue ID tokens. We want this dynamic capability since our controllers for
// loading FederationDomain's and signing keys run in parallel, and thus the signing key might not be
// ready when an FederationDomain is otherwise ready.
//
// If we ever update FederationDomain's to hold their signing key, we might not need this type, since we
// could have an invariant that routes to an FederationDomain's endpoints are only wired up if an
// FederationDomain has a valid signing key.
type dynamicOpenIDConnectECDSAStrategy struct {
	fositeConfig *compose.Config
	jwksProvider jwks.DynamicJWKSProvider
}

var _ openid.OpenIDConnectTokenStrategy = &dynamicOpenIDConnectECDSAStrategy{}

func newDynamicOpenIDConnectECDSAStrategy(
	fositeConfig *compose.Config,
	jwksProvider jwks.DynamicJWKSProvider,
) *dynamicOpenIDConnectECDSAStrategy {
	return &dynamicOpenIDConnectECDSAStrategy{
		fositeConfig: fositeConfig,
		jwksProvider: jwksProvider,
	}
}

func (s *dynamicOpenIDConnectECDSAStrategy) GenerateIDToken(
	ctx context.Context,
	requester fosite.Requester,
) (string, error) {
	_, activeJwk := s.jwksProvider.GetJWKS(s.fositeConfig.IDTokenIssuer)
	if activeJwk == nil {
		plog.Debug("no JWK found for issuer", "issuer", s.fositeConfig.IDTokenIssuer)
		return "", fosite.ErrTemporarilyUnavailable.WithWrap(constable.Error("no JWK found for issuer"))
	}
	key, ok := activeJwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		actualType := "nil"
		if t := reflect.TypeOf(activeJwk.Key); t != nil {
			actualType = t.String()
		}
		plog.Debug(
			"JWK must be of type ecdsa",
			"issuer",
			s.fositeConfig.IDTokenIssuer,
			"actualType",
			actualType,
		)
		return "", fosite.ErrServerError.WithWrap(constable.Error("JWK must be of type ecdsa"))
	}

	return compose.NewOpenIDConnectECDSAStrategy(s.fositeConfig, key).GenerateIDToken(ctx, requester)
}
