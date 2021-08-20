// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/httputil/httperr"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/oidc"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/plog"
)

func NewHandler(
	oauthHelper fosite.OAuth2Provider,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var session openid.DefaultSession
		accessRequest, err := oauthHelper.NewAccessRequest(r.Context(), r, &session)
		if err != nil {
			plog.Info("token request error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(w, accessRequest, err)
			return nil
		}

		accessResponse, err := oauthHelper.NewAccessResponse(r.Context(), accessRequest)
		if err != nil {
			plog.Info("token response error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(w, accessRequest, err)
			return nil
		}

		oauthHelper.WriteAccessResponse(w, accessRequest, accessResponse)

		return nil
	})
}
