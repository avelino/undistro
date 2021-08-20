// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamwatchers

import "github.com/getupio-undistro/undistro/third_party/pinniped/internal/constable"

const (
	ReasonNotFound         = "SecretNotFound"
	ReasonWrongType        = "SecretWrongType"
	ReasonMissingKeys      = "SecretMissingKeys"
	ReasonSuccess          = "Success"
	ReasonInvalidTLSConfig = "InvalidTLSConfig"

	ErrNoCertificates = constable.Error("no certificates found")
)
