// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import "github.com/getupio-undistro/undistro/third_party/pinniped/internal/controllerlib"

type ObservableWithInitialEventOption struct {
	key *controllerlib.Key
}

func NewObservableWithInitialEventOption() *ObservableWithInitialEventOption {
	return &ObservableWithInitialEventOption{}
}

func (i *ObservableWithInitialEventOption) WithInitialEvent(key controllerlib.Key) controllerlib.Option {
	i.key = new(controllerlib.Key)
	*i.key = key
	return controllerlib.WithInitialEvent(key)
}

func (i *ObservableWithInitialEventOption) GetInitialEventKey() *controllerlib.Key {
	return i.key
}
