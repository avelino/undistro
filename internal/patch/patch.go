/*
Copyright 2017 The Kubernetes Authors.
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

package patch

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Helper is a utility for ensuring the proper patching of objects.
type Helper struct {
	client       client.Client
	beforeObject runtime.Object
	before       *unstructured.Unstructured
	after        *unstructured.Unstructured
	changes      map[string]bool
}

// NewHelper returns an initialized Helper
func NewHelper(obj runtime.Object, crClient client.Client) (*Helper, error) {
	// Return early if the object is nil.
	// If you're wondering why we need reflection to do this check, see https://golang.org/doc/faq#nil_error.
	// TODO(vincepri): Remove this check and let it panic if used improperly in a future minor release.
	if obj == nil || (reflect.ValueOf(obj).IsValid() && reflect.ValueOf(obj).IsNil()) {
		return nil, errors.Errorf("expected non-nil object")
	}

	// Convert the object to unstructured to compare against our before copy.
	unstructuredObj, err := toUnstructured(obj)
	if err != nil {
		return nil, err
	}

	return &Helper{
		client:       crClient,
		before:       unstructuredObj,
		beforeObject: obj.DeepCopyObject(),
	}, nil
}

// Patch will attempt to patch the given object, including its status.
func (h *Helper) Patch(ctx context.Context, obj runtime.Object) error {
	if obj == nil {
		return errors.Errorf("expected non-nil object")
	}

	// Convert the object to unstructured to compare against our before copy.
	var err error
	h.after, err = toUnstructured(obj)
	if err != nil {
		return err
	}

	// Calculate and store the top-level field changes (e.g. "metadata", "spec", "status") we have before/after.
	h.changes, err = h.calculateChanges(obj)
	if err != nil {
		return err
	}

	// Issue patches and return errors in an aggregate.
	return kerrors.NewAggregate([]error{
		// Then proceed to patch the rest of the object.
		h.patch(ctx, obj),
		h.patchStatus(ctx, obj),
	})
}

// patch issues a patch for metadata and spec.
func (h *Helper) patch(ctx context.Context, obj runtime.Object) error {
	if !h.shouldPatch("metadata") && !h.shouldPatch("spec") {
		return nil
	}
	beforeObject, afterObject, err := h.calculatePatch(obj, specPatch)
	if err != nil {
		return err
	}
	return h.client.Patch(ctx, afterObject, client.MergeFrom(beforeObject))
}

// patchStatus issues a patch if the status has changed.
func (h *Helper) patchStatus(ctx context.Context, obj runtime.Object) error {
	if !h.shouldPatch("status") {
		return nil
	}
	beforeObject, afterObject, err := h.calculatePatch(obj, statusPatch)
	if err != nil {
		return err
	}
	return h.client.Status().Patch(ctx, afterObject, client.MergeFrom(beforeObject))
}

// calculatePatch returns the before/after objects to be given in a controller-runtime patch, scoped down to the absolute necessary.
func (h *Helper) calculatePatch(afterObj runtime.Object, focus patchType) (runtime.Object, runtime.Object, error) {
	// Get a shallow unsafe copy of the before/after object in unstructured form.
	before := unsafeUnstructuredCopy(h.before, focus)
	after := unsafeUnstructuredCopy(h.after, focus)

	// We've now applied all modifications to local unstructured objects,
	// make copies of the original objects and convert them back.
	beforeObj := h.beforeObject.DeepCopyObject()
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(before.Object, beforeObj); err != nil {
		return nil, nil, err
	}
	afterObj = afterObj.DeepCopyObject()
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(after.Object, afterObj); err != nil {
		return nil, nil, err
	}
	return beforeObj, afterObj, nil
}

func (h *Helper) shouldPatch(in string) bool {
	return h.changes[in]
}

// calculate changes tries to build a patch from the before/after objects we have
// and store in a map which top-level fields (e.g. `metadata`, `spec`, `status`, etc.) have changed.
func (h *Helper) calculateChanges(after runtime.Object) (map[string]bool, error) {
	// Calculate patch data.
	patch := client.MergeFrom(h.beforeObject)
	diff, err := patch.Data(after)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to calculate patch data")
	}

	// Unmarshal patch data into a local map.
	patchDiff := map[string]interface{}{}
	if err := json.Unmarshal(diff, &patchDiff); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal patch data into a map")
	}

	// Return the map.
	res := make(map[string]bool, len(patchDiff))
	for key := range patchDiff {
		res[key] = true
	}
	return res, nil
}

func ControllerObject(ctx context.Context, h *Helper, obj runtime.Object, reterr error) error {
	err := h.Patch(ctx, obj)
	if client.IgnoreNotFound(err) != nil {
		return kerrors.NewAggregate([]error{err, reterr})
	}
	if client.IgnoreNotFound(reterr) != nil {
		return reterr
	}
	return nil
}