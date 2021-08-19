// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

import (
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	pinnipedcontroller "github.com/getupio-undistro/undistro/third_party/pinniped/internal/controller"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/controllerlib"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/crud"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/plog"
)

const minimumRepeatInterval = 30 * time.Second

type garbageCollectorController struct {
	secretInformer        corev1informers.SecretInformer
	kubeClient            kubernetes.Interface
	clock                 clock.Clock
	timeOfMostRecentSweep time.Time
}

func GarbageCollectorController(
	clock clock.Clock,
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	isSecretWithGCAnnotation := func(obj metav1.Object) bool {
		secret, ok := obj.(*v1.Secret)
		if !ok {
			return false
		}
		_, ok = secret.Annotations[crud.SecretLifetimeAnnotationKey]
		return ok
	}
	return controllerlib.New(
		controllerlib.Config{
			Name: "garbage-collector-controller",
			Syncer: &garbageCollectorController{
				secretInformer: secretInformer,
				kubeClient:     kubeClient,
				clock:          clock,
			},
		},
		withInformer(
			secretInformer,
			controllerlib.FilterFuncs{
				AddFunc: isSecretWithGCAnnotation,
				UpdateFunc: func(oldObj, newObj metav1.Object) bool {
					return isSecretWithGCAnnotation(oldObj) || isSecretWithGCAnnotation(newObj)
				},
				DeleteFunc: func(obj metav1.Object) bool { return false }, // ignore all deletes
				ParentFunc: pinnipedcontroller.SingletonQueue(),
			},
			controllerlib.InformerOption{},
		),
	)
}

func (c *garbageCollectorController) Sync(ctx controllerlib.Context) error {
	// make sure we have a consistent, static meaning for the current time during the sync loop
	frozenClock := clock.NewFakeClock(c.clock.Now())

	// The Sync method is triggered upon any change to any Secret, which would make this
	// controller too chatty, so it rate limits itself to a more reasonable interval.
	// Note that even during a period when no secrets are changing, it will still run
	// at the informer's full-resync interval (as long as there are some secrets).
	if since := frozenClock.Since(c.timeOfMostRecentSweep); since < minimumRepeatInterval {
		ctx.Queue.AddAfter(ctx.Key, minimumRepeatInterval-since)
		return nil
	}

	plog.Info("starting storage garbage collection sweep")
	c.timeOfMostRecentSweep = frozenClock.Now()

	listOfSecrets, err := c.secretInformer.Lister().List(labels.Everything())
	if err != nil {
		return err
	}

	for i := range listOfSecrets {
		secret := listOfSecrets[i]

		timeString, ok := secret.Annotations[crud.SecretLifetimeAnnotationKey]
		if !ok {
			continue
		}

		garbageCollectAfterTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, timeString)
		if err != nil {
			plog.WarningErr("could not parse resource timestamp for garbage collection", err, logKV(secret))
			continue
		}

		if garbageCollectAfterTime.Before(frozenClock.Now()) {
			err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Delete(ctx.Context, secret.Name, metav1.DeleteOptions{})
			if err != nil {
				plog.WarningErr("failed to garbage collect resource", err, logKV(secret))
				continue
			}
			plog.Info("storage garbage collector deleted resource", logKV(secret))
		}
	}

	return nil
}

func logKV(secret *v1.Secret) []interface{} {
	return []interface{}{
		"secretName", secret.Name,
		"secretNamespace", secret.Namespace,
		"secretType", string(secret.Type),
		"garbageCollectAfter", secret.Annotations[crud.SecretLifetimeAnnotationKey],
	}
}
