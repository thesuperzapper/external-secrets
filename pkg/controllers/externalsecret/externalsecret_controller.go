/*
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

package externalsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	// Metrics.
	"github.com/external-secrets/external-secrets/pkg/controllers/externalsecret/esmetrics"
	ctrlmetrics "github.com/external-secrets/external-secrets/pkg/controllers/metrics"
	"github.com/external-secrets/external-secrets/pkg/utils"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"

	// Loading registered generators.
	_ "github.com/external-secrets/external-secrets/pkg/generator/register"
	// Loading registered providers.
	_ "github.com/external-secrets/external-secrets/pkg/provider/register"
)

const (
	fieldOwnerTemplate     = "externalsecrets.external-secrets.io/%v"
	errGetES               = "could not get ExternalSecret"
	errConvert             = "could not apply conversion strategy to keys: %v"
	errDecode              = "could not apply decoding strategy to %v[%d]: %v"
	errGenerate            = "could not generate [%d]: %w"
	errRewrite             = "could not rewrite spec.dataFrom[%d]: %v"
	errInvalidKeys         = "secret keys from spec.dataFrom.%v[%d] can only have alphanumeric,'-', '_' or '.' characters. Convert them using rewrite (https://external-secrets.io/latest/guides-datafrom-rewrite)"
	errUpdateSecret        = "could not update Secret"
	errImmutableSecret     = "target secret is immutable but requires an update"
	errUpdateStatus        = "unable to update status"
	errGetExistingSecret   = "could not get existing secret: %w"
	errSetCtrlReference    = "could not set ExternalSecret controller reference: %w"
	errFetchTplFrom        = "error fetching templateFrom data: %w"
	errGetSecretData       = "could not get secret data from provider"
	errDeleteSecret        = "could not delete secret"
	errApplyTemplate       = "could not apply template: %w"
	errExecTpl             = "could not execute template: %w"
	errInvalidCreatePolicy = "invalid creationPolicy=%s. Can not delete secret i do not own"
	errPolicyMergeNotFound = "the desired secret %s was not found. With creationPolicy=Merge the secret won't be created"
	errPolicyMergeMutate   = "unable to mutate secret %s: %w"
	errPolicyMergeUpdate   = "unable to update secret %s: %w"
)

const indexESTargetSecretNameField = ".metadata.targetSecretName"

// Reconciler reconciles a ExternalSecret object.
type Reconciler struct {
	client.Client
	Log                       logr.Logger
	Scheme                    *runtime.Scheme
	RestConfig                *rest.Config
	ControllerClass           string
	RequeueInterval           time.Duration
	ClusterSecretStoreEnabled bool
	EnableFloodGate           bool
	recorder                  record.EventRecorder
}

// Reconcile implements the main reconciliation loop
// for watched objects (ExternalSecret, ClusterSecretStore and SecretStore),
// and updates/creates a Kubernetes secret based on them.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := r.Log.WithValues("ExternalSecret", req.NamespacedName)

	resourceLabels := ctrlmetrics.RefineNonConditionMetricLabels(map[string]string{"name": req.Name, "namespace": req.Namespace})
	start := time.Now()

	syncCallsError := esmetrics.GetCounterVec(esmetrics.SyncCallsErrorKey)

	// use closures to dynamically update resourceLabels
	defer func() {
		esmetrics.GetGaugeVec(esmetrics.ExternalSecretReconcileDurationKey).With(resourceLabels).Set(float64(time.Since(start)))
		esmetrics.GetCounterVec(esmetrics.SyncCallsKey).With(resourceLabels).Inc()
	}()

	externalSecret := &esv1beta1.ExternalSecret{}
	err = r.Get(ctx, req.NamespacedName, externalSecret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// NOTE: this does not actually set the condition on the ExternalSecret, because it does not exist
			//       this is a hack to disable metrics for deleted ExternalSecrets, see:
			//       https://github.com/external-secrets/external-secrets/pull/612
			conditionSynced := NewExternalSecretCondition(esv1beta1.ExternalSecretDeleted, v1.ConditionFalse, esv1beta1.ConditionReasonSecretDeleted, "Secret was deleted")
			SetExternalSecretCondition(&esv1beta1.ExternalSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
			}, *conditionSynced)

			return ctrl.Result{}, nil
		}

		log.Error(err, errGetES)
		syncCallsError.With(resourceLabels).Inc()

		return ctrl.Result{}, err
	}

	// skip reconciliation if deletion timestamp is set on external secret
	if externalSecret.DeletionTimestamp != nil {
		log.Info("external secret is marked for deletion, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// update status of the ExternalSecret when this function returns, if needed.
	// we use the ability of deferred functions to update named return values `result` and `err`.
	currentStatus := externalSecret.Status.DeepCopy()
	defer func() {
		if !equality.Semantic.DeepEqual(currentStatus, externalSecret.Status) {
			if updateErr := r.Status().Update(ctx, externalSecret); updateErr != nil {
				if apierrors.IsConflict(updateErr) {
					log.V(1).Info("conflict while updating status, will requeue")
					result = ctrl.Result{Requeue: true}
					return
				}
				log.Error(updateErr, errUpdateStatus)
				if err == nil {
					err = updateErr
				} else {
					err = fmt.Errorf("%w: %v", updateErr, err)
				}
			}
		}
	}()

	// if extended metrics is enabled, refine the time series vector
	resourceLabels = ctrlmetrics.RefineLabels(resourceLabels, externalSecret.Labels)

	if shouldSkipClusterSecretStore(r, externalSecret) {
		log.Info("skipping cluster secret store as it is disabled")
		return ctrl.Result{}, nil
	}

	// skip when pointing to an unmanaged store
	skip, err := shouldSkipUnmanagedStore(ctx, req.Namespace, r, externalSecret)
	if skip {
		log.Info("skipping unmanaged store as it points to a unmanaged controllerClass")
		return ctrl.Result{}, nil
	}

	// Target Secret Name should default to the ExternalSecret name if not explicitly specified
	secretName := externalSecret.Spec.Target.Name
	if secretName == "" {
		secretName = externalSecret.Name
	}

	// fetch existing secret
	existingSecret := &v1.Secret{}
	err = r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: externalSecret.Namespace}, existingSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, errGetExistingSecret)
		return ctrl.Result{}, err
	}

	// refresh will be skipped if ALL the following conditions are met:
	// 1. refresh interval is not 0
	// 2. resource generation of the ExternalSecret has not changed
	// 3. the last refresh time of the ExternalSecret is within the refresh interval
	// 5. the target secret is valid:
	//     - it exists
	//     - it has the correct data-hash annotation
	if !shouldRefresh(externalSecret) && isSecretValid(existingSecret) {
		log.V(1).Info("skipping refresh")
		return r.getRequeueResult(externalSecret), nil
	}

	dataMap, err := r.getProviderSecretData(ctx, externalSecret)
	if err != nil {
		r.markAsFailed(log, errGetSecretData, err, externalSecret, syncCallsError.With(resourceLabels))
		return ctrl.Result{}, err
	}

	//
	// TODO: there are no cases where `err` is not nil, so this does nothing.
	//       this code was added in https://github.com/external-secrets/external-secrets/pull/3746
	//       so if that is real, we should move this code to somewhere else
	//
	// secret data was not modified.
	//if errors.Is(err, esv1beta1.NotModifiedErr) {
	//	log.Info("secret was not modified as a NotModified was returned by the provider")
	//	r.markAsDone(externalSecret, start, log)
	//
	//	return ctrl.Result{}, nil
	//}

	// if no data was found we can delete the secret if needed.
	if len(dataMap) == 0 {
		switch externalSecret.Spec.Target.DeletionPolicy {
		// delete secret and return early.
		case esv1beta1.DeletionPolicyDelete:
			// safeguard that we only can delete secrets we own
			// this is also implemented in the es validation webhook
			if externalSecret.Spec.Target.CreationPolicy != esv1beta1.CreatePolicyOwner {
				err := fmt.Errorf(errInvalidCreatePolicy, externalSecret.Spec.Target.CreationPolicy)
				r.markAsFailed(log, errDeleteSecret, err, externalSecret, syncCallsError.With(resourceLabels))
				return ctrl.Result{}, err
			}

			// delete the secret, if it exists
			if existingSecret.UID != "" {
				if err := r.Delete(ctx, existingSecret); err != nil && !apierrors.IsNotFound(err) {
					r.markAsFailed(log, errDeleteSecret, err, externalSecret, syncCallsError.With(resourceLabels))
					return ctrl.Result{}, err
				}
			}

			r.markAsDone(externalSecret, start, log, true)
			return r.getRequeueResult(externalSecret), nil
		// In case provider secrets don't exist the kubernetes secret will be kept as-is.
		case esv1beta1.DeletionPolicyRetain:
			r.markAsDone(externalSecret, start, log, false)
			return r.getRequeueResult(externalSecret), nil
		// noop, handled below
		case esv1beta1.DeletionPolicyMerge:
		}
	}

	// mutationFunc is a function which can be applied to a secret to make it match the desired state.
	mutationFunc := func(secret *v1.Secret) error {
		if externalSecret.Spec.Target.CreationPolicy == esv1beta1.CreatePolicyOwner {
			err = controllerutil.SetControllerReference(externalSecret, secret, r.Scheme)
			if err != nil {
				return fmt.Errorf(errSetCtrlReference, err)
			}
		}
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}

		// get the list of keys that are managed by this ExternalSecret
		keys, err := getManagedDataKeys(secret, externalSecret.Name)
		if err != nil {
			return err
		}

		// remove any data keys that are managed by this ExternalSecret, so we can re-add them
		// this ensures keys added by templates are not left behind when they are removed from the template
		for _, key := range keys {
			delete(secret.Data, key)
		}

		err = r.applyTemplate(ctx, externalSecret, secret, dataMap)
		if err != nil {
			return fmt.Errorf(errApplyTemplate, err)
		}

		// set the immutable flag on the secret if requested by the ExternalSecret
		if externalSecret.Spec.Target.Immutable {
			secret.Immutable = ptr.To(true)
		}

		if externalSecret.Spec.Target.CreationPolicy == esv1beta1.CreatePolicyOwner {
			lblValue := utils.ObjectHash(fmt.Sprintf("%v/%v", externalSecret.Namespace, externalSecret.Name))
			secret.Labels[esv1beta1.LabelOwner] = lblValue
		}

		secret.Annotations[esv1beta1.AnnotationDataHash] = utils.ObjectHash(secret.Data)

		return nil
	}

	switch externalSecret.Spec.Target.CreationPolicy { //nolint:exhaustive
	case esv1beta1.CreatePolicyMerge:
		err = r.updateSecret(ctx, existingSecret, mutationFunc, externalSecret)
	case esv1beta1.CreatePolicyNone:
		log.V(1).Info("secret creation skipped due to creationPolicy=None")
		err = nil
	default:
		// create the secret, if it does not exist
		if existingSecret.UID == "" {
			err = r.createSecret(ctx, mutationFunc, externalSecret, secretName)

			// we may have orphaned secrets to clean up,
			// for example, if the target secret name was changed
			if err == nil {
				delErr := deleteOrphanedSecrets(ctx, r.Client, externalSecret, secretName)
				if delErr != nil {
					msg := fmt.Sprintf("failed to clean up orphaned secrets: %v", delErr)
					r.markAsFailed(log, msg, delErr, externalSecret, syncCallsError.With(resourceLabels))
					return ctrl.Result{}, delErr
				}
			}
		} else {
			// update the secret, if it exists
			err = r.updateSecret(ctx, existingSecret, mutationFunc, externalSecret)
		}
	}
	if err != nil {
		// if we got an update conflict, we should requeue immediately
		if apierrors.IsConflict(err) {
			log.Info("conflict while updating secret, will requeue")
			return ctrl.Result{Requeue: true}, nil
		}

		r.markAsFailed(log, errUpdateSecret, err, externalSecret, syncCallsError.With(resourceLabels))
		return ctrl.Result{}, err
	}

	r.markAsDone(externalSecret, start, log, false)
	return r.getRequeueResult(externalSecret), nil
}

// getRequeueResult create a result with requeueAfter based on the ExternalSecret refresh interval.
// this should be used when the ExternalSecret has been SUCCESSFULLY reconciled,
// and ONLY AFTER `markAsDone()` has been called.
func (r *Reconciler) getRequeueResult(externalSecret *esv1beta1.ExternalSecret) ctrl.Result {
	// default to the global requeue interval
	// note, this will never be used because the CRD has a default value of 1 hour
	refreshInterval := r.RequeueInterval
	if externalSecret.Spec.RefreshInterval != nil {
		refreshInterval = externalSecret.Spec.RefreshInterval.Duration
	}

	// if the refresh interval is <= 0, we should not requeue
	if refreshInterval <= 0 {
		return ctrl.Result{}
	}

	timeSinceLastRefresh := 0 * time.Second
	if !externalSecret.Status.RefreshTime.IsZero() {
		lastRefreshTime := externalSecret.Status.RefreshTime.Time
		timeSinceLastRefresh = time.Since(lastRefreshTime)
	}

	// if the last refresh time is in the future, we should requeue immediately
	if timeSinceLastRefresh < 0 {
		return ctrl.Result{Requeue: true}
	}

	if timeSinceLastRefresh < refreshInterval {
		// requeue after the remaining time
		return ctrl.Result{RequeueAfter: refreshInterval - timeSinceLastRefresh}
	} else {
		// requeue immediately
		return ctrl.Result{Requeue: true}
	}
}

func (r *Reconciler) markAsDone(externalSecret *esv1beta1.ExternalSecret, start time.Time, log logr.Logger, wasDeleted bool) {
	oldReadyCondition := GetExternalSecretCondition(externalSecret.Status, esv1beta1.ExternalSecretReady)
	var newReadyCondition *esv1beta1.ExternalSecretStatusCondition
	if wasDeleted {
		newReadyCondition = NewExternalSecretCondition(esv1beta1.ExternalSecretReady, v1.ConditionTrue, esv1beta1.ConditionReasonSecretDeleted, "secret deleted due to DeletionPolicy")
		SetExternalSecretCondition(externalSecret, *newReadyCondition)
	} else {
		newReadyCondition = NewExternalSecretCondition(esv1beta1.ExternalSecretReady, v1.ConditionTrue, esv1beta1.ConditionReasonSecretSynced, "Secret was synced")
		SetExternalSecretCondition(externalSecret, *newReadyCondition)
	}

	externalSecret.Status.RefreshTime = metav1.NewTime(start)
	externalSecret.Status.SyncedResourceVersion = getResourceVersion(externalSecret)

	// if the status or reason has changed, log at the appropriate verbosity level
	if oldReadyCondition == nil || oldReadyCondition.Status != newReadyCondition.Status || oldReadyCondition.Reason != newReadyCondition.Reason {
		if wasDeleted {
			log.Info("deleted secret")
		} else {
			log.Info("reconciled secret")
		}
	} else {
		log.V(1).Info("reconciled secret")
	}
}

func (r *Reconciler) markAsFailed(log logr.Logger, msg string, err error, externalSecret *esv1beta1.ExternalSecret, counter prometheus.Counter) {
	log.Error(err, msg)
	r.recorder.Event(externalSecret, v1.EventTypeWarning, esv1beta1.ReasonUpdateFailed, err.Error())
	conditionSynced := NewExternalSecretCondition(esv1beta1.ExternalSecretReady, v1.ConditionFalse, esv1beta1.ConditionReasonSecretSyncedError, msg)
	SetExternalSecretCondition(externalSecret, *conditionSynced)
	counter.Inc()
}

func deleteOrphanedSecrets(ctx context.Context, cl client.Client, externalSecret *esv1beta1.ExternalSecret, secretName string) error {
	ownerLabel := utils.ObjectHash(fmt.Sprintf("%v/%v", externalSecret.Namespace, externalSecret.Name))

	secretList := &v1.SecretList{}
	listOpts := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			esv1beta1.LabelOwner: ownerLabel,
		}),
		Namespace: externalSecret.Namespace,
	}
	if err := cl.List(ctx, secretList, listOpts); err != nil {
		return err
	}

	// delete all secrets that are not the target secret
	for _, secret := range secretList.Items {
		if secret.Name != secretName {
			if err := cl.Delete(ctx, &secret); err != nil {
				return err
			}
		}
	}

	return nil
}

// createSecret creates a new secret with the given mutation function.
func (r *Reconciler) createSecret(ctx context.Context, mutationFunc func(secret *v1.Secret) error, es *esv1beta1.ExternalSecret, secretName string) error {
	fqdn := fmt.Sprintf(fieldOwnerTemplate, es.Name)

	// define and mutate the new secret
	newSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: es.Namespace,
		},
		Data: make(map[string][]byte),
	}
	if err := mutationFunc(newSecret); err != nil {
		return err
	}

	// note, we set field owner even for Create
	if err := r.Create(ctx, newSecret, client.FieldOwner(fqdn)); err != nil {
		return err
	}

	// set the binding reference to the secret
	// https://github.com/external-secrets/external-secrets/pull/2263
	es.Status.Binding = v1.LocalObjectReference{Name: newSecret.Name}

	r.recorder.Event(es, v1.EventTypeNormal, esv1beta1.ReasonCreated, "Created Secret")
	return nil
}

func (r *Reconciler) updateSecret(ctx context.Context, existingSecret *v1.Secret, mutationFunc func(secret *v1.Secret) error, es *esv1beta1.ExternalSecret) error {
	fqdn := fmt.Sprintf(fieldOwnerTemplate, es.Name)

	// fail if the secret does not exist
	if existingSecret.UID == "" {
		return fmt.Errorf(errPolicyMergeNotFound, existingSecret.Name)
	}

	// mutate a copy of the existing secret with the mutation function
	updatedSecret := existingSecret.DeepCopy()
	if err := mutationFunc(updatedSecret); err != nil {
		return fmt.Errorf(errPolicyMergeMutate, updatedSecret.Name, err)
	}

	// if the secret does not need to be updated, return early
	if equality.Semantic.DeepEqual(existingSecret, updatedSecret) {
		return nil
	}

	// if the existing secret is immutable, we can only update the objet metadata
	if existingSecret.Immutable != nil && *existingSecret.Immutable {
		existingSecret.ObjectMeta = *updatedSecret.ObjectMeta.DeepCopy()
		if !equality.Semantic.DeepEqual(existingSecret, updatedSecret) {
			return fmt.Errorf(errImmutableSecret)
		}
	}

	// update the secret
	if err := r.Update(ctx, updatedSecret, client.FieldOwner(fqdn)); err != nil {
		// if we get a conflict, we should return early to requeue immediately
		// note, we don't wrap this error so we can handle it in the caller
		if apierrors.IsConflict(err) {
			return err
		}
		return fmt.Errorf(errPolicyMergeUpdate, updatedSecret.Name, err)
	}

	// set the binding reference to the secret
	// https://github.com/external-secrets/external-secrets/pull/2263
	es.Status.Binding = v1.LocalObjectReference{Name: updatedSecret.Name}

	r.recorder.Event(es, v1.EventTypeNormal, esv1beta1.ReasonUpdated, "Updated Secret")
	return nil
}

// getManagedDataKeys returns the list of data keys in a secret which are managed by a specified owner.
func getManagedDataKeys(secret *v1.Secret, fieldOwner string) ([]string, error) {
	return getManagedFieldKeys(secret, fieldOwner, func(fields map[string]any) []string {
		dataFields := fields["f:data"]
		if dataFields == nil {
			return nil
		}
		df, ok := dataFields.(map[string]any)
		if !ok {
			return nil
		}

		return slices.Collect(maps.Keys(df))
	})
}

func getManagedFieldKeys(
	secret *v1.Secret,
	fieldOwner string,
	process func(fields map[string]any) []string,
) ([]string, error) {
	fqdn := fmt.Sprintf(fieldOwnerTemplate, fieldOwner)
	var keys []string
	for _, v := range secret.ObjectMeta.ManagedFields {
		if v.Manager != fqdn {
			continue
		}
		fields := make(map[string]any)
		err := json.Unmarshal(v.FieldsV1.Raw, &fields)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling managed fields: %w", err)
		}
		for _, key := range process(fields) {
			if key == "." {
				continue
			}
			keys = append(keys, strings.TrimPrefix(key, "f:"))
		}
	}
	return keys, nil
}

func getResourceVersion(es *esv1beta1.ExternalSecret) string {
	return fmt.Sprintf("%d-%s", es.ObjectMeta.GetGeneration(), hashMeta(es.ObjectMeta))
}

// hashMeta returns a consistent hash of the `metadata.labels` and `metadata.annotations` fields of the given object
func hashMeta(m metav1.ObjectMeta) string {
	type meta struct {
		annotations map[string]string
		labels      map[string]string
	}
	objectMeta := meta{
		annotations: m.Annotations,
		labels:      m.Labels,
	}
	return utils.ObjectHash(objectMeta)
}

func shouldSkipClusterSecretStore(r *Reconciler, es *esv1beta1.ExternalSecret) bool {
	return !r.ClusterSecretStoreEnabled && es.Spec.SecretStoreRef.Kind == esv1beta1.ClusterSecretStoreKind
}

// shouldSkipUnmanagedStore iterates over all secretStore references in the externalSecret spec,
// fetches the store and evaluates the controllerClass property.
// Returns true if any storeRef points to store with a non-matching controllerClass.
func shouldSkipUnmanagedStore(ctx context.Context, namespace string, r *Reconciler, es *esv1beta1.ExternalSecret) (bool, error) {
	var storeList []esv1beta1.SecretStoreRef

	if es.Spec.SecretStoreRef.Name != "" {
		storeList = append(storeList, es.Spec.SecretStoreRef)
	}

	for _, ref := range es.Spec.Data {
		if ref.SourceRef != nil {
			storeList = append(storeList, ref.SourceRef.SecretStoreRef)
		}
	}

	for _, ref := range es.Spec.DataFrom {
		if ref.SourceRef != nil && ref.SourceRef.SecretStoreRef != nil {
			storeList = append(storeList, *ref.SourceRef.SecretStoreRef)
		}

		// verify that generator's controllerClass matches
		if ref.SourceRef != nil && ref.SourceRef.GeneratorRef != nil {
			_, obj, err := resolvers.GeneratorRef(ctx, r.RestConfig, namespace, ref.SourceRef.GeneratorRef)
			if err != nil {
				return false, err
			}
			skipGenerator, err := shouldSkipGenerator(r, obj)
			if err != nil {
				return false, err
			}
			if skipGenerator {
				return true, nil
			}
		}
	}

	for _, ref := range storeList {
		var store esv1beta1.GenericStore

		switch ref.Kind {
		case esv1beta1.SecretStoreKind, "":
			store = &esv1beta1.SecretStore{}
		case esv1beta1.ClusterSecretStoreKind:
			store = &esv1beta1.ClusterSecretStore{}
			namespace = ""
		}

		err := r.Get(ctx, types.NamespacedName{
			Name:      ref.Name,
			Namespace: namespace,
		}, store)
		if err != nil {
			return false, err
		}
		class := store.GetSpec().Controller
		if class != "" && class != r.ControllerClass {
			return true, nil
		}
	}
	return false, nil
}

func shouldRefresh(es *esv1beta1.ExternalSecret) bool {
	// if the refresh interval is 0, and we have synced previously, we should not refresh
	if es.Spec.RefreshInterval.Duration <= 0 && es.Status.SyncedResourceVersion != "" {
		return false
	}

	// if the ExternalSecret has been updated, we should refresh
	if es.Status.SyncedResourceVersion != getResourceVersion(es) {
		return true
	}

	// if the last refresh time is zero, we should refresh
	if es.Status.RefreshTime.IsZero() {
		return true
	}

	// if the last refresh time + refresh interval is before now, we should refresh
	return es.Status.RefreshTime.Add(es.Spec.RefreshInterval.Duration).Before(time.Now())
}

// isSecretValid checks if the secret exists, and it's data is consistent with the calculated hash.
func isSecretValid(existingSecret *v1.Secret) bool {
	// if target secret doesn't exist, or annotations are not set, we need to refresh
	if existingSecret.UID == "" || existingSecret.Annotations == nil {
		return false
	}

	// if the calculated hash is different from the calculation, then it's invalid
	// this is how we know if the data has chanced since we last updated the secret
	if existingSecret.Annotations[esv1beta1.AnnotationDataHash] != utils.ObjectHash(existingSecret.Data) {
		return false
	}

	return true
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.recorder = mgr.GetEventRecorderFor("external-secrets")

	// index ExternalSecrets based on the target secret name,
	// this lets us quickly find all ExternalSecrets which target a specific Secret
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &esv1beta1.ExternalSecret{}, indexESTargetSecretNameField, func(obj client.Object) []string {
		es := obj.(*esv1beta1.ExternalSecret)
		// if the target name is set, use that as the index
		if es.Spec.Target.Name != "" {
			return []string{es.Spec.Target.Name}
		} else {
			// otherwise, use the ExternalSecret name
			return []string{es.Name}
		}
	}); err != nil {
		return err
	}

	// predicate function to ignore secret events unless they have our data-hash annotation
	// and the data-hash is out of date
	secretHasESAnnotation := predicate.NewPredicateFuncs(func(object client.Object) bool {
		secret, ok := object.(*v1.Secret)
		if !ok {
			return false
		}
		dataHash, annotationExists := secret.GetAnnotations()[esv1beta1.AnnotationDataHash]
		if !annotationExists {
			// if the annotation does not exist, we don't manage this secret
			return false
		} else {
			// if the annotation exists, but the hash is different, we need to reconcile
			return dataHash != utils.ObjectHash(secret.Data)
		}
	})

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(opts).
		For(&esv1beta1.ExternalSecret{}).
		// we cant use Owns(), as we don't set ownerReferences when the creationPolicy is not Owner
		// so we instead filter by the presence of our data-hash annotation on the secret
		Watches(
			&v1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findObjectsForSecret),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}, secretHasESAnnotation),
		).
		Complete(r)
}

func (r *Reconciler) findObjectsForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	externalSecretsList := &esv1beta1.ExternalSecretList{}
	err := r.List(
		ctx,
		externalSecretsList,
		client.InNamespace(secret.GetNamespace()),
		client.MatchingFields{indexESTargetSecretNameField: secret.GetName()},
	)
	if err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, len(externalSecretsList.Items))
	for i := range externalSecretsList.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      externalSecretsList.Items[i].GetName(),
				Namespace: externalSecretsList.Items[i].GetNamespace(),
			},
		}
	}
	return requests
}
