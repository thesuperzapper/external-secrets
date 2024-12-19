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

package fake

import (
	"context"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
)

var _ esv1beta1.Provider = &Client{}

type PushSecretCallArgs struct {
	Value     []byte
	RemoteRef esv1beta1.PushSecretRemoteRef
}

// Client is a fake client for testing.
type Client struct {
	// WARNING: only interact with this map using the provided methods so that this is thread-safe.
	pushedSecrets     map[string]PushSecretCallArgs
	pushedSecretsLock sync.RWMutex

	GetSecretFn     func(context.Context, esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error)
	GetSecretMapFn  func(context.Context, esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error)
	GetAllSecretsFn func(context.Context, esv1beta1.ExternalSecretFind) (map[string][]byte, error)
	SecretExistsFn  func(context.Context, esv1beta1.PushSecretRemoteRef) (bool, error)
	SetSecretFn     func() error
	DeleteSecretFn  func() error

	// NewFn returns the fake client as a SecretsClient interface.
	NewFn func(context.Context, esv1beta1.GenericStore, client.Client, string) (esv1beta1.SecretsClient, error)
}

// New returns a fake provider/client.
func New() *Client {
	v := &Client{}
	v.Reset()
	return v
}

// GetAllSecrets implements the provider.Provider interface.
func (v *Client) GetAllSecrets(ctx context.Context, ref esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	return v.GetAllSecretsFn(ctx, ref)
}

func (v *Client) PushSecret(_ context.Context, secret *corev1.Secret, data esv1beta1.PushSecretData) error {
	v.StorePushedSecret(data.GetRemoteKey(), PushSecretCallArgs{
		Value:     secret.Data[data.GetSecretKey()],
		RemoteRef: data,
	})
	return v.SetSecretFn()
}

// ClearPushedSecrets clears the pushed secrets map.
func (v *Client) ClearPushedSecrets() {
	v.pushedSecretsLock.Lock()
	defer v.pushedSecretsLock.Unlock()
	v.pushedSecrets = make(map[string]PushSecretCallArgs)
}

// LoadPushedSecret returns the pushed secret for the given remote key.
func (v *Client) LoadPushedSecret(remoteKey string) (PushSecretCallArgs, bool) {
	v.pushedSecretsLock.RLock()
	defer v.pushedSecretsLock.RUnlock()
	val, ok := v.pushedSecrets[remoteKey]
	return val, ok
}

// StorePushedSecret stores the pushed secret for the given remote key.
func (v *Client) StorePushedSecret(remoteKey string, val PushSecretCallArgs) {
	v.pushedSecretsLock.Lock()
	defer v.pushedSecretsLock.Unlock()
	v.pushedSecrets[remoteKey] = val
}

func (v *Client) DeleteSecret(_ context.Context, _ esv1beta1.PushSecretRemoteRef) error {
	return v.DeleteSecretFn()
}

func (v *Client) SecretExists(ctx context.Context, ref esv1beta1.PushSecretRemoteRef) (bool, error) {
	return v.SecretExistsFn(ctx, ref)
}

// GetSecret implements the provider.Provider interface.
func (v *Client) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	return v.GetSecretFn(ctx, ref)
}

// WithGetSecret wraps secret data returned by this provider.
func (v *Client) WithGetSecret(secData []byte, err error) *Client {
	v.GetSecretFn = func(context.Context, esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
		return secData, err
	}
	return v
}

// GetSecretMap implements the provider.Provider interface.
func (v *Client) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return v.GetSecretMapFn(ctx, ref)
}

func (v *Client) Close(_ context.Context) error {
	return nil
}

func (v *Client) Validate() (esv1beta1.ValidationResult, error) {
	return esv1beta1.ValidationResultReady, nil
}

func (v *Client) ValidateStore(_ esv1beta1.GenericStore) (admission.Warnings, error) {
	return nil, nil
}

// WithGetSecretMap wraps the secret data map returned by this fake provider.
func (v *Client) WithGetSecretMap(secData map[string][]byte, err error) *Client {
	v.GetSecretMapFn = func(context.Context, esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
		return secData, err
	}
	return v
}

// WithGetAllSecrets wraps the secret data map returned by this fake provider.
func (v *Client) WithGetAllSecrets(secData map[string][]byte, err error) *Client {
	v.GetAllSecretsFn = func(context.Context, esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
		return secData, err
	}
	return v
}

// WithSetSecret wraps the secret response to the fake provider.
func (v *Client) WithSetSecret(err error) *Client {
	v.SetSecretFn = func() error {
		return err
	}
	return v
}

// WithNew wraps the fake provider factory function.
func (v *Client) WithNew(f func(context.Context, esv1beta1.GenericStore, client.Client, string) (esv1beta1.SecretsClient, error)) *Client {
	v.NewFn = f
	return v
}

// Capabilities return the provider supported capabilities (ReadOnly, WriteOnly, ReadWrite).
func (v *Client) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

// NewClient returns a new fake provider.
func (v *Client) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube client.Client, namespace string) (esv1beta1.SecretsClient, error) {
	c, err := v.NewFn(ctx, store, kube, namespace)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Reset the fake provider.
func (v *Client) Reset() {
	// Reset the internal state.
	v.ClearPushedSecrets()

	// Reset all functions to their default values.
	v.GetSecretFn = defaultGetSecretFn
	v.GetSecretMapFn = defaultGetSecretMapFn
	v.GetAllSecretsFn = defaultGetAllSecretsFn
	v.SecretExistsFn = defaultSecretExistsFn
	v.SetSecretFn = defaultSetSecretFn
	v.DeleteSecretFn = defaultDeleteSecretFn
	v.NewFn = v.defaultNewFn
}

func (v *Client) defaultNewFn(context.Context, esv1beta1.GenericStore, client.Client, string) (esv1beta1.SecretsClient, error) {
	return v, nil
}

func defaultGetSecretFn(context.Context, esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	return nil, nil
}

func defaultGetSecretMapFn(context.Context, esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return nil, nil
}

func defaultGetAllSecretsFn(context.Context, esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, nil
}

func defaultSecretExistsFn(context.Context, esv1beta1.PushSecretRemoteRef) (bool, error) {
	return false, nil
}

func defaultSetSecretFn() error {
	return nil
}

func defaultDeleteSecretFn() error {
	return nil
}
