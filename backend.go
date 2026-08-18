package arrstack

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// arrstackBackend is the Vault secrets backend that mints dynamic arrproxy
// machine tokens via arrproxy's bearer-gated admin API.
type arrstackBackend struct {
	*framework.Backend

	lock   sync.RWMutex
	client *arrproxyClient
}

// Factory returns a configured arrstack secrets backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *arrstackBackend {
	b := &arrstackBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				configStoragePath,
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathRole(b),
				pathRolesList(b),
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.arrstackToken(),
		},
		Invalidate:  b.invalidate,
		WALRollback: nil,
	}

	return b
}

// reset drops the cached arrproxy client so it is rebuilt from storage on the
// next request. Called when the config changes.
func (b *arrstackBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears the cached client when the config is written from another
// cluster node.
func (b *arrstackBackend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

// getClient returns a cached arrproxy client, building one from stored config if
// necessary.
func (b *arrstackBackend) getClient(ctx context.Context, s logical.Storage) (*arrproxyClient, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}
	b.client = client
	return b.client, nil
}

const backendHelp = `
The arrstack secrets backend mints dynamic arrproxy machine tokens by calling
arrproxy's bearer-gated admin API. Each token is scoped to a subset of the *arr
apps (sonarr/radarr/prowlarr) and bound to a Vault lease: revoking the lease
disables the token in arrproxy.

After mounting this backend, configure it with the arrproxy connection details
using the "config" path, then define one or more roles that constrain the
apps and TTLs of issued tokens. Reading "creds/<role>" mints a new machine
token whose lifetime Vault manages.
`
