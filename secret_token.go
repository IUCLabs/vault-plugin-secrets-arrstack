package arrstack

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// arrstackTokenType is the identifier for the dynamic secret produced by this
// backend.
const arrstackTokenType = "arrstack_token"

func (b *arrstackBackend) arrstackToken() *framework.Secret {
	return &framework.Secret{
		Type: arrstackTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The arrproxy machine token.",
			},
			"id": {
				Type:        framework.TypeString,
				Description: "The arrproxy token id (used for revocation).",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

// tokenRevoke disables the token in arrproxy when the lease is revoked.
func (b *arrstackBackend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	rawID, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, errors.New("secret is missing internal id data")
	}
	id, ok := rawID.(string)
	if !ok {
		return nil, errors.New("secret internal id data is not a string")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := client.RevokeToken(ctx, id); err != nil {
		return nil, fmt.Errorf("revoking arrproxy token: %w", err)
	}
	return nil, nil
}

// tokenRenew extends the lease honoring the role's max_ttl. The arrproxy token
// has a fixed expiry set at mint time, so a renewal can never push the lease
// past that expiry: the new TTL is capped at the remaining time to expiry, and
// an already-expired token is not extended.
func (b *arrstackBackend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}

	rawRole, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("secret is missing internal role data")
	}
	roleName, ok := rawRole.(string)
	if !ok {
		return nil, errors.New("secret internal role data is not a string")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q no longer exists; cannot renew", roleName)
	}

	remaining := time.Duration(-1)
	if rawExp, ok := req.Secret.InternalData["expires_at"].(string); ok {
		if expiresAt, err := time.Parse(time.RFC3339, rawExp); err == nil {
			remaining = time.Until(expiresAt)
		}
	}

	// The token has already reached its fixed expiry: do not extend.
	if remaining <= 0 {
		resp.Secret.TTL = 0
		return resp, nil
	}

	ttl := role.TTL
	if ttl <= 0 {
		ttl = req.Secret.TTL
	}
	if ttl <= 0 || ttl > remaining {
		ttl = remaining
	}
	resp.Secret.TTL = ttl
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}
