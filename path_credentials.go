package arrstack

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// subjectPrefix namespaces every machine-minted subject. arrproxy's admin API
// rejects any subject that does not carry this prefix.
const subjectPrefix = "vault:arrstack:"

func pathCredentials(b *arrstackBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "arrstack",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to mint a token for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
		},
		HelpSynopsis:    "Mint an arrproxy machine token from a role.",
		HelpDescription: "Reading this path mints a new arrproxy machine token scoped to the named role's apps and TTL.",
	}
}

func (b *arrstackBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	return b.mintToken(ctx, req, roleName, role)
}

// mintToken issues a new arrproxy machine token for the given role and wraps it
// in a Vault lease.
func (b *arrstackBackend) mintToken(ctx context.Context, req *logical.Request, roleName string, role *arrstackRole) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	ttl, maxTTL := b.resolveTTLs(role)

	suffix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("generating token label suffix: %w", err)
	}
	label := fmt.Sprintf("vault-%s-%s", roleName, suffix[:8])
	subject := subjectPrefix + roleName

	minted, err := client.MintToken(ctx, mintTokenRequest{
		Subject:    subject,
		Apps:       role.Apps,
		Label:      label,
		TTLSeconds: int64(ttl.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("minting arrproxy token: %w", err)
	}

	// arrproxy is authoritative for the token's fixed expiry. Fall back to the
	// derived expiry only if the response omits it.
	expiresAt := time.Now().Add(ttl)
	if minted.ExpiresAt != nil {
		expiresAt = *minted.ExpiresAt
	}

	internal := map[string]interface{}{
		"id":         minted.ID,
		"role":       roleName,
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	external := map[string]interface{}{
		"token":      minted.Token,
		"id":         minted.ID,
		"apps":       role.Apps,
		"subject":    subject,
		"expires_at": expiresAt.Format(time.RFC3339),
	}

	resp := b.Secret(arrstackTokenType).Response(external, internal)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	if ttl > 0 {
		resp.Secret.Renewable = true
	}

	return resp, nil
}

// resolveTTLs clamps the role's TTL/MaxTTL against the mount and system limits.
func (b *arrstackBackend) resolveTTLs(role *arrstackRole) (ttl, maxTTL time.Duration) {
	sysMaxTTL := b.System().MaxLeaseTTL()

	maxTTL = role.MaxTTL
	if maxTTL <= 0 || maxTTL > sysMaxTTL {
		maxTTL = sysMaxTTL
	}

	ttl = role.TTL
	if ttl <= 0 {
		ttl = b.System().DefaultLeaseTTL()
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl, maxTTL
}
