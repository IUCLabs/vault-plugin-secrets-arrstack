package arrstack

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func createRole(t *testing.T, b *arrstackBackend, s logical.Storage, name string, data map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Storage:   s,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create role %s: err=%v resp=%v", name, err, resp)
	}
}

func TestCredentials_MintAndRevoke(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	m := newMockArrproxy(t)

	writeTestConfig(t, b, s, m.server.URL, m.adminToken)
	createRole(t, b, s, "media", map[string]interface{}{
		"apps":    "sonarr,radarr",
		"ttl":     "1h",
		"max_ttl": "24h",
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/media",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("mint creds: err=%v resp=%v", err, resp)
	}
	if resp.Secret == nil {
		t.Fatal("expected a secret in the response")
	}
	token, _ := resp.Data["token"].(string)
	if token == "" {
		t.Fatal("expected a non-empty token in response data")
	}
	if resp.Data["id"].(string) == "" {
		t.Fatal("expected a non-empty id in response data")
	}
	if resp.Secret.TTL != time.Hour {
		t.Fatalf("expected TTL 1h, got %s", resp.Secret.TTL)
	}
	if !resp.Secret.Renewable {
		t.Fatal("expected the lease to be renewable")
	}
	if m.tokenCount() != 1 {
		t.Fatalf("expected 1 token on server, got %d", m.tokenCount())
	}

	// The subject carries the required prefix and the role name.
	if m.lastRequest.Subject != "vault:arrstack:media" {
		t.Fatalf("expected subject vault:arrstack:media, got %q", m.lastRequest.Subject)
	}
	// The role's apps (sorted) were forwarded.
	if strings.Join(m.lastRequest.Apps, ",") != "radarr,sonarr" {
		t.Fatalf("expected apps radarr,sonarr forwarded, got %v", m.lastRequest.Apps)
	}
	// ttl_seconds is derived from the effective initial lease TTL.
	if m.lastRequest.TTLSeconds != 3600 {
		t.Fatalf("expected ttl_seconds 3600, got %d", m.lastRequest.TTLSeconds)
	}
	// The label is prefixed for attribution.
	if !strings.HasPrefix(m.lastRequest.Label, "vault-media-") {
		t.Fatalf("expected label prefixed vault-media-, got %q", m.lastRequest.Label)
	}

	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/media",
		Storage:   s,
		Secret:    resp.Secret,
	}
	if _, err := b.HandleRequest(ctx, revokeReq); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if m.tokenCount() != 0 {
		t.Fatalf("expected token disabled on revoke, got %d active", m.tokenCount())
	}
}

func TestCredentials_UnknownRole(t *testing.T) {
	b, s := getTestBackend(t)
	m := newMockArrproxy(t)
	writeTestConfig(t, b, s, m.server.URL, m.adminToken)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nope",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error response for an unknown role")
	}
}

func TestCredentials_NotConfigured(t *testing.T) {
	b, s := getTestBackend(t)
	createRole(t, b, s, "media", map[string]interface{}{"apps": "sonarr", "ttl": "1h"})

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/media",
		Storage:   s,
	})
	if err == nil {
		t.Fatal("expected an error when backend is not configured")
	}
}

func TestCredentials_TTLClampedToMaxTTL(t *testing.T) {
	b, s := getTestBackend(t)
	m := newMockArrproxy(t)
	writeTestConfig(t, b, s, m.server.URL, m.adminToken)

	createRole(t, b, s, "short", map[string]interface{}{"apps": "prowlarr", "max_ttl": "2h"})

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/short",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("mint creds: err=%v resp=%v", err, resp)
	}
	if resp.Secret.TTL <= 0 || resp.Secret.TTL > 2*time.Hour {
		t.Fatalf("expected TTL within (0, 2h], got %s", resp.Secret.TTL)
	}
}

func TestCredentials_RenewCappedAtTokenExpiry(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	m := newMockArrproxy(t)
	writeTestConfig(t, b, s, m.server.URL, m.adminToken)
	createRole(t, b, s, "media", map[string]interface{}{"apps": "sonarr", "ttl": "1h", "max_ttl": "24h"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/media",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("mint creds: err=%v resp=%v", err, resp)
	}

	renewResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/media",
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewResp == nil || renewResp.Secret == nil {
		t.Fatal("expected a secret in the renew response")
	}
	// The token's fixed expiry is ~1h out, so the renewed lease can never
	// exceed that remaining window even though max_ttl is 24h.
	if renewResp.Secret.TTL <= 0 || renewResp.Secret.TTL > time.Hour {
		t.Fatalf("expected renewed TTL capped within (0, 1h], got %s", renewResp.Secret.TTL)
	}
}

func TestCredentials_RenewExpiredTokenNotExtended(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	m := newMockArrproxy(t)
	writeTestConfig(t, b, s, m.server.URL, m.adminToken)
	createRole(t, b, s, "media", map[string]interface{}{"apps": "sonarr", "ttl": "1h", "max_ttl": "24h"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/media",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("mint creds: err=%v resp=%v", err, resp)
	}

	// Simulate the arrproxy token having already reached its fixed expiry.
	resp.Secret.InternalData["expires_at"] = time.Now().Add(-time.Minute).Format(time.RFC3339)

	renewResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/media",
		Storage:   s,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewResp.Secret.TTL != 0 {
		t.Fatalf("expected an expired token not to be extended, got TTL %s", renewResp.Secret.TTL)
	}
}
