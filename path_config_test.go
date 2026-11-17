package arrstack

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_WriteReadDelete(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   s,
		Data: map[string]interface{}{
			"base_url":                "https://arrproxy.example.com",
			"admin_token":             "arrproxy-admin-secret",
			"ca_cert":                 "",
			"request_timeout_seconds": 15,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config: err=%v resp=%v", err, resp)
	}

	// Read must not leak the admin token.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("read config: err=%v resp=%v", err, resp)
	}
	if resp.Data["base_url"] != "https://arrproxy.example.com" {
		t.Fatalf("unexpected base_url: %v", resp.Data["base_url"])
	}
	if resp.Data["request_timeout_seconds"] != 15 {
		t.Fatalf("unexpected timeout: %v", resp.Data["request_timeout_seconds"])
	}
	if _, ok := resp.Data["admin_token"]; ok {
		t.Fatal("admin_token must not be returned on read")
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   s,
	}); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	cfg, err := getConfig(ctx, s)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected config to be nil after delete")
	}
}

func TestConfig_RequiredFields(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   s,
		Data:      map[string]interface{}{"base_url": "https://arrproxy.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error response when admin_token is missing")
	}
}

func TestConfig_DefaultTimeout(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	writeTestConfig(t, b, s, "https://arrproxy.example.com", "arrproxy-admin-secret")

	cfg, err := getConfig(ctx, s)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.RequestTimeoutSeconds != 30 {
		t.Fatalf("expected default timeout 30, got %d", cfg.RequestTimeoutSeconds)
	}
}
