package arrstack

import (
	"context"
	"strings"
	"testing"
)

func TestClient_MintToken(t *testing.T) {
	m := newMockArrproxy(t)
	client, err := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	resp, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "vault:arrstack:media",
		Apps:       []string{"sonarr", "radarr"},
		Label:      "vault-media-abcd1234",
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if resp.Token == "" || resp.ID == "" {
		t.Fatalf("expected non-empty token and id, got %+v", resp)
	}
	if resp.ExpiresAt == nil {
		t.Fatal("expected a non-nil expires_at for a positive ttl")
	}
	if m.tokenCount() != 1 {
		t.Fatalf("expected 1 token on server, got %d", m.tokenCount())
	}
	if m.lastRequest.Subject != "vault:arrstack:media" {
		t.Fatalf("expected subject forwarded, got %q", m.lastRequest.Subject)
	}
}

func TestClient_MintToken_ForwardsMethods(t *testing.T) {
	m := newMockArrproxy(t)
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})

	if _, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "vault:arrstack:readonly",
		Apps:       []string{"sonarr"},
		Methods:    []string{"GET", "HEAD"},
		TTLSeconds: 60,
	}); err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if strings.Join(m.lastRequest.Methods, ",") != "GET,HEAD" {
		t.Fatalf("expected methods forwarded, got %v", m.lastRequest.Methods)
	}
}

func TestClient_MintToken_RejectsUnknownMethod(t *testing.T) {
	m := newMockArrproxy(t)
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})

	_, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "vault:arrstack:readonly",
		Apps:       []string{"sonarr"},
		Methods:    []string{"FETCH"},
		TTLSeconds: 60,
	})
	if err == nil {
		t.Fatal("expected arrproxy to reject an unknown HTTP method")
	}
}

func TestClient_MintToken_RejectsBadSubject(t *testing.T) {
	m := newMockArrproxy(t)
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})

	_, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "media",
		Apps:       []string{"sonarr"},
		TTLSeconds: 60,
	})
	if err == nil {
		t.Fatal("expected an error when the subject lacks the vault:arrstack: prefix")
	}
}

func TestClient_RevokeToken(t *testing.T) {
	m := newMockArrproxy(t)
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})

	resp, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "vault:arrstack:media",
		Apps:       []string{"prowlarr"},
		TTLSeconds: 60,
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if err := client.RevokeToken(context.Background(), resp.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if m.tokenCount() != 0 {
		t.Fatalf("expected 0 active tokens after revoke, got %d", m.tokenCount())
	}
}

func TestClient_RevokeToken_Idempotent(t *testing.T) {
	m := newMockArrproxy(t)
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})

	if err := client.RevokeToken(context.Background(), "does-not-exist"); err != nil {
		t.Fatalf("revoking a missing id should be idempotent, got %v", err)
	}
}

func TestClient_AuthFailure(t *testing.T) {
	m := newMockArrproxy(t)
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: "wrong-token"})

	_, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "vault:arrstack:media",
		Apps:       []string{"sonarr"},
		TTLSeconds: 60,
	})
	if err == nil {
		t.Fatal("expected an auth error, got nil")
	}
}

func TestClient_ServerError(t *testing.T) {
	m := newMockArrproxy(t)
	m.mintErr = true
	client, _ := newClient(&arrstackConfig{BaseURL: m.server.URL, AdminToken: m.adminToken})

	_, err := client.MintToken(context.Background(), mintTokenRequest{
		Subject:    "vault:arrstack:media",
		Apps:       []string{"sonarr"},
		TTLSeconds: 60,
	})
	if err == nil {
		t.Fatal("expected a server error, got nil")
	}
}

func TestNewClient_Validation(t *testing.T) {
	cases := []struct {
		name    string
		config  *arrstackConfig
		wantErr bool
	}{
		{"nil config", nil, true},
		{"missing base_url", &arrstackConfig{AdminToken: "t"}, true},
		{"missing admin_token", &arrstackConfig{BaseURL: "http://x"}, true},
		{"invalid ca_cert", &arrstackConfig{BaseURL: "http://x", AdminToken: "t", CACert: "not-a-pem"}, true},
		{"valid", &arrstackConfig{BaseURL: "http://x", AdminToken: "t"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newClient(tc.config)
			if (err != nil) != tc.wantErr {
				t.Fatalf("newClient err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	client, err := newClient(&arrstackConfig{BaseURL: "https://arrproxy.example.com/", AdminToken: "t"})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if client.baseURL != "https://arrproxy.example.com" {
		t.Fatalf("expected trailing slash trimmed, got %q", client.baseURL)
	}
}
