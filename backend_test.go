package arrstack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// getTestBackend returns a configured backend backed by in-memory storage.
func getTestBackend(t *testing.T) (*arrstackBackend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unexpected error creating backend: %v", err)
	}
	return b.(*arrstackBackend), config.StorageView
}

// mockToken is a token row held by the fake arrproxy admin server.
type mockToken struct {
	Subject   string
	Apps      []string
	Label     string
	ExpiresAt *time.Time
	Disabled  bool
}

// mockArrproxy is an in-memory fake of arrproxy's admin token API. It mirrors
// the real handler's checks: bearer auth, the vault:arrstack: subject prefix,
// and a non-empty subset of the configured apps.
type mockArrproxy struct {
	server *httptest.Server

	mu         sync.Mutex
	tokens     map[string]*mockToken // id -> token
	counter    int
	adminToken string
	apps       map[string]bool

	mintErr     bool
	lastRequest mintTokenRequest
}

func newMockArrproxy(t *testing.T) *mockArrproxy {
	t.Helper()
	m := &mockArrproxy{
		tokens:     make(map[string]*mockToken),
		adminToken: "arrproxy-admin-secret",
		apps:       map[string]bool{"sonarr": true, "radarr": true, "prowlarr": true},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/admin/tokens", m.handleMint)
	mux.HandleFunc("DELETE /api/admin/tokens/{id}", m.handleRevoke)

	m.server = httptest.NewServer(m.authMiddleware(mux))
	t.Cleanup(m.server.Close)
	return m
}

// authMiddleware fails closed to 404 when no admin token is set and 401 on a
// mismatch, matching arrproxy's adminAuth.
func (m *mockArrproxy) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+m.adminToken {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *mockArrproxy) tokenCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tokens {
		if !t.Disabled {
			n++
		}
	}
	return n
}

func (m *mockArrproxy) handleMint(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mintErr {
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
		return
	}

	var req mintTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.lastRequest = req

	if !strings.HasPrefix(req.Subject, "vault:arrstack:") || strings.TrimSpace(strings.TrimPrefix(req.Subject, "vault:arrstack:")) == "" {
		http.Error(w, "subject must be namespaced with vault:arrstack:", http.StatusBadRequest)
		return
	}
	if len(req.Apps) == 0 {
		http.Error(w, "apps must be a non-empty subset", http.StatusBadRequest)
		return
	}
	for _, a := range req.Apps {
		if !m.apps[a] {
			http.Error(w, "unknown app", http.StatusBadRequest)
			return
		}
	}
	if req.TTLSeconds < 0 {
		http.Error(w, "ttl_seconds must not be negative", http.StatusBadRequest)
		return
	}

	m.counter++
	id := "tok-" + strconv.Itoa(m.counter)
	var expiresAt *time.Time
	if req.TTLSeconds > 0 {
		exp := time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
		expiresAt = &exp
	}
	m.tokens[id] = &mockToken{
		Subject:   req.Subject,
		Apps:      req.Apps,
		Label:     req.Label,
		ExpiresAt: expiresAt,
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         id,
		"token":      "arr_" + id + "_plaintext",
		"expires_at": expiresAt,
	})
}

func (m *mockArrproxy) handleRevoke(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := r.PathValue("id")
	if tok, ok := m.tokens[id]; ok {
		tok.Disabled = true
	}
	// Idempotent: a missing id still returns 204.
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeTestConfig stores a config pointing at the given base URL.
func writeTestConfig(t *testing.T, b *arrstackBackend, s logical.Storage, baseURL, adminToken string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   s,
		Data: map[string]interface{}{
			"base_url":    baseURL,
			"admin_token": adminToken,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("failed to write config: err=%v resp=%v", err, resp)
	}
}
