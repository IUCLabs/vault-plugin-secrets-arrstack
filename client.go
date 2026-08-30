package arrstack

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// errBackendNotConfigured is returned when an operation needs the arrproxy
// connection config but none has been written yet.
var errBackendNotConfigured = errors.New("arrstack backend not configured: write connection details to config/ first")

const defaultHTTPTimeout = 30 * time.Second

// arrproxyClient talks to arrproxy's admin API (/api/admin/tokens) using the
// admin bearer token for authentication.
type arrproxyClient struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
}

func newClient(config *arrstackConfig) (*arrproxyClient, error) {
	if config == nil {
		return nil, errors.New("arrstack client configuration is nil")
	}
	if config.BaseURL == "" {
		return nil, errors.New("base_url is required")
	}
	if config.AdminToken == "" {
		return nil, errors.New("admin_token is required")
	}

	timeout := defaultHTTPTimeout
	if config.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(config.RequestTimeoutSeconds) * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.CACert)) {
			return nil, errors.New("ca_cert is not a valid PEM certificate bundle")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return &arrproxyClient{
		baseURL:    strings.TrimRight(config.BaseURL, "/"),
		adminToken: config.AdminToken,
		httpClient: &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// mintTokenRequest is the payload for POST /api/admin/tokens. The subject MUST
// carry the "vault:arrstack:" prefix or arrproxy rejects the request.
type mintTokenRequest struct {
	Subject string   `json:"subject"`
	Apps    []string `json:"apps"`
	// Methods limits the token to those HTTP methods. Omitted when empty so
	// arrproxy versions predating method scoping see the request unchanged.
	Methods    []string `json:"methods,omitempty"`
	Label      string   `json:"label"`
	TTLSeconds int64    `json:"ttl_seconds"`
}

// mintTokenResponse is the subset of the admin-mint response we consume. The
// plaintext token is returned exactly once. ExpiresAt is nil when the token
// has no expiry (ttl_seconds == 0).
type mintTokenResponse struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// MintToken mints a new arrproxy machine token for the given namespaced subject.
func (c *arrproxyClient) MintToken(ctx context.Context, req mintTokenRequest) (*mintTokenResponse, error) {
	var out mintTokenResponse
	if err := c.do(ctx, http.MethodPost, "/api/admin/tokens", req, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, errors.New("arrproxy returned an empty token")
	}
	if out.ID == "" {
		return nil, errors.New("arrproxy returned an empty token id")
	}
	return &out, nil
}

// RevokeToken disables a token by id. arrproxy treats this as idempotent: a
// missing or already-disabled id still returns 204.
func (c *arrproxyClient) RevokeToken(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id is required to revoke")
	}
	return c.do(ctx, http.MethodDelete, "/api/admin/tokens/"+id, nil, nil)
}

// do performs an authenticated HTTP request against the arrproxy admin API and
// decodes the JSON response into out (when non-nil).
func (c *arrproxyClient) do(ctx context.Context, method, path string, payload, out interface{}) error {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.adminToken)
	req.Header.Set("Accept", "application/json")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling arrproxy %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("arrproxy %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding arrproxy response: %w", err)
	}
	return nil
}
