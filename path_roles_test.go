package arrstack

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRole_WriteReadListDelete(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/media",
		Storage:   s,
		Data: map[string]interface{}{
			"apps":    "sonarr,radarr",
			"ttl":     "1h",
			"max_ttl": "24h",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write role: err=%v resp=%v", err, resp)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/media",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("read role: err=%v resp=%v", err, resp)
	}
	apps := resp.Data["apps"].([]string)
	// Stored de-duplicated and sorted.
	if len(apps) != 2 || apps[0] != "radarr" || apps[1] != "sonarr" {
		t.Fatalf("unexpected apps: %v", apps)
	}
	if resp.Data["ttl"].(int64) != 3600 {
		t.Fatalf("unexpected ttl: %v", resp.Data["ttl"])
	}
	if resp.Data["max_ttl"].(int64) != 86400 {
		t.Fatalf("unexpected max_ttl: %v", resp.Data["max_ttl"])
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "media" {
		t.Fatalf("unexpected role list: %v", keys)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/media",
		Storage:   s,
	}); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	role, _ := b.getRole(ctx, s, "media")
	if role != nil {
		t.Fatal("expected role to be gone after delete")
	}
}

func TestRole_AllThreeApps(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/all",
		Storage:   s,
		Data:      map[string]interface{}{"apps": "sonarr,radarr,prowlarr"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write role: err=%v resp=%v", err, resp)
	}
	role, _ := b.getRole(ctx, s, "all")
	if len(role.Apps) != 3 {
		t.Fatalf("expected 3 apps, got %v", role.Apps)
	}
}

func TestRole_UnknownAppRejected(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Storage:   s,
		Data:      map[string]interface{}{"apps": "sonarr,lidarr"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error for an app outside sonarr/radarr/prowlarr")
	}
}

func TestRole_EmptyAppsRejected(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/empty",
		Storage:   s,
		Data:      map[string]interface{}{"ttl": "1h"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error when apps is empty")
	}
}

func TestRole_TTLGreaterThanMaxTTLRejected(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Storage:   s,
		Data: map[string]interface{}{
			"apps":    "sonarr",
			"ttl":     "48h",
			"max_ttl": "1h",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when ttl > max_ttl")
	}
}

func TestRole_MethodsStoredNormalized(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/readonly",
		Storage:   s,
		Data: map[string]interface{}{
			"apps":    "sonarr",
			"methods": "get, head ,GET",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write role: err=%v resp=%v", err, resp)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/readonly",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("read role: err=%v resp=%v", err, resp)
	}
	methods := resp.Data["methods"].([]string)
	// Uppercased, de-duplicated and sorted.
	if strings.Join(methods, ",") != "GET,HEAD" {
		t.Fatalf("unexpected methods: %v", methods)
	}
}

func TestRole_MethodsDefaultEmpty(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/unrestricted",
		Storage:   s,
		Data:      map[string]interface{}{"apps": "sonarr"},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write role: err=%v resp=%v", err, resp)
	}

	role, _ := b.getRole(ctx, s, "unrestricted")
	if len(role.Methods) != 0 {
		t.Fatalf("expected no method scope by default, got %v", role.Methods)
	}
}

func TestRole_UnknownMethodRejected(t *testing.T) {
	b, s := getTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Storage:   s,
		Data:      map[string]interface{}{"apps": "sonarr", "methods": "GET,FETCH"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error for a method outside the known HTTP set")
	}
	role, _ := b.getRole(context.Background(), s, "bad")
	if role != nil {
		t.Fatal("expected the role not to be stored when methods are invalid")
	}
}

func TestRole_MethodsClearedOnUpdate(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	createRole(t, b, s, "media", map[string]interface{}{"apps": "sonarr", "methods": "GET"})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/media",
		Storage:   s,
		Data:      map[string]interface{}{"methods": ""},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("update role: err=%v resp=%v", err, resp)
	}
	role, _ := b.getRole(ctx, s, "media")
	if len(role.Methods) != 0 {
		t.Fatalf("expected methods cleared, got %v", role.Methods)
	}
	if len(role.Apps) != 1 {
		t.Fatalf("expected apps preserved across the update, got %v", role.Apps)
	}
}

func TestValidateMethods(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"empty is unrestricted", nil, nil, false},
		{"lowercase normalized", []string{"get"}, []string{"GET"}, false},
		{"trimmed dedup and sort", []string{" head ", "GET", "head"}, []string{"GET", "HEAD"}, false},
		{"all known", []string{"OPTIONS", "DELETE", "PATCH", "PUT", "POST", "HEAD", "GET"},
			[]string{"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}, false},
		{"unknown", []string{"GET", "FETCH"}, nil, true},
		{"empty entry", []string{""}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateMethods(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateMethods err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestValidateApps(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"single", []string{"sonarr"}, []string{"sonarr"}, false},
		{"dedup and sort", []string{"radarr", "sonarr", "radarr"}, []string{"radarr", "sonarr"}, false},
		{"all three", []string{"prowlarr", "sonarr", "radarr"}, []string{"prowlarr", "radarr", "sonarr"}, false},
		{"empty", nil, nil, true},
		{"unknown", []string{"sonarr", "lidarr"}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateApps(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateApps err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v want %v", got, tc.want)
				}
			}
		})
	}
}
