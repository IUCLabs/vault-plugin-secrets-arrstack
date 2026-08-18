package arrstack

import (
	"context"
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
