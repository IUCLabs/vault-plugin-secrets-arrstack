package arrstack

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "role/"

// knownApps is the fixed set of *arr apps arrproxy fronts. A role's apps must be
// a non-empty subset of these.
var knownApps = map[string]bool{
	"sonarr":   true,
	"radarr":   true,
	"prowlarr": true,
}

// knownMethods mirrors arrproxy's accepted HTTP method scope. Validating here
// rejects a typo at role write instead of at mint.
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodOptions: true,
}

// arrstackRole constrains the machine tokens minted from the creds/<name> path.
type arrstackRole struct {
	// Apps is the subset of sonarr/radarr/prowlarr a minted token may reach.
	Apps []string `json:"apps"`
	// Methods, when non-empty, limits a minted token to those HTTP methods.
	// Empty means unrestricted.
	Methods []string `json:"methods,omitempty"`
	// TTL is the default lease duration for tokens issued from this role.
	TTL time.Duration `json:"ttl"`
	// MaxTTL is the maximum lease duration for tokens issued from this role.
	MaxTTL time.Duration `json:"max_ttl"`
}

func (r *arrstackRole) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"apps":    r.Apps,
		"methods": r.Methods,
		"ttl":     int64(r.TTL.Seconds()),
		"max_ttl": int64(r.MaxTTL.Seconds()),
	}
}

// validateApps returns the requested apps de-duplicated and sorted if they form
// a non-empty subset of knownApps; otherwise it returns an error.
func validateApps(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, fmt.Errorf("apps must be a non-empty subset of sonarr/radarr/prowlarr")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(requested))
	for _, a := range requested {
		if !knownApps[a] {
			return nil, fmt.Errorf("unknown app %q: apps must be a subset of sonarr/radarr/prowlarr", a)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, nil
}

// validateMethods uppercase-normalizes, de-duplicates and sorts a requested
// method scope. An empty request yields a nil scope, meaning unrestricted.
func validateMethods(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(requested))
	for _, m := range requested {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !knownMethods[m] {
			return nil, fmt.Errorf("unknown method %q: methods must be a subset of GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS", m)
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

func pathRole(b *arrstackBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "arrstack",
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
			"apps": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated subset of sonarr/radarr/prowlarr a minted token may reach.",
				Required:    true,
			},
			"methods": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Optional comma-separated HTTP methods a minted token is limited to (GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS). Empty means unrestricted.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for tokens minted from this role.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL for tokens minted from this role.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
		},
		ExistenceCheck:  b.pathRoleExistenceCheck,
		HelpSynopsis:    "Manage roles that constrain minted arrproxy tokens.",
		HelpDescription: "Roles define the allowed apps and TTLs applied to machine tokens issued from creds/<name>.",
	}
}

func pathRolesList(b *arrstackBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "arrstack",
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRolesList,
			},
		},
		HelpSynopsis:    "List the configured roles.",
		HelpDescription: "List the roles configured on this arrstack backend.",
	}
}

func (b *arrstackBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *arrstackBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *arrstackBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{Data: role.toResponseData()}, nil
}

func (b *arrstackBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &arrstackRole{}
	}

	if v, ok := data.GetOk("apps"); ok {
		apps, err := validateApps(v.([]string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		role.Apps = apps
	}
	if v, ok := data.GetOk("methods"); ok {
		methods, err := validateMethods(v.([]string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		role.Methods = methods
	}
	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}

	if len(role.Apps) == 0 {
		return logical.ErrorResponse("apps must be a non-empty subset of sonarr/radarr/prowlarr"), nil
	}
	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl must not be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name, role); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *arrstackBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, roleStoragePrefix+data.Get("name").(string)); err != nil {
		return nil, fmt.Errorf("error deleting arrstack role: %w", err)
	}
	return nil, nil
}

func (b *arrstackBackend) getRole(ctx context.Context, s logical.Storage, name string) (*arrstackRole, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}
	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &arrstackRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, role *arrstackRole) error {
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, role)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role %q", name)
	}
	return s.Put(ctx, entry)
}
