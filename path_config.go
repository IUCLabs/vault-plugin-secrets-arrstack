package arrstack

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// arrstackConfig holds the connection details for the arrproxy admin API.
type arrstackConfig struct {
	BaseURL               string `json:"base_url"`
	AdminToken            string `json:"admin_token"`
	CACert                string `json:"ca_cert"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
}

func pathConfig(b *arrstackBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "arrstack",
			OperationSuffix: "config",
		},
		Fields: map[string]*framework.FieldSchema{
			"base_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the arrproxy deployment, e.g. https://arrproxy.example.com.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Base URL",
				},
			},
			"admin_token": {
				Type:        framework.TypeString,
				Description: "arrproxy admin bearer token (ARRPROXY_ADMIN_TOKEN) used to mint and revoke machine tokens.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Admin Token",
					Sensitive: true,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA certificate used to verify the arrproxy TLS certificate. Empty uses the system trust store.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "CA Certificate (PEM)",
				},
			},
			"request_timeout_seconds": {
				Type:        framework.TypeInt,
				Description: "HTTP timeout in seconds for calls to the arrproxy admin API (default 30).",
				Default:     30,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the connection to the arrproxy admin API.",
		HelpDescription: "Configure the base URL, admin token, and optional CA certificate the backend uses to mint arrproxy machine tokens.",
	}
}

func (b *arrstackBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *arrstackBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	// The admin token is deliberately not returned.
	return &logical.Response{
		Data: map[string]interface{}{
			"base_url":                config.BaseURL,
			"ca_cert":                 config.CACert,
			"request_timeout_seconds": config.RequestTimeoutSeconds,
		},
	}, nil
}

func (b *arrstackBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = &arrstackConfig{}
	}

	if v, ok := data.GetOk("base_url"); ok {
		config.BaseURL = v.(string)
	}
	if v, ok := data.GetOk("admin_token"); ok {
		config.AdminToken = v.(string)
	}
	if v, ok := data.GetOk("ca_cert"); ok {
		config.CACert = v.(string)
	}
	if v, ok := data.GetOk("request_timeout_seconds"); ok {
		config.RequestTimeoutSeconds = v.(int)
	} else if req.Operation == logical.CreateOperation {
		config.RequestTimeoutSeconds = data.Get("request_timeout_seconds").(int)
	}

	if config.BaseURL == "" {
		return logical.ErrorResponse("base_url is required"), nil
	}
	if config.AdminToken == "" {
		return logical.ErrorResponse("admin_token is required"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *arrstackBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

// getConfig reads and decodes the stored arrstack config, returning nil if none
// exists.
func getConfig(ctx context.Context, s logical.Storage) (*arrstackConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &arrstackConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}
