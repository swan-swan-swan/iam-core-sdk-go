package applications

import "time"

// Application is a non-sensitive IAM Core application view.
type Application struct {
	OpenID                  string
	Name                    string
	DisplayName             string
	Description             string
	Status                  string
	Enabled                 bool
	MigrationStatus         string
	Builtin                 bool
	OIDCClientCount         int64
	HTTPResourceServerCount int64
	PolicyDocumentCount     int64
	LoginPolicyRuleCount    int64
	CanDelete               bool
	DeleteBlockReasons      []string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// CreateInput contains the mutable values accepted when creating an application.
type CreateInput struct {
	Name        string
	DisplayName string
	Description string
}

// UpdateInput contains the application display values that may be changed.
type UpdateInput struct {
	DisplayName string
	Description string
}

// DeleteBlock describes references that prevent an application hard delete.
// It can be decoded from a conflict with client.ErrorData.
type DeleteBlock struct {
	OIDCClientCount         int64    `json:"oidc_client_count"`
	HTTPResourceServerCount int64    `json:"http_resource_server_count"`
	PolicyDocumentCount     int64    `json:"policy_document_count"`
	LoginPolicyRuleCount    int64    `json:"login_policy_rule_count"`
	BlockReasons            []string `json:"block_reasons"`
}

type applicationWire struct {
	OpenID                  string    `json:"open_id"`
	Name                    string    `json:"name"`
	DisplayName             string    `json:"display_name"`
	Description             string    `json:"description"`
	Status                  string    `json:"status"`
	Enabled                 bool      `json:"enabled"`
	MigrationStatus         string    `json:"migration_status"`
	Builtin                 bool      `json:"builtin"`
	OIDCClientCount         int64     `json:"oidc_client_count"`
	HTTPResourceServerCount int64     `json:"http_resource_server_count"`
	PolicyDocumentCount     int64     `json:"policy_document_count"`
	LoginPolicyRuleCount    int64     `json:"login_policy_rule_count"`
	CanDelete               bool      `json:"can_delete"`
	DeleteBlockReasons      []string  `json:"delete_block_reasons"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

func (wire applicationWire) application() Application {
	return Application{
		OpenID: wire.OpenID, Name: wire.Name, DisplayName: wire.DisplayName,
		Description: wire.Description, Status: wire.Status, Enabled: wire.Enabled,
		MigrationStatus: wire.MigrationStatus, Builtin: wire.Builtin,
		OIDCClientCount: wire.OIDCClientCount, HTTPResourceServerCount: wire.HTTPResourceServerCount,
		PolicyDocumentCount: wire.PolicyDocumentCount, LoginPolicyRuleCount: wire.LoginPolicyRuleCount,
		CanDelete: wire.CanDelete, DeleteBlockReasons: append([]string(nil), wire.DeleteBlockReasons...),
		CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}
}
