package policies

import (
	"encoding/json"
	"time"
)

// BoundRole is one role currently bound to a Policy Document.
type BoundRole struct{ ID, OpenID, Name, DisplayName string }

// Document is a complete Policy Document management response.
type Document struct {
	ID                    string
	OpenID                string
	ApplicationOpenID     string
	Name                  string
	DisplayName           string
	PolicyType            string
	Status                string
	Editable              bool
	BoundRoles            []BoundRole
	Body                  json.RawMessage
	CompiledHash          string
	AuthorizationRevision uint64
	AuthorizationHash     string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// UpsertInput is a complete Policy Document create or replacement request.
type UpsertInput struct {
	ApplicationOpenID string
	Name              string
	DisplayName       string
	PolicyType        string
	RoleOpenIDs       []string
	Document          json.RawMessage
	Publish           bool
}

// PreviewInput requests validation and compilation preview without persistence.
type PreviewInput struct {
	ApplicationOpenID string
	RoleOpenIDs       []string
	Document          json.RawMessage
}

// BindingsInput replaces the full Role binding set for one Policy Document.
type BindingsInput struct {
	ApplicationOpenID string
	RoleOpenIDs       []string
}

// CompiledRule is one read-only compiled Policy Document rule.
type CompiledRule struct {
	PolicyDocumentOpenID      string
	PolicyDocumentName        string
	PolicyDocumentDisplayName string
	PolicyType                string
	RoleOpenID                string
	RoleName                  string
	RoleDisplayName           string
	StatementIndex            uint16
	Subject                   string
	Domain                    string
	Object                    string
	Action                    string
	Effect                    string
	Checksum                  string
	UpdatedAt                 time.Time
}

// PreviewRule is one ephemeral rule returned by Policy Document preview.
type PreviewRule struct{ Subject, Domain, Object, Action, Effect string }

// Impact is the non-sensitive Policy Document change impact summary.
type Impact struct {
	AffectedRoles         []string `json:"affected_roles"`
	AffectedUserCount     int64    `json:"affected_user_count"`
	LosingAccessUserCount int64    `json:"losing_access_user_count"`
	CompiledRuleCount     int      `json:"compiled_rule_count"`
}

// Preview is a server-produced validation, compiled rule, and impact result.
type Preview struct {
	Valid         bool
	CompiledRules []PreviewRule
	Impact        Impact
}

// Conflict is the authoritative version head and non-sensitive impact returned by a conflict.
type Conflict struct {
	AuthorizationRevision uint64 `json:"authorization_revision"`
	AuthorizationHash     string `json:"authorization_hash"`
	CompiledHash          string `json:"compiled_hash"`
	Impact                Impact `json:"impact"`
}

type boundRoleWire struct {
	ID          string `json:"id"`
	OpenID      string `json:"open_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

func (w boundRoleWire) value() BoundRole { return BoundRole{w.ID, w.OpenID, w.Name, w.DisplayName} }

type documentWire struct {
	ID                    string          `json:"id"`
	OpenID                string          `json:"open_id"`
	ApplicationOpenID     string          `json:"application_open_id"`
	Name                  string          `json:"name"`
	DisplayName           string          `json:"display_name"`
	PolicyType            string          `json:"policy_type"`
	Editable              bool            `json:"editable"`
	Status                string          `json:"status"`
	BoundRoles            []boundRoleWire `json:"bound_roles"`
	Document              json.RawMessage `json:"document"`
	CompiledHash          string          `json:"compiled_hash"`
	AuthorizationRevision uint64          `json:"authorization_revision"`
	AuthorizationHash     string          `json:"authorization_hash"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

func (w documentWire) value() Document {
	roles := make([]BoundRole, len(w.BoundRoles))
	for i := range w.BoundRoles {
		roles[i] = w.BoundRoles[i].value()
	}
	return Document{ID: w.ID, OpenID: w.OpenID, ApplicationOpenID: w.ApplicationOpenID, Name: w.Name, DisplayName: w.DisplayName, PolicyType: w.PolicyType, Status: w.Status, Editable: w.Editable, BoundRoles: roles, Body: append(json.RawMessage(nil), w.Document...), CompiledHash: w.CompiledHash, AuthorizationRevision: w.AuthorizationRevision, AuthorizationHash: w.AuthorizationHash, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}
}

type documentPageWire struct {
	Items    []documentWire `json:"items"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
	Total    int64          `json:"total"`
}

type compiledRuleWire struct {
	PolicyDocumentOpenID      string    `json:"policy_document_open_id"`
	PolicyDocumentName        string    `json:"policy_document_name"`
	PolicyDocumentDisplayName string    `json:"policy_document_display_name"`
	PolicyType                string    `json:"policy_type"`
	RoleOpenID                string    `json:"role_open_id"`
	RoleName                  string    `json:"role_name"`
	RoleDisplayName           string    `json:"role_display_name"`
	StatementIndex            uint16    `json:"statement_index"`
	Subject                   string    `json:"subject"`
	Domain                    string    `json:"dom"`
	Object                    string    `json:"obj"`
	Action                    string    `json:"act"`
	Effect                    string    `json:"eft"`
	Checksum                  string    `json:"checksum"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

func (w compiledRuleWire) value() CompiledRule {
	return CompiledRule{w.PolicyDocumentOpenID, w.PolicyDocumentName, w.PolicyDocumentDisplayName, w.PolicyType, w.RoleOpenID, w.RoleName, w.RoleDisplayName, w.StatementIndex, w.Subject, w.Domain, w.Object, w.Action, w.Effect, w.Checksum, w.UpdatedAt}
}

type compiledRulePageWire struct {
	Items    []compiledRuleWire `json:"items"`
	Page     int                `json:"page"`
	PageSize int                `json:"pageSize"`
	Total    int64              `json:"total"`
}

type previewRuleWire struct {
	Subject string `json:"subject"`
	Domain  string `json:"dom"`
	Object  string `json:"obj"`
	Action  string `json:"act"`
	Effect  string `json:"eft"`
}

func (w previewRuleWire) value() PreviewRule {
	return PreviewRule{w.Subject, w.Domain, w.Object, w.Action, w.Effect}
}

type impactWire struct {
	AffectedRoles         []string `json:"affected_roles"`
	AffectedUserCount     int64    `json:"affected_user_count"`
	LosingAccessUserCount int64    `json:"losing_access_user_count"`
	CompiledRuleCount     int      `json:"compiled_rule_count"`
}

func (w impactWire) value() Impact {
	return Impact{append([]string(nil), w.AffectedRoles...), w.AffectedUserCount, w.LosingAccessUserCount, w.CompiledRuleCount}
}

type previewWire struct {
	Valid         bool              `json:"valid"`
	CompiledRules []previewRuleWire `json:"compiled_rules"`
	Impact        impactWire        `json:"impact"`
}

func (w previewWire) value() Preview {
	rules := make([]PreviewRule, len(w.CompiledRules))
	for i := range w.CompiledRules {
		rules[i] = w.CompiledRules[i].value()
	}
	return Preview{w.Valid, rules, w.Impact.value()}
}
