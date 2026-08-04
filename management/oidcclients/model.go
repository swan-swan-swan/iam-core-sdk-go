package oidcclients

import (
	"time"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

// OIDCClient is a non-sensitive OIDC client view.
type OIDCClient struct {
	ID            string
	ApplicationID string
	ClientID      string
	DisplayName   string
	Description   string
	AllowedScopes []string
	RedirectURIs  []string
	PKCEPolicy    string
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CreateInput contains the non-sensitive OIDC client creation fields.
type CreateInput struct {
	ClientID      string
	DisplayName   string
	Description   string
	AllowedScopes []string
	RedirectURIs  []string
	PKCEPolicy    string
}

// Security is the current non-sensitive security configuration.
type Security struct {
	ClientID              string
	ClientType            string
	PKCEPolicy            string
	AllowedScopes         []string
	AccessTokenTTLSeconds uint32
	IDTokenTTLSeconds     uint32
	GroupsTokenTTLSeconds uint32
	LegacyRolesClaim      bool
	Revision              uint64
	Hash                  string
}

// UpdateSecurityInput is a revision-controlled complete security update.
type UpdateSecurityInput struct {
	ClientType            string
	PKCEPolicy            string
	AllowedScopes         []string
	AccessTokenTTLSeconds uint32
	IDTokenTTLSeconds     uint32
	GroupsTokenTTLSeconds uint32
	LegacyRolesClaim      bool
	Revision              uint64
}

// SecurityConflict can be decoded from a conflict with client.ErrorData.
type SecurityConflict struct {
	Revision      uint64   `json:"revision"`
	Hash          string   `json:"hash"`
	ImpactSummary []string `json:"impactSummary"`
}

// Credential contains credential metadata and the secret returned by a
// successful creation response. Secret is empty for replayed responses.
type Credential struct {
	ID        string
	ClientID  string
	Secret    management.SensitiveString
	ExpiresAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

type oidcClientWire struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"applicationId"`
	ClientID      string    `json:"clientId"`
	DisplayName   string    `json:"displayName"`
	Description   string    `json:"description"`
	AllowedScopes []string  `json:"allowedScopes"`
	RedirectURIs  []string  `json:"redirectUris"`
	PKCEPolicy    string    `json:"pkcePolicy"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func (wire oidcClientWire) client() OIDCClient {
	return OIDCClient{
		ID: wire.ID, ApplicationID: wire.ApplicationID, ClientID: wire.ClientID,
		DisplayName: wire.DisplayName, Description: wire.Description,
		AllowedScopes: append([]string(nil), wire.AllowedScopes...),
		RedirectURIs:  append([]string(nil), wire.RedirectURIs...),
		PKCEPolicy:    wire.PKCEPolicy, Enabled: wire.Enabled,
		CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}
}

type securityWire struct {
	ClientID              string   `json:"clientId"`
	ClientType            string   `json:"clientType"`
	PKCEPolicy            string   `json:"pkcePolicy"`
	AllowedScopes         []string `json:"allowedScopes"`
	AccessTokenTTLSeconds uint32   `json:"accessTokenTtlSeconds"`
	IDTokenTTLSeconds     uint32   `json:"idTokenTtlSeconds"`
	GroupsTokenTTLSeconds uint32   `json:"groupsTokenTtlSeconds"`
	LegacyRolesClaim      bool     `json:"legacyRolesClaim"`
	Revision              uint64   `json:"revision"`
	Hash                  string   `json:"hash"`
}

func (wire securityWire) security() Security {
	return Security{
		ClientID: wire.ClientID, ClientType: wire.ClientType, PKCEPolicy: wire.PKCEPolicy,
		AllowedScopes:         append([]string(nil), wire.AllowedScopes...),
		AccessTokenTTLSeconds: wire.AccessTokenTTLSeconds, IDTokenTTLSeconds: wire.IDTokenTTLSeconds,
		GroupsTokenTTLSeconds: wire.GroupsTokenTTLSeconds, LegacyRolesClaim: wire.LegacyRolesClaim,
		Revision: wire.Revision, Hash: wire.Hash,
	}
}

type credentialWire struct {
	ID        string     `json:"id"`
	ClientID  string     `json:"clientId"`
	Secret    string     `json:"secret,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

func (wire *credentialWire) credential() Credential {
	secret := management.NewSensitiveString(wire.Secret)
	wire.Secret = ""
	return Credential{
		ID: wire.ID, ClientID: wire.ClientID, Secret: secret,
		ExpiresAt: copyTime(wire.ExpiresAt), RevokedAt: copyTime(wire.RevokedAt), CreatedAt: wire.CreatedAt,
	}
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
