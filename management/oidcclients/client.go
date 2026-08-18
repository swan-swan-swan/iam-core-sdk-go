package oidcclients

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"time"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const (
	applicationsPath = "/api/v1/applications"
	oidcClientsPath  = "/api/v1/oidc-clients"
)

// Client manages OIDC clients, security configuration, and credentials.
type Client struct {
	transport management.Transport
}

// New creates an OIDC management client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// List returns the OIDC clients owned by an application.
func (c *Client) List(ctx context.Context, applicationOpenID string) ([]OIDCClient, management.Metadata, error) {
	const operation = "management.oidcclients.list"
	if !validApplicationOpenID(applicationOpenID) {
		return nil, management.Metadata{}, invalidArgument(operation)
	}
	var response []oidcClientWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodGet,
		Path: applicationsPath + "/" + applicationOpenID + "/oidc-clients",
	}, &response)
	if err != nil {
		return nil, metadata, err
	}
	items := make([]OIDCClient, len(response))
	for i := range response {
		items[i] = response[i].client()
	}
	return items, metadata, nil
}

// Create creates an OIDC client under an application.
func (c *Client) Create(ctx context.Context, applicationOpenID string, input CreateInput) (OIDCClient, management.Metadata, error) {
	const operation = "management.oidcclients.create"
	if !validApplicationOpenID(applicationOpenID) || !validClientID(input.ClientID) || !validRequired(input.DisplayName) || !validStringList(input.AllowedScopes) || !validStringList(input.RedirectURIs) {
		return OIDCClient{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ClientID      string   `json:"clientId"`
		DisplayName   string   `json:"displayName"`
		Description   string   `json:"description"`
		AllowedScopes []string `json:"allowedScopes"`
		RedirectURIs  []string `json:"redirectUris"`
	}{
		ClientID: input.ClientID, DisplayName: input.DisplayName, Description: input.Description,
		AllowedScopes: append([]string(nil), input.AllowedScopes...), RedirectURIs: append([]string(nil), input.RedirectURIs...),
	}
	var response oidcClientWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodPost,
		Path: applicationsPath + "/" + applicationOpenID + "/oidc-clients", Body: body,
	}, &response)
	if err != nil {
		return OIDCClient{}, metadata, err
	}
	return response.client(), metadata, nil
}

// Get returns one OIDC client's non-sensitive configuration.
func (c *Client) Get(ctx context.Context, clientID string) (OIDCClient, management.Metadata, error) {
	const operation = "management.oidcclients.get"
	if !validClientID(clientID) {
		return OIDCClient{}, management.Metadata{}, invalidArgument(operation)
	}
	var response oidcClientWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodGet, Path: oidcClientsPath + "/" + clientID,
	}, &response)
	if err != nil {
		return OIDCClient{}, metadata, err
	}
	return response.client(), metadata, nil
}

// GetSecurity returns an OIDC client's non-sensitive security configuration.
func (c *Client) GetSecurity(ctx context.Context, clientID string) (Security, management.Metadata, error) {
	const operation = "management.oidcclients.get_security"
	if !validClientID(clientID) {
		return Security{}, management.Metadata{}, invalidArgument(operation)
	}
	var response securityWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodGet, Path: oidcClientsPath + "/" + clientID + "/security",
	}, &response)
	if err != nil {
		return Security{}, metadata, err
	}
	return response.security(), metadata, nil
}

// UpdateSecurity conditionally replaces an OIDC client's security configuration.
func (c *Client) UpdateSecurity(ctx context.Context, clientID string, input UpdateSecurityInput) (Security, management.Metadata, error) {
	const operation = "management.oidcclients.update_security"
	if !validClientID(clientID) || input.Revision == 0 || !validSecurityInput(input) {
		return Security{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ClientType            string   `json:"clientType"`
		AllowedScopes         []string `json:"allowedScopes"`
		AccessTokenTTLSeconds uint32   `json:"accessTokenTtlSeconds"`
		IDTokenTTLSeconds     uint32   `json:"idTokenTtlSeconds"`
		GroupsTokenTTLSeconds uint32   `json:"groupsTokenTtlSeconds"`
		Revision              uint64   `json:"revision"`
	}{
		ClientType:            input.ClientType,
		AllowedScopes:         append([]string(nil), input.AllowedScopes...),
		AccessTokenTTLSeconds: input.AccessTokenTTLSeconds, IDTokenTTLSeconds: input.IDTokenTTLSeconds,
		GroupsTokenTTLSeconds: input.GroupsTokenTTLSeconds,
		Revision:              input.Revision,
	}
	var response securityWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodPut, Path: oidcClientsPath + "/" + clientID + "/security", Body: body,
	}, &response)
	if err != nil {
		return Security{}, metadata, err
	}
	return response.security(), metadata, nil
}

// CreateCredential creates a confidential-client credential exactly once.
func (c *Client) CreateCredential(ctx context.Context, clientID string, expiresAt *time.Time, options ...CredentialOption) (Credential, management.Metadata, error) {
	const operation = "management.oidcclients.create_credential"
	if !validClientID(clientID) {
		return Credential{}, management.Metadata{}, invalidArgument(operation)
	}
	configured := credentialOptions{}
	for _, option := range options {
		if nilInterface(option) {
			return Credential{}, management.Metadata{}, invalidArgument(operation)
		}
		option.applyCredential(&configured)
	}
	if !validIdempotencyKey(configured.idempotencyKey) {
		return Credential{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	}{ExpiresAt: copyTime(expiresAt)}
	var response credentialWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodPost, Path: oidcClientsPath + "/" + clientID + "/credentials",
		Body: body, IdempotencyKey: configured.idempotencyKey,
	}, &response)
	if err != nil {
		return Credential{}, metadata, err
	}
	return response.credential(), metadata, nil
}

// RevokeCredential revokes one credential without retrying.
func (c *Client) RevokeCredential(ctx context.Context, clientID, credentialID string) (management.Metadata, error) {
	const operation = "management.oidcclients.revoke_credential"
	if !validClientID(clientID) || !validPathID(credentialID) {
		return management.Metadata{}, invalidArgument(operation)
	}
	return c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodDelete,
		Path: oidcClientsPath + "/" + clientID + "/credentials/" + credentialID,
	}, nil)
}

func validApplicationOpenID(value string) bool {
	if len(value) != 26 || !strings.HasPrefix(value, "op_app_") {
		return false
	}
	for _, character := range value[len("op_app_"):] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validClientID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !asciiAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if asciiAlphaNumeric(character) || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validPathID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if asciiAlphaNumeric(character) || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func validRequired(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func validStringList(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !validRequired(value) {
			return false
		}
	}
	return true
}

func validSecurityInput(input UpdateSecurityInput) bool {
	if input.ClientType != "public" && input.ClientType != "confidential" {
		return false
	}
	return validStringList(input.AllowedScopes) && input.AccessTokenTTLSeconds > 0 && input.IDTokenTTLSeconds > 0 && input.GroupsTokenTTLSeconds > 0 && input.GroupsTokenTTLSeconds <= 300
}

func validIdempotencyKey(value string) bool {
	if value == "" || len(value) > 255 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func invalidArgument(operation string) error {
	return &management.Error{Kind: management.KindInvalidArgument, Operation: operation}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
