package oidcclients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const (
	testApplicationID = "op_app_0123456789abcdefghj"
	testClientID      = "ops-portal"
)

type captureTransport struct {
	requests []management.Request
	response any
	err      error
}

type oidcStaticTokenSource string

func (s oidcStaticTokenSource) AccessToken(context.Context) (string, error) { return string(s), nil }

// TestClientAcceptsLegacyServerFieldsWithoutPublishingThem 验证滚动升级期间严格解码器可吞掉旧 Server 字段，但公共模型不再暴露它们。
func TestClientAcceptsLegacyServerFieldsWithoutPublishingThem(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/v1/oidc-clients/ops-portal/security" {
			_, _ = writer.Write([]byte(`{"code":0,"message":"ok","data":{"clientId":"ops-portal","clientType":"confidential","pkcePolicy":"recommended","allowedScopes":["openid","roles"],"accessTokenTtlSeconds":300,"idTokenTtlSeconds":300,"groupsTokenTtlSeconds":120,"legacyRolesClaim":true,"revision":7,"hash":"abc"}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"code":0,"message":"ok","data":{"id":"oc_1","applicationId":"op_app_1","clientId":"ops-portal","displayName":"Ops","description":"portal","pkcePolicy":"recommended","allowedScopes":["openid"],"redirectUris":["https://ops.example/callback"],"enabled":true,"createdAt":"2026-08-18T00:00:00Z","updatedAt":"2026-08-18T00:00:00Z"}}`))
	}))
	defer server.Close()

	transport, err := management.New(management.Config{BaseURL: server.URL, TokenSource: oidcStaticTokenSource("token")})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	security, _, err := client.GetSecurity(context.Background(), "ops-portal")
	if err != nil {
		t.Fatalf("GetSecurity() error = %v", err)
	}
	if security.ClientID != "ops-portal" || !reflect.DeepEqual(security.AllowedScopes, []string{"openid"}) {
		t.Fatalf("security = %#v", security)
	}
	if _, _, err := client.Get(context.Background(), "ops-portal"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func (t *captureTransport) Do(_ context.Context, request management.Request, out any) (management.Metadata, error) {
	t.requests = append(t.requests, request)
	if t.err != nil {
		return management.Metadata{RequestID: "request-1"}, t.err
	}
	if out != nil && t.response != nil {
		encoded, err := json.Marshal(t.response)
		if err != nil {
			return management.Metadata{}, err
		}
		if err := json.Unmarshal(encoded, out); err != nil {
			return management.Metadata{}, err
		}
	}
	return management.Metadata{RequestID: "request-1"}, nil
}

func TestClientUsesExactOIDCContracts(t *testing.T) {
	expiresAt := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name      string
		response  any
		invoke    func(*Client) error
		operation string
		method    string
		path      string
		body      string
		key       string
	}{
		{name: "list", response: []any{}, invoke: func(c *Client) error { _, _, err := c.List(context.Background(), testApplicationID); return err }, operation: "management.oidcclients.list", method: http.MethodGet, path: "/api/v1/applications/" + testApplicationID + "/oidc-clients"},
		{name: "create", response: oidcClientResponse(), invoke: func(c *Client) error {
			_, _, err := c.Create(context.Background(), testApplicationID, CreateInput{ClientID: testClientID, DisplayName: "Ops", Description: "portal", AllowedScopes: []string{"openid", "groups"}, RedirectURIs: []string{"https://ops.example/callback"}})
			return err
		}, operation: "management.oidcclients.create", method: http.MethodPost, path: "/api/v1/applications/" + testApplicationID + "/oidc-clients", body: `{"clientId":"ops-portal","displayName":"Ops","description":"portal","allowedScopes":["openid","groups"],"redirectUris":["https://ops.example/callback"]}`},
		{name: "get", response: oidcClientResponse(), invoke: func(c *Client) error { _, _, err := c.Get(context.Background(), testClientID); return err }, operation: "management.oidcclients.get", method: http.MethodGet, path: "/api/v1/oidc-clients/" + testClientID},
		{name: "get security", response: securityResponse(), invoke: func(c *Client) error { _, _, err := c.GetSecurity(context.Background(), testClientID); return err }, operation: "management.oidcclients.get_security", method: http.MethodGet, path: "/api/v1/oidc-clients/" + testClientID + "/security"},
		{name: "update security", response: securityResponse(), invoke: func(c *Client) error {
			_, _, err := c.UpdateSecurity(context.Background(), testClientID, UpdateSecurityInput{ClientType: "confidential", AllowedScopes: []string{"openid"}, AccessTokenTTLSeconds: 300, IDTokenTTLSeconds: 300, GroupsTokenTTLSeconds: 120, Revision: 7})
			return err
		}, operation: "management.oidcclients.update_security", method: http.MethodPut, path: "/api/v1/oidc-clients/" + testClientID + "/security", body: `{"clientType":"confidential","allowedScopes":["openid"],"accessTokenTtlSeconds":300,"idTokenTtlSeconds":300,"groupsTokenTtlSeconds":120,"revision":7}`},
		{name: "create credential", response: credentialResponse("secret-marker"), invoke: func(c *Client) error {
			_, _, err := c.CreateCredential(context.Background(), testClientID, &expiresAt, WithIdempotencyKey("key-1"))
			return err
		}, operation: "management.oidcclients.create_credential", method: http.MethodPost, path: "/api/v1/oidc-clients/" + testClientID + "/credentials", body: `{"expiresAt":"2027-01-02T03:04:05Z"}`, key: "key-1"},
		{name: "revoke credential", invoke: func(c *Client) error {
			_, err := c.RevokeCredential(context.Background(), testClientID, "occ_0123456789abcdef")
			return err
		}, operation: "management.oidcclients.revoke_credential", method: http.MethodDelete, path: "/api/v1/oidc-clients/" + testClientID + "/credentials/occ_0123456789abcdef"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &captureTransport{response: test.response}
			client, err := New(transport)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.invoke(client); err != nil {
				t.Fatal(err)
			}
			if len(transport.requests) != 1 {
				t.Fatalf("requests = %d, want 1", len(transport.requests))
			}
			request := transport.requests[0]
			if request.Operation != test.operation || request.Method != test.method || request.Path != test.path || request.Query != nil || request.IdempotencyKey != test.key {
				t.Fatalf("request = %#v", request)
			}
			if got := marshalBody(t, request.Body); got != test.body {
				t.Fatalf("body = %s, want %s", got, test.body)
			}
		})
	}
}

func TestOIDCClientRejectsInvalidArgumentsBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	checks := []func() error{
		func() error { _, _, err := client.List(context.Background(), "bad"); return err },
		func() error { _, _, err := client.Get(context.Background(), " x"); return err },
		func() error {
			_, _, err := client.Create(context.Background(), testApplicationID, CreateInput{ClientID: "x", DisplayName: "Ops", AllowedScopes: []string{"openid"}, RedirectURIs: []string{"https://ops.example/callback"}})
			return err
		},
		func() error {
			_, _, err := client.UpdateSecurity(context.Background(), testClientID, UpdateSecurityInput{})
			return err
		},
		func() error {
			_, _, err := client.UpdateSecurity(context.Background(), testClientID, UpdateSecurityInput{ClientType: "public", AllowedScopes: []string{"openid"}, AccessTokenTTLSeconds: 1, IDTokenTTLSeconds: 1, GroupsTokenTTLSeconds: 301, Revision: 1})
			return err
		},
		func() error {
			_, _, err := client.CreateCredential(context.Background(), testClientID, nil)
			return err
		},
		func() error {
			_, _, err := client.CreateCredential(context.Background(), testClientID, nil, WithIdempotencyKey(" key"))
			return err
		},
		func() error {
			_, err := client.RevokeCredential(context.Background(), testClientID, " bad")
			return err
		},
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, management.ErrInvalidArgument) {
			t.Fatalf("check %d error = %v", i, err)
		}
	}
	if len(transport.requests) != 0 {
		t.Fatalf("requests = %d, want 0", len(transport.requests))
	}
}

func TestOIDCConversionsCopyDataAndKeepSecretRedacted(t *testing.T) {
	wire := oidcClientResponse()
	wire["allowedScopes"] = []string{"openid", "groups"}
	wire["redirectUris"] = []string{"https://ops.example/callback"}
	transport := &captureTransport{response: []any{wire}}
	client, _ := New(transport)
	items, _, err := client.List(context.Background(), testApplicationID)
	if err != nil {
		t.Fatal(err)
	}
	wire["allowedScopes"].([]string)[0] = "changed"
	wire["redirectUris"].([]string)[0] = "changed"
	if !reflect.DeepEqual(items[0].AllowedScopes, []string{"openid", "groups"}) || !reflect.DeepEqual(items[0].RedirectURIs, []string{"https://ops.example/callback"}) {
		t.Fatalf("client aliases wire slices: %#v", items[0])
	}

	transport.response = credentialResponse("secret-marker")
	credential, _, err := client.CreateCredential(context.Background(), testClientID, nil, WithIdempotencyKey("key-2"))
	if err != nil {
		t.Fatal(err)
	}
	if credential.Secret.Reveal() != "secret-marker" {
		t.Fatal("secret was not available through explicit reveal")
	}
	for _, rendered := range []string{fmt.Sprint(credential.Secret), fmt.Sprintf("%#v", credential.Secret), fmt.Sprintf("%#v", credential), string(mustJSON(t, credential.Secret)), string(mustJSON(t, credential))} {
		if strings.Contains(rendered, "secret-marker") {
			t.Fatalf("secret leaked through %q", rendered)
		}
	}
}

func TestSecurityConflictDataIsTypedAndDefensivelyDecoded(t *testing.T) {
	err := &management.Error{Kind: management.KindConflict, Data: json.RawMessage(`{"revision":8,"hash":"sha256:next","impactSummary":["allowed_scopes"]}`)}
	var conflict SecurityConflict
	if !management.ErrorData(err, &conflict) || conflict.Revision != 8 || !reflect.DeepEqual(conflict.ImpactSummary, []string{"allowed_scopes"}) {
		t.Fatalf("conflict = %#v", conflict)
	}
}

func TestNewRejectsNilOIDCTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error = %v", err)
		}
	}
}

func oidcClientResponse() map[string]any {
	return map[string]any{
		"id": testClientID, "applicationId": testApplicationID, "clientId": testClientID,
		"displayName": "Ops", "description": "portal", "allowedScopes": []string{"openid"},
		"redirectUris": []string{"https://ops.example/callback"}, "pkcePolicy": "required", "enabled": true,
		"createdAt": "2026-08-04T01:02:03Z", "updatedAt": "2026-08-04T02:03:04Z",
	}
}

func securityResponse() map[string]any {
	return map[string]any{
		"clientId": testClientID, "clientType": "confidential", "pkcePolicy": "required",
		"allowedScopes": []string{"openid"}, "accessTokenTtlSeconds": 300, "idTokenTtlSeconds": 300,
		"groupsTokenTtlSeconds": 120, "legacyRolesClaim": false, "revision": 7, "hash": "sha256:current",
	}
}

func credentialResponse(secret string) map[string]any {
	return map[string]any{
		"id": "occ_0123456789abcdef", "clientId": testClientID, "secret": secret,
		"createdAt": "2026-08-04T01:02:03Z",
	}
}

func marshalBody(t *testing.T, body any) string {
	t.Helper()
	if body == nil {
		return ""
	}
	return string(mustJSON(t, body))
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
