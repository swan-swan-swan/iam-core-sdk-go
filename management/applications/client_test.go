package applications

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const testApplicationID = "op_app_0123456789abcdefghj"

type captureTransport struct {
	requests []management.Request
	response any
	err      error
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

func TestClientUsesExactApplicationContracts(t *testing.T) {
	tests := []struct {
		name      string
		response  any
		invoke    func(*Client) error
		operation string
		method    string
		path      string
		body      string
	}{
		{name: "list", response: map[string]any{"items": []any{}}, invoke: func(c *Client) error { _, _, err := c.List(context.Background()); return err }, operation: "management.applications.list", method: http.MethodGet, path: "/api/v1/applications"},
		{name: "get", response: applicationResponse(), invoke: func(c *Client) error { _, _, err := c.Get(context.Background(), testApplicationID); return err }, operation: "management.applications.get", method: http.MethodGet, path: "/api/v1/applications/" + testApplicationID},
		{name: "create", response: applicationResponse(), invoke: func(c *Client) error {
			_, _, err := c.Create(context.Background(), CreateInput{Name: "ops", DisplayName: "Ops", Description: "portal"})
			return err
		}, operation: "management.applications.create", method: http.MethodPost, path: "/api/v1/applications", body: `{"name":"ops","display_name":"Ops","description":"portal"}`},
		{name: "update", response: applicationResponse(), invoke: func(c *Client) error {
			_, _, err := c.Update(context.Background(), testApplicationID, UpdateInput{DisplayName: "Ops 2", Description: "new"})
			return err
		}, operation: "management.applications.update", method: http.MethodPut, path: "/api/v1/applications/" + testApplicationID, body: `{"display_name":"Ops 2","description":"new"}`},
		{name: "set enabled", response: applicationResponse(), invoke: func(c *Client) error {
			_, _, err := c.SetEnabled(context.Background(), testApplicationID, false)
			return err
		}, operation: "management.applications.set_enabled", method: http.MethodPut, path: "/api/v1/applications/" + testApplicationID + "/status", body: `{"enabled":false}`},
		{name: "hard delete", invoke: func(c *Client) error { _, err := c.HardDelete(context.Background(), testApplicationID); return err }, operation: "management.applications.hard_delete", method: http.MethodDelete, path: "/api/v1/applications/" + testApplicationID},
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
			if request.Operation != test.operation || request.Method != test.method || request.Path != test.path || request.Query != nil || request.IdempotencyKey != "" {
				t.Fatalf("request = %#v", request)
			}
			if got := marshalBody(t, request.Body); got != test.body {
				t.Fatalf("body = %s, want %s", got, test.body)
			}
		})
	}
}

func TestClientRejectsInvalidApplicationArgumentsBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	checks := []func() error{
		func() error { _, _, err := client.Get(context.Background(), "bad"); return err },
		func() error {
			_, _, err := client.Create(context.Background(), CreateInput{Name: " ops", DisplayName: "Ops"})
			return err
		},
		func() error {
			_, _, err := client.Create(context.Background(), CreateInput{Name: "ops", DisplayName: ""})
			return err
		},
		func() error {
			_, _, err := client.Update(context.Background(), testApplicationID, UpdateInput{DisplayName: " Ops"})
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

func TestApplicationConversionCopiesSlicesAndConflictDataIsTyped(t *testing.T) {
	wire := applicationResponse()
	wire["delete_block_reasons"] = []string{"oidc_clients"}
	transport := &captureTransport{response: map[string]any{"items": []any{wire}}}
	client, _ := New(transport)
	items, _, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].OpenID != testApplicationID || !reflect.DeepEqual(items[0].DeleteBlockReasons, []string{"oidc_clients"}) {
		t.Fatalf("items = %#v", items)
	}
	wire["delete_block_reasons"].([]string)[0] = "changed"
	if items[0].DeleteBlockReasons[0] != "oidc_clients" {
		t.Fatal("returned delete block reasons alias wire data")
	}

	conflict := &management.Error{Kind: management.KindConflict, Data: json.RawMessage(`{"oidc_client_count":2,"http_resource_server_count":1,"policy_document_count":3,"login_policy_rule_count":4,"block_reasons":["clients"]}`)}
	var block DeleteBlock
	if !management.ErrorData(conflict, &block) || block.OIDCClientCount != 2 || !reflect.DeepEqual(block.BlockReasons, []string{"clients"}) {
		t.Fatalf("block = %#v", block)
	}
}

func TestNewRejectsNilApplicationTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error = %v", err)
		}
	}
}

func applicationResponse() map[string]any {
	return map[string]any{
		"open_id": testApplicationID, "name": "ops", "display_name": "Ops", "description": "portal",
		"status": "enabled", "enabled": true, "migration_status": "ready", "builtin": false,
		"oidc_client_count": 1, "http_resource_server_count": 2, "policy_document_count": 3,
		"login_policy_rule_count": 4, "can_delete": false, "delete_block_reasons": []string{},
		"created_at": "2026-08-04T01:02:03Z", "updated_at": "2026-08-04T02:03:04Z",
	}
}

func marshalBody(t *testing.T, body any) string {
	t.Helper()
	if body == nil {
		return ""
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
