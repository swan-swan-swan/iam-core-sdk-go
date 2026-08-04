package groupmappings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const (
	testApplicationOpenID = "op_app_0123456789abcdefghj"
	testClientID          = "ops-portal"
	testRoleOpenID        = "op_rol_0123456789abcdefghj"
)

type captureTransport struct {
	requests []management.Request
	response any
	err      error
}

func (t *captureTransport) Do(_ context.Context, request management.Request, out any) (management.Metadata, error) {
	t.requests = append(t.requests, request)
	metadata := management.Metadata{RequestID: "request-1"}
	if t.err != nil {
		return metadata, t.err
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
	return metadata, nil
}

func TestClientUsesExactGroupMappingContracts(t *testing.T) {
	path := "/api/v1/applications/" + testApplicationOpenID + "/oidc-clients/" + testClientID + "/group-mappings"
	tests := []struct {
		name      string
		invoke    func(*Client) error
		operation string
		method    string
		path      string
		query     url.Values
		body      string
	}{
		{name: "get", invoke: func(c *Client) error {
			_, _, err := c.Get(context.Background(), testApplicationOpenID, testClientID)
			return err
		}, operation: "management.groupmappings.get", method: http.MethodGet, path: path},
		{name: "create", invoke: func(c *Client) error {
			_, _, err := c.Create(context.Background(), testApplicationOpenID, testClientID, testRoleOpenID, "ops/admin@eu", 0)
			return err
		}, operation: "management.groupmappings.create", method: http.MethodPost, path: path, body: `{"roleOpenId":"` + testRoleOpenID + `","groupValue":"ops/admin@eu","revision":0}`},
		{name: "update", invoke: func(c *Client) error {
			_, _, err := c.Update(context.Background(), testApplicationOpenID, testClientID, testRoleOpenID, "ops/read-only", 3)
			return err
		}, operation: "management.groupmappings.update", method: http.MethodPut, path: path + "/" + testRoleOpenID, body: `{"groupValue":"ops/read-only","revision":3}`},
		{name: "soft delete", invoke: func(c *Client) error {
			_, _, err := c.SoftDelete(context.Background(), testApplicationOpenID, testClientID, testRoleOpenID, 3)
			return err
		}, operation: "management.groupmappings.soft_delete", method: http.MethodDelete, path: path + "/" + testRoleOpenID, query: url.Values{"revision": {"3"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &captureTransport{response: snapshotResponse()}
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
			if request.Operation != test.operation || request.Method != test.method || request.Path != test.path || !reflect.DeepEqual(request.Query, test.query) || request.IdempotencyKey != "" {
				t.Fatalf("request = %#v", request)
			}
			if got := marshalBody(t, request.Body); got != test.body {
				t.Fatalf("body = %s, want %s", got, test.body)
			}
		})
	}
}

func TestClientRejectsInvalidGroupMappingArgumentsBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	checks := []func() error{
		func() error {
			_, _, err := client.Get(context.Background(), "op_app_0123456789abcdefghi!", testClientID)
			return err
		},
		func() error { _, _, err := client.Get(context.Background(), testApplicationOpenID, "ab"); return err },
		func() error {
			_, _, err := client.Create(context.Background(), testApplicationOpenID, testClientID, "op_rol_0123456789abcdefghi!", "ops", 0)
			return err
		},
		func() error {
			_, _, err := client.Create(context.Background(), testApplicationOpenID, testClientID, testRoleOpenID, " ops", 0)
			return err
		},
		func() error {
			_, _, err := client.Create(context.Background(), testApplicationOpenID, testClientID, testRoleOpenID, "ops+admin", 0)
			return err
		},
		func() error {
			_, _, err := client.Update(context.Background(), testApplicationOpenID, testClientID, testRoleOpenID, "", 1)
			return err
		},
		func() error {
			_, _, err := client.SoftDelete(context.Background(), testApplicationOpenID, testClientID, "bad", 1)
			return err
		},
	}
	for index, check := range checks {
		if err := check(); !errors.Is(err, management.ErrInvalidArgument) {
			t.Fatalf("check %d error = %v", index, err)
		}
	}
	if len(transport.requests) != 0 {
		t.Fatalf("requests = %d, want 0", len(transport.requests))
	}
}

func TestGroupMappingSnapshotAndConflictAreTypedAndDefensivelyCopied(t *testing.T) {
	wire := snapshotWire{
		ApplicationOpenID: testApplicationOpenID, ClientID: testClientID,
		Mappings: []mappingWire{{RoleOpenID: testRoleOpenID, GroupValue: "ops/admin"}},
		Revision: 4, Hash: "sha256:current",
	}
	snapshot := wire.snapshot()
	wire.Mappings[0].GroupValue = "changed"
	wire.Mappings = append(wire.Mappings, mappingWire{})
	if len(snapshot.Mappings) != 1 || snapshot.Mappings[0].GroupValue != "ops/admin" || snapshot.Revision != 4 {
		t.Fatalf("snapshot aliases wire data: %#v", snapshot)
	}

	err := &management.Error{Kind: management.KindConflict, Data: json.RawMessage(`{"revision":5,"hash":"sha256:next","impact":{"action":"stale_revision","affectedMappings":2}}`)}
	var conflict Conflict
	if !management.ErrorData(err, &conflict) || conflict.Revision != 5 || conflict.Hash != "sha256:next" || conflict.Impact.Action != "stale_revision" || conflict.Impact.AffectedMappings != 2 {
		t.Fatalf("conflict = %#v", conflict)
	}
}

func TestNewRejectsNilGroupMappingTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error = %v", err)
		}
	}
}

func snapshotResponse() map[string]any {
	return map[string]any{
		"applicationOpenId": testApplicationOpenID, "clientId": testClientID,
		"mappings": []any{map[string]any{"roleOpenId": testRoleOpenID, "groupValue": "ops/admin"}},
		"revision": 4, "hash": "sha256:current",
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
