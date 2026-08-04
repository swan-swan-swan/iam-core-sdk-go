package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const (
	testApplicationOpenID    = "op_app_0123456789abcdefghj"
	testResourceServerOpenID = "op_rsv_0123456789abcdefghj"
	testResourceOpenID       = "op_res_0123456789abcdefghj"
	testActionOpenID         = "op_act_0123456789abcdefghj"
	testMappingOpenID        = "op_hmm_0123456789abcdefghj"
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

func TestClientUsesExactCatalogContracts(t *testing.T) {
	base := "/api/v1/applications/" + testApplicationOpenID
	tests := []struct {
		name      string
		response  any
		invoke    func(*Client) error
		operation string
		method    string
		path      string
		body      string
	}{
		{name: "get", response: catalogResponse(), invoke: func(c *Client) error { _, _, err := c.Get(context.Background(), testApplicationOpenID); return err }, operation: "management.catalog.get", method: http.MethodGet, path: base + "/http-resource-catalog"},
		{name: "create resource server", response: resourceServerResponse(), invoke: func(c *Client) error {
			_, _, err := c.CreateResourceServer(context.Background(), testApplicationOpenID, ResourceServerInput{Code: "ops", Name: "Ops"})
			return err
		}, operation: "management.catalog.create_resource_server", method: http.MethodPost, path: base + "/http-resource-servers", body: `{"code":"ops","name":"Ops"}`},
		{name: "update resource server", response: resourceServerResponse(), invoke: func(c *Client) error {
			_, _, err := c.UpdateResourceServer(context.Background(), testApplicationOpenID, testResourceServerOpenID, ResourceServerInput{Code: "ops", Name: "Ops v2"})
			return err
		}, operation: "management.catalog.update_resource_server", method: http.MethodPut, path: base + "/http-resource-servers/" + testResourceServerOpenID, body: `{"code":"ops","name":"Ops v2"}`},
		{name: "create resource", response: resourceResponse(), invoke: func(c *Client) error {
			_, _, err := c.CreateResource(context.Background(), testApplicationOpenID, ResourceInput{ResourceServerOpenID: testResourceServerOpenID, Code: "jobs", Name: "Jobs", RouteTemplate: "/api/jobs/:id"})
			return err
		}, operation: "management.catalog.create_resource", method: http.MethodPost, path: base + "/http-resources", body: `{"resource_server_open_id":"` + testResourceServerOpenID + `","code":"jobs","name":"Jobs","route_template":"/api/jobs/:id"}`},
		{name: "update resource", response: resourceResponse(), invoke: func(c *Client) error {
			_, _, err := c.UpdateResource(context.Background(), testApplicationOpenID, testResourceOpenID, ResourceInput{ResourceServerOpenID: testResourceServerOpenID, Code: "jobs", Name: "Jobs v2", RouteTemplate: "/api/jobs/:id"})
			return err
		}, operation: "management.catalog.update_resource", method: http.MethodPut, path: base + "/http-resources/" + testResourceOpenID, body: `{"resource_server_open_id":"` + testResourceServerOpenID + `","code":"jobs","name":"Jobs v2","route_template":"/api/jobs/:id"}`},
		{name: "create action", response: actionResponse(), invoke: func(c *Client) error {
			_, _, err := c.CreateAction(context.Background(), testApplicationOpenID, ActionInput{ResourceServerOpenID: testResourceServerOpenID, Code: "jobs.read", Name: "Read jobs"})
			return err
		}, operation: "management.catalog.create_action", method: http.MethodPost, path: base + "/http-actions", body: `{"resource_server_open_id":"` + testResourceServerOpenID + `","code":"jobs.read","name":"Read jobs"}`},
		{name: "update action", response: actionResponse(), invoke: func(c *Client) error {
			_, _, err := c.UpdateAction(context.Background(), testApplicationOpenID, testActionOpenID, ActionInput{ResourceServerOpenID: testResourceServerOpenID, Code: "jobs.read", Name: "Read jobs v2"})
			return err
		}, operation: "management.catalog.update_action", method: http.MethodPut, path: base + "/http-actions/" + testActionOpenID, body: `{"resource_server_open_id":"` + testResourceServerOpenID + `","code":"jobs.read","name":"Read jobs v2"}`},
		{name: "put method mapping", response: methodMappingResponse(), invoke: func(c *Client) error {
			_, _, err := c.PutMethodMapping(context.Background(), testApplicationOpenID, MethodMappingInput{ResourceOpenID: testResourceOpenID, ActionOpenID: testActionOpenID, Method: http.MethodGet})
			return err
		}, operation: "management.catalog.put_method_mapping", method: http.MethodPut, path: base + "/http-method-mappings", body: `{"resource_open_id":"` + testResourceOpenID + `","action_open_id":"` + testActionOpenID + `","method":"GET"}`},
		{name: "publish", invoke: func(c *Client) error { _, err := c.Publish(context.Background(), testApplicationOpenID); return err }, operation: "management.catalog.publish", method: http.MethodPost, path: base + "/http-resource-catalog/publish"},
		{name: "deactivate", invoke: func(c *Client) error {
			_, err := c.Deactivate(context.Background(), testApplicationOpenID, EntityMethodMapping, testMappingOpenID)
			return err
		}, operation: "management.catalog.deactivate", method: http.MethodDelete, path: base + "/http-resource-catalog/method_mapping/" + testMappingOpenID},
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

func TestCatalogResponsesPreserveHashAndReferenceBlockCopies(t *testing.T) {
	transport := &captureTransport{response: catalogResponse()}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	got, metadata, err := client.Get(context.Background(), testApplicationOpenID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RequestID != "request-1" || got.Version != "managed-v1" || got.Hash != "sha256:catalog" || len(got.Resources) != 1 || got.Resources[0].CanonicalResource != "http:/api/jobs/:id" {
		t.Fatalf("catalog = %#v metadata = %#v", got, metadata)
	}

	errConflict := &management.Error{Kind: management.KindConflict, Data: json.RawMessage(`{"references":["policy:ops-read"]}`)}
	var block ReferenceBlock
	if !management.ErrorData(errConflict, &block) || !reflect.DeepEqual(block.References, []string{"policy:ops-read"}) {
		t.Fatalf("block = %#v", block)
	}
	block.References[0] = "changed"
	if string(errConflict.Data) != `{"references":["policy:ops-read"]}` {
		t.Fatal("conflict aliases error data")
	}
}

func TestCatalogWireAcceptsAllV181ServerFieldsWithoutExposingInternalIDs(t *testing.T) {
	encoded, err := json.Marshal(catalogResponse())
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire catalogWire
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	got := wire.value()
	if got.ResourceServers[0].OpenID != testResourceServerOpenID || got.Resources[0].ResourceServerOpenID != testResourceServerOpenID || got.MethodMappings[0].ActionOpenID != testActionOpenID {
		t.Fatalf("catalog = %#v", got)
	}
}

func TestCatalogRejectsInvalidArgumentsBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	checks := []func() error{
		func() error { _, _, err := client.Get(context.Background(), "bad"); return err },
		func() error {
			_, _, err := client.CreateResourceServer(context.Background(), testApplicationOpenID, ResourceServerInput{Code: "Bad", Name: "Ops"})
			return err
		},
		func() error {
			_, _, err := client.UpdateResourceServer(context.Background(), testApplicationOpenID, "op_rsv_bad", ResourceServerInput{Code: "ops", Name: "Ops"})
			return err
		},
		func() error {
			_, _, err := client.CreateResource(context.Background(), testApplicationOpenID, ResourceInput{ResourceServerOpenID: testResourceServerOpenID, Code: "jobs", Name: "Jobs", RouteTemplate: "relative"})
			return err
		},
		func() error {
			_, _, err := client.CreateAction(context.Background(), testApplicationOpenID, ActionInput{ResourceServerOpenID: testResourceServerOpenID, Code: "jobs", Name: " Jobs"})
			return err
		},
		func() error {
			_, _, err := client.PutMethodMapping(context.Background(), testApplicationOpenID, MethodMappingInput{ResourceOpenID: testResourceOpenID, ActionOpenID: testActionOpenID, Method: "get"})
			return err
		},
		func() error {
			_, err := client.Deactivate(context.Background(), testApplicationOpenID, EntityResource, testActionOpenID)
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

func TestNewRejectsNilCatalogTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error = %v", err)
		}
	}
}

func catalogResponse() map[string]any {
	return map[string]any{"resource_servers": []any{resourceServerResponse()}, "resources": []any{resourceResponse()}, "actions": []any{actionResponse()}, "method_mappings": []any{methodMappingResponse()}, "catalog_mode": "managed", "system_managed": false, "read_only": false, "catalog_version": "managed-v1", "catalog_hash": "sha256:catalog", "sync_status": "not_applicable"}
}
func resourceServerResponse() map[string]any {
	return map[string]any{"id": 1, "uni_id": "rsv_0123456789abcdefghijklm", "open_id": testResourceServerOpenID, "application_open_id": testApplicationOpenID, "code": "ops", "name": "Ops", "active": true}
}
func resourceResponse() map[string]any {
	return map[string]any{"id": 2, "uni_id": "res_0123456789abcdefghijklm", "open_id": testResourceOpenID, "application_open_id": testApplicationOpenID, "resource_server_id": 1, "resource_server_open_id": testResourceServerOpenID, "code": "jobs", "name": "Jobs", "route_template": "/api/jobs/:id", "canonical_resource": "http:/api/jobs/:id", "active": true}
}
func actionResponse() map[string]any {
	return map[string]any{"id": 3, "uni_id": "act_0123456789abcdefghijklm", "open_id": testActionOpenID, "application_open_id": testApplicationOpenID, "resource_server_id": 1, "resource_server_open_id": testResourceServerOpenID, "code": "jobs.read", "name": "Read jobs", "active": true}
}
func methodMappingResponse() map[string]any {
	return map[string]any{"id": 4, "uni_id": "hmm_0123456789abcdefghijklm", "open_id": testMappingOpenID, "application_open_id": testApplicationOpenID, "resource_id": 2, "resource_open_id": testResourceOpenID, "action_id": 3, "action_open_id": testActionOpenID, "method": "GET", "active": true}
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
