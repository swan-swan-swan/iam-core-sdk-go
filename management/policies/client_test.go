package policies

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
	testPolicyOpenID      = "op_pdc_0123456789abcdefghj"
	testRoleOpenID        = "op_rol_0123456789abcdefghj"
)

type captureTransport struct {
	requests []management.Request
	response any
	err      error
}

func (t *captureTransport) Do(_ context.Context, request management.Request, out any) (management.Metadata, error) {
	t.requests = append(t.requests, request)
	metadata := management.Metadata{TraceID: "trace-1"}
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

func TestClientUsesExactPolicyContracts(t *testing.T) {
	document := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}`)
	listOptions := ListOptions{ApplicationOpenID: testApplicationOpenID, PolicyType: "custom", Name: "ops-read", DisplayName: "Ops Read", Keyword: "read", RoleOpenID: testRoleOpenID, Status: "published", Page: 2, PageSize: 20}
	compiledOptions := CompiledRuleOptions{ApplicationOpenID: testApplicationOpenID, PolicyDocumentOpenID: testPolicyOpenID, PolicyType: "custom", RoleOpenID: testRoleOpenID, Effect: "allow", Domain: "http", Action: "GET", ResourceKeyword: "/jobs", Page: 3, PageSize: 10}
	tests := []struct {
		name                    string
		response                any
		invoke                  func(*Client) error
		operation, method, path string
		query                   url.Values
		body                    string
	}{
		{name: "list", response: policyPageResponse(), invoke: func(c *Client) error { _, _, err := c.List(context.Background(), listOptions); return err }, operation: "management.policies.list", method: http.MethodGet, path: "/api/v1/policy-documents", query: url.Values{"application_open_id": {testApplicationOpenID}, "policy_type": {"custom"}, "name": {"ops-read"}, "display_name": {"Ops Read"}, "keyword": {"read"}, "role_open_id": {testRoleOpenID}, "status": {"published"}, "page": {"2"}, "page_size": {"20"}}},
		{name: "get", response: policyResponse(), invoke: func(c *Client) error {
			_, _, err := c.Get(context.Background(), testPolicyOpenID, testApplicationOpenID)
			return err
		}, operation: "management.policies.get", method: http.MethodGet, path: "/api/v1/policy-documents/" + testPolicyOpenID, query: url.Values{"application_open_id": {testApplicationOpenID}}},
		{name: "create", response: policyResponse(), invoke: func(c *Client) error {
			_, _, err := c.Create(context.Background(), UpsertInput{ApplicationOpenID: testApplicationOpenID, Name: "ops-read", DisplayName: "Ops Read", PolicyType: "custom", RoleOpenIDs: []string{testRoleOpenID}, Document: document, Publish: true})
			return err
		}, operation: "management.policies.create", method: http.MethodPost, path: "/api/v1/policy-documents", body: `{"application_open_id":"` + testApplicationOpenID + `","name":"ops-read","display_name":"Ops Read","policy_type":"custom","role_open_ids":["` + testRoleOpenID + `"],"document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]},"publish":true}`},
		{name: "update", response: policyResponse(), invoke: func(c *Client) error {
			_, _, err := c.Update(context.Background(), testPolicyOpenID, UpsertInput{ApplicationOpenID: testApplicationOpenID, Name: "ops-read", DisplayName: "Ops Read v2", PolicyType: "custom", RoleOpenIDs: []string{testRoleOpenID}, Document: document})
			return err
		}, operation: "management.policies.update", method: http.MethodPut, path: "/api/v1/policy-documents/" + testPolicyOpenID, body: `{"application_open_id":"` + testApplicationOpenID + `","name":"ops-read","display_name":"Ops Read v2","policy_type":"custom","role_open_ids":["` + testRoleOpenID + `"],"document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]},"publish":false}`},
		{name: "preview", response: previewResponse(), invoke: func(c *Client) error {
			_, _, err := c.Preview(context.Background(), PreviewInput{ApplicationOpenID: testApplicationOpenID, RoleOpenIDs: []string{testRoleOpenID}, Document: document})
			return err
		}, operation: "management.policies.preview", method: http.MethodPost, path: "/api/v1/policy-documents/preview", body: `{"application_open_id":"` + testApplicationOpenID + `","role_open_ids":["` + testRoleOpenID + `"],"document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}}`},
		{name: "set bindings", response: policyResponse(), invoke: func(c *Client) error {
			_, _, err := c.SetBindings(context.Background(), testPolicyOpenID, BindingsInput{ApplicationOpenID: testApplicationOpenID, RoleOpenIDs: []string{testRoleOpenID}})
			return err
		}, operation: "management.policies.set_bindings", method: http.MethodPut, path: "/api/v1/policy-documents/" + testPolicyOpenID + "/bindings", body: `{"application_open_id":"` + testApplicationOpenID + `","role_open_ids":["` + testRoleOpenID + `"]}`},
		{name: "list compiled rules", response: compiledPageResponse(), invoke: func(c *Client) error {
			_, _, err := c.ListCompiledRules(context.Background(), compiledOptions)
			return err
		}, operation: "management.policies.list_compiled_rules", method: http.MethodGet, path: "/api/v1/policy-compiled-rules", query: url.Values{"application_open_id": {testApplicationOpenID}, "policy_document_open_id": {testPolicyOpenID}, "policy_type": {"custom"}, "role_open_id": {testRoleOpenID}, "effect": {"allow"}, "dom": {"http"}, "act": {"GET"}, "resource_keyword": {"/jobs"}, "page": {"3"}, "page_size": {"10"}}},
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
			if request.Operation != test.operation || request.Method != test.method || request.Path != test.path || !reflect.DeepEqual(request.Query, test.query) || request.IdempotencyKey != "" {
				t.Fatalf("request = %#v", request)
			}
			if got := marshalBody(t, request.Body); got != test.body {
				t.Fatalf("body = %s, want %s", got, test.body)
			}
		})
	}
}

func TestPolicyDocumentInputAndOutputAreDefensivelyCopied(t *testing.T) {
	document := json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	roles := []string{testRoleOpenID}
	transport := &captureTransport{response: policyResponse()}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	got, metadata, err := client.Create(context.Background(), UpsertInput{ApplicationOpenID: testApplicationOpenID, Name: "ops-read", DisplayName: "Ops Read", PolicyType: "custom", RoleOpenIDs: roles, Document: document, Publish: true})
	if err != nil {
		t.Fatal(err)
	}
	copy(document, `{"Changed":true}`)
	roles[0] = "op_rol_changed"
	if body := marshalBody(t, transport.requests[0].Body); body != `{"application_open_id":"`+testApplicationOpenID+`","name":"ops-read","display_name":"Ops Read","policy_type":"custom","role_open_ids":["`+testRoleOpenID+`"],"document":{"Version":"2012-10-17","Statement":[]},"publish":true}` {
		t.Fatalf("request aliases caller data: %s", body)
	}
	if metadata.TraceID != "trace-1" || got.AuthorizationRevision != 7 || got.AuthorizationHash != "sha256:auth" || got.CompiledHash != "sha256:compiled" || string(got.Body) != `{"Version":"2012-10-17","Statement":[]}` {
		t.Fatalf("document = %#v metadata = %#v", got, metadata)
	}
	got.Body[2] = 'X'
	got.BoundRoles[0].OpenID = "changed"
	second, _, err := client.Get(context.Background(), testPolicyOpenID, testApplicationOpenID)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Body) != `{"Version":"2012-10-17","Statement":[]}` || second.BoundRoles[0].OpenID != testRoleOpenID {
		t.Fatal("response state was aliased")
	}
}

func TestPolicyRejectsInvalidArgumentsAndNonObjectDocumentsBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	valid := UpsertInput{ApplicationOpenID: testApplicationOpenID, Name: "ops-read", DisplayName: "Ops Read", PolicyType: "custom", Document: json.RawMessage(`{}`)}
	checks := []func() error{
		func() error { _, _, err := client.List(context.Background(), ListOptions{}); return err },
		func() error { _, _, err := client.Get(context.Background(), "bad", testApplicationOpenID); return err },
		func() error {
			input := valid
			input.Name = " bad"
			_, _, err := client.Create(context.Background(), input)
			return err
		},
		func() error {
			input := valid
			input.Document = json.RawMessage(`[]`)
			_, _, err := client.Create(context.Background(), input)
			return err
		},
		func() error {
			input := valid
			input.Document = json.RawMessage(`{} trailing`)
			_, _, err := client.Update(context.Background(), testPolicyOpenID, input)
			return err
		},
		func() error {
			_, _, err := client.Preview(context.Background(), PreviewInput{ApplicationOpenID: testApplicationOpenID, Document: json.RawMessage(`null`)})
			return err
		},
		func() error {
			_, _, err := client.SetBindings(context.Background(), testPolicyOpenID, BindingsInput{ApplicationOpenID: testApplicationOpenID, RoleOpenIDs: []string{"bad"}})
			return err
		},
		func() error {
			_, _, err := client.ListCompiledRules(context.Background(), CompiledRuleOptions{ApplicationOpenID: testApplicationOpenID, Effect: "maybe"})
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

func TestPolicyConflictDataPreservesRevisionAndHash(t *testing.T) {
	errConflict := &management.Error{Kind: management.KindConflict, Data: json.RawMessage(`{"authorization_revision":9,"authorization_hash":"sha256:next","compiled_hash":"sha256:compiled-next","impact":{"affected_roles":["ops"],"affected_user_count":3,"losing_access_user_count":1,"compiled_rule_count":2}}`)}
	var conflict Conflict
	if !management.ErrorData(errConflict, &conflict) || conflict.AuthorizationRevision != 9 || conflict.AuthorizationHash != "sha256:next" || conflict.CompiledHash != "sha256:compiled-next" || conflict.Impact.AffectedUserCount != 3 || !reflect.DeepEqual(conflict.Impact.AffectedRoles, []string{"ops"}) {
		t.Fatalf("conflict = %#v", conflict)
	}
	conflict.Impact.AffectedRoles[0] = "changed"
	if string(errConflict.Data) == "" || string(errConflict.Data) == "changed" {
		t.Fatal("conflict aliases raw error data")
	}
}

func TestNewRejectsNilPolicyTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error = %v", err)
		}
	}
}

func policyResponse() map[string]any {
	return map[string]any{"id": "42", "open_id": testPolicyOpenID, "application_open_id": testApplicationOpenID, "name": "ops-read", "display_name": "Ops Read", "policy_type": "custom", "editable": true, "status": "published", "bound_roles": []any{map[string]any{"id": "8", "open_id": testRoleOpenID, "name": "ops", "display_name": "Ops"}}, "document": json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`), "compiled_hash": "sha256:compiled", "authorization_revision": 7, "authorization_hash": "sha256:auth", "created_at": "2026-08-04T01:02:03Z", "updated_at": "2026-08-04T02:03:04Z"}
}
func policyPageResponse() map[string]any {
	return map[string]any{"items": []any{policyResponse()}, "page": 2, "pageSize": 20, "total": 1}
}
func previewResponse() map[string]any {
	return map[string]any{"valid": true, "compiled_rules": []any{map[string]any{"subject": "ops", "dom": "http", "obj": "/jobs", "act": "GET", "eft": "allow"}}, "impact": map[string]any{"affected_roles": []string{"ops"}, "affected_user_count": 3, "losing_access_user_count": 0, "compiled_rule_count": 1}}
}
func compiledPageResponse() map[string]any {
	return map[string]any{"items": []any{map[string]any{"policy_document_open_id": testPolicyOpenID, "policy_document_name": "ops-read", "policy_document_display_name": "Ops Read", "policy_type": "custom", "role_open_id": testRoleOpenID, "role_name": "ops", "role_display_name": "Ops", "statement_index": 0, "subject": "ops", "dom": "http", "obj": "/jobs", "act": "GET", "eft": "allow", "checksum": "sha256:rule", "updated_at": "2026-08-04T02:03:04Z"}}, "page": 3, "pageSize": 10, "total": 1}
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
