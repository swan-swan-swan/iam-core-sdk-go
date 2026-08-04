package admission

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
	testRuleOpenID        = "op_lpr_0123456789abcdefghj"
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

func TestClientUsesExactAdmissionContractsForBothScopes(t *testing.T) {
	mutation := Mutation{SubjectType: "role", SubjectOpenID: testRoleOpenID, Effect: "deny", ExpectedRevision: 7}
	listResponse := admissionListResponse()
	changeResponse := admissionChangeResponse()
	tests := []struct {
		name      string
		response  any
		invoke    func(*Client) error
		operation string
		method    string
		path      string
		query     url.Values
		body      string
	}{
		{name: "application list", response: listResponse, invoke: func(c *Client) error {
			_, _, err := c.List(context.Background(), ApplicationScope(testApplicationOpenID), ListOptions{Page: 2, PageSize: 50, Sort: "updated_at", Order: "desc"})
			return err
		}, operation: "management.admission.list", method: http.MethodGet, path: "/api/v1/applications/" + testApplicationOpenID + "/login-admission-rules", query: url.Values{"page": {"2"}, "page_size": {"50"}, "sort": {"updated_at"}, "order": {"desc"}}},
		{name: "application create", response: changeResponse, invoke: func(c *Client) error {
			_, _, err := c.Create(context.Background(), ApplicationScope(testApplicationOpenID), mutation)
			return err
		}, operation: "management.admission.create", method: http.MethodPost, path: "/api/v1/applications/" + testApplicationOpenID + "/login-admission-rules", body: `{"subject_type":"role","subject_open_id":"` + testRoleOpenID + `","effect":"deny","login_policy_revision":7}`},
		{name: "application update", response: changeResponse, invoke: func(c *Client) error {
			_, _, err := c.Update(context.Background(), ApplicationScope(testApplicationOpenID), testRuleOpenID, mutation)
			return err
		}, operation: "management.admission.update", method: http.MethodPut, path: "/api/v1/applications/" + testApplicationOpenID + "/login-admission-rules/" + testRuleOpenID, body: `{"subject_type":"role","subject_open_id":"` + testRoleOpenID + `","effect":"deny","login_policy_revision":7}`},
		{name: "application soft delete", response: changeResponse, invoke: func(c *Client) error {
			_, _, err := c.SoftDelete(context.Background(), ApplicationScope(testApplicationOpenID), testRuleOpenID, 7)
			return err
		}, operation: "management.admission.soft_delete", method: http.MethodDelete, path: "/api/v1/applications/" + testApplicationOpenID + "/login-admission-rules/" + testRuleOpenID, query: url.Values{"login_policy_revision": {"7"}}},
		{name: "client list", response: listResponse, invoke: func(c *Client) error {
			_, _, err := c.List(context.Background(), ClientScope(testApplicationOpenID, testClientID), ListOptions{})
			return err
		}, operation: "management.admission.list", method: http.MethodGet, path: "/api/v1/applications/" + testApplicationOpenID + "/oidc-clients/" + testClientID + "/login-admission-rules"},
		{name: "client create", response: changeResponse, invoke: func(c *Client) error {
			_, _, err := c.Create(context.Background(), ClientScope(testApplicationOpenID, testClientID), mutation)
			return err
		}, operation: "management.admission.create", method: http.MethodPost, path: "/api/v1/applications/" + testApplicationOpenID + "/oidc-clients/" + testClientID + "/login-admission-rules", body: `{"subject_type":"role","subject_open_id":"` + testRoleOpenID + `","effect":"deny","login_policy_revision":7}`},
		{name: "client update", response: changeResponse, invoke: func(c *Client) error {
			_, _, err := c.Update(context.Background(), ClientScope(testApplicationOpenID, testClientID), testRuleOpenID, mutation)
			return err
		}, operation: "management.admission.update", method: http.MethodPut, path: "/api/v1/applications/" + testApplicationOpenID + "/oidc-clients/" + testClientID + "/login-admission-rules/" + testRuleOpenID, body: `{"subject_type":"role","subject_open_id":"` + testRoleOpenID + `","effect":"deny","login_policy_revision":7}`},
		{name: "client soft delete", response: changeResponse, invoke: func(c *Client) error {
			_, _, err := c.SoftDelete(context.Background(), ClientScope(testApplicationOpenID, testClientID), testRuleOpenID, 7)
			return err
		}, operation: "management.admission.soft_delete", method: http.MethodDelete, path: "/api/v1/applications/" + testApplicationOpenID + "/oidc-clients/" + testClientID + "/login-admission-rules/" + testRuleOpenID, query: url.Values{"login_policy_revision": {"7"}}},
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

func TestClientRejectsAmbiguousScopesAndInvalidArgumentsBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	validMutation := Mutation{SubjectType: "role", SubjectOpenID: testRoleOpenID, Effect: "allow", ExpectedRevision: 0}
	checks := []func() error{
		func() error {
			_, _, err := client.List(context.Background(), ClientScope(testApplicationOpenID, ""), ListOptions{})
			return err
		},
		func() error {
			_, _, err := client.List(context.Background(), Scope{ApplicationOpenID: testApplicationOpenID}, ListOptions{})
			return err
		},
		func() error {
			_, _, err := client.List(context.Background(), ApplicationScope("op_app_0123456789abcdefghi!"), ListOptions{})
			return err
		},
		func() error {
			_, _, err := client.List(context.Background(), ApplicationScope(testApplicationOpenID), ListOptions{Page: -1})
			return err
		},
		func() error {
			_, _, err := client.List(context.Background(), ApplicationScope(testApplicationOpenID), ListOptions{PageSize: 101})
			return err
		},
		func() error {
			_, _, err := client.List(context.Background(), ApplicationScope(testApplicationOpenID), ListOptions{Sort: "name"})
			return err
		},
		func() error {
			_, _, err := client.List(context.Background(), ApplicationScope(testApplicationOpenID), ListOptions{Order: "sideways"})
			return err
		},
		func() error {
			_, _, err := client.Create(context.Background(), ApplicationScope(testApplicationOpenID), Mutation{SubjectType: "team", SubjectOpenID: testRoleOpenID, Effect: "allow"})
			return err
		},
		func() error {
			_, _, err := client.Create(context.Background(), ApplicationScope(testApplicationOpenID), Mutation{SubjectType: "user", SubjectOpenID: testRoleOpenID, Effect: "allow"})
			return err
		},
		func() error {
			_, _, err := client.Create(context.Background(), ApplicationScope(testApplicationOpenID), Mutation{SubjectType: "role", SubjectOpenID: testRoleOpenID, Effect: "audit"})
			return err
		},
		func() error {
			_, _, err := client.Update(context.Background(), ApplicationScope(testApplicationOpenID), "bad", validMutation)
			return err
		},
		func() error {
			_, _, err := client.SoftDelete(context.Background(), ApplicationScope(testApplicationOpenID), testRuleOpenID, 0)
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

func TestAdmissionResponsesAreTypedAndDefensivelyCopied(t *testing.T) {
	wire := admissionListWire{Items: []ruleWire{{OpenID: testRuleOpenID, ApplicationOpenID: testApplicationOpenID, Scope: "application", SubjectType: "role", SubjectOpenID: testRoleOpenID, Effect: "allow"}}, Page: 1, PageSize: 20, Total: 1, Revision: 8, Hash: "sha256:current"}
	result := wire.result()
	wire.Items[0].Effect = "deny"
	wire.Items = append(wire.Items, ruleWire{})
	if len(result.Items) != 1 || result.Items[0].Effect != "allow" || result.Revision != 8 || result.Hash != "sha256:current" {
		t.Fatalf("result aliases wire data: %#v", result)
	}

	err := &management.Error{Kind: management.KindConflict, Data: json.RawMessage(`{"login_policy_revision":9,"login_policy_hash":"sha256:next","impact":{"scope":"client","application_open_id":"` + testApplicationOpenID + `","client_id":"` + testClientID + `","operation":"update"}}`)}
	var conflict Conflict
	if !management.ErrorData(err, &conflict) || conflict.Revision != 9 || conflict.Hash != "sha256:next" || conflict.Impact.ClientID != testClientID || conflict.Impact.Operation != "update" {
		t.Fatalf("conflict = %#v", conflict)
	}
}

func TestNewRejectsNilAdmissionTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error = %v", err)
		}
	}
}

func admissionListResponse() map[string]any {
	return map[string]any{
		"items": []any{admissionRuleResponse()}, "page": 1, "page_size": 20, "total": 1,
		"login_policy_revision": 8, "login_policy_hash": "sha256:current",
	}
}

func admissionChangeResponse() map[string]any {
	return map[string]any{
		"rule": admissionRuleResponse(), "login_policy_revision": 8, "login_policy_hash": "sha256:current",
	}
}

func admissionRuleResponse() map[string]any {
	return map[string]any{
		"open_id": testRuleOpenID, "application_open_id": testApplicationOpenID, "client_id": testClientID,
		"scope": "client", "subject_type": "role", "subject_open_id": testRoleOpenID, "effect": "deny",
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
