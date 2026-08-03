package httpauthz

import (
	"strings"
	"testing"
)

func TestDecodeDecisionAcceptsExactEnvelopeAndAdditiveFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Decision
	}{
		{
			name: "allow",
			body: validDecisionResponse,
			want: Decision{ID: "dec-1", Allowed: true, ReasonCode: "policy_allow", RequestID: "req-1", TraceID: "trace-1"},
		},
		{
			name: "deny",
			body: `{"code":0,"message":"success","data":{"decision_id":"dec-2","allowed":false,"reason_code":"default_deny"},"request_id":"req-2","trace_id":"trace-2"}`,
			want: Decision{ID: "dec-2", Allowed: false, ReasonCode: "default_deny", RequestID: "req-2", TraceID: "trace-2"},
		},
		{
			name: "additive unknown fields",
			body: `{"extension":{"version":1},"code":0,"message":"success","data":{"new_flag":[1,2,3],"decision_id":"dec-3","allowed":true,"reason_code":"policy_allow"},"request_id":"req-3","trace_id":"trace-3","server_time":"now"}`,
			want: Decision{ID: "dec-3", Allowed: true, ReasonCode: "policy_allow", RequestID: "req-3", TraceID: "trace-3"},
		},
		{
			name: "optional correlation IDs omitted",
			body: ` { "code" : 0 , "message" : "success" , "data" : { "decision_id" : "dec-4", "allowed" : true, "reason_code" : "policy_allow" } } `,
			want: Decision{ID: "dec-4", Allowed: true, ReasonCode: "policy_allow"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeDecision([]byte(test.body))
			if err != nil {
				t.Fatalf("decodeDecision() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeDecision() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDecodeDecisionRejectsInvalidEnvelope(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty", body: ``},
		{name: "non JSON", body: `not-json`},
		{name: "null root", body: `null`},
		{name: "array root", body: `[]`},
		{name: "bare response", body: `{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}`},
		{name: "missing code", body: `{"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "null code", body: `{"code":null,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "string code", body: `{"code":"0","message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "fraction code", body: `{"code":0.0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "nonzero code", body: `{"code":7,"message":"failure","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "missing message", body: `{"code":0,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "null message", body: `{"code":0,"message":null,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "wrong message type", body: `{"code":0,"message":true,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "empty message", body: `{"code":0,"message":"","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "blank message", body: `{"code":0,"message":" \t","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "padded message", body: `{"code":0,"message":" success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "control message", body: `{"code":0,"message":"succ\u0000ess","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "missing data", body: `{"code":0,"message":"success"}`},
		{name: "null data", body: `{"code":0,"message":"success","data":null}`},
		{name: "array data", body: `{"code":0,"message":"success","data":[]}`},
		{name: "string data", body: `{"code":0,"message":"success","data":"decision"}`},
		{name: "missing decision ID", body: `{"code":0,"message":"success","data":{"allowed":true,"reason_code":"policy_allow"}}`},
		{name: "null decision ID", body: `{"code":0,"message":"success","data":{"decision_id":null,"allowed":true,"reason_code":"policy_allow"}}`},
		{name: "wrong decision ID type", body: `{"code":0,"message":"success","data":{"decision_id":1,"allowed":true,"reason_code":"policy_allow"}}`},
		{name: "empty decision ID", body: `{"code":0,"message":"success","data":{"decision_id":"","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "padded decision ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1 ","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "control decision ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-\u00001","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "missing allowed", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","reason_code":"policy_allow"}}`},
		{name: "null allowed", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":null,"reason_code":"policy_allow"}}`},
		{name: "string allowed", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":"true","reason_code":"policy_allow"}}`},
		{name: "number allowed", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":1,"reason_code":"policy_allow"}}`},
		{name: "missing reason code", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true}}`},
		{name: "null reason code", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":null}}`},
		{name: "wrong reason code type", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":1}}`},
		{name: "empty reason code", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":""}}`},
		{name: "padded reason code", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":" policy_allow"}}`},
		{name: "control reason code", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy\u007fallow"}}`},
		{name: "null request ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"request_id":null}`},
		{name: "wrong request ID type", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"request_id":1}`},
		{name: "padded request ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"request_id":" req-1"}`},
		{name: "control request ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"request_id":"req-\u00011"}`},
		{name: "null trace ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"trace_id":null}`},
		{name: "wrong trace ID type", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"trace_id":[]}`},
		{name: "padded trace ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"trace_id":"trace-1 "}`},
		{name: "control trace ID", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"trace_id":"trace-\u000a1"}`},
		{name: "trailing object", body: validDecisionResponse + `{}`},
		{name: "trailing primitive", body: validDecisionResponse + ` true`},
		{name: "invalid UTF-8", body: validDecisionResponse[:len(validDecisionResponse)-1] + "\xff}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if decision, err := decodeDecision([]byte(test.body)); err == nil {
				t.Fatalf("decodeDecision() = %#v, nil error", decision)
			}
		})
	}
}

func TestDecodeDecisionRejectsDuplicateKeysAtEnvelopeAndData(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "root required", body: `{"code":0,"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "root escaped required", body: `{"code":0,"\u0063ode":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "root unknown", body: `{"code":0,"message":"success","extension":1,"extension":2,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "data required", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"allowed":false,"reason_code":"policy_allow"}}`},
		{name: "data escaped required", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"\u0061llowed":false,"reason_code":"policy_allow"}}`},
		{name: "data unknown", body: `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow","extension":1,"extension":2}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if decision, err := decodeDecision([]byte(test.body)); err == nil {
				t.Fatalf("decodeDecision() = %#v, nil error", decision)
			}
		})
	}
}

func TestDecodeDecisionRejectsCaseConflictsWithRequiredFields(t *testing.T) {
	tests := []string{
		`{"Code":0,"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`,
		`{"code":0,"Message":"ignored","message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`,
		`{"code":0,"message":"success","data":{"Decision_ID":"ignored","decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`,
	}
	for _, body := range tests {
		if decision, err := decodeDecision([]byte(body)); err == nil {
			t.Fatalf("decodeDecision(%q) = %#v, nil error", body, decision)
		}
	}
}

func TestDecodeDecisionRejectsOversizedBody(t *testing.T) {
	body := []byte(strings.Repeat(" ", (1<<20)+1))
	if decision, err := decodeDecision(body); err == nil {
		t.Fatalf("decodeDecision() = %#v, nil error", decision)
	}
}
