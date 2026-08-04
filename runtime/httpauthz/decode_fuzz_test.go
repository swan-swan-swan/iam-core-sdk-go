package httpauthz

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzDecodeDecision(f *testing.F) {
	for _, seed := range []string{
		validDecisionResponse,
		`{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":false,"reason_code":"default_deny"}}`,
		`{"code":0,"code":1}`,
		`{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":"true","reason_code":"policy_allow"}}`,
		validDecisionResponse + `{}`,
		`not-json`,
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		decision, err := decodeDecision(body)
		if err != nil {
			return
		}
		if len(body) > 1<<20 {
			t.Fatalf("accepted oversized body: %d", len(body))
		}
		for name, value := range map[string]string{
			"decision ID": decision.ID,
			"reason code": decision.ReasonCode,
		} {
			if value == "" || value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsControl) {
				t.Fatalf("accepted invalid %s %q", name, value)
			}
		}
		for name, value := range map[string]string{"request ID": decision.RequestID, "trace ID": decision.TraceID} {
			if value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsControl) {
				t.Fatalf("accepted invalid %s %q", name, value)
			}
		}
	})
}
