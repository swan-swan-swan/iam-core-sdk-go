package client

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestErrorIsMatchesKindSentinel(t *testing.T) {
	err := &Error{Kind: KindRateLimited, Operation: "management.applications.list", StatusCode: 429}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("errors.Is() did not match ErrRateLimited")
	}
	if errors.Is(err, ErrForbidden) {
		t.Fatal("errors.Is() matched an unrelated kind sentinel")
	}
}

func TestErrorStringReportsSafeMetadataWithoutSensitiveContent(t *testing.T) {
	const (
		token  = "access-token-should-not-appear"
		query  = "client_secret=should-not-appear"
		body   = "raw-response-should-not-appear"
		secret = "Secret-should-not-appear"
	)
	err := &Error{
		Kind:       KindForbidden,
		Operation:  "management.oidcclients.rotate_credential",
		StatusCode: 403,
		Data:       json.RawMessage(`{"authorization":"Bearer ` + token + `","query":"` + query + `","body":"` + body + `","secret":"` + secret + `"}`),
	}

	got := err.Error()
	for _, want := range []string{"management.oidcclients.rotate_credential", "forbidden", "403"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	}
	for _, forbidden := range []string{token, query, body, secret, "authorization"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(forbidden)) {
			t.Errorf("Error() leaked %q: %q", forbidden, got)
		}
	}
}

func TestErrorDataDecodesStructuredData(t *testing.T) {
	type data struct {
		Reason string `json:"reason"`
	}
	err := &Error{Data: json.RawMessage(`{"reason":"request is invalid"}`)}
	var got data
	if !ErrorData(err, &got) {
		t.Fatal("ErrorData() = false, want true")
	}
	if got.Reason != "request is invalid" {
		t.Errorf("decoded reason = %q, want %q", got.Reason, "request is invalid")
	}
	if ErrorData(errors.New("unrelated"), &got) {
		t.Fatal("ErrorData() = true for an unrelated error")
	}
}

func TestCloneErrorDataCopiesAndCapsResponseData(t *testing.T) {
	const responseBodyLimit = 1 << 20
	raw := json.RawMessage(`{"reason":"` + strings.Repeat("x", responseBodyLimit) + `"}`)

	got := cloneErrorData(raw)
	if len(got) != responseBodyLimit {
		t.Fatalf("copied data length = %d, want %d", len(got), responseBodyLimit)
	}
	raw[0] = '['
	if got[0] != '{' {
		t.Fatal("copied data aliases the original response data")
	}
}
