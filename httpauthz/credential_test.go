package httpauthz

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestCredentialHeaderDistinguishesMissingFromValidBearer(t *testing.T) {
	missing := httptest.NewRequest(http.MethodGet, "/", nil)
	if token, present, err := credentialHeader(missing); err != nil || present || token != "" {
		t.Fatalf("missing credentialHeader() = redacted/%v/%v", present, err)
	}

	valid := httptest.NewRequest(http.MethodGet, "/", nil)
	valid.Header.Set("Authorization", "Bearer opaque-token")
	if token, present, err := credentialHeader(valid); err != nil || !present || token != "opaque-token" {
		t.Fatalf("valid credentialHeader() = redacted/%v/%v", present, err)
	}
}

func TestCredentialHeaderAcceptsRFC6750B64TokenGrammar(t *testing.T) {
	for _, token := range []string{
		"a", "AZaz09-._~+/", "opaque-token", "header.payload.signature", "token=", "token==", "token=====",
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		got, present, err := credentialHeader(request)
		if err != nil || !present || got != token {
			t.Fatalf("credentialHeader() rejected valid RFC 6750 token: present/error=%v/%v", present, err)
		}
	}
}

func TestCredentialHeaderRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name   string
		values map[string][]string
	}{
		{name: "present empty slice", values: map[string][]string{"Authorization": {}}},
		{name: "empty", values: map[string][]string{"Authorization": {""}}},
		{name: "prefix only", values: map[string][]string{"Authorization": {"Bearer "}}},
		{name: "lowercase scheme", values: map[string][]string{"Authorization": {"bearer token"}}},
		{name: "uppercase scheme", values: map[string][]string{"Authorization": {"BEARER token"}}},
		{name: "missing space", values: map[string][]string{"Authorization": {"Bearertoken"}}},
		{name: "tab separator", values: map[string][]string{"Authorization": {"Bearer\ttoken"}}},
		{name: "two spaces", values: map[string][]string{"Authorization": {"Bearer  token"}}},
		{name: "leading whitespace", values: map[string][]string{"Authorization": {" Bearer token"}}},
		{name: "trailing whitespace", values: map[string][]string{"Authorization": {"Bearer token "}}},
		{name: "whitespace in token", values: map[string][]string{"Authorization": {"Bearer tok en"}}},
		{name: "unicode whitespace", values: map[string][]string{"Authorization": {"Bearer tok\u00a0en"}}},
		{name: "comma joined", values: map[string][]string{"Authorization": {"Bearer one,Bearer two"}}},
		{name: "quote in token", values: map[string][]string{"Authorization": {`Bearer tok"en`}}},
		{name: "backslash in token", values: map[string][]string{"Authorization": {`Bearer tok\en`}}},
		{name: "semicolon in token", values: map[string][]string{"Authorization": {"Bearer tok;en"}}},
		{name: "colon in token", values: map[string][]string{"Authorization": {"Bearer tok:en"}}},
		{name: "leading equals", values: map[string][]string{"Authorization": {"Bearer =token"}}},
		{name: "equals only", values: map[string][]string{"Authorization": {"Bearer ==="}}},
		{name: "internal equals", values: map[string][]string{"Authorization": {"Bearer tok=en"}}},
		{name: "body after padding", values: map[string][]string{"Authorization": {"Bearer token==suffix"}}},
		{name: "non ASCII", values: map[string][]string{"Authorization": {"Bearer tokéen"}}},
		{name: "emoji", values: map[string][]string{"Authorization": {"Bearer tok😀en"}}},
		{name: "zero width format", values: map[string][]string{"Authorization": {"Bearer tok\u200ben"}}},
		{name: "bidi format", values: map[string][]string{"Authorization": {"Bearer tok\u202een"}}},
		{name: "multiple", values: map[string][]string{"Authorization": {"Bearer one", "Bearer two"}}},
		{name: "multiple casing", values: map[string][]string{"Authorization": {"Bearer one"}, "authorization": {"Bearer two"}}},
		{name: "newline", values: map[string][]string{"Authorization": {"Bearer tok\nen"}}},
		{name: "carriage return", values: map[string][]string{"Authorization": {"Bearer tok\ren"}}},
		{name: "nul", values: map[string][]string{"Authorization": {"Bearer tok\x00en"}}},
		{name: "invalid utf8", values: map[string][]string{"Authorization": {"Bearer tok\xffen"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for key, values := range test.values {
				request.Header[key] = append([]string(nil), values...)
			}
			token, present, err := credentialHeader(request)
			if err == nil || !present || token != "" {
				t.Fatalf("credentialHeader() = redacted/%v/%v", present, err)
			}
			var typed *core.Error
			if !errors.As(err, &typed) || typed == nil || typed.Kind != core.KindUnauthenticated {
				t.Fatalf("credentialHeader() error kind = %T", err)
			}
			for _, values := range test.values {
				for _, value := range values {
					if value != "" && strings.Contains(err.Error(), value) {
						t.Fatal("credential error disclosed the header value")
					}
				}
			}
		})
	}
}

func TestCredentialHeaderTreatsNoncanonicalMapKeyCaseInsensitively(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header["authorization"] = []string{"Bearer opaque-token"}
	token, present, err := credentialHeader(request)
	if err != nil || !present || token != "opaque-token" {
		t.Fatalf("credentialHeader() = redacted/%v/%v", present, err)
	}
}

func TestCredentialHeaderRejectsNilRequest(t *testing.T) {
	if token, present, err := credentialHeader(nil); err == nil || present || token != "" {
		t.Fatalf("credentialHeader(nil) = redacted/%v/%v", present, err)
	}
}
