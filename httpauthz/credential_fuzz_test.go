package httpauthz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzCredentialHeader(f *testing.F) {
	for _, seed := range []string{
		"Bearer token", "", "bearer token", "Bearer ", "Bearer one,two",
		"Bearer two words", "Bearer tok\nen", "Bearer tok\x00en", "Bearer tok\u00a0en",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header["Authorization"] = []string{value}
		token, present, err := credentialHeader(request)
		if !present {
			t.Fatal("explicit Authorization header reported missing")
		}
		if err != nil {
			if token != "" {
				t.Fatal("rejected header returned a token")
			}
			if err.Error() != "httpauthz.credential: unauthenticated" {
				t.Fatal("credential error was not the fixed sanitized classification")
			}
			return
		}
		if !strings.HasPrefix(value, "Bearer ") || token != strings.TrimPrefix(value, "Bearer ") ||
			token == "" || strings.Contains(token, ",") || !validAccessToken(token) {
			t.Fatal("accepted header was not canonical Bearer")
		}
	})
}
