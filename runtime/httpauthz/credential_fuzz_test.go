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
		`Bearer tok"en`, `Bearer tok\en`, "Bearer =token", "Bearer tok=en", "Bearer token==suffix",
		"Bearer tokéen", "Bearer tok😀en", "Bearer tok\u200ben", "Bearer tok\u202een", "Bearer AZaz09-._~+/==",
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
		if !strings.HasPrefix(value, "Bearer ") || token != strings.TrimPrefix(value, "Bearer ") || !validRFC6750TokenForTest(token) {
			t.Fatal("accepted header was not canonical Bearer")
		}
	})
}

func validRFC6750TokenForTest(token string) bool {
	body := false
	padding := false
	for index := 0; index < len(token); index++ {
		character := token[index]
		if character == '=' {
			if !body {
				return false
			}
			padding = true
			continue
		}
		if padding || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._~+/", rune(character))) {
			return false
		}
		body = true
	}
	return body
}
