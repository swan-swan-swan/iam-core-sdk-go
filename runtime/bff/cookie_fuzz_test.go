package bff

import (
	"net/http"
	"testing"
)

func FuzzCookie(f *testing.F) {
	for _, seed := range []string{"opaque_ID-123", "", "space value", "semi;colon", "line\nbreak", "../path", "é"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		valid := validCookieValue(value)
		cookie := http.Cookie{Name: "flow", Value: value, Path: "/", HttpOnly: true}
		if valid && (cookie.Valid() != nil || cookie.String() == "") {
			t.Fatalf("accepted value cannot be serialized safely: %q", value)
		}
		if valid {
			for _, character := range value {
				if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
					(character >= '0' && character <= '9') || character == '-' || character == '_') {
					t.Fatalf("non-opaque cookie value accepted: %q", value)
				}
			}
		}
	})
}
