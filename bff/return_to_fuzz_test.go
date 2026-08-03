package bff

import (
	"net/url"
	"strings"
	"testing"
	"unicode"
)

func FuzzReturnTo(f *testing.F) {
	for _, seed := range []string{
		"/", "/profile", "/profile?tab=security", "//evil.example", "https://evil.example/",
		`\\evil.example\path`, "/%2f%2fevil.example", "/%252f%252fevil.example", "", " /",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		err := validateRelativeReturnTo(value)
		if err != nil {
			return
		}
		current := value
		for layer := range 8 {
			assertSafeReturnToLayer(t, current, layer)
			decoded, decodeErr := url.PathUnescape(current)
			if decodeErr != nil {
				t.Fatalf("accepted return target has malformed encoding at layer %d", layer)
			}
			if decoded == current {
				return
			}
			current = decoded
		}
		t.Fatal("accepted return target exceeded the maximum decoding depth")
	})
}

func assertSafeReturnToLayer(t *testing.T, value string, layer int) {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Scheme != "" || parsed.Path == "" ||
		!strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.ContainsRune(value, '\\') ||
		strings.TrimSpace(value) != value {
		t.Fatalf("unsafe relative return accepted at decoded layer %d", layer)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			t.Fatalf("control character accepted at decoded layer %d", layer)
		}
	}
}
