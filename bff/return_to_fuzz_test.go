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
		parsed, parseErr := url.Parse(value)
		if parseErr != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Scheme != "" || parsed.Path == "" ||
			!strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.ContainsRune(value, '\\') ||
			strings.TrimSpace(value) != value {
			t.Fatalf("unsafe relative return accepted: %q (%#v)", value, parsed)
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				t.Fatalf("control character accepted in %q", value)
			}
		}
	})
}
