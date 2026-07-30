package authn

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzReturnTo(f *testing.F) {
	f.Add("/")
	f.Add("/assets?page=1")
	f.Add("https://evil.example")
	f.Add("//evil.example")
	f.Add(`/\evil`)
	f.Add("/assets\r\nX-Injected: true")
	f.Add("/assets\x00private")

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1<<20 {
			t.Skip()
		}
		if err := validateRelativeReturnTo(value); err != nil {
			return
		}
		parsed, err := url.Parse(value)
		if err != nil {
			t.Fatalf("accepted return_to does not parse: %v", err)
		}
		if parsed.Scheme != "" || parsed.Host != "" {
			t.Fatalf("accepted return_to has scheme or host: %q", value)
		}
		if !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
			t.Fatalf("accepted return_to does not begin with exactly one slash: %q", value)
		}
	})
}
