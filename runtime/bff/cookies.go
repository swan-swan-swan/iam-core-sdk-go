package bff

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func validateCookieTemplate(configured http.Cookie, production bool) (http.Cookie, error) {
	if configured.Name == "" || configured.Value != "" || configured.Path != "/" || configured.Domain != "" ||
		!configured.HttpOnly || configured.SameSite != http.SameSiteLaxMode || configured.MaxAge != 0 ||
		!configured.Expires.IsZero() || configured.Raw != "" || configured.RawExpires != "" ||
		len(configured.Unparsed) != 0 || configured.Partitioned || configured.Quoted {
		return http.Cookie{}, errors.New("invalid cookie configuration")
	}
	if production && (!configured.Secure || !strings.HasPrefix(configured.Name, "__Host-")) {
		return http.Cookie{}, errors.New("insecure production cookie")
	}
	if strings.HasPrefix(configured.Name, "__Host-") && !configured.Secure {
		return http.Cookie{}, errors.New("invalid __Host cookie")
	}
	probe := configured
	probe.Value = "opaque"
	if probe.Valid() != nil || probe.String() == "" {
		return http.Cookie{}, errors.New("invalid cookie configuration")
	}
	return configured, nil
}

func (c *Client) setCookie(w http.ResponseWriter, template http.Cookie, value string) error {
	if w == nil || !validCookieValue(value) {
		return errors.New("invalid cookie")
	}
	cookie := template
	cookie.Value = value
	if cookie.Valid() != nil || cookie.String() == "" {
		return errors.New("invalid cookie")
	}
	http.SetCookie(w, &cookie)
	return nil
}

func (c *Client) clearCookie(w http.ResponseWriter, template http.Cookie) {
	if w == nil {
		return
	}
	cookie := template
	cookie.Value = ""
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0).UTC()
	http.SetCookie(w, &cookie)
}

func oneCookieValue(request *http.Request, name string) (string, error) {
	if request == nil || name == "" {
		return "", errors.New("invalid cookie")
	}
	cookies := request.CookiesNamed(name)
	if len(cookies) != 1 || !validCookieValue(cookies[0].Value) {
		return "", errors.New("invalid cookie")
	}
	return cookies[0].Value, nil
}

func validCookieValue(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validateRedirectURL(value string) (*url.URL, error) {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return nil, errors.New("invalid redirect URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != value {
		return nil, errors.New("invalid redirect URL")
	}
	return parsed, nil
}

func isLoopbackHTTPURL(parsed *url.URL) bool {
	return parsed != nil && parsed.Scheme == "http" && isLoopbackHostname(parsed.Hostname())
}

func isLoopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) validReturnTo(value string) bool {
	if _, allowed := c.allowedReturnTo[value]; allowed {
		return validateAllowedAbsoluteReturnTo(value) == nil
	}
	return validateRelativeReturnTo(value) == nil
}

func validateRelativeReturnTo(value string) error {
	if err := validateRelativeReturnToLayer(value, true); err != nil {
		return errors.New("invalid return URL")
	}
	current := value
	for range 8 {
		if err := validateRelativeReturnToLayer(current, false); err != nil {
			return errors.New("invalid return URL")
		}
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return errors.New("invalid return URL")
		}
		if decoded == current {
			return nil
		}
		current = decoded
	}
	return errors.New("invalid return URL")
}

func validateRelativeReturnToLayer(value string, canonical bool) error {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return errors.New("invalid return URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Opaque != "" || parsed.User != nil || parsed.Host != "" ||
		parsed.Scheme != "" || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") ||
		strings.HasPrefix(parsed.Path, "//") || (canonical && parsed.String() != value) {
		return errors.New("invalid return URL")
	}
	return nil
}

func validateAllowedAbsoluteReturnTo(value string) error {
	if err := validateAbsoluteReturnToLayer(value, true); err != nil {
		return err
	}
	current := value
	for range 8 {
		if err := validateAbsoluteReturnToLayer(current, false); err != nil {
			return err
		}
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return errors.New("invalid allowed return URL")
		}
		if decoded == current {
			return nil
		}
		current = decoded
	}
	return errors.New("invalid allowed return URL")
}

func validateAbsoluteReturnToLayer(value string, canonical bool) error {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return errors.New("invalid allowed return URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || (canonical && parsed.String() != value) {
		return errors.New("invalid allowed return URL")
	}
	if parsed.Scheme == "http" && !isLoopbackHostname(parsed.Hostname()) {
		return errors.New("invalid allowed return URL")
	}
	return nil
}

func containsUnsafeURLCharacter(value string) bool {
	if !utf8.ValidString(value) || strings.ContainsRune(value, '\\') {
		return true
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
