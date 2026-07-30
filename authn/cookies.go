package authn

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

func normalizeCookie(configured http.Cookie, defaultName string) (http.Cookie, error) {
	if configured.Name == "" {
		if cookieHasConfiguration(configured) {
			return http.Cookie{}, errors.New("cookie name is empty")
		}
		return http.Cookie{
			Name:     defaultName,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}, nil
	}
	if configured.Value != "" || configured.Path != "/" || configured.Domain != "" ||
		!configured.HttpOnly || configured.SameSite != http.SameSiteLaxMode ||
		configured.MaxAge != 0 || !configured.Expires.IsZero() || configured.Raw != "" ||
		configured.RawExpires != "" || len(configured.Unparsed) != 0 {
		return http.Cookie{}, errors.New("unsafe cookie configuration")
	}
	probe := configured
	probe.Value = "valid"
	if probe.Valid() != nil || probe.String() == "" {
		return http.Cookie{}, errors.New("invalid cookie configuration")
	}
	if strings.HasPrefix(configured.Name, "__Host-") &&
		(!configured.Secure || configured.Path != "/" || configured.Domain != "") {
		return http.Cookie{}, errors.New("invalid __Host cookie")
	}
	if configured.Secure && !strings.HasPrefix(configured.Name, "__Host-") {
		return http.Cookie{}, errors.New("production cookie must use __Host prefix")
	}
	return configured, nil
}

func cookieHasConfiguration(cookie http.Cookie) bool {
	return cookie.Value != "" || cookie.Path != "" || cookie.Domain != "" ||
		cookie.Expires != (time.Time{}) || cookie.RawExpires != "" || cookie.MaxAge != 0 ||
		cookie.Secure || cookie.HttpOnly || cookie.SameSite != 0 || cookie.Raw != "" ||
		len(cookie.Unparsed) != 0 || cookie.Partitioned
}

func (s *Service) setCookie(w http.ResponseWriter, template http.Cookie, value string) error {
	if !validCookieValue(value) {
		return errors.New("invalid cookie value")
	}
	cookie := template
	cookie.Value = value
	if cookie.Valid() != nil || cookie.String() == "" {
		return errors.New("invalid cookie")
	}
	http.SetCookie(w, &cookie)
	return nil
}

func (s *Service) clearCookie(w http.ResponseWriter, template http.Cookie) {
	cookie := template
	cookie.Value = ""
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0).UTC()
	http.SetCookie(w, &cookie)
}

func validCookieValue(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func (s *Service) ensureRequestCookieSecurity(request *http.Request) error {
	if s.sessionCookie.Secure && s.flowCookie.Secure {
		return nil
	}
	if !s.allowInsecureLocalCookie || request == nil || !isLocalHost(request.Host) {
		return errors.New("insecure cookie request host")
	}
	return nil
}

func isLocalURL(parsed *url.URL) bool {
	return parsed != nil && parsed.Scheme == "http" && isLocalHostname(parsed.Hostname())
}

func isLocalHost(hostport string) bool {
	if hostport == "" || strings.ContainsAny(hostport, `/\@`) {
		return false
	}
	parsed, err := url.Parse("//" + hostport)
	return err == nil && parsed.User == nil && parsed.Host == hostport &&
		parsed.Hostname() != "" && isLocalHostname(parsed.Hostname())
}

func isLocalHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
