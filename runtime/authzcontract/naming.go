// Package authzcontract 提供业务授权名称与逻辑路由的统一严格契约。
package authzcontract

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	// ErrInvalidAction 表示业务 Action 不符合命名契约，不包含输入值。
	ErrInvalidAction = errors.New("invalid authorization action")
	// ErrInvalidRouteName 表示逻辑路由名称不符合命名契约，不包含输入值。
	ErrInvalidRouteName = errors.New("invalid authorization route name")
	// ErrInvalidRouteTemplate 表示路由模板不是合法的绝对路径，不包含输入值。
	ErrInvalidRouteTemplate = errors.New("invalid authorization route template")
	serverPattern           = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	internalDomainPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	businessDomainPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	routePattern            = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*){2,}$`)
)

// Action 表示由授权命名空间、业务域和固定动词组成的业务能力。
type Action struct {
	// Server 是授权命名空间。
	Server string
	// Domain 是稳定的业务能力域。
	Domain string
	// Verb 是契约词表内的业务动作。
	Verb string
}

// String 返回未经大小写或空白归一化的三段业务 Action。
func (a Action) String() string { return a.Server + ":" + a.Domain + ":" + a.Verb }

// ParseAction 严格解析最多 64 字符的三段业务 Action。
func ParseAction(raw string) (Action, error) {
	parts := strings.Split(raw, ":")
	if len(raw) > 64 || len(parts) != 3 || !serverPattern.MatchString(parts[0]) || !allowedVerb(parts[2]) {
		return Action{}, ErrInvalidAction
	}
	pattern := businessDomainPattern
	if parts[0] == "iam" {
		pattern = internalDomainPattern
	} else if strings.Contains(parts[1], "00") || strings.Contains(parts[1], "01") {
		return Action{}, ErrInvalidAction
	}
	if !pattern.MatchString(parts[1]) {
		return Action{}, ErrInvalidAction
	}
	return Action{Server: parts[0], Domain: parts[1], Verb: parts[2]}, nil
}

func allowedVerb(verb string) bool {
	switch verb {
	case "access", "discover", "select", "create", "update", "delete", "execute", "preview", "publish", "approve", "bind", "revoke", "rotate", "reveal", "export", "import":
		return true
	}
	return false
}

// RouteName 表示已校验的至少三段点分逻辑路由名称。
type RouteName struct{ raw string }

// ParseRouteName 严格解析最多 64 字符、每段为 lower-kebab 的点分名称。
func ParseRouteName(raw string) (RouteName, error) {
	if len(raw) > 64 || !routePattern.MatchString(raw) {
		return RouteName{}, ErrInvalidRouteName
	}
	return RouteName{raw: raw}, nil
}

// String 返回校验后的原始逻辑路由名称。
func (r RouteName) String() string { return r.raw }

// CanonicalResource 返回服务端与逻辑路由确定的完整 HTTP 资源坐标。
// IAM 内部资源继续沿用 lower-snake 坐标，业务平台直接使用点分 Route Name。
func (r RouteName) CanonicalResource(server string) string {
	if server == "iam" {
		return "http:iam:" + strings.ReplaceAll(r.raw, ".", "_")
	}
	return "http:" + server + ":" + r.raw
}

// ValidateRouteTemplate 校验无协议、主机、查询串和片段的绝对框架路径。
func ValidateRouteTemplate(raw string) error {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || !utf8.ValidString(raw) || strings.ContainsAny(raw, "?#\\") || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return ErrInvalidRouteTemplate
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidRouteTemplate
	}
	return nil
}
