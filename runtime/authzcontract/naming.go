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
	tokenPattern            = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	routePattern            = regexp.MustCompile(`^[a-z0-9]+(?:\.[a-z0-9]+){2,}$`)
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
	if len(raw) > 64 || len(parts) != 3 || !tokenPattern.MatchString(parts[0]) || !tokenPattern.MatchString(parts[1]) || !allowedVerb(parts[2]) {
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

// ParseRouteName 严格解析最多 64 字符的点分小写字母数字名称。
func ParseRouteName(raw string) (RouteName, error) {
	if len(raw) > 64 || !routePattern.MatchString(raw) {
		return RouteName{}, ErrInvalidRouteName
	}
	return RouteName{raw: raw}, nil
}

// ResourceCode 将逻辑路由名称中的点确定性替换为下划线。
func (r RouteName) ResourceCode() string { return strings.ReplaceAll(r.raw, ".", "_") }

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
