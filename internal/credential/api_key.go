// Package credential 提供 Runtime 与 Management 共用的纯凭据格式规则，不执行认证。
package credential

import (
	"encoding/base64"
	"regexp"
)

// apiKeyPattern 固定凭据格式，凭据真实性仍由 IAM 在线验证。
var apiKeyPattern = regexp.MustCompile(`^iak_([0-7][0-9A-HJKMNP-TV-Z]{25})\.([A-Za-z0-9_-]{43})$`)

// APIKeyID 返回格式正确的密钥对应公开凭据标识；不代表已认证。
func APIKeyID(raw string) (string, bool) {
	parts := apiKeyPattern.FindStringSubmatch(raw)
	if len(parts) != 3 {
		return "", false
	}
	bytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(bytes) != 32 || base64.RawURLEncoding.EncodeToString(bytes) != parts[2] {
		return "", false
	}
	return "op_sak_" + parts[1], true
}
