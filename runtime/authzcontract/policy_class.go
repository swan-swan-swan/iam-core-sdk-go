package authzcontract

import (
	"errors"
	"net/http"
)

// PolicyClass 表示代码声明的目录策略类别，不直接授予请求权限。
type PolicyClass string

const (
	// PolicyClassFullAccess 表示域内完整业务访问能力。
	PolicyClassFullAccess PolicyClass = "FullAccess"
	// PolicyClassReadOnlyAccess 表示显式只读业务能力。
	PolicyClassReadOnlyAccess PolicyClass = "ReadOnlyAccess"
	// PolicyClassCardAccess 表示应用卡片入口及必要辅助操作。
	PolicyClassCardAccess PolicyClass = "CardAccess"
)

// ErrInvalidPolicyClass 表示类别或其与Method、Action的组合不合法，不包含原始输入。
var ErrInvalidPolicyClass = errors.New("invalid authorization policy_class")

// ValidatePolicyClass 校验精确类别及动词边界，不推断或归一化分类。
func ValidatePolicyClass(method, action string, class PolicyClass) error {
	parsed, err := ParseAction(action)
	if err != nil {
		return err
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
	default:
		return ErrInvalidPolicyClass
	}
	switch class {
	case PolicyClassFullAccess:
		return nil
	case PolicyClassReadOnlyAccess:
		switch parsed.Verb {
		case "select", "discover", "preview", "export":
			return nil
		}
	case PolicyClassCardAccess:
		if method == http.MethodGet && parsed.Verb == "access" {
			return nil
		}
	}
	return ErrInvalidPolicyClass
}
