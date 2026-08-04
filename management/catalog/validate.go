package catalog

import (
	"reflect"
	"strings"
)

func validPublicID(value, prefix string) bool {
	if len(value) != len(prefix)+19 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !asciiAlphaNumeric(character) {
			return false
		}
	}
	return true
}

func validCode(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if asciiLowerNumeric(character) || strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func validName(value string) bool { return value != "" && strings.TrimSpace(value) == value }
func validRouteTemplate(value string) bool {
	return strings.HasPrefix(value, "/") && strings.TrimSpace(value) == value
}

func validMethod(value string) bool {
	switch value {
	case "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE":
		return true
	default:
		return false
	}
}

func validEntity(entityType EntityType, openID string) bool {
	switch entityType {
	case EntityResourceServer:
		return validPublicID(openID, "op_rsv_")
	case EntityResource:
		return validPublicID(openID, "op_res_")
	case EntityAction:
		return validPublicID(openID, "op_act_")
	case EntityMethodMapping:
		return validPublicID(openID, "op_hmm_")
	default:
		return false
	}
}

func asciiAlphaNumeric(character rune) bool {
	return asciiLowerNumeric(character) || character >= 'A' && character <= 'Z'
}
func asciiLowerNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
