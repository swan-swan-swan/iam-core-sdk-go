package admission

import "strings"

const applicationsPath = "/api/v1/applications"

func admissionPath(scope Scope) (string, bool) {
	if !validPublicID(scope.ApplicationOpenID, "op_app_") {
		return "", false
	}
	path := applicationsPath + "/" + scope.ApplicationOpenID
	switch scope.kind {
	case applicationScopeKind:
		if scope.ClientID != "" {
			return "", false
		}
	case clientScopeKind:
		if !validClientID(scope.ClientID) {
			return "", false
		}
		path += "/oidc-clients/" + scope.ClientID
	default:
		return "", false
	}
	return path + "/login-admission-rules", true
}

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

func validClientID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !asciiAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if asciiAlphaNumeric(character) || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}
