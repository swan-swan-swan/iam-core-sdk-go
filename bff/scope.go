package bff

import (
	"slices"
	"strings"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func reconcileScopes(tokenResponse string, access, id []string) ([]string, error) {
	sources := make([][]string, 0, 3)
	if strings.TrimSpace(tokenResponse) != "" {
		sources = append(sources, normalizeScopes(strings.Fields(tokenResponse)))
	}
	if access != nil {
		sources = append(sources, normalizeScopes(access))
	}
	if id != nil {
		sources = append(sources, normalizeScopes(id))
	}
	if len(sources) == 0 {
		return nil, core.NewError(core.KindProtocol, "bff.scope", 0, false, nil)
	}
	for _, source := range sources[1:] {
		if !slices.Equal(source, sources[0]) {
			return nil, core.NewError(core.KindProtocol, "bff.scope", 0, false, nil)
		}
	}
	return append([]string(nil), sources[0]...), nil
}

func validateGrantedScopes(granted, requested []string) error {
	requestedSet := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		requestedSet[scope] = struct{}{}
	}
	for _, scope := range granted {
		if !validScopeToken(scope) || scope == "roles" {
			return core.NewError(core.KindProtocol, "bff.scope", 0, false, nil)
		}
		if _, requestedByClient := requestedSet[scope]; !requestedByClient {
			return core.NewError(core.KindProtocol, "bff.scope", 0, false, nil)
		}
	}
	return nil
}

func validScopeString(value string) bool {
	parts := strings.Split(value, " ")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if !validScopeToken(part) {
			return false
		}
	}
	return true
}

func normalizeScopes(scopes []string) []string {
	if scopes == nil {
		return nil
	}
	unique := make(map[string]struct{}, len(scopes))
	for _, raw := range scopes {
		if scope := strings.TrimSpace(raw); scope != "" {
			unique[scope] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for scope := range unique {
		result = append(result, scope)
	}
	slices.Sort(result)
	return result
}

func normalizeGroups(groups []string) []string {
	if groups == nil {
		return nil
	}
	return normalizeScopes(groups)
}

func reconcileGroups(sources ...[]string) ([]string, error) {
	available := make([][]string, 0, len(sources))
	for _, source := range sources {
		if source != nil {
			available = append(available, normalizeGroups(source))
		}
	}
	if len(available) == 0 {
		return []string{}, nil
	}
	for _, source := range available[1:] {
		if !slices.Equal(source, available[0]) {
			return nil, core.NewError(core.KindProtocol, "bff.groups", 0, false, nil)
		}
	}
	return append([]string{}, available[0]...), nil
}
