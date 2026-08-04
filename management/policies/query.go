package policies

import (
	"net/url"
	"strconv"
)

// ListOptions configures one bounded Policy Document page.
type ListOptions struct {
	ApplicationOpenID, PolicyType, Name, DisplayName, Keyword, RoleOpenID, Status string
	Page, PageSize                                                                int
}

// CompiledRuleOptions configures one bounded read-only compiled-rule page.
// Domain is an opaque server filter; the SDK assigns no RPC behavior to it.
type CompiledRuleOptions struct {
	ApplicationOpenID, PolicyDocumentOpenID, PolicyType, RoleOpenID, Effect, Domain, Action, ResourceKeyword string
	Page, PageSize                                                                                           int
}

func listQuery(options ListOptions) url.Values {
	query := make(url.Values)
	addString(query, "application_open_id", options.ApplicationOpenID)
	addString(query, "policy_type", options.PolicyType)
	addString(query, "name", options.Name)
	addString(query, "display_name", options.DisplayName)
	addString(query, "keyword", options.Keyword)
	addString(query, "role_open_id", options.RoleOpenID)
	addString(query, "status", options.Status)
	addInt(query, "page", options.Page)
	addInt(query, "page_size", options.PageSize)
	return query
}
func compiledRuleQuery(options CompiledRuleOptions) url.Values {
	query := make(url.Values)
	addString(query, "application_open_id", options.ApplicationOpenID)
	addString(query, "policy_document_open_id", options.PolicyDocumentOpenID)
	addString(query, "policy_type", options.PolicyType)
	addString(query, "role_open_id", options.RoleOpenID)
	addString(query, "effect", options.Effect)
	addString(query, "dom", options.Domain)
	addString(query, "act", options.Action)
	addString(query, "resource_keyword", options.ResourceKeyword)
	addInt(query, "page", options.Page)
	addInt(query, "page_size", options.PageSize)
	return query
}
func addString(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}
func addInt(query url.Values, key string, value int) {
	if value != 0 {
		query.Set(key, strconv.Itoa(value))
	}
}
