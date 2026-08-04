package policies

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const documentsPath = "/api/v1/policy-documents"

// Client manages Policy Documents through the shared Management transport.
type Client struct{ transport management.Transport }

// New creates a Policy Document management client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// List returns one bounded Policy Document page.
func (c *Client) List(ctx context.Context, options ListOptions) (management.Page[Document], management.Metadata, error) {
	const operation = "management.policies.list"
	if !validListOptions(options) {
		return management.Page[Document]{}, management.Metadata{}, invalidArgument(operation)
	}
	var response documentPageWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodGet, Path: documentsPath, Query: listQuery(options)}, &response)
	if err != nil {
		return management.Page[Document]{}, metadata, err
	}
	items := make([]Document, len(response.Items))
	for i := range response.Items {
		items[i] = response.Items[i].value()
	}
	return management.Page[Document]{Items: items, Page: response.Page, PageSize: response.PageSize, Total: response.Total}, metadata, nil
}

// Get returns one Policy Document in an explicit Application scope.
func (c *Client) Get(ctx context.Context, policyDocumentOpenID, applicationOpenID string) (Document, management.Metadata, error) {
	const operation = "management.policies.get"
	if !validPublicID(policyDocumentOpenID, "op_pdc_") || !validPublicID(applicationOpenID, "op_app_") {
		return Document{}, management.Metadata{}, invalidArgument(operation)
	}
	var response documentWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodGet, Path: documentsPath + "/" + policyDocumentOpenID, Query: url.Values{"application_open_id": {applicationOpenID}}}, &response)
	if err != nil {
		return Document{}, metadata, err
	}
	return response.value(), metadata, nil
}

// Create creates a custom Policy Document.
func (c *Client) Create(ctx context.Context, input UpsertInput) (Document, management.Metadata, error) {
	return c.upsert(ctx, "management.policies.create", http.MethodPost, "", input)
}

// Update completely replaces a custom Policy Document.
func (c *Client) Update(ctx context.Context, policyDocumentOpenID string, input UpsertInput) (Document, management.Metadata, error) {
	return c.upsert(ctx, "management.policies.update", http.MethodPut, policyDocumentOpenID, input)
}

func (c *Client) upsert(ctx context.Context, operation, method, openID string, input UpsertInput) (Document, management.Metadata, error) {
	document, ok := cloneJSONObject(input.Document)
	if !validUpsert(input) || !ok || method == http.MethodPut && !validPublicID(openID, "op_pdc_") {
		return Document{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ApplicationOpenID string          `json:"application_open_id"`
		Name              string          `json:"name"`
		DisplayName       string          `json:"display_name"`
		PolicyType        string          `json:"policy_type"`
		RoleOpenIDs       []string        `json:"role_open_ids"`
		Document          json.RawMessage `json:"document"`
		Publish           bool            `json:"publish"`
	}{input.ApplicationOpenID, input.Name, input.DisplayName, input.PolicyType, append([]string(nil), input.RoleOpenIDs...), document, input.Publish}
	path := documentsPath
	if method == http.MethodPut {
		path += "/" + openID
	}
	var response documentWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: method, Path: path, Body: body}, &response)
	if err != nil {
		return Document{}, metadata, err
	}
	return response.value(), metadata, nil
}

// Preview requests server-side validation and compilation without persistence.
func (c *Client) Preview(ctx context.Context, input PreviewInput) (Preview, management.Metadata, error) {
	const operation = "management.policies.preview"
	document, ok := cloneJSONObject(input.Document)
	if !validPublicID(input.ApplicationOpenID, "op_app_") || !validRoleOpenIDs(input.RoleOpenIDs) || !ok {
		return Preview{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ApplicationOpenID string          `json:"application_open_id"`
		RoleOpenIDs       []string        `json:"role_open_ids"`
		Document          json.RawMessage `json:"document"`
	}{input.ApplicationOpenID, append([]string(nil), input.RoleOpenIDs...), document}
	var response previewWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodPost, Path: documentsPath + "/preview", Body: body}, &response)
	if err != nil {
		return Preview{}, metadata, err
	}
	return response.value(), metadata, nil
}

// SetBindings replaces one Policy Document's complete role binding set.
func (c *Client) SetBindings(ctx context.Context, policyDocumentOpenID string, input BindingsInput) (Document, management.Metadata, error) {
	const operation = "management.policies.set_bindings"
	if !validPublicID(policyDocumentOpenID, "op_pdc_") || !validPublicID(input.ApplicationOpenID, "op_app_") || !validRoleOpenIDs(input.RoleOpenIDs) {
		return Document{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ApplicationOpenID string   `json:"application_open_id"`
		RoleOpenIDs       []string `json:"role_open_ids"`
	}{input.ApplicationOpenID, append([]string(nil), input.RoleOpenIDs...)}
	var response documentWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodPut, Path: documentsPath + "/" + policyDocumentOpenID + "/bindings", Body: body}, &response)
	if err != nil {
		return Document{}, metadata, err
	}
	return response.value(), metadata, nil
}

// ListCompiledRules returns one bounded read-only page of server-produced compiled rules.
func (c *Client) ListCompiledRules(ctx context.Context, options CompiledRuleOptions) (management.Page[CompiledRule], management.Metadata, error) {
	const operation = "management.policies.list_compiled_rules"
	if !validCompiledRuleOptions(options) {
		return management.Page[CompiledRule]{}, management.Metadata{}, invalidArgument(operation)
	}
	var response compiledRulePageWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodGet, Path: "/api/v1/policy-compiled-rules", Query: compiledRuleQuery(options)}, &response)
	if err != nil {
		return management.Page[CompiledRule]{}, metadata, err
	}
	items := make([]CompiledRule, len(response.Items))
	for i := range response.Items {
		items[i] = response.Items[i].value()
	}
	return management.Page[CompiledRule]{Items: items, Page: response.Page, PageSize: response.PageSize, Total: response.Total}, metadata, nil
}

func validUpsert(input UpsertInput) bool {
	return validPublicID(input.ApplicationOpenID, "op_app_") && validText(input.Name, true) && validText(input.DisplayName, true) && input.PolicyType == "custom" && validRoleOpenIDs(input.RoleOpenIDs)
}
func validListOptions(options ListOptions) bool {
	if !validPublicID(options.ApplicationOpenID, "op_app_") || !validPage(options.Page, options.PageSize) || !optionalText(options.Name) || !optionalText(options.DisplayName) || !optionalText(options.Keyword) {
		return false
	}
	if options.PolicyType != "" && options.PolicyType != "system" && options.PolicyType != "custom" {
		return false
	}
	if options.Status != "" && options.Status != "draft" && options.Status != "published" && options.Status != "disabled" {
		return false
	}
	return options.RoleOpenID == "" || validPublicID(options.RoleOpenID, "op_rol_")
}
func validCompiledRuleOptions(options CompiledRuleOptions) bool {
	if !validPublicID(options.ApplicationOpenID, "op_app_") || !validPage(options.Page, options.PageSize) || !optionalText(options.Domain) || !optionalText(options.Action) || !optionalText(options.ResourceKeyword) {
		return false
	}
	if options.PolicyDocumentOpenID != "" && !validPublicID(options.PolicyDocumentOpenID, "op_pdc_") || options.RoleOpenID != "" && !validPublicID(options.RoleOpenID, "op_rol_") {
		return false
	}
	if options.PolicyType != "" && options.PolicyType != "system" && options.PolicyType != "custom" || options.Effect != "" && options.Effect != "allow" && options.Effect != "deny" {
		return false
	}
	return true
}
func validPage(page, pageSize int) bool { return page >= 0 && pageSize >= 0 && pageSize <= 100 }
func validText(value string, required bool) bool {
	if value == "" {
		return !required
	}
	return strings.TrimSpace(value) == value
}
func optionalText(value string) bool { return validText(value, false) }
func validRoleOpenIDs(values []string) bool {
	for _, value := range values {
		if !validPublicID(value, "op_rol_") {
			return false
		}
	}
	return true
}
func validPublicID(value, prefix string) bool {
	if len(value) != len(prefix)+19 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func cloneJSONObject(input json.RawMessage) (json.RawMessage, bool) {
	if !json.Valid(input) {
		return nil, false
	}
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, false
	}
	return append(json.RawMessage(nil), input...), true
}
func invalidArgument(operation string) error {
	return &management.Error{Kind: management.KindInvalidArgument, Operation: operation}
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
