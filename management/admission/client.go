package admission

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strconv"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

// Client manages Application-level and OIDC Client-level login admission rules.
type Client struct {
	transport management.Transport
}

// New creates an admission management client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// List returns one bounded page of rules for the explicit scope.
func (c *Client) List(ctx context.Context, scope Scope, options ListOptions) (ListResult, management.Metadata, error) {
	const operation = "management.admission.list"
	path, ok := admissionPath(scope)
	if !ok || !validListOptions(options) {
		return ListResult{}, management.Metadata{}, invalidArgument(operation)
	}
	var response admissionListWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodGet, Path: path, Query: listQuery(options),
	}, &response)
	if err != nil {
		return ListResult{}, metadata, err
	}
	return response.result(), metadata, nil
}

// Create creates a revision-controlled rule in the explicit scope.
func (c *Client) Create(ctx context.Context, scope Scope, mutation Mutation) (Change, management.Metadata, error) {
	return c.mutate(ctx, "management.admission.create", http.MethodPost, scope, "", mutation)
}

// Update replaces one rule at the caller-provided policy revision.
func (c *Client) Update(ctx context.Context, scope Scope, ruleOpenID string, mutation Mutation) (Change, management.Metadata, error) {
	return c.mutate(ctx, "management.admission.update", http.MethodPut, scope, ruleOpenID, mutation)
}

// SoftDelete deletes one rule while preserving the service's audit history.
func (c *Client) SoftDelete(ctx context.Context, scope Scope, ruleOpenID string, expectedRevision uint64) (Change, management.Metadata, error) {
	const operation = "management.admission.soft_delete"
	path, ok := admissionPath(scope)
	if !ok || !validPublicID(ruleOpenID, "op_lpr_") || expectedRevision == 0 {
		return Change{}, management.Metadata{}, invalidArgument(operation)
	}
	var response changeWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodDelete, Path: path + "/" + ruleOpenID,
		Query: url.Values{"login_policy_revision": {strconv.FormatUint(expectedRevision, 10)}},
	}, &response)
	if err != nil {
		return Change{}, metadata, err
	}
	return response.change(), metadata, nil
}

func (c *Client) mutate(ctx context.Context, operation, method string, scope Scope, ruleOpenID string, mutation Mutation) (Change, management.Metadata, error) {
	path, ok := admissionPath(scope)
	if !ok || !validMutation(mutation) || method == http.MethodPut && !validPublicID(ruleOpenID, "op_lpr_") {
		return Change{}, management.Metadata{}, invalidArgument(operation)
	}
	if method == http.MethodPut {
		path += "/" + ruleOpenID
	}
	body := struct {
		SubjectType         string `json:"subject_type"`
		SubjectOpenID       string `json:"subject_open_id"`
		Effect              string `json:"effect"`
		LoginPolicyRevision uint64 `json:"login_policy_revision"`
	}{mutation.SubjectType, mutation.SubjectOpenID, mutation.Effect, mutation.ExpectedRevision}
	var response changeWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: method, Path: path, Body: body,
	}, &response)
	if err != nil {
		return Change{}, metadata, err
	}
	return response.change(), metadata, nil
}

func validMutation(mutation Mutation) bool {
	if mutation.SubjectType != "user" && mutation.SubjectType != "role" {
		return false
	}
	prefix := "op_usr_"
	if mutation.SubjectType == "role" {
		prefix = "op_rol_"
	}
	return validPublicID(mutation.SubjectOpenID, prefix) && (mutation.Effect == "allow" || mutation.Effect == "deny")
}

func validListOptions(options ListOptions) bool {
	if options.Page < 0 || options.PageSize < 0 || options.PageSize > 100 {
		return false
	}
	if options.Sort != "" && options.Sort != "created_at" && options.Sort != "updated_at" && options.Sort != "subject_open_id" && options.Sort != "effect" {
		return false
	}
	return options.Order == "" || options.Order == "asc" || options.Order == "desc"
}

func listQuery(options ListOptions) url.Values {
	var query url.Values
	add := func(key, value string) {
		if query == nil {
			query = make(url.Values)
		}
		query.Set(key, value)
	}
	if options.Page != 0 {
		add("page", strconv.Itoa(options.Page))
	}
	if options.PageSize != 0 {
		add("page_size", strconv.Itoa(options.PageSize))
	}
	if options.Sort != "" {
		add("sort", options.Sort)
	}
	if options.Order != "" {
		add("order", options.Order)
	}
	return query
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
