package applications

import (
	"context"
	"net/http"
	"reflect"
	"strings"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const applicationsPath = "/api/v1/applications"

// Client manages IAM Core applications through the shared Management transport.
type Client struct {
	transport management.Transport
}

// New creates an applications client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// List returns all applications.
func (c *Client) List(ctx context.Context) ([]Application, management.Metadata, error) {
	var response struct {
		Items []applicationWire `json:"items"`
	}
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: "management.applications.list", Method: http.MethodGet, Path: applicationsPath,
	}, &response)
	if err != nil {
		return nil, metadata, err
	}
	items := make([]Application, len(response.Items))
	for i := range response.Items {
		items[i] = response.Items[i].application()
	}
	return items, metadata, nil
}

// Get returns one application by public Open ID.
func (c *Client) Get(ctx context.Context, applicationOpenID string) (Application, management.Metadata, error) {
	const operation = "management.applications.get"
	if !validApplicationOpenID(applicationOpenID) {
		return Application{}, management.Metadata{}, invalidArgument(operation)
	}
	var response applicationWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodGet, Path: applicationsPath + "/" + applicationOpenID,
	}, &response)
	if err != nil {
		return Application{}, metadata, err
	}
	return response.application(), metadata, nil
}

// Create creates an application.
func (c *Client) Create(ctx context.Context, input CreateInput) (Application, management.Metadata, error) {
	const operation = "management.applications.create"
	if !validRequired(input.Name) || !validRequired(input.DisplayName) {
		return Application{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
	}{input.Name, input.DisplayName, input.Description}
	var response applicationWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodPost, Path: applicationsPath, Body: body,
	}, &response)
	if err != nil {
		return Application{}, metadata, err
	}
	return response.application(), metadata, nil
}

// Update changes an application's display values.
func (c *Client) Update(ctx context.Context, applicationOpenID string, input UpdateInput) (Application, management.Metadata, error) {
	const operation = "management.applications.update"
	if !validApplicationOpenID(applicationOpenID) || !validRequired(input.DisplayName) {
		return Application{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
	}{input.DisplayName, input.Description}
	var response applicationWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodPut, Path: applicationsPath + "/" + applicationOpenID, Body: body,
	}, &response)
	if err != nil {
		return Application{}, metadata, err
	}
	return response.application(), metadata, nil
}

// SetEnabled changes the authoritative application status.
func (c *Client) SetEnabled(ctx context.Context, applicationOpenID string, enabled bool) (Application, management.Metadata, error) {
	const operation = "management.applications.set_enabled"
	if !validApplicationOpenID(applicationOpenID) {
		return Application{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		Enabled bool `json:"enabled"`
	}{enabled}
	var response applicationWire
	metadata, err := c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodPut, Path: applicationsPath + "/" + applicationOpenID + "/status", Body: body,
	}, &response)
	if err != nil {
		return Application{}, metadata, err
	}
	return response.application(), metadata, nil
}

// HardDelete permanently deletes an application with no blocking references.
func (c *Client) HardDelete(ctx context.Context, applicationOpenID string) (management.Metadata, error) {
	const operation = "management.applications.hard_delete"
	if !validApplicationOpenID(applicationOpenID) {
		return management.Metadata{}, invalidArgument(operation)
	}
	return c.transport.Do(ctx, management.Request{
		Operation: operation, Method: http.MethodDelete, Path: applicationsPath + "/" + applicationOpenID,
	}, nil)
}

func validApplicationOpenID(value string) bool {
	if len(value) != 26 || !strings.HasPrefix(value, "op_app_") {
		return false
	}
	for _, character := range value[len("op_app_"):] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validRequired(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
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
