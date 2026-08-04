package catalog

import (
	"context"
	"net/http"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const applicationsPath = "/api/v1/applications"

// Client manages HTTP resource catalogs through the shared Management transport.
type Client struct{ transport management.Transport }

// New creates a Catalog management client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// Get returns the complete catalog snapshot for an Application.
func (c *Client) Get(ctx context.Context, applicationOpenID string) (Catalog, management.Metadata, error) {
	const operation = "management.catalog.get"
	base, ok := applicationBase(applicationOpenID)
	if !ok {
		return Catalog{}, management.Metadata{}, invalidArgument(operation)
	}
	var response catalogWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodGet, Path: base + "/http-resource-catalog"}, &response)
	if err != nil {
		return Catalog{}, metadata, err
	}
	return response.value(), metadata, nil
}

// CreateResourceServer creates a resource server.
func (c *Client) CreateResourceServer(ctx context.Context, applicationOpenID string, input ResourceServerInput) (ResourceServer, management.Metadata, error) {
	const operation = "management.catalog.create_resource_server"
	base, ok := applicationBase(applicationOpenID)
	if !ok || !validCode(input.Code) || !validName(input.Name) {
		return ResourceServer{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}{input.Code, input.Name}
	var response resourceServerWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodPost, Path: base + "/http-resource-servers", Body: body}, &response)
	if err != nil {
		return ResourceServer{}, metadata, err
	}
	return response.value(), metadata, nil
}

// UpdateResourceServer replaces a resource server's editable fields.
func (c *Client) UpdateResourceServer(ctx context.Context, applicationOpenID, openID string, input ResourceServerInput) (ResourceServer, management.Metadata, error) {
	const operation = "management.catalog.update_resource_server"
	base, ok := applicationBase(applicationOpenID)
	if !ok || !validPublicID(openID, "op_rsv_") || !validCode(input.Code) || !validName(input.Name) {
		return ResourceServer{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}{input.Code, input.Name}
	var response resourceServerWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodPut, Path: base + "/http-resource-servers/" + openID, Body: body}, &response)
	if err != nil {
		return ResourceServer{}, metadata, err
	}
	return response.value(), metadata, nil
}

// CreateResource creates an HTTP route resource.
func (c *Client) CreateResource(ctx context.Context, applicationOpenID string, input ResourceInput) (Resource, management.Metadata, error) {
	return c.mutateResource(ctx, "management.catalog.create_resource", http.MethodPost, applicationOpenID, "", input)
}

// UpdateResource replaces an HTTP route resource's editable fields.
func (c *Client) UpdateResource(ctx context.Context, applicationOpenID, openID string, input ResourceInput) (Resource, management.Metadata, error) {
	return c.mutateResource(ctx, "management.catalog.update_resource", http.MethodPut, applicationOpenID, openID, input)
}

func (c *Client) mutateResource(ctx context.Context, operation, method, applicationOpenID, openID string, input ResourceInput) (Resource, management.Metadata, error) {
	base, ok := applicationBase(applicationOpenID)
	if !ok || method == http.MethodPut && !validPublicID(openID, "op_res_") || !validPublicID(input.ResourceServerOpenID, "op_rsv_") || !validCode(input.Code) || !validName(input.Name) || !validRouteTemplate(input.RouteTemplate) {
		return Resource{}, management.Metadata{}, invalidArgument(operation)
	}
	path := base + "/http-resources"
	if method == http.MethodPut {
		path += "/" + openID
	}
	body := struct {
		ResourceServerOpenID string `json:"resource_server_open_id"`
		Code                 string `json:"code"`
		Name                 string `json:"name"`
		RouteTemplate        string `json:"route_template"`
	}{input.ResourceServerOpenID, input.Code, input.Name, input.RouteTemplate}
	var response resourceWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: method, Path: path, Body: body}, &response)
	if err != nil {
		return Resource{}, metadata, err
	}
	return response.value(), metadata, nil
}

// CreateAction creates an HTTP authorization action.
func (c *Client) CreateAction(ctx context.Context, applicationOpenID string, input ActionInput) (Action, management.Metadata, error) {
	return c.mutateAction(ctx, "management.catalog.create_action", http.MethodPost, applicationOpenID, "", input)
}

// UpdateAction replaces an HTTP authorization action's editable fields.
func (c *Client) UpdateAction(ctx context.Context, applicationOpenID, openID string, input ActionInput) (Action, management.Metadata, error) {
	return c.mutateAction(ctx, "management.catalog.update_action", http.MethodPut, applicationOpenID, openID, input)
}

func (c *Client) mutateAction(ctx context.Context, operation, method, applicationOpenID, openID string, input ActionInput) (Action, management.Metadata, error) {
	base, ok := applicationBase(applicationOpenID)
	if !ok || method == http.MethodPut && !validPublicID(openID, "op_act_") || !validPublicID(input.ResourceServerOpenID, "op_rsv_") || !validCode(input.Code) || !validName(input.Name) {
		return Action{}, management.Metadata{}, invalidArgument(operation)
	}
	path := base + "/http-actions"
	if method == http.MethodPut {
		path += "/" + openID
	}
	body := struct {
		ResourceServerOpenID string `json:"resource_server_open_id"`
		Code                 string `json:"code"`
		Name                 string `json:"name"`
	}{input.ResourceServerOpenID, input.Code, input.Name}
	var response actionWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: method, Path: path, Body: body}, &response)
	if err != nil {
		return Action{}, metadata, err
	}
	return response.value(), metadata, nil
}

// PutMethodMapping creates or replaces one method mapping.
func (c *Client) PutMethodMapping(ctx context.Context, applicationOpenID string, input MethodMappingInput) (MethodMapping, management.Metadata, error) {
	const operation = "management.catalog.put_method_mapping"
	base, ok := applicationBase(applicationOpenID)
	if !ok || !validPublicID(input.ResourceOpenID, "op_res_") || !validPublicID(input.ActionOpenID, "op_act_") || !validMethod(input.Method) {
		return MethodMapping{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		ResourceOpenID string `json:"resource_open_id"`
		ActionOpenID   string `json:"action_open_id"`
		Method         string `json:"method"`
	}{input.ResourceOpenID, input.ActionOpenID, input.Method}
	var response methodMappingWire
	metadata, err := c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodPut, Path: base + "/http-method-mappings", Body: body}, &response)
	if err != nil {
		return MethodMapping{}, metadata, err
	}
	return response.value(), metadata, nil
}

// Publish explicitly publishes a managed Catalog with one bodyless POST.
func (c *Client) Publish(ctx context.Context, applicationOpenID string) (management.Metadata, error) {
	const operation = "management.catalog.publish"
	base, ok := applicationBase(applicationOpenID)
	if !ok {
		return management.Metadata{}, invalidArgument(operation)
	}
	return c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodPost, Path: base + "/http-resource-catalog/publish"}, nil)
}

// Deactivate disables one unreferenced typed Catalog entity.
func (c *Client) Deactivate(ctx context.Context, applicationOpenID string, entityType EntityType, entityOpenID string) (management.Metadata, error) {
	const operation = "management.catalog.deactivate"
	base, ok := applicationBase(applicationOpenID)
	if !ok || !validEntity(entityType, entityOpenID) {
		return management.Metadata{}, invalidArgument(operation)
	}
	return c.transport.Do(ctx, management.Request{Operation: operation, Method: http.MethodDelete, Path: base + "/http-resource-catalog/" + string(entityType) + "/" + entityOpenID}, nil)
}

func applicationBase(openID string) (string, bool) {
	if !validPublicID(openID, "op_app_") {
		return "", false
	}
	return applicationsPath + "/" + openID, true
}
func invalidArgument(operation string) error {
	return &management.Error{Kind: management.KindInvalidArgument, Operation: operation}
}
