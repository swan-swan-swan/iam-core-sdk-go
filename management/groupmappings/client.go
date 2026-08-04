package groupmappings

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const applicationsPath = "/api/v1/applications"

// Client manages OIDC Client-specific Role-to-group mappings.
type Client struct {
	transport management.Transport
}

// New creates a group mapping management client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// Get returns the complete mapping snapshot for one OIDC Client.
func (c *Client) Get(ctx context.Context, applicationOpenID, clientID string) (Snapshot, management.Metadata, error) {
	const operation = "management.groupmappings.get"
	path, ok := groupMappingsPath(applicationOpenID, clientID)
	if !ok {
		return Snapshot{}, management.Metadata{}, invalidArgument(operation)
	}
	return c.do(ctx, management.Request{Operation: operation, Method: http.MethodGet, Path: path})
}

// Create creates one mapping at the caller-provided revision.
func (c *Client) Create(ctx context.Context, applicationOpenID, clientID, roleOpenID, groupValue string, expectedRevision uint64) (Snapshot, management.Metadata, error) {
	const operation = "management.groupmappings.create"
	path, ok := groupMappingsPath(applicationOpenID, clientID)
	if !ok || !validPublicID(roleOpenID, "op_rol_") || !validGroupValue(groupValue) {
		return Snapshot{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		RoleOpenID string `json:"roleOpenId"`
		GroupValue string `json:"groupValue"`
		Revision   uint64 `json:"revision"`
	}{roleOpenID, groupValue, expectedRevision}
	return c.do(ctx, management.Request{Operation: operation, Method: http.MethodPost, Path: path, Body: body})
}

// Update changes one mapping at the caller-provided revision.
func (c *Client) Update(ctx context.Context, applicationOpenID, clientID, roleOpenID, groupValue string, expectedRevision uint64) (Snapshot, management.Metadata, error) {
	const operation = "management.groupmappings.update"
	path, ok := groupMappingsPath(applicationOpenID, clientID)
	if !ok || !validPublicID(roleOpenID, "op_rol_") || !validGroupValue(groupValue) {
		return Snapshot{}, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		GroupValue string `json:"groupValue"`
		Revision   uint64 `json:"revision"`
	}{groupValue, expectedRevision}
	return c.do(ctx, management.Request{Operation: operation, Method: http.MethodPut, Path: path + "/" + roleOpenID, Body: body})
}

// SoftDelete removes one mapping while preserving the service's audit history.
func (c *Client) SoftDelete(ctx context.Context, applicationOpenID, clientID, roleOpenID string, expectedRevision uint64) (Snapshot, management.Metadata, error) {
	const operation = "management.groupmappings.soft_delete"
	path, ok := groupMappingsPath(applicationOpenID, clientID)
	if !ok || !validPublicID(roleOpenID, "op_rol_") {
		return Snapshot{}, management.Metadata{}, invalidArgument(operation)
	}
	return c.do(ctx, management.Request{
		Operation: operation, Method: http.MethodDelete, Path: path + "/" + roleOpenID,
		Query: url.Values{"revision": {strconv.FormatUint(expectedRevision, 10)}},
	})
}

func (c *Client) do(ctx context.Context, request management.Request) (Snapshot, management.Metadata, error) {
	var response snapshotWire
	metadata, err := c.transport.Do(ctx, request, &response)
	if err != nil {
		return Snapshot{}, metadata, err
	}
	return response.snapshot(), metadata, nil
}

func groupMappingsPath(applicationOpenID, clientID string) (string, bool) {
	if !validPublicID(applicationOpenID, "op_app_") || !validClientID(clientID) {
		return "", false
	}
	return applicationsPath + "/" + applicationOpenID + "/oidc-clients/" + clientID + "/group-mappings", true
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

func validGroupValue(value string) bool {
	if len(value) == 0 || len(value) > 128 || !asciiAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if asciiAlphaNumeric(character) || strings.ContainsRune("._:@/-", character) {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
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
