package catalog

// ResourceServer is one HTTP authorization resource server.
type ResourceServer struct {
	OpenID            string
	ApplicationOpenID string
	Code              string
	Name              string
	Active            bool
}

// Resource is one HTTP route resource in a resource server.
type Resource struct {
	OpenID               string
	ApplicationOpenID    string
	ResourceServerOpenID string
	Code                 string
	Name                 string
	RouteTemplate        string
	CanonicalResource    string
	Active               bool
}

// Action is one stable authorization action.
type Action struct {
	OpenID               string
	ApplicationOpenID    string
	ResourceServerOpenID string
	Code                 string
	Name                 string
	Active               bool
}

// MethodMapping associates an HTTP method and resource with an action.
type MethodMapping struct {
	OpenID            string
	ApplicationOpenID string
	ResourceOpenID    string
	ActionOpenID      string
	Method            string
	Active            bool
}

// Catalog is the complete HTTP authorization catalog snapshot.
type Catalog struct {
	ResourceServers []ResourceServer
	Resources       []Resource
	Actions         []Action
	MethodMappings  []MethodMapping
	Mode            string
	SystemManaged   bool
	ReadOnly        bool
	Version         string
	Hash            string
	SyncStatus      string
}

// ResourceServerInput contains editable resource server fields.
type ResourceServerInput struct{ Code, Name string }

// ResourceInput contains editable HTTP resource fields.
type ResourceInput struct{ ResourceServerOpenID, Code, Name, RouteTemplate string }

// ActionInput contains editable HTTP action fields.
type ActionInput struct{ ResourceServerOpenID, Code, Name string }

// MethodMappingInput contains an HTTP method mapping's complete editable state.
type MethodMappingInput struct{ ResourceOpenID, ActionOpenID, Method string }

// EntityType identifies the typed catalog entity in a deactivate path.
type EntityType string

const (
	EntityResourceServer EntityType = "resource_server"
	EntityResource       EntityType = "resource"
	EntityAction         EntityType = "action"
	EntityMethodMapping  EntityType = "method_mapping"
)

// ReferenceBlock is the non-sensitive reference summary supplied when a Catalog entity cannot be deactivated.
type ReferenceBlock struct {
	References []string `json:"references"`
}

type resourceServerWire struct {
	ID                uint64 `json:"id"`
	UniID             string `json:"uni_id"`
	OpenID            string `json:"open_id"`
	ApplicationOpenID string `json:"application_open_id"`
	Code              string `json:"code"`
	Name              string `json:"name"`
	Active            bool   `json:"active"`
}

func (w resourceServerWire) value() ResourceServer {
	return ResourceServer{w.OpenID, w.ApplicationOpenID, w.Code, w.Name, w.Active}
}

type resourceWire struct {
	ID                   uint64 `json:"id"`
	UniID                string `json:"uni_id"`
	OpenID               string `json:"open_id"`
	ApplicationOpenID    string `json:"application_open_id"`
	ResourceServerID     uint64 `json:"resource_server_id"`
	ResourceServerOpenID string `json:"resource_server_open_id"`
	Code                 string `json:"code"`
	Name                 string `json:"name"`
	RouteTemplate        string `json:"route_template"`
	CanonicalResource    string `json:"canonical_resource"`
	Active               bool   `json:"active"`
}

func (w resourceWire) value() Resource {
	return Resource{w.OpenID, w.ApplicationOpenID, w.ResourceServerOpenID, w.Code, w.Name, w.RouteTemplate, w.CanonicalResource, w.Active}
}

type actionWire struct {
	ID                   uint64 `json:"id"`
	UniID                string `json:"uni_id"`
	OpenID               string `json:"open_id"`
	ApplicationOpenID    string `json:"application_open_id"`
	ResourceServerID     uint64 `json:"resource_server_id"`
	ResourceServerOpenID string `json:"resource_server_open_id"`
	Code                 string `json:"code"`
	Name                 string `json:"name"`
	Active               bool   `json:"active"`
}

func (w actionWire) value() Action {
	return Action{w.OpenID, w.ApplicationOpenID, w.ResourceServerOpenID, w.Code, w.Name, w.Active}
}

type methodMappingWire struct {
	ID                uint64 `json:"id"`
	UniID             string `json:"uni_id"`
	OpenID            string `json:"open_id"`
	ApplicationOpenID string `json:"application_open_id"`
	ResourceID        uint64 `json:"resource_id"`
	ResourceOpenID    string `json:"resource_open_id"`
	ActionID          uint64 `json:"action_id"`
	ActionOpenID      string `json:"action_open_id"`
	Method            string `json:"method"`
	Active            bool   `json:"active"`
}

func (w methodMappingWire) value() MethodMapping {
	return MethodMapping{w.OpenID, w.ApplicationOpenID, w.ResourceOpenID, w.ActionOpenID, w.Method, w.Active}
}

type catalogWire struct {
	ResourceServers []resourceServerWire `json:"resource_servers"`
	Resources       []resourceWire       `json:"resources"`
	Actions         []actionWire         `json:"actions"`
	MethodMappings  []methodMappingWire  `json:"method_mappings"`
	Mode            string               `json:"catalog_mode"`
	SystemManaged   bool                 `json:"system_managed"`
	ReadOnly        bool                 `json:"read_only"`
	Version         string               `json:"catalog_version"`
	Hash            string               `json:"catalog_hash"`
	SyncStatus      string               `json:"sync_status"`
}

func (w catalogWire) value() Catalog {
	result := Catalog{Mode: w.Mode, SystemManaged: w.SystemManaged, ReadOnly: w.ReadOnly, Version: w.Version, Hash: w.Hash, SyncStatus: w.SyncStatus}
	result.ResourceServers = make([]ResourceServer, len(w.ResourceServers))
	for i := range w.ResourceServers {
		result.ResourceServers[i] = w.ResourceServers[i].value()
	}
	result.Resources = make([]Resource, len(w.Resources))
	for i := range w.Resources {
		result.Resources[i] = w.Resources[i].value()
	}
	result.Actions = make([]Action, len(w.Actions))
	for i := range w.Actions {
		result.Actions[i] = w.Actions[i].value()
	}
	result.MethodMappings = make([]MethodMapping, len(w.MethodMappings))
	for i := range w.MethodMappings {
		result.MethodMappings[i] = w.MethodMappings[i].value()
	}
	return result
}
