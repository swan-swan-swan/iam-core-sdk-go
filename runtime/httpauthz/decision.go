package httpauthz

type Decision struct {
	ID         string
	Allowed    bool
	ReasonCode string
	Action     string
	RequestID  string
	TraceID    string
}

type Route struct {
	method         string
	resourceServer string
	resource       string
	action         string
	compiled       bool
}

func (r Route) Method() string         { return r.method }
func (r Route) ResourceServer() string { return r.resourceServer }
func (r Route) Resource() string       { return r.resource }
func (r Route) Action() string         { return r.action }

type decisionRequest struct {
	ResourceServer string `json:"resource_server"`
	Resource       string `json:"resource"`
	HTTPMethod     string `json:"http_method"`
	ExpectedAction string `json:"expected_action,omitempty"`
}
