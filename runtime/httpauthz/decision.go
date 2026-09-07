package httpauthz

// Decision 表示 IAM Core 返回的单次授权决定。
type Decision struct {
	ID         string
	Allowed    bool
	ReasonCode string
	Action     string
	RequestID  string
	TraceID    string
}

// Route 保存清单编译产生的完整且不可变的逻辑路由。
type Route struct {
	name           string
	routeTemplate  string
	method         string
	resourceServer string
	resource       string
	action         string
	compiled       bool
}

// Name 返回稳定的逻辑路由名称。
func (r Route) Name() string { return r.name }

// RouteTemplate 返回用于路由注册及目录对账的绝对模板。
func (r Route) RouteTemplate() string { return r.routeTemplate }

// Method 返回声明的 HTTP 方法。
func (r Route) Method() string { return r.method }

// ResourceServer 返回 Action 第一段的授权命名空间。
func (r Route) ResourceServer() string { return r.resourceServer }

// Resource 返回从逻辑路由名称派生的稳定资源编码。
func (r Route) Resource() string { return r.resource }

// Action 返回声明的业务能力。
func (r Route) Action() string { return r.action }

type decisionRequest struct {
	ResourceServer string `json:"resource_server"`
	Resource       string `json:"resource"`
	HTTPMethod     string `json:"http_method"`
	ExpectedAction string `json:"expected_action,omitempty"`
}
