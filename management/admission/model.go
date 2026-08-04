package admission

import "time"

type scopeKind uint8

const (
	applicationScopeKind scopeKind = iota + 1
	clientScopeKind
)

// Scope identifies either an Application-level or OIDC Client-level admission policy.
// Construct values with ApplicationScope or ClientScope so the two paths cannot be confused.
type Scope struct {
	ApplicationOpenID string
	ClientID          string
	kind              scopeKind
}

// ApplicationScope selects Application-level admission rules.
func ApplicationScope(applicationOpenID string) Scope {
	return Scope{ApplicationOpenID: applicationOpenID, kind: applicationScopeKind}
}

// ClientScope selects admission rules for one OIDC Client under an Application.
func ClientScope(applicationOpenID, clientID string) Scope {
	return Scope{ApplicationOpenID: applicationOpenID, ClientID: clientID, kind: clientScopeKind}
}

// Mutation is the complete revision-controlled admission rule input.
type Mutation struct {
	SubjectType      string
	SubjectOpenID    string
	Effect           string
	ExpectedRevision uint64
}

// Rule is a non-sensitive login admission rule.
type Rule struct {
	OpenID            string
	ApplicationOpenID string
	ClientID          string
	Scope             string
	SubjectType       string
	SubjectOpenID     string
	Effect            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Change contains the changed rule and the new authoritative policy head.
type Change struct {
	Rule     Rule
	Revision uint64
	Hash     string
}

// ListOptions configures one bounded admission-rule page.
type ListOptions struct {
	Page     int
	PageSize int
	Sort     string
	Order    string
}

// ListResult is one admission-rule page and its authoritative policy head.
type ListResult struct {
	Items    []Rule
	Page     int
	PageSize int
	Total    int64
	Revision uint64
	Hash     string
}

// Conflict can be decoded from client.ErrorData for a stale policy revision.
type Conflict struct {
	Revision uint64 `json:"login_policy_revision"`
	Hash     string `json:"login_policy_hash"`
	Impact   Impact `json:"impact"`
}

// Impact is the non-sensitive scope summary returned with a revision conflict.
type Impact struct {
	Scope             string `json:"scope"`
	ApplicationOpenID string `json:"application_open_id"`
	ClientID          string `json:"client_id,omitempty"`
	Operation         string `json:"operation"`
}

type ruleWire struct {
	OpenID            string    `json:"open_id"`
	ApplicationOpenID string    `json:"application_open_id"`
	ClientID          string    `json:"client_id,omitempty"`
	Scope             string    `json:"scope"`
	SubjectType       string    `json:"subject_type"`
	SubjectOpenID     string    `json:"subject_open_id"`
	Effect            string    `json:"effect"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (wire ruleWire) rule() Rule {
	return Rule{
		OpenID: wire.OpenID, ApplicationOpenID: wire.ApplicationOpenID, ClientID: wire.ClientID,
		Scope: wire.Scope, SubjectType: wire.SubjectType, SubjectOpenID: wire.SubjectOpenID,
		Effect: wire.Effect, CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}
}

type changeWire struct {
	Rule     ruleWire `json:"rule"`
	Revision uint64   `json:"login_policy_revision"`
	Hash     string   `json:"login_policy_hash"`
}

func (wire changeWire) change() Change {
	return Change{Rule: wire.Rule.rule(), Revision: wire.Revision, Hash: wire.Hash}
}

type admissionListWire struct {
	Items    []ruleWire `json:"items"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Total    int64      `json:"total"`
	Revision uint64     `json:"login_policy_revision"`
	Hash     string     `json:"login_policy_hash"`
}

func (wire admissionListWire) result() ListResult {
	items := make([]Rule, len(wire.Items))
	for index := range wire.Items {
		items[index] = wire.Items[index].rule()
	}
	return ListResult{
		Items: items, Page: wire.Page, PageSize: wire.PageSize, Total: wire.Total,
		Revision: wire.Revision, Hash: wire.Hash,
	}
}
