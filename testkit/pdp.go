package testkit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// HTTPDecision configures one response from PDP. Zero HTTPStatus means 200.
type HTTPDecision struct {
	HTTPStatus int
	Code       int
	Message    string
	DecisionID string
	ReasonCode string
	Allowed    bool
	Delay      time.Duration
}

// PDPCall is the credential and frozen route tuple received by PDP.
type PDPCall struct {
	Authorization  string
	ResourceServer string
	Resource       string
	HTTPMethod     string
}

// PDP is an in-process IAM Core authorization decision endpoint for tests.
type PDP struct {
	t         testing.TB
	server    *httptest.Server
	mu        sync.Mutex
	queued    []HTTPDecision
	calls     []PDPCall
	closeOnce sync.Once
}

// NewPDP starts a PDP that denies requests unless a decision is explicitly queued.
func NewPDP(t testing.TB) *PDP {
	t.Helper()
	p := &PDP{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorization/v1/decisions", p.handleDecision)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// URL returns the fake PDP issuer URL.
func (p *PDP) URL() string {
	return p.server.URL
}

// Enqueue appends one response to the FIFO decision queue.
func (p *PDP) Enqueue(decision HTTPDecision) {
	p.mu.Lock()
	p.queued = append(p.queued, decision)
	p.mu.Unlock()
}

// Calls returns a snapshot of received decision requests.
// Authorization values are retained by contract; callers must not log them.
func (p *PDP) Calls() []PDPCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PDPCall(nil), p.calls...)
}

// Close stops the fake PDP server.
func (p *PDP) Close() {
	p.closeOnce.Do(p.server.Close)
}

func (p *PDP) handleDecision(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		ResourceServer string `json:"resource_server"`
		Resource       string `json:"resource"`
		HTTPMethod     string `json:"http_method"`
	}
	_ = json.NewDecoder(request.Body).Decode(&payload)

	p.mu.Lock()
	p.calls = append(p.calls, PDPCall{
		Authorization:  request.Header.Get("Authorization"),
		ResourceServer: payload.ResourceServer,
		Resource:       payload.Resource,
		HTTPMethod:     payload.HTTPMethod,
	})
	decision := HTTPDecision{
		HTTPStatus: http.StatusOK,
		Message:    "success",
		DecisionID: "default-deny",
		ReasonCode: "default_deny",
	}
	if len(p.queued) > 0 {
		decision = p.queued[0]
		p.queued = p.queued[1:]
		if decision.HTTPStatus == 0 {
			decision.HTTPStatus = http.StatusOK
		}
		if decision.Message == "" {
			decision.Message = "success"
		}
		if decision.DecisionID == "" {
			decision.DecisionID = "queued-decision"
		}
		if decision.ReasonCode == "" {
			decision.ReasonCode = "default_deny"
			if decision.Allowed {
				decision.ReasonCode = "policy_allow"
			}
		}
	}
	p.mu.Unlock()

	if decision.Delay > 0 {
		timer := time.NewTimer(decision.Delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-request.Context().Done():
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(decision.HTTPStatus)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    decision.Code,
		"message": decision.Message,
		"data": map[string]any{
			"decision_id": decision.DecisionID,
			"allowed":     decision.Allowed,
			"reason_code": decision.ReasonCode,
		},
	})
}
