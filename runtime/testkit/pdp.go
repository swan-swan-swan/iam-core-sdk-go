package testkit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxPDPRequestBytes int64 = 1 << 20

// HTTPDecision configures one response from PDP. Zero HTTPStatus means 200.
type HTTPDecision struct {
	HTTPStatus int
	Code       int
	Message    string
	DecisionID string
	ReasonCode string
	Allowed    bool
	Action     string
	Delay      time.Duration
}

// PDPCall is the credential and frozen route tuple received by PDP.
type PDPCall struct {
	Authorization  string
	ResourceServer string
	Resource       string
	HTTPMethod     string
	ExpectedAction string
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	call, err := decodePDPCall(request)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.calls = append(p.calls, call)
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
			"action":      decision.Action,
		},
	})
}

func decodePDPCall(request *http.Request) (PDPCall, error) {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
		return PDPCall{}, errors.New("invalid content type")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxPDPRequestBytes+1))
	if err != nil || int64(len(body)) > maxPDPRequestBytes {
		return PDPCall{}, errors.New("invalid body")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return PDPCall{}, errors.New("invalid body")
	}
	values := make(map[string]string, 4)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return PDPCall{}, errors.New("invalid body")
		}
		if _, duplicate := values[key]; duplicate {
			return PDPCall{}, errors.New("invalid body")
		}
		switch key {
		case "resource_server", "resource", "http_method", "expected_action":
		default:
			return PDPCall{}, errors.New("invalid body")
		}
		var value string
		if decoder.Decode(&value) != nil {
			return PDPCall{}, errors.New("invalid body")
		}
		values[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(values) < 3 {
		return PDPCall{}, errors.New("invalid body")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return PDPCall{}, errors.New("invalid body")
	}
	resourceServer, resource, method := values["resource_server"], values["resource"], values["http_method"]
	if !validPDPValue(resourceServer) || !validPDPValue(resource) || !validPDPMethod(method) ||
		(values["expected_action"] != "" && !validPDPAction(values["expected_action"])) {
		return PDPCall{}, errors.New("invalid decision coordinates")
	}
	return PDPCall{
		Authorization: request.Header.Get("Authorization"), ResourceServer: resourceServer,
		Resource: resource, HTTPMethod: method, ExpectedAction: values["expected_action"],
	}, nil
}

func validPDPValue(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func validPDPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func validPDPAction(action string) bool {
	parts := strings.Split(action, ":")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || part[0] < 'a' || part[0] > 'z' {
			return false
		}
		for _, character := range part[1:] {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}
