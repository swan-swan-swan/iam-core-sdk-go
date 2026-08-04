package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

type countingFlowBackend struct {
	session.Backend
	putCalls     atomic.Int32
	consumeCalls atomic.Int32
}

func (b *countingFlowBackend) PutFlow(ctx context.Context, flow *session.Flow) error {
	b.putCalls.Add(1)
	return b.Backend.PutFlow(ctx, flow)
}

func (b *countingFlowBackend) ConsumeFlow(ctx context.Context, id string) (*session.Flow, error) {
	b.consumeCalls.Add(1)
	return b.Backend.ConsumeFlow(ctx, id)
}

func TestMeReturnsOnlyTypedAuthContextWithoutLifecycleSecrets(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	response := httptest.NewRecorder()
	request := requestWithSessionCookie(item.ID)
	client.MeHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Me response status/content-type/cache=%d/%q/%q", response.Code, response.Header().Get("Content-Type"), response.Header().Get("Cache-Control"))
	}
	var auth core.AuthContext
	if err := json.Unmarshal(response.Body.Bytes(), &auth); err != nil || auth.Subject != item.Auth.Subject ||
		!reflect.DeepEqual(auth.Groups, item.Auth.Groups) {
		t.Fatalf("Me AuthContext=%#v err=%v", auth, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"Source", "SessionID", "Tokens", "FlowID", "AccessToken", "RefreshToken", "IDToken", "Nonce", "CodeVerifier",
		"source", "session_id", "tokens", "flow_id", "access_token", "refresh_token", "id_token", "nonce", "code_verifier",
	} {
		if _, exposed := fields[forbidden]; exposed {
			t.Fatalf("Me exposed forbidden field %q", forbidden)
		}
	}
	body := response.Body.String()
	for _, secret := range []string{
		item.ID, item.Tokens.AccessToken, item.Tokens.RefreshToken, item.Tokens.IDToken,
		"authorization-code-sensitive", "client-secret-sensitive", "nonce-sensitive", "verifier-sensitive",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("Me exposed lifecycle secret material")
		}
	}
}

func TestMeRequiresPresentAuthenticatedSession(t *testing.T) {
	client, _, _ := newRefreshTestClient(t)
	response := httptest.NewRecorder()
	client.MeHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/me", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Me status=%d", response.Code)
	}
}

func TestLifecycleHandlersRejectWrongMethodsWithNoSideEffects(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	flow := &session.Flow{
		ID: "flow-cookie-sensitive", State: "state-sensitive", Nonce: "nonce-sensitive",
		CodeVerifier: "verifier-sensitive", ClientID: testClientID,
		RedirectURL: issuer.Server.URL + "/callback", ReturnTo: "/",
		CreatedAt: refreshTestNow, ExpiresAt: refreshTestNow.Add(10 * time.Minute),
	}
	if err := backend.PutFlow(t.Context(), flow); err != nil {
		t.Fatal(err)
	}
	counting := &countingFlowBackend{Backend: backend}
	client.backend = counting
	tests := []struct {
		name    string
		method  string
		handler http.Handler
		flow    bool
	}{
		{name: "login", method: http.MethodPost, handler: client.LoginHandler()},
		{name: "callback", method: http.MethodPost, handler: client.CallbackHandler(), flow: true},
		{name: "me", method: http.MethodPost, handler: client.MeHandler()},
		{name: "local logout", method: http.MethodGet, handler: client.LocalLogoutHandler()},
		{name: "central logout", method: http.MethodGet, handler: client.CentralLogoutHandler()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before, err := backend.Get(t.Context(), item.ID)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, "/auth?return_to=%2F", nil)
			request.AddCookie(&http.Cookie{Name: client.sessionCookie.Name, Value: item.ID})
			if test.flow {
				request.AddCookie(&http.Cookie{Name: client.flowCookie.Name, Value: "flow-cookie-sensitive"})
			}
			test.handler.ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed || len(response.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("status=%d Set-Cookie=%v", response.Code, response.Header().Values("Set-Cookie"))
			}
			after, err := backend.Get(t.Context(), item.ID)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("wrong-method handler mutated session state")
			}
			if test.flow {
				stored, err := backend.ConsumeFlow(t.Context(), flow.ID)
				if err != nil || !reflect.DeepEqual(stored, flow) {
					t.Fatalf("wrong-method callback consumed or mutated Flow: flow=%#v err=%v", stored, err)
				}
			}
		})
	}
	if counting.putCalls.Load() != 0 || counting.consumeCalls.Load() != 0 {
		t.Fatalf("wrong-method handlers performed Flow work: put=%d consume=%d", counting.putCalls.Load(), counting.consumeCalls.Load())
	}
	if issuer.RefreshCalls() != 0 || issuer.UserInfoCalls() != 0 || issuer.EndSessionCalls() != 0 {
		t.Fatal("wrong-method handler performed remote work")
	}
}
