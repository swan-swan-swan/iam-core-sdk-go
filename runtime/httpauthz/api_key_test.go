package httpauthz_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpauthz"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAPIKeyRequireAuthenticatesOnlineAndEnforcesPolicy 验证真实 SDK 请求链路，无 JWT 或 Token 换取。
func TestAPIKeyRequireAuthenticatesOnlineAndEnforcesPolicy(t *testing.T) {
	key := "iak_01ARZ3NDEKTSV4RRFFQ69G5FAV." + strings.Repeat("A", 43)
	resolves, decisions, calls := 0, 0, 0
	revoked, allowed := false, true
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "ApiKey "+key || r.Header.Get("Cookie") != "" {
			t.Error("incorrect credential forwarding")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/authorization/v1/credentials/resolve":
			resolves++
			if revoked {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"code":40101,"message":"invalid_api_key","data":null}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "success", "data": map[string]any{"subject_type": "service_account", "subject_open_id": "op_sa_beacon", "credential_open_id": "op_sak_01ARZ3NDEKTSV4RRFFQ69G5FAV", "application_open_id": "op_app_orders", "expires_at": time.Now().Add(time.Hour).UTC()}})
		case "/authorization/v1/decisions":
			decisions++
			var input map[string]any
			if json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 4 || input["resource"] != "orders.item.list" {
				t.Error("PDP request not bound to compiled route")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "success", "data": map[string]any{"decision_id": "dec-key", "allowed": allowed, "reason_code": "policy", "action": "orders:orders:select"}})
		default:
			t.Error("unexpected authentication endpoint")
			w.WriteHeader(500)
		}
	}))
	defer iam.Close()
	pdp, err := httpauthz.NewPDPClient(httpauthz.PDPConfig{IssuerURL: iam.URL, HTTPClient: iam.Client()})
	if err != nil {
		t.Fatal(err)
	}
	verifier := &fakeVerifier{}
	s, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp, APIKeyAuthenticator: pdp, APIKeyAuthorizer: pdp})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		auth, ok := core.AuthContextFromContext(r.Context())
		if !ok || auth.Subject != "op_sa_beacon" || auth.CredentialOpenID == "" || auth.AuthorizedParty != "" {
			t.Error("identity was lost or masqueraded as client")
		}
		w.WriteHeader(200)
	}))
	if err != nil {
		t.Fatal(err)
	}
	call := func() int {
		req := httptest.NewRequest("GET", "/orders", nil)
		req.Header.Set("Authorization", "ApiKey "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if status := call(); status != 200 || resolves != 1 || decisions != 1 || calls != 1 || verifier.calls != 0 {
		t.Fatalf("initial status=%d resolve=%d decide=%d handler=%d JWT=%d", status, resolves, decisions, calls, verifier.calls)
	}
	allowed = false
	if status := call(); status != 403 || calls != 1 {
		t.Fatalf("missing permission status=%d handler=%d", status, calls)
	}
	revoked = true
	if status := call(); status != 401 || decisions != 2 || calls != 1 {
		t.Fatalf("revoked status=%d decide=%d handler=%d", status, decisions, calls)
	}
}

// TestAPIKeyIdentityFailsClosed 验证过期、重复字段及重定向响应不能成为程序身份。
func TestAPIKeyIdentityFailsClosed(t *testing.T) {
	key := "iak_01ARZ3NDEKTSV4RRFFQ69G5FAV." + strings.Repeat("A", 43)
	for name, response := range map[string]string{
		"expired":     `{"code":0,"message":"success","data":{"subject_type":"service_account","subject_open_id":"op_sa_x","credential_open_id":"op_sak_01ARZ3NDEKTSV4RRFFQ69G5FAV","application_open_id":"op_app_x","expires_at":"2020-01-01T00:00:00Z"}}`,
		"duplicate":   `{"code":0,"message":"success","data":{"subject_type":"user","subject_type":"service_account"}}`,
		"secret-body": key,
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(response))
			}))
			defer upstream.Close()
			pdp, err := httpauthz.NewPDPClient(httpauthz.PDPConfig{IssuerURL: upstream.URL, HTTPClient: upstream.Client()})
			if err != nil {
				t.Fatal(err)
			}
			auth, err := pdp.AuthenticateAPIKey(t.Context(), core.APIKeySourceFunc(func(context.Context) (string, error) { return key, nil }))
			if err == nil || auth.Subject != "" || strings.Contains(fmt.Sprint(err), key) {
				t.Fatalf("unsafe identity result: %v", err)
			}
		})
	}
	followed := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed++ }))
	defer destination.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	pdp, err := httpauthz.NewPDPClient(httpauthz.PDPConfig{IssuerURL: upstream.URL, HTTPClient: upstream.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pdp.AuthenticateAPIKey(t.Context(), core.APIKeySourceFunc(func(context.Context) (string, error) { return key, nil }))
	if err == nil || followed != 0 {
		t.Fatal("API Key redirect followed")
	}
}
