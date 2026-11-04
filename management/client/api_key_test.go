package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAPIKeyManagementTransportUsesDirectCredential 验证受控客户端直接使用 Key，无需 TokenSource。
func TestAPIKeyManagementTransportUsesDirectCredential(t *testing.T) {
	key := "iak_01ARZ3NDEKTSV4RRFFQ69G5FAV." + strings.Repeat("A", 43)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "ApiKey "+key || r.Header.Get("Cookie") != "" {
			t.Error("unexpected auth scheme or cookie")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"success","data":null}`))
	}))
	defer server.Close()
	source := APIKeySourceFunc(func(context.Context) (string, error) { return key, nil })
	c, err := New(Config{BaseURL: server.URL, APIKeySource: source})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(t.Context(), Request{Operation: "management.userdirectory.search", Method: "GET", Path: "/api/v1/user-directory/users"}, nil); err != nil || calls != 1 {
		t.Fatalf("direct call failed: %v calls=%d", err, calls)
	}
	if _, err := New(Config{BaseURL: server.URL, APIKeySource: source, TokenSource: staticTokenSource("token")}); err == nil {
		t.Fatal("ambiguous credential sources accepted")
	}
}

// TestAPIKeyManagementRejectsTypedNilSource 避免带类型的空源绕过配置互斥后触发 panic。
func TestAPIKeyManagementRejectsTypedNilSource(t *testing.T) {
	var source APIKeySourceFunc
	if _, err := New(Config{BaseURL: "https://iam.example.com", APIKeySource: source, TokenSource: staticTokenSource("token")}); err == nil {
		t.Fatal("typed nil API Key source accepted")
	}
}
