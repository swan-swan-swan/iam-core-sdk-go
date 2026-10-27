package httpcatalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
)

// TestRegistrarCredentialsRotateAcrossSyncAndHeartbeat 验证同步及续约读取同一凭据源的当前值。
func TestRegistrarCredentialsRotateAcrossSyncAndHeartbeat(t *testing.T) {
	secret := "first-secret"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, value, ok := r.BasicAuth()
		if !ok || id != "beacon-catalog-registrar" || value != secret {
			t.Error("request did not use current registrar credentials")
		}
		requests++
		if r.Method == http.MethodPut {
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		writeHeartbeatSuccess(t, w, body, heartbeatHash)
	}))
	defer server.Close()
	source := httpcatalog.RegistrarCredentialSourceFunc(func(context.Context) (httpcatalog.RegistrarCredentials, error) {
		return httpcatalog.RegistrarCredentials{ClientID: "beacon-catalog-registrar", ClientSecret: secret}, nil
	})
	r, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify-server", Release: "test", Credentials: source})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Register(catalogSpec(t, "/notifications", "notify.task.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	secret = "rotated-secret"
	if err := r.HeartbeatOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d", requests)
	}
	_, err = httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify-server", Release: "test", Credentials: source, Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "token", nil })})
	if err == nil {
		t.Fatal("mixed credential modes accepted")
	}
}

// TestRegistrarFailuresExposeStatusWithoutCredentials 验证诊断保留状态码但不泄露凭据或响应正文。
func TestRegistrarFailuresExposeStatusWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("remote-sensitive-body"))
	}))
	defer server.Close()
	for name, source := range map[string]httpcatalog.RegistrarCredentialSource{
		"response": httpcatalog.RegistrarCredentialSourceFunc(func(context.Context) (httpcatalog.RegistrarCredentials, error) {
			return httpcatalog.RegistrarCredentials{ClientID: "beacon-catalog-registrar", ClientSecret: "sensitive-secret"}, nil
		}),
		"provider": httpcatalog.RegistrarCredentialSourceFunc(func(context.Context) (httpcatalog.RegistrarCredentials, error) {
			return httpcatalog.RegistrarCredentials{}, errors.New("provider-sensitive-secret")
		}),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify-server", Release: "test", Credentials: source})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Register(catalogSpec(t, "/notifications", "notify.task.select", "beacon:notify:select")); err != nil {
				t.Fatal(err)
			}
			_, err = r.Sync(t.Context())
			if err == nil {
				t.Fatal("missing authentication error")
			}
			if name == "response" && !strings.Contains(err.Error(), "HTTP 401") {
				t.Fatal("status code missing")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("sensitive diagnostic exposed")
			}
		})
	}
}
