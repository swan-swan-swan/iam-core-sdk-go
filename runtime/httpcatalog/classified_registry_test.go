package httpcatalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
)

// classifiedGoldenDigest 固定 SDK 与 IAM 共用清单的规范摘要。
const classifiedGoldenDigest = "sha256:dcbe88742790dfa490d74f88444874892dfb17b1d1aff5888f169c2b58ada700"

// classifiedFixture 读取跨组件共用的五字段清单。
func classifiedFixture(t *testing.T) httpcatalog.ClassifiedManifest {
	t.Helper()
	b, err := os.ReadFile("testdata/classified-manifest-v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var m httpcatalog.ClassifiedManifest
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// classifiedConfig 提供分类注册测试的固定身份和注入凭据。
func classifiedConfig(url string) httpcatalog.Config {
	return httpcatalog.Config{BaseURL: url, Application: "opsgw", Service: "ops-gateway-server", Release: "policy-classification-cutover", DeploymentGeneration: 101, Credentials: httpcatalog.RegistrarCredentialSourceFunc(func(context.Context) (httpcatalog.RegistrarCredentials, error) {
		return httpcatalog.RegistrarCredentials{ClientID: "opsgw-catalog-registrar", ClientSecret: "injected-secret"}, nil
	})}
}

// classifiedRegistry 将固定清单逐条登记到 v4 Registry。
func classifiedRegistry(t *testing.T, url string) *httpcatalog.Registry {
	t.Helper()
	r, err := httpcatalog.NewClassifiedRegistry(classifiedConfig(url))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range classifiedFixture(t).Routes {
		s, err := httpauthz.NewClassifiedRouteSpec(v.Method, v.RouteTemplate, v.Name, v.Action, v.PolicyClass)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.RegisterClassified(s); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// TestClassifiedGoldenDigest 防止字段顺序、schema或类别丢失破坏跨组件摘要。
func TestClassifiedGoldenDigest(t *testing.T) {
	m := classifiedFixture(t)
	got, err := m.ManifestDigest()
	if err != nil || got != classifiedGoldenDigest {
		t.Fatalf("digest=%s error=%v", got, err)
	}
	m.Release = "another-release"
	m.DeploymentGeneration++
	if got, _ := m.ManifestDigest(); got != classifiedGoldenDigest {
		t.Fatal("deployment metadata changed digest")
	}
	m.Routes[0].PolicyClass = authzcontract.PolicyClassFullAccess
	if got, _ := m.ManifestDigest(); got == classifiedGoldenDigest {
		t.Fatal("class-only change did not change digest")
	}
}

// TestClassifiedRegistryModesAndCopies 防止混用schema、同Action冲突或导出别名修改内部清单。
func TestClassifiedRegistryModesAndCopies(t *testing.T) {
	r := classifiedRegistry(t, "http://127.0.0.1:1")
	m, err := r.ExportClassifiedManifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != "4" || m.Routes[0].Name != "admin.application.select" {
		t.Fatalf("manifest=%#v", m)
	}
	if digest, _ := m.ManifestDigest(); digest != classifiedGoldenDigest {
		t.Fatalf("digest=%s", digest)
	}
	s, err := httpauthz.NewClassifiedRouteSpec("GET", "/api/v1/portal/apps/:applicationOpenId/open", "portal.app.jenkins.open", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.RegisterClassified(s); err != nil {
		t.Fatal("identical repeat rejected")
	}
	s.PolicyClass = authzcontract.PolicyClassFullAccess
	if err = r.RegisterClassified(s); err == nil {
		t.Fatal("same-name class conflict accepted")
	}
	s.Spec.Name = "portal.app.jenkins.alternative"
	if err = r.RegisterClassified(s); err == nil {
		t.Fatal("same-action class conflict accepted")
	}
	s.PolicyClass = ""
	if err = r.RegisterClassified(s); err == nil {
		t.Fatal("forged class accepted")
	}
	if err = r.Register(s.Spec); err == nil {
		t.Fatal("v4 accepted v3 Register")
	}
	v3, err := httpcatalog.NewRegistry(classifiedConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if err = v3.RegisterClassified(s); err == nil {
		t.Fatal("v3 accepted classified Register")
	}
	if _, err = v3.ExportClassifiedManifest(); err == nil {
		t.Fatal("v3 exported v4")
	}
	m.Routes[0].PolicyClass = ""
	again, err := r.ExportClassifiedManifest()
	if err != nil {
		t.Fatal(err)
	}
	if digest, _ := again.ManifestDigest(); digest != classifiedGoldenDigest {
		t.Fatal("export alias mutated registry")
	}
	var nilRegistry *httpcatalog.Registry
	if err = nilRegistry.RegisterClassified(s); err == nil {
		t.Fatal("nil registry accepted route")
	}
	if _, err = nilRegistry.ExportClassifiedManifest(); err == nil {
		t.Fatal("nil registry exported")
	}
}

// TestClassifiedSyncHeartbeatWire 验证真实PUT五字段报文、Registrar认证和续约摘要。
func TestClassifiedSyncHeartbeatWire(t *testing.T) {
	puts, posts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "opsgw-catalog-registrar" || secret != "injected-secret" {
			t.Error("wrong registrar authentication")
		}
		if r.Method == http.MethodPut {
			puts++
			b, _ := io.ReadAll(r.Body)
			var m httpcatalog.ClassifiedManifest
			if err := json.Unmarshal(b, &m); err != nil {
				t.Error(err)
			}
			if m.SchemaVersion != "4" || len(m.Routes) != 3 {
				t.Errorf("wrong classified manifest: %s", b)
			}
			if digest, _ := m.ManifestDigest(); digest != classifiedGoldenDigest {
				t.Error("wire digest differs from golden")
			}
			var raw struct {
				Routes []map[string]json.RawMessage `json:"routes"`
			}
			_ = json.Unmarshal(b, &raw)
			for _, v := range raw.Routes {
				if len(v) != 5 {
					t.Error("route wire field count changed")
				}
			}
		} else if r.Method == http.MethodPost {
			posts++
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["manifest_hash"] != classifiedGoldenDigest || b["deployment_generation"] != float64(101) || b["catalog_hash"] != heartbeatHash {
				t.Errorf("heartbeat=%v", b)
			}
		} else {
			t.Error("unexpected request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":0,"data":{"application":"opsgw","catalog_hash":"`+heartbeatHash+`","deployment_generation":101,"manifest_hash":"`+classifiedGoldenDigest+`","changed":true}}`)
	}))
	defer server.Close()
	registry := classifiedRegistry(t, server.URL)
	if _, err := registry.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := registry.HeartbeatOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := registry.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	extra, err := httpauthz.NewClassifiedRouteSpec("GET", "/api/v1/portal/apps/:id/cloud-roles", "portal.app.jenkins.cloudroles", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.RegisterClassified(extra); err != nil {
		t.Fatal(err)
	}
	if err = registry.Check(t.Context()); err == nil {
		t.Fatal("changed manifest remained healthy")
	}
	if err = registry.HeartbeatOnce(t.Context()); !errors.Is(err, httpcatalog.ErrManifestChanged) {
		t.Fatalf("heartbeat error=%v", err)
	}
	if _, err = registry.Sync(t.Context()); !errors.Is(err, httpcatalog.ErrManifestChanged) {
		t.Fatalf("sync error=%v", err)
	}
	if puts != 1 || posts != 1 {
		t.Fatalf("unexpected network calls: PUT=%d POST=%d", puts, posts)
	}
}

// TestClassifiedSyncFailsClosed 防止旧服务端错误、错误摘要或代次冲突触发自动v3回退。
func TestClassifiedSyncFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"old-server", 400, `{"code":400,"message":"sensitive-response"}`},
		{"downgrade", 409, `{"code":409,"message":"catalog_schema_downgrade sensitive-response"}`},
		{"digest", 200, `{"code":0,"data":{"application":"opsgw","catalog_hash":"` + heartbeatHash + `","deployment_generation":101,"manifest_hash":"` + heartbeatHash + `"}}`},
		{"generation", 200, `{"code":0,"data":{"application":"opsgw","catalog_hash":"` + heartbeatHash + `","deployment_generation":100,"manifest_hash":"` + classifiedGoldenDigest + `"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			registry := classifiedRegistry(t, server.URL)
			_, err := registry.Sync(t.Context())
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unsafe result=%v", err)
			}
			if err = registry.Check(t.Context()); err == nil {
				t.Fatal("failed registry healthy")
			}
			if err = registry.HeartbeatOnce(t.Context()); err == nil {
				t.Fatal("unregistered heartbeat accepted")
			}
			if requests != 1 {
				t.Fatalf("automatically retried/downgraded: %d", requests)
			}
			if tc.status == 409 {
				if _, err = registry.Sync(t.Context()); !errors.Is(err, httpcatalog.ErrGenerationConflict) {
					t.Fatal("generation conflict did not fence instance")
				}
				if requests != 1 {
					t.Fatal("fenced instance re-registered")
				}
			}
		})
	}
}

// TestClassifiedHeartbeatDowngradeFences 防止续约被旧协议拒绝后重新发布或剥离分类。
func TestClassifiedHeartbeatDowngradeFences(t *testing.T) {
	puts, posts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts++
			_, _ = io.WriteString(w, `{"code":0,"data":{"application":"opsgw","catalog_hash":"`+heartbeatHash+`","deployment_generation":101,"manifest_hash":"`+classifiedGoldenDigest+`"}}`)
		} else {
			posts++
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"code":409,"message":"catalog_schema_downgrade"}`)
		}
	}))
	defer server.Close()
	registry := classifiedRegistry(t, server.URL)
	if _, err := registry.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := registry.HeartbeatOnce(t.Context()); !errors.Is(err, httpcatalog.ErrGenerationConflict) {
		t.Fatalf("heartbeat=%v", err)
	}
	if err := registry.Check(t.Context()); err == nil {
		t.Fatal("fenced instance healthy")
	}
	if _, err := registry.Sync(t.Context()); !errors.Is(err, httpcatalog.ErrGenerationConflict) {
		t.Fatalf("sync=%v", err)
	}
	if err := registry.RunHeartbeat(t.Context()); !errors.Is(err, httpcatalog.ErrGenerationConflict) {
		t.Fatalf("heartbeat loop=%v", err)
	}
	if puts != 1 || posts != 1 {
		t.Fatalf("unexpected requests: PUT=%d POST=%d", puts, posts)
	}
}

// TestClassifiedConflictIdentifiesPolicyClass 防止冲突被报告为无法定位的普通同步错误。
func TestClassifiedConflictIdentifiesPolicyClass(t *testing.T) {
	registry := classifiedRegistry(t, "http://127.0.0.1:1")
	spec, err := httpauthz.NewClassifiedRouteSpec("GET", "/another", "portal.app.jenkins.another", "opsgw:jenkins:access", authzcontract.PolicyClassFullAccess)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.RegisterClassified(spec); err == nil || !strings.Contains(err.Error(), "policy_class") {
		t.Fatalf("class conflict error=%v", err)
	}
	spec.PolicyClass = "sensitive-value"
	if err = registry.RegisterClassified(spec); err == nil || !strings.Contains(err.Error(), "policy_class") || strings.Contains(err.Error(), "sensitive-value") {
		t.Fatalf("class validation error=%v", err)
	}
}
