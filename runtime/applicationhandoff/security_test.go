package applicationhandoff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

// TestClientClonesHTTPClientDropsCookiesAndNeverFollowsRedirects 验证调用方 Client 不被修改，且凭据不会跨重定向或 Cookie Jar 传播。
func TestClientClonesHTTPClientDropsCookiesAndNeverFollowsRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") != "" {
			t.Fatalf("Cookie = %q", request.Header.Get("Cookie"))
		}
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer source.Close()
	jar, _ := cookiejar.New(nil)
	originalRedirect := func(*http.Request, []*http.Request) error { return nil }
	injected := &http.Client{Jar: jar, CheckRedirect: originalRedirect}
	client, err := New(Config{BaseURL: source.URL, HTTPClient: injected})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Create(t.Context(), staticToken("bearer-secret"), validCreateInput())
	if err == nil || redirected.Load() != 0 || injected.Jar != jar || injected.CheckRedirect == nil {
		t.Fatalf("err/redirected = %v/%d", err, redirected.Load())
	}
}

// TestCreateBoundsTimeoutAndResponseBody 验证总超时与响应体上限都失败关闭。
func TestCreateBoundsTimeoutAndResponseBody(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			writer.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		client, _ := New(Config{BaseURL: server.URL, Timeout: 20 * time.Millisecond})
		_, err := client.Create(t.Context(), staticToken("bearer-secret"), validCreateInput())
		var typed *core.Error
		if !errors.As(err, &typed) || typed.Kind != core.KindIAMUnavailable || !typed.Retryable {
			t.Fatalf("error = %#v", err)
		}
	})
	t.Run("body limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"code":0,"message":"ok","data":"` + strings.Repeat("x", maxResponseBodyBytes) + `"}`))
		}))
		defer server.Close()
		client, _ := New(Config{BaseURL: server.URL})
		_, err := client.Create(t.Context(), staticToken("bearer-secret"), validCreateInput())
		var typed *core.Error
		if !errors.As(err, &typed) || typed.Kind != core.KindProtocol {
			t.Fatalf("error = %#v", err)
		}
	})
}

// TestCreateErrorsNeverExposeTokenOrResponse 验证 TokenSource 错误、非 2xx 正文和格式化 Client 均不泄漏敏感值。
func TestCreateErrorsNeverExposeTokenOrResponse(t *testing.T) {
	const secret = "do-not-leak-token"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"code":403,"message":"` + secret + `"}`))
	}))
	defer server.Close()
	client, _ := New(Config{BaseURL: server.URL})
	for _, invoke := range []func() error{
		func() error {
			_, err := client.Create(t.Context(), core.TokenSourceFunc(func(context.Context) (string, error) { return "", errors.New(secret) }), validCreateInput())
			return err
		},
		func() error {
			_, err := client.Create(t.Context(), staticToken(secret), validCreateInput())
			return err
		},
	} {
		err := invoke()
		if err == nil || strings.Contains(fmt.Sprintf("%v", err), secret) {
			t.Fatalf("unsafe error = %v", err)
		}
	}
	if strings.Contains(fmt.Sprintf("%v", client), secret) {
		t.Fatal("client formatting leaked token")
	}
}

// TestCreateRejectsMalformedBearerBeforeNetwork 验证空主体、空白和控制字符 Token 均不会进入请求头。
func TestCreateRejectsMalformedBearerBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	client, _ := New(Config{BaseURL: server.URL})
	for _, token := range []string{"=", "bad token", "bad\ntoken"} {
		if _, err := client.Create(t.Context(), staticToken(token), validCreateInput()); err == nil {
			t.Errorf("Create(token=%q) error = nil", token)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d", requests.Load())
	}
}

func staticToken(value string) core.TokenSource {
	return core.TokenSourceFunc(func(context.Context) (string, error) { return value, nil })
}

func validCreateInput() CreateInput {
	return CreateInput{ApplicationOpenID: testApplicationOpenID, DecisionID: "dec_0123456789abcdef0123456789abcdef", CorrelationID: "op_cor_1"}
}
