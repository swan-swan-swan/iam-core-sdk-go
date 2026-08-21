package applicationhandoff

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

const testApplicationOpenID = "op_app_0123456789abcdefghj"

// TestCreateUsesRequestScopedBearerAndExactWireContract 验证 Client 每次只读取一次调用方 Token，并使用冻结 JSON 契约。
func TestCreateUsesRequestScopedBearerAndExactWireContract(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/application-handoffs" || request.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer user-access-token" {
			t.Fatalf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(request.Body)
		if got := string(body); got != `{"applicationOpenId":"op_app_0123456789abcdefghj","decisionId":"dec_0123456789abcdef0123456789abcdef","correlationId":"op_cor_1"}` {
			t.Fatalf("body = %s", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"code":0,"message":"ok","data":{"handoffId":"op_hnd_0123456789abcdefghj","launchUrl":"https://jms.example.test/custom-sso?token=one-time","expiresIn":60}}`))
	}))
	defer server.Close()

	client, err := New(Config{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	output, err := client.Create(t.Context(), core.TokenSourceFunc(func(context.Context) (string, error) {
		tokenCalls.Add(1)
		return "user-access-token", nil
	}), CreateInput{ApplicationOpenID: testApplicationOpenID, DecisionID: "dec_0123456789abcdef0123456789abcdef", CorrelationID: "op_cor_1"})
	if err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 1 || output.HandoffID != "op_hnd_0123456789abcdefghj" || output.ExpiresIn != time.Minute || !strings.HasPrefix(output.LaunchURL, "https://jms.example.test/") {
		t.Fatalf("calls/output = %d / %#v", tokenCalls.Load(), output)
	}
}

// TestCreateRejectsInvalidInputBeforeTokenAndNetwork 验证 Subject 不属于输入协议，且无效上下文 ID 在取 Token 前失败。
func TestCreateRejectsInvalidInputBeforeTokenAndNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	var tokenCalls atomic.Int32
	_, err = client.Create(t.Context(), core.TokenSourceFunc(func(context.Context) (string, error) {
		tokenCalls.Add(1)
		return "secret-token", nil
	}), CreateInput{ApplicationOpenID: testApplicationOpenID, DecisionID: "bad", CorrelationID: "op_cor_1"})
	if err == nil || tokenCalls.Load() != 0 || requests.Load() != 0 {
		t.Fatalf("err/calls/requests = %v/%d/%d", err, tokenCalls.Load(), requests.Load())
	}
}

// TestNewNormalizesOnlySafeBaseURLs 验证末尾斜线不会改变端点，生产地址必须 HTTPS，且拒绝凭据、查询与片段。
func TestNewNormalizesOnlySafeBaseURLs(t *testing.T) {
	for _, value := range []string{
		"http://iam.example.test", "https://user@iam.example.test", "https://iam.example.test?token=x", "https://iam.example.test/#fragment", " https://iam.example.test",
	} {
		if _, err := New(Config{BaseURL: value}); err == nil {
			t.Errorf("New(%q) error = nil", value)
		}
	}
	client, err := New(Config{BaseURL: "https://iam.example.test/root/"})
	if err != nil || client.endpoint != "https://iam.example.test/root/api/v1/application-handoffs" {
		t.Fatalf("endpoint/error = %q/%v", client.endpoint, err)
	}
}
