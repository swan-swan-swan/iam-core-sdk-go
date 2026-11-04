package httpauthz

import (
	"bytes"
	"context"
	"encoding/json"
	wirecredential "github.com/swan-swan-swan/iam-core-sdk-go/v3/internal/credential"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/internal/nilcheck"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// apiKeyIdentityFields 限定身份解析响应的精确规范字段名。
var apiKeyIdentityFields = map[string]struct{}{"subject_type": {}, "subject_open_id": {}, "credential_open_id": {}, "application_open_id": {}, "expires_at": {}, "never_expires": {}}

// AuthenticateAPIKey 每次向可信 IAM 在线确认服务账号身份，不签发或缓存 Token。
func (c *PDPClient) AuthenticateAPIKey(ctx context.Context, source core.APIKeySource) (auth core.AuthContext, resultErr error) {
	if c == nil || ctx == nil || c.httpClient == nil {
		return auth, newPDPError(core.KindInvalidConfig, credentialOperation, 0, false)
	}
	started := time.Now()
	defer func() {
		outcome := "authenticated"
		if resultErr != nil {
			outcome = "error"
		}
		c.observer.Observe(ctx, core.Event{Operation: "httpauthz.api_key.authenticate", Outcome: outcome, CredentialSource: "api_key", Duration: time.Since(started)})
	}()
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	key, id, err := readAPIKey(callCtx, source)
	if err != nil {
		return auth, err
	}
	endpoint := strings.TrimSuffix(c.endpoint, "/decisions") + "/credentials/resolve"
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return auth, newPDPError(core.KindInvalidConfig, credentialOperation, 0, false)
	}
	request.Header.Set("Authorization", "ApiKey "+key)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return auth, ctx.Err()
		}
		return auth, newPDPError(core.KindIAMUnavailable, credentialOperation, 0, true)
	}
	if response == nil || response.Body == nil {
		return auth, newPDPError(core.KindIAMUnavailable, credentialOperation, 0, true)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return auth, decisionStatusError(response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDecisionResponseBytes+1))
	if err != nil {
		return auth, newPDPError(core.KindIAMUnavailable, credentialOperation, 200, true)
	}
	if int64(len(body)) > maxDecisionResponseBytes || !utf8.Valid(body) || !isJSONMediaType(response.Header.Get("Content-Type")) {
		return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') || walkObjectWithData(decoder, rootDecisionFields, apiKeyIdentityFields, true) != nil {
		return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
	}
	var envelope struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
		Data    *struct {
			SubjectType   string          `json:"subject_type"`
			Subject       string          `json:"subject_open_id"`
			CredentialID  string          `json:"credential_open_id"`
			ApplicationID string          `json:"application_open_id"`
			ExpiresAt     json.RawMessage `json:"expires_at"`
			NeverExpires  json.RawMessage `json:"never_expires"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Code == nil || *envelope.Code != 0 || !safeDecisionMetadata(envelope.Message, true) || envelope.Data == nil {
		return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
	}
	identity := envelope.Data
	if identity.SubjectType != "service_account" || !validIdentityID(identity.Subject, "op_sa_") || identity.CredentialID != id || !validIdentityID(identity.ApplicationID, "op_app_") {
		return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
	}
	neverExpires := false
	if len(identity.NeverExpires) > 0 {
		switch string(identity.NeverExpires) {
		case "true":
			neverExpires = true
		case "false":
		default:
			return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
		}
	}
	var expires time.Time
	if neverExpires {
		if string(identity.ExpiresAt) != "null" {
			return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
		}
	} else {
		if json.Unmarshal(identity.ExpiresAt, &expires) != nil || expires.IsZero() {
			return auth, newPDPError(core.KindProtocol, credentialOperation, 200, false)
		}
		if !expires.After(time.Now()) {
			return auth, newPDPError(core.KindUnauthenticated, credentialOperation, 401, false)
		}
	}
	return core.AuthContext{Subject: identity.Subject, SubjectType: "service_account", CredentialOpenID: identity.CredentialID, ApplicationOpenID: identity.ApplicationID, AuthenticationMethod: "api_key", Issuer: strings.TrimSuffix(c.endpoint, "/authorization/v1/decisions"), ExpiresAt: expires, NeverExpires: neverExpires}, nil
}

// DecideAPIKey 直接携带同一凭据向 IAM 请求一次路由策略判定。
func (c *PDPClient) DecideAPIKey(ctx context.Context, source core.APIKeySource, route Route) (decision Decision, resultErr error) {
	if c == nil || ctx == nil || !validRoute(route) {
		return decision, newPDPError(core.KindInvalidConfig, decideOperation, 0, false)
	}
	started := time.Now()
	defer func() { c.record(ctx, resultErr, started) }()
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	key, _, err := readAPIKey(callCtx, source)
	if err != nil {
		return decision, err
	}
	return c.sendDecision(ctx, callCtx, "ApiKey "+key, route)
}

// readAPIKey 校验注入源和传输格式，错误不得含有原始凭据。
func readAPIKey(ctx context.Context, source core.APIKeySource) (string, string, error) {
	if nilcheck.IsNil(source) {
		return "", "", newPDPError(core.KindInvalidConfig, credentialOperation, 0, false)
	}
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	key, err := source.APIKey(ctx)
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	id, valid := wirecredential.APIKeyID(key)
	if err != nil || !valid {
		return "", "", newPDPError(core.KindUnauthenticated, credentialOperation, 0, false)
	}
	return key, id, nil
}

// validIdentityID 验证在线解析的公开身份，避免响应中夹带敏感材料。
func validIdentityID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) <= len(prefix) || len(value) > 64 {
		return false
	}
	for _, r := range strings.TrimPrefix(value, prefix) {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
