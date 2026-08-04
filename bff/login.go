package bff

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	internalrandom "github.com/swan-swan-swan/iam-core-client-sdk-go/internal/random"
)

func (c *Client) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowOnlyMethod(w, request, http.MethodGet) {
			return
		}
		if err := c.beginLogin(w, request); err != nil {
			writeBFFError(w, err)
		}
	})
}

func (c *Client) beginLogin(w http.ResponseWriter, request *http.Request) (resultErr error) {
	const operation = "bff.login"
	started := c.clock.Now()
	ctx := requestContext(request)
	defer func() { c.record(ctx, operation, resultErr, started) }()
	if w == nil || request == nil || request.Method != http.MethodGet {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	returnValues := query["return_to"]
	if len(returnValues) != 1 || !c.validReturnTo(returnValues[0]) {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	flowID, err := c.randomID()
	if err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	state, err := c.randomID()
	if err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	nonce, err := c.randomID()
	if err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	verifier, err := c.randomID()
	if err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	if !validPKCEVerifier(verifier) {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	now := c.clock.Now()
	expiresAt := now.Add(c.flowTTL)
	if !expiresAt.After(now) {
		return bffError(core.KindInvalidConfig, operation, 0, false)
	}
	flow := &session.Flow{
		ID: flowID, State: state, Nonce: nonce, CodeVerifier: verifier,
		ClientID: c.clientID, RedirectURL: c.redirectURL, ReturnTo: returnValues[0],
		CreatedAt: now, ExpiresAt: expiresAt,
	}
	if err := c.backend.PutFlow(request.Context(), flow); err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	authorizationURL, err := c.authorizationURL(flow)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	if err := c.setCookie(w, c.flowCookie, flowID); err != nil {
		return bffError(core.KindInvalidConfig, operation, 0, false)
	}
	redirectWithoutBody(w, authorizationURL)
	return nil
}

func (c *Client) authorizationURL(flow *session.Flow) (string, error) {
	if flow == nil {
		return "", errors.New("invalid flow")
	}
	endpoint, err := url.Parse(c.core.Metadata().AuthorizationEndpoint)
	if err != nil || endpoint.Hostname() == "" {
		return "", errors.New("invalid authorization endpoint")
	}
	query := endpoint.Query()
	query.Set("response_type", "code")
	query.Set("client_id", c.clientID)
	query.Set("redirect_uri", c.redirectURL)
	query.Set("scope", strings.Join(c.scopes, " "))
	query.Set("state", flow.State)
	query.Set("nonce", flow.Nonce)
	query.Set("code_challenge", pkceChallenge(flow.CodeVerifier))
	query.Set("code_challenge_method", "S256")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func (c *Client) randomID() (string, error) {
	c.randomMu.Lock()
	defer c.randomMu.Unlock()
	return internalrandom.ID(c.random, 32)
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) != 43 {
		return false
	}
	for _, character := range verifier {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func redirectWithoutBody(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func writeBFFError(w http.ResponseWriter, err error) {
	if w == nil {
		return
	}
	status := http.StatusServiceUnavailable
	var typed *core.Error
	if errors.As(err, &typed) {
		switch typed.Kind {
		case core.KindInvalidConfig, core.KindProtocol:
			status = http.StatusBadRequest
		case core.KindUnauthenticated, core.KindForbidden, core.KindCredentialConflict:
			status = http.StatusUnauthorized
		case core.KindIAMUnavailable, core.KindSessionUnavailable:
			status = http.StatusServiceUnavailable
		}
	}
	http.Error(w, http.StatusText(status), status)
}

func requestContext(request *http.Request) context.Context {
	if request == nil {
		return context.Background()
	}
	return request.Context()
}
