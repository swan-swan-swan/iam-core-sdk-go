package bff

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

func (c *Client) LocalLogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowOnlyMethod(w, request, http.MethodPost) {
			return
		}
		if err := c.localLogout(w, request); err != nil {
			writeBFFError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (c *Client) CentralLogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowOnlyMethod(w, request, http.MethodPost) {
			return
		}
		if err := c.centralLogout(w, request); err != nil {
			writeBFFError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// GlobalLogoutHandler clears the current application's local session and
// redirects the top-level browser to the trusted IAM end-session endpoint.
// Unlike CentralLogoutHandler it never performs a server-to-server request,
// because only browser navigation can clear cookies owned by other origins.
func (c *Client) GlobalLogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowOnlyMethod(w, request, http.MethodPost) {
			return
		}
		location, err := c.globalLogout(w, request)
		if err != nil {
			writeBFFError(w, err)
			return
		}
		http.Redirect(w, request, location, http.StatusSeeOther)
	})
}

func (c *Client) globalLogout(w http.ResponseWriter, request *http.Request) (string, error) {
	const operation = "bff.global_logout"
	c.clearCookie(w, c.sessionCookie)
	endpoint, err := url.Parse(c.core.Metadata().EndSessionEndpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", bffError(core.KindProtocol, operation, 0, false)
	}
	sessionID, present, err := c.logoutSessionID(request)
	if err != nil || !present {
		return endpoint.String(), err
	}
	item, err := c.backend.Get(request.Context(), sessionID)
	if err != nil && !errors.Is(err, session.ErrNotFound) && !errors.Is(err, session.ErrExpired) {
		return "", c.sessionBackendError(operation, err)
	}
	if deleteErr := c.backend.Delete(request.Context(), sessionID); deleteErr != nil &&
		!errors.Is(deleteErr, session.ErrNotFound) {
		return "", c.sessionBackendError(operation, deleteErr)
	}
	if err == nil && strings.TrimSpace(item.Tokens.IDToken) != "" {
		query := endpoint.Query()
		query.Set("id_token_hint", item.Tokens.IDToken)
		endpoint.RawQuery = query.Encode()
	}
	return endpoint.String(), nil
}

func (c *Client) localLogout(w http.ResponseWriter, request *http.Request) error {
	const operation = "bff.local_logout"
	c.clearCookie(w, c.sessionCookie)
	sessionID, present, err := c.logoutSessionID(request)
	if err != nil || !present {
		return err
	}
	if err := c.backend.Delete(request.Context(), sessionID); err != nil {
		return c.sessionBackendError(operation, err)
	}
	return nil
}

func (c *Client) centralLogout(w http.ResponseWriter, request *http.Request) error {
	const operation = "bff.central_logout"
	c.clearCookie(w, c.sessionCookie)
	sessionID, present, err := c.logoutSessionID(request)
	if err != nil || !present {
		return err
	}
	item, err := c.backend.Get(request.Context(), sessionID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
			return nil
		}
		return c.sessionBackendError(operation, err)
	}
	accessToken := item.Tokens.AccessToken
	idToken := item.Tokens.IDToken
	if err := c.backend.Delete(request.Context(), sessionID); err != nil {
		return c.sessionBackendError(operation, err)
	}
	if accessToken != strings.TrimSpace(accessToken) || idToken == "" || idToken != strings.TrimSpace(idToken) {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	return c.endSession(request.Context(), accessToken, idToken)
}

func (c *Client) logoutSessionID(request *http.Request) (string, bool, error) {
	const operation = "bff.logout_cookie"
	if request == nil {
		return "", false, bffError(core.KindProtocol, operation, 0, false)
	}
	cookies := request.CookiesNamed(c.sessionCookie.Name)
	if len(cookies) == 0 {
		return "", false, nil
	}
	if len(cookies) != 1 || !validCookieValue(cookies[0].Value) {
		return "", false, bffError(core.KindProtocol, operation, 0, false)
	}
	return cookies[0].Value, true, nil
}

func (c *Client) endSession(
	ctx context.Context,
	accessToken, idToken string,
) (resultErr error) {
	const operation = "bff.end_session"
	started := c.clock.Now()
	defer func() { c.record(ctx, operation, resultErr, started) }()
	if ctx == nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, c.endSessionTimeout)
	defer cancel()
	endpoint, err := url.Parse(c.core.Metadata().EndSessionEndpoint)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	query := endpoint.Query()
	query.Set("id_token_hint", idToken)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(operationCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	request.Header.Set("Accept", "application/json")
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if contextErr := operationContextError(ctx, operationCtx, operation, 0); contextErr != nil {
			return contextErr
		}
		return bffError(core.KindIAMUnavailable, operation, 0, true)
	}
	defer response.Body.Close()
	body, bodyErr := readBoundedEndSessionBody(response.Body)
	if bodyErr != nil {
		if contextErr := operationContextError(ctx, operationCtx, operation, response.StatusCode); contextErr != nil {
			return contextErr
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return statusOAuthError(operation, response.StatusCode)
	}
	if bodyErr != nil {
		return bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	if len(body) == 0 {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	var decoded any
	if decodeUniqueJSON(body, &decoded) != nil {
		return bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	return nil
}

func readBoundedEndSessionBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, errors.New("missing response body")
	}
	read, err := io.ReadAll(io.LimitReader(body, maxOAuthResponseBytes+1))
	if err != nil || len(read) > maxOAuthResponseBytes {
		return nil, errors.New("invalid response body")
	}
	return read, nil
}
