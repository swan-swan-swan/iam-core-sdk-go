package bff

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

var frontchannelPlatformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type FrontchannelLogoutConfig struct {
	PlatformID string
	IAMOrigin  string
	Audience   string
}

func (c *Client) FrontchannelLogoutHandler(cfg FrontchannelLogoutConfig) (http.Handler, error) {
	platform := strings.TrimSpace(cfg.PlatformID)
	audience := strings.TrimSpace(cfg.Audience)
	origin, err := url.Parse(strings.TrimSpace(cfg.IAMOrigin))
	if err != nil || !frontchannelPlatformPattern.MatchString(platform) || audience == "" ||
		origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		(origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, configureError()
	}
	iamOrigin := origin.Scheme + "://" + origin.Host
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowOnlyMethod(w, request, http.MethodGet) {
			return
		}
		query, parseErr := url.ParseQuery(request.URL.RawQuery)
		if parseErr != nil || len(query) != 1 || len(query["logout_token"]) != 1 {
			writeBFFError(w, bffError(core.KindUnauthenticated, "bff.frontchannel_logout", 0, false))
			return
		}
		verified, verifyErr := c.core.VerifyLogoutToken(request.Context(), query.Get("logout_token"), audience)
		if verifyErr != nil {
			writeBFFError(w, verifyErr)
			return
		}
		c.clearCookie(w, c.sessionCookie)
		sessionID, present, cookieErr := c.logoutSessionID(request)
		if cookieErr != nil {
			writeBFFError(w, cookieErr)
			return
		}
		if present {
			if deleteErr := c.backend.Delete(request.Context(), sessionID); deleteErr != nil &&
				!errors.Is(deleteErr, session.ErrNotFound) && !errors.Is(deleteErr, session.ErrExpired) {
				writeBFFError(w, c.sessionBackendError("bff.frontchannel_logout", deleteErr))
				return
			}
		}
		message, _ := json.Marshal(map[string]string{
			"type": "iam.frontchannel_logout", "platform": platform,
			"tx_id": verified.TxID, "status": "success",
		})
		target, _ := json.Marshal(iamOrigin)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; frame-ancestors "+iamOrigin)
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=\"utf-8\"><script>parent.postMessage(%s,%s)</script>", message, target)
	}), nil
}
