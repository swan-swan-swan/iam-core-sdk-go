package bff

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
)

func TestFrontchannelLogoutVerifiesTokenClearsSessionAndConstrainsMessage(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	token := signFrontchannelToken(t, issuer, testClientID, "tx_123", refreshTestNow.Add(time.Minute))
	handler, err := client.FrontchannelLogoutHandler(FrontchannelLogoutConfig{
		PlatformID: "portal", IAMOrigin: "https://iam.example.test", Audience: testClientID,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?logout_token="+token, nil)
	request.AddCookie(&http.Cookie{Name: client.sessionCookie.Name, Value: item.ID})
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "\"tx_123\"") ||
		!strings.Contains(response.Body.String(), "\"portal\"") ||
		!strings.Contains(response.Body.String(), "\"https://iam.example.test\"") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session remained: %v", err)
	}
	assertSessionCookieCleared(t, response, client.sessionCookie.Name)
}

func TestFrontchannelLogoutRejectsWrongAudienceWithoutClearingSession(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	token := signFrontchannelToken(t, issuer, "admin", "tx_123", refreshTestNow.Add(time.Minute))
	handler, err := client.FrontchannelLogoutHandler(FrontchannelLogoutConfig{
		PlatformID: "portal", IAMOrigin: "https://iam.example.test", Audience: testClientID,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?logout_token="+token, nil)
	request.AddCookie(&http.Cookie{Name: client.sessionCookie.Name, Value: item.ID})
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	if _, err := backend.Get(t.Context(), item.ID); err != nil {
		t.Fatalf("session was cleared: %v", err)
	}
}

func signFrontchannelToken(t *testing.T, issuer *refreshIssuer, audience, txID string, expiresAt time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer.Server.URL, "aud": audience, "exp": expiresAt.Unix(),
		"tx_id": txID, "purpose": "frontchannel_logout",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "refresh-key"
	raw, err := token.SignedString(issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
