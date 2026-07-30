// Command nethttp demonstrates the IAM Core SDK with the net/http adapter.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	iamcore "github.com/swan-swan-swan/iam-core-client-sdk-go"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/memory"
)

const defaultIssuer = "https://iam.wuhl-goose.top"

func main() {
	if err := run(); err != nil {
		// SDK errors are redacted. Configuration values and secrets are never logged.
		slog.Error("IAM Core example stopped")
		os.Exit(1)
	}
}

func run() error {
	clientID, clientSecret, redirectURL, err := requiredConfiguration()
	if err != nil {
		return err
	}

	// Memory is intended only for development, tests, and a single process.
	// It does not share sessions or refresh locks between application replicas.
	sessionBackend := memory.New(memory.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := iamcore.New(ctx, iamcore.Config{
		IssuerURL:            envOrDefault("IAMCORE_ISSUER_URL", defaultIssuer),
		ClientID:             clientID,
		ClientSecretProvider: iamcore.StaticSecret(clientSecret),
		RedirectURL:          redirectURL,
		Session: iamcore.SessionConfig{
			Backend: sessionBackend,
		},
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/login", client.LoginHandler())
	mux.Handle("/auth/callback", client.CallbackHandler())
	mux.Handle("/auth/logout", client.LogoutHandler())
	mux.Handle("/profile", client.Authenticate(http.HandlerFunc(profile)))
	mux.Handle("/assets", client.RequirePermission(iamcore.Permission{
		ResourceServer: "asset-api",
		Resource:       "assets",
	})(http.HandlerFunc(assets)))

	server := &http.Server{
		Addr:              envOrDefault("HTTP_ADDR", ":8080"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func profile(w http.ResponseWriter, request *http.Request) {
	identity, ok := iamcore.IdentityFromContext(request.Context())
	if !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(identity)
}

func assets(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"assets":[]}`))
}

func requiredConfiguration() (string, string, string, error) {
	clientID := os.Getenv("IAMCORE_CLIENT_ID")
	clientSecret := os.Getenv("IAMCORE_CLIENT_SECRET")
	redirectURL := os.Getenv("IAMCORE_REDIRECT_URL")
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return "", "", "", errors.New("IAM Core environment configuration is incomplete")
	}
	return clientID, clientSecret, redirectURL, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
