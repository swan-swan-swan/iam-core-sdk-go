// Command bff demonstrates the IAM Core server-side browser flow.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session/memory"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const startupTimeout = 10 * time.Second

type configuration struct {
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
	address      string
}

func main() {
	if err := run(); err != nil {
		// Never log configuration values, remote error details, or credential material.
		slog.Error("IAM Core BFF stopped", slog.String("reason", "startup configuration is missing or invalid, IAM is unavailable, or the server stopped"))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfiguration()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	runtime, err := core.New(ctx, core.Config{
		IssuerURL: cfg.issuerURL,
		Audiences: []string{cfg.clientID},
	})
	if err != nil {
		return errors.New("IAM Core discovery is invalid or unavailable")
	}

	backend := memory.New(memory.Options{})
	client, err := bff.New(bff.Config{
		Core:     runtime,
		ClientID: cfg.clientID,
		ClientSecret: bff.SecretProviderFunc(func(context.Context) (string, error) {
			return cfg.clientSecret, nil
		}),
		RedirectURL: cfg.redirectURL,
		Scopes:      bff.DefaultScopes(),
		Backend:     backend,
		SessionCookie: http.Cookie{
			Name:        "__Host-example_session",
			Value:       "",
			Path:        "/",
			Domain:      "",
			HttpOnly:    true,
			Secure:      true,
			SameSite:    http.SameSiteLaxMode,
			MaxAge:      0,
			Expires:     time.Time{},
			Partitioned: false,
		},
		FlowCookie: http.Cookie{
			Name:        "__Host-example_flow",
			Value:       "",
			Path:        "/",
			Domain:      "",
			HttpOnly:    true,
			Secure:      true,
			SameSite:    http.SameSiteLaxMode,
			MaxAge:      0,
			Expires:     time.Time{},
			Partitioned: false,
		},
	})
	if err != nil {
		return errors.New("IAM Core BFF configuration is invalid")
	}

	mux := http.NewServeMux()
	mux.Handle("GET /auth/login", client.LoginHandler())
	mux.Handle("GET /auth/callback", client.CallbackHandler())
	mux.Handle("GET /me", client.MeHandler())
	mux.Handle("POST /auth/logout/local", client.LocalLogoutHandler())
	mux.Handle("POST /auth/logout/central", client.CentralLogoutHandler())

	// The internal listener is intended to run behind trusted TLS termination;
	// browser-facing URLs and the registered redirect URL remain HTTPS.
	server := &http.Server{
		Addr:              cfg.address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server.ListenAndServe()
}

func loadConfiguration() (configuration, error) {
	values := []string{
		os.Getenv("IAMCORE_ISSUER_URL"),
		os.Getenv("IAMCORE_CLIENT_ID"),
		os.Getenv("IAMCORE_CLIENT_SECRET"),
		os.Getenv("IAMCORE_REDIRECT_URL"),
		os.Getenv("HTTP_ADDR"),
	}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) {
			return configuration{}, errors.New("IAM Core environment configuration is incomplete")
		}
	}
	return configuration{
		issuerURL: values[0], clientID: values[1], clientSecret: values[2],
		redirectURL: values[3], address: values[4],
	}, nil
}
