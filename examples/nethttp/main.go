// Command nethttp demonstrates a Bearer-only IAM Core resource server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

const startupTimeout = 10 * time.Second

type configuration struct {
	issuerURL string
	audience  string
	address   string
}

func main() {
	if err := run(); err != nil {
		// Do not log configuration values or credential material.
		slog.Error("IAM Core resource server stopped", slog.String("reason", "startup configuration is missing or invalid, or IAM is unavailable"))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfiguration()
	if err != nil {
		return err
	}

	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
		Name: "list_orders", Method: http.MethodGet, ResourceServer: "orders_api", Resource: "orders",
	}})
	if err != nil {
		return errors.New("resource server route configuration is invalid")
	}
	binder := manifest.NewBinder()
	route, err := binder.Bind("list_orders")
	if err != nil {
		return errors.New("resource server route configuration is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	runtime, err := core.New(ctx, core.Config{IssuerURL: cfg.issuerURL, Audiences: []string{cfg.audience}})
	if err != nil {
		return errors.New("IAM Core configuration is invalid or unavailable")
	}
	pdp, err := httpauthz.NewPDPClient(httpauthz.PDPConfig{IssuerURL: cfg.issuerURL})
	if err != nil {
		return errors.New("IAM authorization configuration is invalid")
	}
	service, err := httpauthz.New(httpauthz.Config{Verifier: runtime, PDP: pdp})
	if err != nil {
		return errors.New("IAM authorization configuration is invalid")
	}
	protected, err := service.Require(route, http.HandlerFunc(listOrders))
	if err != nil {
		return errors.New("IAM authorization route configuration is invalid")
	}
	if err := binder.Validate(); err != nil {
		return errors.New("resource server route configuration is incomplete")
	}

	mux := http.NewServeMux()
	mux.Handle("/orders", protected)
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
	cfg := configuration{
		issuerURL: strings.TrimSpace(os.Getenv("IAMCORE_ISSUER_URL")),
		audience:  strings.TrimSpace(os.Getenv("IAMCORE_AUDIENCE")),
		address:   strings.TrimSpace(os.Getenv("HTTP_ADDR")),
	}
	if cfg.issuerURL == "" {
		return configuration{}, errors.New("IAMCORE_ISSUER_URL must be set")
	}
	if cfg.audience == "" {
		return configuration{}, errors.New("IAMCORE_AUDIENCE must be set")
	}
	if cfg.address == "" {
		return configuration{}, errors.New("HTTP_ADDR must be set")
	}
	return cfg, nil
}

func listOrders(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"orders":[]}`))
}
