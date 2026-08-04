// Command example demonstrates a Bearer-only IAM Core resource server with Gin.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	ginadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
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
		slog.Error("IAM Core Gin resource server stopped", slog.String("reason", "startup configuration is missing or invalid, or IAM is unavailable"))
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
	protected, err := ginadapter.Require(service, route)
	if err != nil {
		return errors.New("IAM authorization route configuration is invalid")
	}
	if err := binder.Validate(); err != nil {
		return errors.New("resource server route configuration is incomplete")
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.GET("/orders", protected, listOrders)
	server := &http.Server{
		Addr:              cfg.address,
		Handler:           router,
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
	if cfg.issuerURL == "" || cfg.audience == "" || cfg.address == "" {
		return configuration{}, errors.New("IAM Core environment configuration is incomplete")
	}
	return cfg, nil
}

func listOrders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"orders": []string{}})
}
