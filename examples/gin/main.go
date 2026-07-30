// Command gin demonstrates the IAM Core SDK with the Gin adapter.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	ginframework "github.com/gin-gonic/gin"
	iamcore "github.com/swan-swan-swan/iam-core-client-sdk-go"
	ginmw "github.com/swan-swan-swan/iam-core-client-sdk-go/middleware/gin"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/memory"
)

const defaultIssuer = "https://iam.wuhl-goose.top"

func main() {
	if err := run(); err != nil {
		// Do not log Client Secrets, tokens, cookies, or Session IDs.
		slog.Error("IAM Core Gin example stopped")
		os.Exit(1)
	}
}

func run() error {
	// Inject a Redis-backed session.Backend here in a multi-replica deployment.
	backend := memory.New(memory.Options{})
	client, err := newIAMClient(context.Background(), backend)
	if err != nil {
		return err
	}

	router := ginframework.New()
	router.GET("/auth/login", ginframework.WrapH(client.LoginHandler()))
	router.GET("/auth/callback", ginframework.WrapH(client.CallbackHandler()))
	router.GET("/auth/logout", ginframework.WrapH(client.LogoutHandler()))
	router.GET("/profile", ginmw.Authenticate(client), profile)
	router.GET(
		"/assets",
		ginmw.RequirePermission(client, "asset-api", "assets"),
		assets,
	)

	server := &http.Server{
		Addr:              envOrDefault("HTTP_ADDR", ":8080"),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func newIAMClient(ctx context.Context, backend session.Backend) (*iamcore.Client, error) {
	clientID := os.Getenv("IAMCORE_CLIENT_ID")
	clientSecret := os.Getenv("IAMCORE_CLIENT_SECRET")
	redirectURL := os.Getenv("IAMCORE_REDIRECT_URL")
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, errors.New("IAM Core environment configuration is incomplete")
	}

	discoveryContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return iamcore.New(discoveryContext, iamcore.Config{
		IssuerURL:            envOrDefault("IAMCORE_ISSUER_URL", defaultIssuer),
		ClientID:             clientID,
		ClientSecretProvider: iamcore.StaticSecret(clientSecret),
		RedirectURL:          redirectURL,
		Session: iamcore.SessionConfig{
			Backend: backend,
		},
	})
}

func profile(c *ginframework.Context) {
	identity, ok := ginmw.Identity(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.JSON(http.StatusOK, identity)
}

func assets(c *ginframework.Context) {
	c.JSON(http.StatusOK, ginframework.H{"assets": []string{}})
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
