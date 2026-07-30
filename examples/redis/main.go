// Command redis demonstrates encrypted Redis-backed IAM Core sessions.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	iamcore "github.com/swan-swan-swan/iam-core-client-sdk-go"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	redisstore "github.com/swan-swan-swan/iam-core-client-sdk-go/session/redis"
)

const defaultIssuer = "https://iam.wuhl-goose.top"

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func main() {
	if err := run(); err != nil {
		// Never attach the error here: a third-party configuration error could
		// contain a Redis URL or other sensitive input.
		slog.Error("IAM Core Redis example stopped")
		os.Exit(1)
	}
}

func run() error {
	key, err := currentAESKey()
	if err != nil {
		return err
	}
	codec, err := session.NewAESGCMCodec(session.Key{
		ID:    envOrDefault("IAMCORE_SESSION_KEY_ID", "current"),
		Bytes: key,
	}, nil)
	if err != nil {
		return err
	}

	addresses := redisAddresses()
	if len(addresses) == 0 {
		return errors.New("IAMCORE_REDIS_ADDRS must contain at least one address")
	}
	redisClient := goredis.NewUniversalClient(&goredis.UniversalOptions{
		Addrs:    addresses,
		Username: os.Getenv("IAMCORE_REDIS_USERNAME"),
		Password: os.Getenv("IAMCORE_REDIS_PASSWORD"),
		DB:       0,
	})
	defer redisClient.Close()

	backend, err := redisstore.New(redisClient, redisstore.Options{
		Prefix: envOrDefault("IAMCORE_REDIS_PREFIX", "iamcore"),
		Codec:  codec,
		Clock:  wallClock{},
		Random: rand.Reader,
	})
	if err != nil {
		return err
	}

	clientID := os.Getenv("IAMCORE_CLIENT_ID")
	clientSecret := os.Getenv("IAMCORE_CLIENT_SECRET")
	redirectURL := os.Getenv("IAMCORE_REDIRECT_URL")
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return errors.New("IAM Core environment configuration is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := iamcore.New(ctx, iamcore.Config{
		IssuerURL:            envOrDefault("IAMCORE_ISSUER_URL", defaultIssuer),
		ClientID:             clientID,
		ClientSecretProvider: iamcore.StaticSecret(clientSecret),
		RedirectURL:          redirectURL,
		Session: iamcore.SessionConfig{
			Backend: backend,
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

func currentAESKey() ([]byte, error) {
	encoded := os.Getenv("IAMCORE_SESSION_AES_KEY")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("IAMCORE_SESSION_AES_KEY must be base64 for exactly 32 bytes")
	}
	return decoded, nil
}

func redisAddresses() []string {
	value := envOrDefault("IAMCORE_REDIS_ADDRS", "127.0.0.1:6379")
	parts := strings.Split(value, ",")
	addresses := make([]string, 0, len(parts))
	for _, part := range parts {
		if address := strings.TrimSpace(part); address != "" {
			addresses = append(addresses, address)
		}
	}
	return addresses
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

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
