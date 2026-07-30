package oidc

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
)

type contextualKeySet struct {
	url       string
	transport transport.Client
	timeout   time.Duration

	mu       sync.RWMutex
	inflight *jwksInflight
	keys     []jose.JSONWebKey
}

type jwksInflight struct {
	done    chan struct{}
	keys    []jose.JSONWebKey
	err     error
	waiters int
}

func newContextualKeySet(
	url string,
	httpClient *http.Client,
	timeout time.Duration,
) *contextualKeySet {
	if httpClient == nil {
		httpClient = transport.NewDefaultHTTPClient()
	} else {
		cloned := *httpClient
		cloned.Jar = nil
		cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		httpClient = &cloned
	}
	return &contextualKeySet{
		url:       url,
		transport: transport.Client{HTTP: httpClient},
		timeout:   timeout,
	}
}

func (set *contextualKeySet) VerifySignature(
	ctx context.Context,
	rawToken string,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("jwks verification unavailable")
	}
	header, err := parseProtectedHeader(rawToken)
	if err != nil {
		return nil, errors.New("invalid token header")
	}
	signature, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(signature.Signatures) != 1 {
		return nil, errors.New("invalid token signature")
	}
	if payload, ok := verifyWithKeyID(signature, set.cachedKeys(), header.KeyID); ok {
		return payload, nil
	}
	keys, err := set.remoteKeys(ctx)
	if err != nil {
		return nil, errors.New("jwks verification unavailable")
	}
	if payload, ok := verifyWithKeyID(signature, keys, header.KeyID); ok {
		return payload, nil
	}
	return nil, errors.New("token signature verification failed")
}

func verifyWithKeyID(
	signature *jose.JSONWebSignature,
	keys []jose.JSONWebKey,
	keyID string,
) ([]byte, bool) {
	for index := range keys {
		key := &keys[index]
		if key.KeyID != keyID {
			continue
		}
		payload, err := signature.Verify(key)
		if err == nil {
			return payload, true
		}
	}
	return nil, false
}

func (set *contextualKeySet) cachedKeys() []jose.JSONWebKey {
	set.mu.RLock()
	defer set.mu.RUnlock()
	return append([]jose.JSONWebKey(nil), set.keys...)
}

func (set *contextualKeySet) remoteKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	set.mu.Lock()
	if set.inflight == nil {
		set.inflight = &jwksInflight{done: make(chan struct{})}
		current := set.inflight
		fetchContext := context.WithoutCancel(ctx)
		go func() {
			keys, err := set.fetch(fetchContext)
			current.keys = keys
			current.err = err
			close(current.done)

			set.mu.Lock()
			if err == nil {
				set.keys = append([]jose.JSONWebKey(nil), keys...)
			}
			if set.inflight == current {
				set.inflight = nil
			}
			set.mu.Unlock()
		}()
	}
	current := set.inflight
	current.waiters++
	set.mu.Unlock()

	defer func() {
		set.mu.Lock()
		current.waiters--
		set.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-current.done:
		return append([]jose.JSONWebKey(nil), current.keys...), current.err
	}
}

func (set *contextualKeySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	requestContext, cancel := withTimeout(ctx, set.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, set.url, nil)
	if err != nil {
		return nil, errors.New("invalid jwks endpoint")
	}
	request.Header.Set("Accept", "application/json")
	response, err := set.transport.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, errors.New("jwks endpoint unavailable")
	}
	var document jose.JSONWebKeySet
	if err := transport.DecodeJSON(response.Body, &document); err != nil || len(document.Keys) == 0 {
		return nil, errors.New("invalid jwks response")
	}
	for index := range document.Keys {
		key := &document.Keys[index]
		if !key.Valid() || key.KeyID == "" {
			return nil, errors.New("invalid jwks key")
		}
	}
	return document.Keys, nil
}
