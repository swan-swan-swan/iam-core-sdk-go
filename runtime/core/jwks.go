package core

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

var errJWKSUnavailable = errors.New("jwks unavailable")

type keySet struct {
	url             string
	transport       transportClient
	timeout         time.Duration
	refreshInterval time.Duration
	clock           Clock

	mu             sync.RWMutex
	keys           []jose.JSONWebKey
	inflight       *jwksInflight
	lastRefresh    time.Time
	lastRefreshErr error
	hasRefreshed   bool
}

type jwksInflight struct {
	done chan struct{}
	keys []jose.JSONWebKey
	err  error
}

func newKeySet(url string, transport transportClient, timeout, refreshInterval time.Duration, clock Clock) *keySet {
	return &keySet{url: url, transport: transport, timeout: timeout, refreshInterval: refreshInterval, clock: clock}
}

func (set *keySet) verifySignature(ctx context.Context, rawToken string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("verification unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	header, err := parseProtectedHeader(rawToken)
	if err != nil {
		return nil, errors.New("invalid token header")
	}
	signature, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(signature.Signatures) != 1 {
		return nil, errors.New("invalid token signature")
	}
	if payload, found, verifyErr := verifyWithKeyID(signature, set.cachedKeys(), header.keyID); found {
		if verifyErr == nil {
			return payload, nil
		}
		return nil, errors.New("signature verification failed")
	}
	keys, err := set.remoteKeys(ctx)
	if err != nil {
		return nil, err
	}
	if payload, _, verifyErr := verifyWithKeyID(signature, keys, header.keyID); verifyErr == nil {
		return payload, nil
	}
	return nil, errors.New("signature verification failed")
}

func verifyWithKeyID(signature *jose.JSONWebSignature, keys []jose.JSONWebKey, keyID string) ([]byte, bool, error) {
	found := false
	for index := range keys {
		if keys[index].KeyID != keyID {
			continue
		}
		found = true
		payload, err := signature.Verify(&keys[index])
		if err == nil {
			return payload, true, nil
		}
	}
	return nil, found, errors.New("signature verification failed")
}

func (set *keySet) cachedKeys() []jose.JSONWebKey {
	set.mu.RLock()
	defer set.mu.RUnlock()
	return append([]jose.JSONWebKey(nil), set.keys...)
}

func (set *keySet) remoteKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	if ctx == nil {
		return nil, errors.New("verification unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	set.mu.Lock()
	if set.inflight == nil {
		now := set.clock.Now()
		if set.hasRefreshed && now.Sub(set.lastRefresh) < set.refreshInterval {
			keys := append([]jose.JSONWebKey(nil), set.keys...)
			err := set.lastRefreshErr
			set.mu.Unlock()
			return keys, err
		}
		set.lastRefresh = now
		set.hasRefreshed = true
		set.inflight = &jwksInflight{done: make(chan struct{})}
		current := set.inflight
		fetchContext := context.WithoutCancel(ctx)
		go func() {
			keys, err := set.fetch(fetchContext)
			set.mu.Lock()
			current.keys, current.err = keys, err
			set.lastRefreshErr = err
			if err == nil {
				set.keys = append([]jose.JSONWebKey(nil), keys...)
			}
			if set.inflight == current {
				set.inflight = nil
			}
			close(current.done)
			set.mu.Unlock()
		}()
	}
	current := set.inflight
	set.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-current.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		set.mu.RLock()
		defer set.mu.RUnlock()
		return append([]jose.JSONWebKey(nil), current.keys...), current.err
	}
}

func (set *keySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	requestContext, cancel := context.WithTimeout(ctx, set.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, set.url, nil)
	if err != nil {
		return nil, errJWKSUnavailable
	}
	response, err := set.transport.getJSON(request)
	if err != nil || response.status != http.StatusOK {
		return nil, errJWKSUnavailable
	}
	var document jose.JSONWebKeySet
	if decodeJSON(response.body, &document) != nil || len(document.Keys) == 0 {
		return nil, errJWKSUnavailable
	}
	for index := range document.Keys {
		key := &document.Keys[index]
		if !key.Valid() || key.KeyID == "" ||
			(key.Algorithm != "" && key.Algorithm != "RS256") ||
			(key.Use != "" && key.Use != "sig") {
			return nil, errJWKSUnavailable
		}
	}
	return document.Keys, nil
}
