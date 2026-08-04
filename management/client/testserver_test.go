package client

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
)

type tokenSourceFunc func(context.Context) (string, error)

func (f tokenSourceFunc) AccessToken(ctx context.Context) (string, error) {
	return f(ctx)
}

func staticTokenSource(token string) TokenSource {
	return tokenSourceFunc(func(context.Context) (string, error) { return token, nil })
}

type countingTokenSource struct {
	token string
	err   error
	calls atomic.Int32
}

func (s *countingTokenSource) AccessToken(context.Context) (string, error) {
	s.calls.Add(1)
	return s.token, s.err
}

type recordingObserver struct {
	mu     sync.Mutex
	events []Event
	panic  bool
}

func (o *recordingObserver) Observe(_ context.Context, event Event) {
	if o.panic {
		panic("observer implementation panic")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}

func (o *recordingObserver) snapshot() []Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]Event(nil), o.events...)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

var errTestTokenSource = errors.New("token source failed")
