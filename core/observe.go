package core

import (
	"context"
	"time"
)

type Event struct {
	Operation        string
	Outcome          string
	CredentialSource string
	Duration         time.Duration
}

type Observer interface {
	Observe(context.Context, Event)
}

type ObserverFunc func(context.Context, Event)

func (f ObserverFunc) Observe(ctx context.Context, event Event) {
	f(ctx, event)
}

type NopObserver struct{}

func (NopObserver) Observe(context.Context, Event) {}
