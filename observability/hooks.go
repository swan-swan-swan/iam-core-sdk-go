package observability

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

type Hooks interface {
	Observe(context.Context, Event)
}

type Nop struct{}

func (Nop) Observe(context.Context, Event) {}
