package client

import (
	"context"
	"time"
)

// Event records the outcome of one management API operation.
type Event struct {
	Operation  string
	Outcome    string
	StatusCode int
	Duration   time.Duration
}

// Observer receives management API request events.
type Observer interface {
	Observe(context.Context, Event)
}
