package session

import (
	"context"
	"time"
)

type SessionStore interface {
	Create(context.Context, *Session) error
	Get(context.Context, string) (*Session, error)
	CompareAndSwap(context.Context, string, uint64, *Session) error
	Delete(context.Context, string) error
}

type FlowStore interface {
	PutFlow(context.Context, *Flow) error
	ConsumeFlow(context.Context, string) (*Flow, error)
}

type Lock interface {
	Valid(context.Context) bool
	Unlock(context.Context) error
}

type RefreshLocker interface {
	Lock(context.Context, string, time.Duration) (Lock, error)
}

type Backend interface {
	SessionStore
	FlowStore
	RefreshLocker
}

type Clock interface {
	Now() time.Time
}
