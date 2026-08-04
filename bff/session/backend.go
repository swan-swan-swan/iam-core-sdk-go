package session

import (
	"context"
	"time"
)

type Lease interface {
	Valid(context.Context) bool
	Release(context.Context) error
}

type Backend interface {
	PutFlow(context.Context, *Flow) error
	ConsumeFlow(context.Context, string) (*Flow, error)
	Create(context.Context, *Session) error
	Get(context.Context, string) (*Session, error)
	CompareAndSwap(context.Context, string, uint64, *Session) error
	Delete(context.Context, string) error
	AcquireRefreshLease(context.Context, string, time.Duration) (Lease, error)
	CompareAndSwapWithLease(context.Context, Lease, string, uint64, *Session) error
	DeleteWithLease(context.Context, Lease, string, uint64) error
}
