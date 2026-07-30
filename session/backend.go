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

// RefreshCommitter applies refresh mutations while fencing stale lock owners.
// Implementations must validate the lock ownership token, lock expiry, and
// current Session version in the same atomic operation that mutates or deletes
// the Session. Third-party Backend implementations must not check ownership
// and then mutate in a separate operation.
type RefreshCommitter interface {
	CompareAndSwapWithLock(context.Context, Lock, string, uint64, *Session) error
	DeleteWithLock(context.Context, Lock, string, uint64) error
}

type Backend interface {
	SessionStore
	FlowStore
	RefreshLocker
	RefreshCommitter
}

type Clock interface {
	Now() time.Time
}
