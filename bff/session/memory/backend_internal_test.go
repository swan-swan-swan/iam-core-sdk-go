package memory

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session/sessiontest"
)

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { panic("typed-nil clock invoked") }

type typedNilReader struct{}

func (*typedNilReader) Read([]byte) (int, error) { panic("typed-nil reader invoked") }

func TestNewRejectsTypedNilOptionsAndDefaultsAbsentOptions(t *testing.T) {
	var clock *typedNilClock
	var random *typedNilReader
	if backend := New(Options{Clock: clock}); backend != nil {
		t.Fatal("New accepted a typed-nil Clock")
	}
	if backend := New(Options{Random: random}); backend != nil {
		t.Fatal("New accepted a typed-nil Random")
	}
	if backend := New(Options{}); backend == nil {
		t.Fatal("New rejected absent optional collaborators")
	}
}

func TestAcquireRefreshLeaseRandomFailureLeavesNoState(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := &sessiontest.Clock{}
	clock.Set(now)
	sensitiveDetail := "entropy-provider-sensitive-detail"
	backend := New(Options{
		Clock:  clock,
		Random: failingReader{err: errors.New(sensitiveDetail)},
	})
	item := liveSession("random-failure-session", now)
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal("failed to arrange live Session")
	}

	lease, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute)
	if !errors.Is(err, ErrRandomSource) {
		t.Fatal("random source failure had the wrong classification")
	}
	if lease != nil {
		t.Fatal("random source failure returned a Lease")
	}
	if strings.Contains(err.Error(), sensitiveDetail) || strings.Contains(err.Error(), item.ID) {
		t.Fatal("random source failure exposed sensitive details")
	}
	if backend.nextFence != 0 {
		t.Fatalf("random source failure consumed fence %d", backend.nextFence)
	}
	if len(backend.leases) != 0 {
		t.Fatal("random source failure installed lease state")
	}

	backend.random = bytes.NewReader(bytes.Repeat([]byte{1}, 32))
	lease, err = backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute)
	if err != nil {
		t.Fatal("valid acquisition after random failure did not succeed")
	}
	owned, ok := lease.(*refreshLease)
	if !ok {
		t.Fatal("valid acquisition returned an unexpected Lease type")
	}
	if owned.fence != 1 {
		t.Fatalf("first successful fence = %d, want 1", owned.fence)
	}
	if !lease.Valid(context.Background()) {
		t.Fatal("first successful Lease is invalid")
	}
}

func TestAcquireRefreshLeaseFenceExhaustionCannotWrap(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := &sessiontest.Clock{}
	clock.Set(now)
	backend := New(Options{
		Clock:  clock,
		Random: bytes.NewReader(bytes.Repeat([]byte{1}, 32)),
	})
	item := liveSession("fence-exhaustion-session", now)
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal("failed to arrange live Session")
	}
	backend.nextFence = math.MaxUint64

	lease, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute)
	if !errors.Is(err, ErrFenceExhausted) {
		t.Fatal("fence exhaustion had the wrong classification")
	}
	if lease != nil {
		t.Fatal("fence exhaustion returned a Lease")
	}
	if backend.nextFence != math.MaxUint64 {
		t.Fatalf("fence exhaustion wrapped to %d", backend.nextFence)
	}
	if len(backend.leases) != 0 {
		t.Fatal("fence exhaustion installed lease state")
	}
}

func liveSession(id string, now time.Time) *session.Session {
	return &session.Session{
		ID:            id,
		Version:       1,
		ExpiresAt:     now.Add(2 * time.Hour),
		IdleExpiresAt: now.Add(time.Hour),
	}
}
