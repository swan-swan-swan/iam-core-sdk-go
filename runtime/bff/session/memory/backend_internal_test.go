package memory

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/sessiontest"
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

type blockingReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	err     error
}

func newBlockingReader() *blockingReader {
	return &blockingReader{started: make(chan struct{}), release: make(chan struct{})}
}

func (r *blockingReader) Read(value []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	if r.err != nil {
		return 0, r.err
	}
	for index := range value {
		value[index] = 1
	}
	return len(value), nil
}

func TestAcquireRefreshLeaseCancellationWinsOverEntropyFailure(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := &sessiontest.Clock{}
	clock.Set(now)
	secret := "entropy-error-sensitive-detail"
	random := newBlockingReader()
	random.err = errors.New(secret)
	backend := New(Options{Clock: clock, Random: random})
	item := liveSession("cancel-entropy-error", now)
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal("failed to arrange live Session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	type acquireResult struct {
		lease session.Lease
		err   error
	}
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		acquired <- acquireResult{lease: lease, err: err}
	}()
	select {
	case <-random.started:
	case <-time.After(time.Second):
		t.Fatal("entropy read did not start")
	}
	cancel()
	close(random.release)
	result := <-acquired
	if result.lease != nil {
		t.Fatal("canceled entropy failure returned a Lease")
	}
	if result.err != context.Canceled {
		t.Fatal("entropy failure took precedence over exact context.Canceled")
	}
	if strings.Contains(result.err.Error(), secret) {
		t.Fatal("canceled entropy failure exposed provider detail")
	}
	if backend.nextFence != 0 || len(backend.leases) != 0 {
		t.Fatal("canceled entropy failure mutated fence or lease state")
	}
}

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

func TestAcquireRefreshLeaseCancellationDuringEntropyDoesNotBlockOrMutate(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := &sessiontest.Clock{}
	clock.Set(now)
	random := newBlockingReader()
	backend := New(Options{Clock: clock, Random: random})
	item := liveSession("cancel-during-entropy", now)
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal("failed to arrange live Session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	type acquireResult struct {
		lease session.Lease
		err   error
	}
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		acquired <- acquireResult{lease: lease, err: err}
	}()
	select {
	case <-random.started:
	case <-time.After(time.Second):
		t.Fatal("entropy read did not start")
	}

	getResult := make(chan error, 1)
	go func() {
		_, err := backend.Get(context.Background(), item.ID)
		getResult <- err
	}()
	backendBlocked := false
	select {
	case err := <-getResult:
		if err != nil {
			t.Error("Get failed while entropy acquisition was blocked")
		}
	case <-time.After(100 * time.Millisecond):
		backendBlocked = true
	}

	cancel()
	close(random.release)
	result := <-acquired
	if backendBlocked {
		if err := <-getResult; err != nil {
			t.Error("Get failed after blocked entropy acquisition was released")
		}
		t.Error("blocking entropy read held the backend state lock")
	}
	if result.lease != nil || result.err != context.Canceled {
		t.Errorf("canceled acquisition returned lease/error = %v/%v, want nil/exact context.Canceled", result.lease != nil, result.err)
	}
	if backend.nextFence != 0 || len(backend.leases) != 0 {
		t.Error("canceled entropy acquisition mutated fence or lease state")
	}
}

func TestAcquireRefreshLeaseRechecksSessionExpiryAfterEntropy(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := &sessiontest.Clock{}
	clock.Set(now)
	random := newBlockingReader()
	backend := New(Options{Clock: clock, Random: random})
	item := liveSession("expires-during-entropy", now)
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal("failed to arrange live Session")
	}

	type acquireResult struct {
		lease session.Lease
		err   error
	}
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute)
		acquired <- acquireResult{lease: lease, err: err}
	}()
	select {
	case <-random.started:
	case <-time.After(time.Second):
		t.Fatal("entropy read did not start")
	}
	clock.Set(item.IdleExpiresAt)
	close(random.release)
	result := <-acquired
	if result.lease != nil || !errors.Is(result.err, session.ErrExpired) {
		t.Fatalf("post-entropy expiry returned lease/error = %v/%v, want nil/ErrExpired", result.lease != nil, result.err)
	}
	if backend.nextFence != 0 || len(backend.leases) != 0 {
		t.Fatal("post-entropy expiry mutated fence or lease state")
	}
}

func TestAcquireRefreshLeaseRechecksSessionExistenceAfterEntropy(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := &sessiontest.Clock{}
	clock.Set(now)
	random := newBlockingReader()
	backend := New(Options{Clock: clock, Random: random})
	item := liveSession("deleted-during-entropy", now)
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal("failed to arrange live Session")
	}

	type acquireResult struct {
		lease session.Lease
		err   error
	}
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute)
		acquired <- acquireResult{lease: lease, err: err}
	}()
	select {
	case <-random.started:
	case <-time.After(time.Second):
		t.Fatal("entropy read did not start")
	}
	deleted := make(chan error, 1)
	go func() { deleted <- backend.Delete(context.Background(), item.ID) }()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatal("Delete failed during entropy acquisition")
		}
	case <-time.After(100 * time.Millisecond):
		close(random.release)
		<-acquired
		<-deleted
		t.Fatal("Delete was blocked by entropy acquisition")
	}
	close(random.release)
	result := <-acquired
	if result.lease != nil || !errors.Is(result.err, session.ErrNotFound) {
		t.Fatalf("post-entropy deletion returned lease/error = %v/%v, want nil/ErrNotFound", result.lease != nil, result.err)
	}
	if backend.nextFence != 0 || len(backend.leases) != 0 {
		t.Fatal("post-entropy deletion mutated fence or lease state")
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
