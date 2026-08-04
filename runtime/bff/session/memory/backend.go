package memory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/internal/nilcheck"
)

var errInvalidInput = errors.New("session memory: invalid input")

var (
	// ErrRandomSource classifies a failure to obtain refresh lease entropy.
	ErrRandomSource = errors.New("session memory: random source failed")
	// ErrFenceExhausted reports that no further fencing number can be issued.
	ErrFenceExhausted = errors.New("session memory: fencing numbers exhausted")
)

type Options struct {
	Clock  core.Clock
	Random io.Reader
}

type Backend struct {
	mu        sync.Mutex
	randomMu  sync.Mutex
	clock     core.Clock
	random    io.Reader
	flows     map[string]*session.Flow
	sessions  map[string]*session.Session
	leases    map[string]leaseRecord
	nextFence uint64
}

type leaseRecord struct {
	fence     uint64
	expiresAt time.Time
	owner     string
}

type refreshLease struct {
	backend   *Backend
	sessionID string
	fence     uint64
	expiresAt time.Time
	owner     string
}

// New constructs a single-process Backend. Absent Clock and Random values use
// safe defaults; a typed-nil collaborator is invalid and returns nil.
func New(options Options) *Backend {
	if (options.Clock != nil && nilcheck.IsNil(options.Clock)) ||
		(options.Random != nil && nilcheck.IsNil(options.Random)) {
		return nil
	}
	if options.Clock == nil {
		options.Clock = core.RealClock{}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &Backend{
		clock:    options.Clock,
		random:   options.Random,
		flows:    make(map[string]*session.Flow),
		sessions: make(map[string]*session.Session),
		leases:   make(map[string]leaseRecord),
	}
}

func (b *Backend) PutFlow(ctx context.Context, flow *session.Flow) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if flow == nil || !validID(flow.ID) || flow.ExpiresAt.IsZero() {
		return errInvalidInput
	}
	copied := cloneFlow(flow)

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	now := b.clock.Now()
	if flowExpired(copied, now) {
		return session.ErrExpired
	}
	if current, ok := b.flows[copied.ID]; ok {
		if !flowExpired(current, now) {
			return session.ErrConflict
		}
		delete(b.flows, copied.ID)
	}
	b.flows[copied.ID] = copied
	return nil
}

func (b *Backend) ConsumeFlow(ctx context.Context, id string) (*session.Flow, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !validID(id) {
		return nil, errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	flow, ok := b.flows[id]
	if !ok {
		return nil, session.ErrNotFound
	}
	delete(b.flows, id)
	if flowExpired(flow, b.clock.Now()) {
		return nil, session.ErrExpired
	}
	return cloneFlow(flow), nil
}

func (b *Backend) Create(ctx context.Context, item *session.Session) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateCreatedSession(item); err != nil {
		return err
	}
	copied := cloneSession(item)

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	now := b.clock.Now()
	if sessionExpired(copied, now) {
		return session.ErrExpired
	}
	if current, ok := b.sessions[copied.ID]; ok {
		if !sessionExpired(current, now) {
			return session.ErrConflict
		}
		b.deleteSessionLocked(copied.ID)
	}
	b.sessions[copied.ID] = copied
	return nil
}

func (b *Backend) Get(ctx context.Context, id string) (*session.Session, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !validID(id) {
		return nil, errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	item, ok := b.sessions[id]
	if !ok {
		return nil, session.ErrNotFound
	}
	if sessionExpired(item, b.clock.Now()) {
		b.deleteSessionLocked(id)
		return nil, session.ErrExpired
	}
	return cloneSession(item), nil
}

func (b *Backend) CompareAndSwap(
	ctx context.Context,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if next == nil {
		return errInvalidInput
	}
	copied := cloneSession(next)

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateReplacement(id, expectedVersion, copied); err != nil {
		return err
	}
	return b.compareAndSwapLocked(id, expectedVersion, copied, b.clock.Now())
}

func (b *Backend) Delete(ctx context.Context, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !validID(id) {
		return errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	b.deleteSessionLocked(id)
	return nil
}

func (b *Backend) AcquireRefreshLease(
	ctx context.Context,
	sessionID string,
	duration time.Duration,
) (session.Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !validID(sessionID) || duration <= 0 {
		return nil, errInvalidInput
	}
	b.mu.Lock()
	if err := contextError(ctx); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	now := b.clock.Now()
	if err := b.prepareRefreshLeaseAcquisitionLocked(sessionID, now); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	b.mu.Unlock()

	owner, entropyErr := b.randomOwner()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if entropyErr != nil {
		return nil, ErrRandomSource
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	now = b.clock.Now()
	if err := b.prepareRefreshLeaseAcquisitionLocked(sessionID, now); err != nil {
		return nil, err
	}
	b.nextFence++
	record := leaseRecord{
		fence:     b.nextFence,
		expiresAt: now.Add(duration),
		owner:     owner,
	}
	b.leases[sessionID] = record
	return &refreshLease{
		backend:   b,
		sessionID: sessionID,
		fence:     record.fence,
		expiresAt: record.expiresAt,
		owner:     record.owner,
	}, nil
}

func (b *Backend) CompareAndSwapWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if next == nil {
		return errInvalidInput
	}
	copied := cloneSession(next)

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateReplacement(id, expectedVersion, copied); err != nil {
		return err
	}
	now := b.clock.Now()
	if !b.ownsLeaseLocked(lease, id, now) {
		return session.ErrLeaseLost
	}
	return b.compareAndSwapLocked(id, expectedVersion, copied, now)
}

func (b *Backend) DeleteWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !validID(id) || expectedVersion == 0 {
		return errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	now := b.clock.Now()
	if !b.ownsLeaseLocked(lease, id, now) {
		return session.ErrLeaseLost
	}
	current, ok := b.sessions[id]
	if !ok {
		return session.ErrNotFound
	}
	if sessionExpired(current, now) {
		b.deleteSessionLocked(id)
		return session.ErrExpired
	}
	if current.Version != expectedVersion {
		return session.ErrConflict
	}
	b.deleteSessionLocked(id)
	return nil
}

func (l *refreshLease) Valid(ctx context.Context) bool {
	if contextError(ctx) != nil || l == nil || l.backend == nil {
		return false
	}
	l.backend.mu.Lock()
	defer l.backend.mu.Unlock()
	if contextError(ctx) != nil {
		return false
	}
	return l.backend.ownsLeaseLocked(l, l.sessionID, l.backend.clock.Now())
}

func (l *refreshLease) Release(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if l == nil || l.backend == nil {
		return session.ErrLeaseLost
	}
	l.backend.mu.Lock()
	defer l.backend.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if !l.backend.ownsLeaseLocked(l, l.sessionID, l.backend.clock.Now()) {
		return session.ErrLeaseLost
	}
	delete(l.backend.leases, l.sessionID)
	return nil
}

func (b *Backend) compareAndSwapLocked(
	id string,
	expectedVersion uint64,
	next *session.Session,
	now time.Time,
) error {
	current, ok := b.sessions[id]
	if !ok {
		return session.ErrNotFound
	}
	if sessionExpired(current, now) {
		b.deleteSessionLocked(id)
		return session.ErrExpired
	}
	if current.Version != expectedVersion {
		return session.ErrConflict
	}
	if sessionExpired(next, now) {
		return session.ErrExpired
	}
	b.sessions[id] = next
	return nil
}

func (b *Backend) ownsLeaseLocked(candidate session.Lease, id string, now time.Time) bool {
	lease, ok := candidate.(*refreshLease)
	if !ok || lease == nil || lease.backend != b || lease.sessionID != id {
		return false
	}
	record, ok := b.leases[id]
	if !ok || record.fence != lease.fence || record.owner != lease.owner ||
		!record.expiresAt.Equal(lease.expiresAt) || !record.expiresAt.After(now) {
		return false
	}
	return true
}

func (b *Backend) deleteSessionLocked(id string) {
	delete(b.sessions, id)
	delete(b.leases, id)
}

func (b *Backend) prepareRefreshLeaseAcquisitionLocked(sessionID string, now time.Time) error {
	item, ok := b.sessions[sessionID]
	if !ok {
		return session.ErrNotFound
	}
	if sessionExpired(item, now) {
		b.deleteSessionLocked(sessionID)
		return session.ErrExpired
	}
	if current, ok := b.leases[sessionID]; ok && current.expiresAt.After(now) {
		return session.ErrConflict
	}
	if b.nextFence == ^uint64(0) {
		return ErrFenceExhausted
	}
	return nil
}

func (b *Backend) randomOwner() (string, error) {
	ownerBytes := make([]byte, 32)
	b.randomMu.Lock()
	_, err := io.ReadFull(b.random, ownerBytes)
	b.randomMu.Unlock()
	if err != nil {
		clear(ownerBytes)
		return "", err
	}
	owner := base64.RawURLEncoding.EncodeToString(ownerBytes)
	clear(ownerBytes)
	return owner, nil
}

func validateCreatedSession(item *session.Session) error {
	if item == nil || !validID(item.ID) || item.Version != 1 || item.ExpiresAt.IsZero() || item.IdleExpiresAt.IsZero() {
		return errInvalidInput
	}
	return nil
}

func validateReplacement(id string, expectedVersion uint64, next *session.Session) error {
	if !validID(id) || expectedVersion == 0 || expectedVersion == ^uint64(0) || next == nil ||
		next.ID != id || next.Version != expectedVersion+1 || next.ExpiresAt.IsZero() || next.IdleExpiresAt.IsZero() {
		return errInvalidInput
	}
	return nil
}

func flowExpired(flow *session.Flow, now time.Time) bool {
	return !flow.ExpiresAt.After(now)
}

func sessionExpired(item *session.Session, now time.Time) bool {
	return !item.ExpiresAt.After(now) || !item.IdleExpiresAt.After(now)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errInvalidInput
	}
	return ctx.Err()
}

func validID(id string) bool {
	return strings.TrimSpace(id) != ""
}

func cloneFlow(flow *session.Flow) *session.Flow {
	copied := *flow
	return &copied
}

func cloneSession(item *session.Session) *session.Session {
	copied := *item
	copied.Tokens.GrantedScopes = slices.Clone(item.Tokens.GrantedScopes)
	copied.Auth.Audience = slices.Clone(item.Auth.Audience)
	copied.Auth.Scopes = slices.Clone(item.Auth.Scopes)
	copied.Auth.Groups = slices.Clone(item.Auth.Groups)
	return &copied
}

var _ session.Backend = (*Backend)(nil)
var _ session.Lease = (*refreshLease)(nil)
