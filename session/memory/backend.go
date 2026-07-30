package memory

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/random"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

var errInvalidInput = errors.New("session memory: invalid input")

type Options struct {
	Clock  session.Clock
	Random io.Reader
}

type Backend struct {
	mu       sync.Mutex
	randomMu sync.Mutex
	clock    session.Clock
	random   io.Reader
	sessions map[string]*session.Session
	flows    map[string]*session.Flow
	locks    map[string]lockRecord
}

type lockRecord struct {
	token     string
	expiresAt time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func New(options Options) *Backend {
	if options.Clock == nil {
		options.Clock = realClock{}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &Backend{
		clock:    options.Clock,
		random:   options.Random,
		sessions: make(map[string]*session.Session),
		flows:    make(map[string]*session.Flow),
		locks:    make(map[string]lockRecord),
	}
}

func (b *Backend) Create(_ context.Context, item *session.Session) error {
	if err := validateCreatedSession(item); err != nil {
		return err
	}
	copied := cloneSession(item)

	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	if err := validateSessionExpiry(item, now); err != nil {
		return err
	}
	if current, exists := b.sessions[item.ID]; exists {
		if sessionExpired(current, now) {
			delete(b.sessions, item.ID)
		} else {
			return session.ErrVersionConflict
		}
	}
	b.sessions[item.ID] = copied
	return nil
}

func (b *Backend) Get(_ context.Context, id string) (*session.Session, error) {
	if !validID(id) {
		return nil, errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	item, exists := b.sessions[id]
	if !exists {
		return nil, session.ErrNotFound
	}
	if sessionExpired(item, now) {
		delete(b.sessions, id)
		return nil, session.ErrExpired
	}
	return cloneSession(item), nil
}

func (b *Backend) CompareAndSwap(
	_ context.Context,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	if !validID(id) || expectedVersion == 0 || expectedVersion == ^uint64(0) ||
		next == nil || next.ID != id || next.Version != expectedVersion+1 {
		return errInvalidInput
	}
	copied := cloneSession(next)

	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	current, exists := b.sessions[id]
	if !exists {
		return session.ErrNotFound
	}
	if sessionExpired(current, now) {
		delete(b.sessions, id)
		return session.ErrExpired
	}
	if current.Version != expectedVersion {
		return session.ErrVersionConflict
	}
	if err := validateSessionExpiry(next, now); err != nil {
		return err
	}
	b.sessions[id] = copied
	return nil
}

func (b *Backend) Delete(_ context.Context, id string) error {
	if !validID(id) {
		return errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, id)
	return nil
}

func (b *Backend) PutFlow(_ context.Context, flow *session.Flow) error {
	if flow == nil || !validID(flow.ID) {
		return errInvalidInput
	}
	if flow.ExpiresAt.IsZero() {
		return errInvalidInput
	}
	copied := cloneFlow(flow)

	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	if !flow.ExpiresAt.After(now) {
		return session.ErrExpired
	}
	if current, exists := b.flows[flow.ID]; exists {
		if !current.ExpiresAt.After(now) {
			delete(b.flows, flow.ID)
		} else {
			return session.ErrVersionConflict
		}
	}
	b.flows[flow.ID] = copied
	return nil
}

func (b *Backend) ConsumeFlow(_ context.Context, id string) (*session.Flow, error) {
	if !validID(id) {
		return nil, errInvalidInput
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	flow, exists := b.flows[id]
	if !exists {
		return nil, session.ErrNotFound
	}
	delete(b.flows, id)
	if !flow.ExpiresAt.After(now) {
		return nil, session.ErrExpired
	}
	return cloneFlow(flow), nil
}

func (b *Backend) Lock(_ context.Context, id string, duration time.Duration) (session.Lock, error) {
	if !validID(id) || duration <= 0 {
		return nil, errInvalidInput
	}
	b.randomMu.Lock()
	token, err := random.ID(b.random, 32)
	b.randomMu.Unlock()
	if err != nil {
		return nil, errors.New("session memory: random source failed")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	if now.Add(duration).Before(now) {
		return nil, errInvalidInput
	}
	if current, exists := b.locks[id]; exists {
		if current.expiresAt.After(now) {
			return nil, session.ErrLocked
		}
		delete(b.locks, id)
	}
	b.locks[id] = lockRecord{token: token, expiresAt: now.Add(duration)}
	return &ownedLock{backend: b, id: id, token: token}, nil
}

func (b *Backend) Prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	for id, item := range b.sessions {
		if sessionExpired(item, now) {
			delete(b.sessions, id)
		}
	}
	for id, flow := range b.flows {
		if !flow.ExpiresAt.After(now) {
			delete(b.flows, id)
		}
	}
	for id, lock := range b.locks {
		if !lock.expiresAt.After(now) {
			delete(b.locks, id)
		}
	}
}

type ownedLock struct {
	backend *Backend
	id      string
	token   string
}

func (l *ownedLock) Valid(_ context.Context) bool {
	l.backend.mu.Lock()
	defer l.backend.mu.Unlock()
	now := l.backend.clock.Now()
	current, exists := l.backend.locks[l.id]
	if !exists {
		return false
	}
	if !current.expiresAt.After(now) {
		delete(l.backend.locks, l.id)
		return false
	}
	return sameToken(current.token, l.token)
}

func (l *ownedLock) Unlock(_ context.Context) error {
	l.backend.mu.Lock()
	defer l.backend.mu.Unlock()
	now := l.backend.clock.Now()
	current, exists := l.backend.locks[l.id]
	if !exists {
		return session.ErrLockLost
	}
	if !current.expiresAt.After(now) {
		delete(l.backend.locks, l.id)
		return session.ErrLockLost
	}
	if !sameToken(current.token, l.token) {
		return session.ErrLockLost
	}
	delete(l.backend.locks, l.id)
	return nil
}

func sameToken(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func validateCreatedSession(item *session.Session) error {
	if item == nil || !validID(item.ID) || item.Version != 1 {
		return errInvalidInput
	}
	if item.ExpiresAt.IsZero() {
		return errInvalidInput
	}
	return nil
}

func validateSessionExpiry(item *session.Session, now time.Time) error {
	if item.ExpiresAt.IsZero() {
		return errInvalidInput
	}
	if sessionExpired(item, now) {
		return session.ErrExpired
	}
	return nil
}

func sessionExpired(item *session.Session, now time.Time) bool {
	return !item.ExpiresAt.After(now) ||
		(!item.IdleExpiresAt.IsZero() && !item.IdleExpiresAt.After(now))
}

func validID(id string) bool {
	return strings.TrimSpace(id) != ""
}

func cloneSession(item *session.Session) *session.Session {
	if item == nil {
		return nil
	}
	cloned := *item
	cloned.GrantedScopes = append([]string(nil), item.GrantedScopes...)
	cloned.Identity.Roles = append([]string(nil), item.Identity.Roles...)
	cloned.Identity.Scopes = append([]string(nil), item.Identity.Scopes...)
	if item.Identity.ExtraClaims != nil {
		cloned.Identity.ExtraClaims = make(map[string]json.RawMessage, len(item.Identity.ExtraClaims))
		for name, raw := range item.Identity.ExtraClaims {
			cloned.Identity.ExtraClaims[name] = append(json.RawMessage(nil), raw...)
		}
	}
	return &cloned
}

func cloneFlow(flow *session.Flow) *session.Flow {
	if flow == nil {
		return nil
	}
	cloned := *flow
	return &cloned
}
