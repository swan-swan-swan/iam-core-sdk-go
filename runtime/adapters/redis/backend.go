package redis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

var (
	ErrInvalidOptions     = errors.New("redis adapter: invalid options")
	ErrInvalidInput       = errors.New("redis adapter: invalid input")
	ErrEncodeFailed       = errors.New("redis adapter: encode failed")
	ErrDecodeFailed       = errors.New("redis adapter: decode failed")
	ErrRandomSource       = errors.New("redis adapter: random source failed")
	ErrFenceExhausted     = errors.New("redis adapter: fencing numbers exhausted")
	ErrBackendUnavailable = errors.New("redis adapter: backend unavailable")
	errFenceOverflow      = errors.New("fence overflow")
)

const (
	maxPrefixLength      = 256
	ownerByteLength      = 32
	generationByteLength = 32
)

type Options struct {
	Prefix string
	Codec  Codec
	Clock  core.Clock
	Random io.Reader
}

type Backend struct {
	client   goredis.UniversalClient
	prefix   string
	codec    Codec
	clock    core.Clock
	random   io.Reader
	randomMu sync.Mutex
}

func New(client goredis.UniversalClient, options Options) (session.Backend, error) {
	if isNil(client) || isNil(options.Codec) || isNil(options.Clock) ||
		isNil(options.Random) || !safePrefix(options.Prefix) {
		return nil, ErrInvalidOptions
	}
	return &Backend{client: client, prefix: options.Prefix, codec: options.Codec, clock: options.Clock, random: options.Random}, nil
}

func (b *Backend) PutFlow(ctx context.Context, flow *session.Flow) error {
	if flow == nil || !validID(flow.ID) || flow.ExpiresAt.IsZero() {
		return ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	ttl, err := deadlineTTL(flow.ExpiresAt, b.clock.Now())
	if err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, flow)
	if err != nil {
		return err
	}
	result, err := b.client.SetArgs(ctx, b.flowKey(flow.ID), payload, goredis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	if errors.Is(err, goredis.Nil) || (err == nil && result != "OK") {
		return session.ErrConflict
	}
	if err != nil {
		return backendError(err)
	}
	return nil
}

func (b *Backend) ConsumeFlow(ctx context.Context, id string) (*session.Flow, error) {
	if !validID(id) {
		return nil, ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	payload, err := b.client.GetDel(ctx, b.flowKey(id)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, backendError(err)
	}
	var flow session.Flow
	if err := decodeModel(b.codec, payload, &flow); err != nil {
		return nil, err
	}
	if flow.ID != id || !validID(flow.ID) || flow.ExpiresAt.IsZero() {
		return nil, ErrDecodeFailed
	}
	if !flow.ExpiresAt.After(b.clock.Now()) {
		return nil, session.ErrExpired
	}
	return &flow, nil
}

func (b *Backend) Create(ctx context.Context, item *session.Session) error {
	if item == nil || !validID(item.ID) || item.Version != 1 || item.ExpiresAt.IsZero() || item.IdleExpiresAt.IsZero() {
		return ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	ttl, err := sessionTTL(item, b.clock.Now())
	if err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, item)
	if err != nil {
		return err
	}
	generation, err := b.randomToken(generationByteLength)
	if err != nil {
		return err
	}
	return b.watchSession(ctx, item.ID, func(tx *goredis.Tx) error {
		stored, readErr := b.readStored(ctx, tx, item.ID)
		switch {
		case readErr == nil && !sessionExpired(stored.item, b.clock.Now()):
			return session.ErrConflict
		case readErr == nil:
		case errors.Is(readErr, session.ErrNotFound):
		default:
			return readErr
		}
		_, err := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.Del(ctx, b.leaseKey(item.ID))
			pipe.HSet(ctx, b.sessionKey(item.ID),
				"version", "1", "payload", payload, "generation", generation, "last_fence", "0")
			pipe.PExpire(ctx, b.sessionKey(item.ID), ttl)
			return nil
		})
		return err
	})
}

func (b *Backend) Get(ctx context.Context, id string) (*session.Session, error) {
	if !validID(id) {
		return nil, ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	stored, err := b.readStored(ctx, b.client, id)
	if err != nil {
		return nil, mapReadError(err)
	}
	if !sessionExpired(stored.item, b.clock.Now()) {
		return stored.item, nil
	}
	err = b.watchSession(ctx, id, func(tx *goredis.Tx) error {
		current, readErr := b.readStored(ctx, tx, id)
		if readErr != nil {
			return readErr
		}
		if !sameStored(stored, current) || !sessionExpired(current.item, b.clock.Now()) {
			return session.ErrConflict
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.Del(ctx, b.sessionKey(id), b.leaseKey(id))
			return nil
		})
		if pipeErr != nil {
			return pipeErr
		}
		return session.ErrExpired
	})
	return nil, err
}

type redisHashReader interface {
	HMGet(context.Context, string, ...string) *goredis.SliceCmd
}

type storedSession struct {
	item        *session.Session
	versionText string
	payload     []byte
	generation  string
	lastFence   string
}

func (b *Backend) readStored(ctx context.Context, reader redisHashReader, id string) (*storedSession, error) {
	values, err := reader.HMGet(ctx, b.sessionKey(id), "version", "payload", "generation", "last_fence").Result()
	if err != nil {
		return nil, err
	}
	if len(values) != 4 {
		return nil, ErrDecodeFailed
	}
	missing := 0
	for _, value := range values {
		if value == nil {
			missing++
		}
	}
	if missing == 4 {
		return nil, session.ErrNotFound
	}
	if missing != 0 {
		return nil, ErrDecodeFailed
	}
	versionText, ok := redisText(values[0])
	if !ok {
		return nil, ErrDecodeFailed
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != versionText {
		return nil, ErrDecodeFailed
	}
	payload, ok := redisBytes(values[1])
	if !ok {
		return nil, ErrDecodeFailed
	}
	generation, ok := redisText(values[2])
	if !ok || !validOpaqueToken(generation, generationByteLength) {
		return nil, ErrDecodeFailed
	}
	lastFence, ok := redisText(values[3])
	if !ok || !canonicalUint64(lastFence) {
		return nil, ErrDecodeFailed
	}
	var item session.Session
	if err := decodeModel(b.codec, payload, &item); err != nil {
		return nil, err
	}
	if item.ID != id || !validID(item.ID) || item.Version != version || item.ExpiresAt.IsZero() || item.IdleExpiresAt.IsZero() {
		return nil, ErrDecodeFailed
	}
	return &storedSession{item: &item, versionText: versionText, payload: payload, generation: generation, lastFence: lastFence}, nil
}

func sameStored(left, right *storedSession) bool {
	return left != nil && right != nil && left.versionText == right.versionText &&
		bytes.Equal(left.payload, right.payload) && left.generation == right.generation && left.lastFence == right.lastFence
}

func (b *Backend) CompareAndSwap(ctx context.Context, id string, expectedVersion uint64, next *session.Session) error {
	if err := validateReplacement(id, expectedVersion, next); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	ttl, err := sessionTTL(next, b.clock.Now())
	if err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, next)
	if err != nil {
		return err
	}
	return b.watchSession(ctx, id, func(tx *goredis.Tx) error {
		stored, readErr := b.readStored(ctx, tx, id)
		if readErr != nil {
			return readErr
		}
		if sessionExpired(stored.item, b.clock.Now()) {
			return b.deleteExpired(ctx, tx, id)
		}
		if stored.item.Version != expectedVersion {
			return session.ErrConflict
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.HSet(ctx, b.sessionKey(id), "version", strconv.FormatUint(next.Version, 10), "payload", payload)
			pipe.PExpire(ctx, b.sessionKey(id), ttl)
			return nil
		})
		return pipeErr
	})
}

func (b *Backend) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, err := b.client.Del(ctx, b.sessionKey(id), b.leaseKey(id)).Result(); err != nil {
		return backendError(err)
	}
	return nil
}

func (b *Backend) AcquireRefreshLease(ctx context.Context, sessionID string, duration time.Duration) (session.Lease, error) {
	if !validID(sessionID) || duration <= 0 {
		return nil, ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	owner, err := b.randomToken(ownerByteLength)
	if err != nil {
		return nil, err
	}
	var acquired *refreshLease
	err = b.watchSession(ctx, sessionID, func(tx *goredis.Tx) error {
		stored, readErr := b.readStored(ctx, tx, sessionID)
		if readErr != nil {
			return readErr
		}
		if sessionExpired(stored.item, b.clock.Now()) {
			return b.deleteExpired(ctx, tx, sessionID)
		}
		sessionPTTL, pttlErr := tx.PTTL(ctx, b.sessionKey(sessionID)).Result()
		if pttlErr != nil {
			return pttlErr
		}
		if sessionPTTL == -time.Millisecond {
			return ErrDecodeFailed
		}
		if sessionPTTL <= 0 {
			return session.ErrNotFound
		}
		leasePTTL, pttlErr := tx.PTTL(ctx, b.leaseKey(sessionID)).Result()
		if pttlErr != nil {
			return pttlErr
		}
		if leasePTTL > 0 {
			return session.ErrConflict
		}
		if leasePTTL != -2*time.Millisecond && leasePTTL != 0 {
			return ErrDecodeFailed
		}
		nextFence, incrementErr := incrementFence(stored.lastFence)
		if errors.Is(incrementErr, errFenceOverflow) {
			return ErrFenceExhausted
		}
		if incrementErr != nil {
			return ErrDecodeFailed
		}
		leaseTTL := ceilMillisecond(duration)
		if sessionPTTL < leaseTTL {
			leaseTTL = sessionPTTL
		}
		if leaseTTL <= 0 {
			return session.ErrNotFound
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.HSet(ctx, b.sessionKey(sessionID), "last_fence", strconv.FormatUint(nextFence, 10))
			pipe.HSet(ctx, b.leaseKey(sessionID), "owner", owner, "fence", nextFence, "generation", stored.generation)
			pipe.PExpire(ctx, b.leaseKey(sessionID), leaseTTL)
			return nil
		})
		if pipeErr == nil {
			acquired = &refreshLease{backend: b, sessionID: sessionID, key: b.leaseKey(sessionID), owner: owner, fence: nextFence, generation: stored.generation}
		}
		return pipeErr
	})
	if err != nil {
		return nil, err
	}
	return acquired, nil
}

func (b *Backend) CompareAndSwapWithLease(ctx context.Context, lease session.Lease, id string, expectedVersion uint64, next *session.Session) error {
	if err := validateReplacement(id, expectedVersion, next); err != nil {
		return err
	}
	owned, credentials, ok := b.ownedLease(lease, id)
	if !ok {
		return session.ErrLeaseLost
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	ttl, err := sessionTTL(next, b.clock.Now())
	if err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, next)
	if err != nil {
		return err
	}
	err = b.watchSession(ctx, id, func(tx *goredis.Tx) error {
		stored, readErr := b.readStored(ctx, tx, id)
		if readErr != nil {
			return readErr
		}
		if sessionExpired(stored.item, b.clock.Now()) {
			return b.deleteExpired(ctx, tx, id)
		}
		if validErr := b.validateLease(ctx, tx, id, credentials); validErr != nil {
			return validErr
		}
		if stored.item.Version != expectedVersion {
			return session.ErrConflict
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.HSet(ctx, b.sessionKey(id), "version", strconv.FormatUint(next.Version, 10), "payload", payload)
			pipe.PExpire(ctx, b.sessionKey(id), ttl)
			pipe.Del(ctx, b.leaseKey(id))
			return nil
		})
		return pipeErr
	})
	if err == nil {
		owned.markConsumed()
	}
	return err
}

func (b *Backend) DeleteWithLease(ctx context.Context, lease session.Lease, id string, expectedVersion uint64) error {
	if !validID(id) || expectedVersion == 0 {
		return ErrInvalidInput
	}
	owned, credentials, ok := b.ownedLease(lease, id)
	if !ok {
		return session.ErrLeaseLost
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	err := b.watchSession(ctx, id, func(tx *goredis.Tx) error {
		stored, readErr := b.readStored(ctx, tx, id)
		if readErr != nil {
			return readErr
		}
		if sessionExpired(stored.item, b.clock.Now()) {
			return b.deleteExpired(ctx, tx, id)
		}
		if validErr := b.validateLease(ctx, tx, id, credentials); validErr != nil {
			return validErr
		}
		if stored.item.Version != expectedVersion {
			return session.ErrConflict
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.Del(ctx, b.sessionKey(id), b.leaseKey(id))
			return nil
		})
		return pipeErr
	})
	if err == nil {
		owned.markConsumed()
	}
	return err
}

type refreshLease struct {
	mu sync.Mutex

	backend    *Backend
	sessionID  string
	key        string
	owner      string
	fence      uint64
	generation string
	consumed   bool
	acked      bool
}

type leaseCredentials struct {
	owner      string
	fence      uint64
	generation string
}

func (l *refreshLease) Valid(ctx context.Context) bool {
	if l == nil || l.backend == nil || contextError(ctx) != nil {
		return false
	}
	l.mu.Lock()
	if l.consumed {
		l.mu.Unlock()
		return false
	}
	credentials := leaseCredentials{owner: l.owner, fence: l.fence, generation: l.generation}
	l.mu.Unlock()
	return l.backend.validateLease(ctx, l.backend.client, l.sessionID, credentials) == nil
}

func (l *refreshLease) Release(ctx context.Context) error {
	if l == nil || l.backend == nil {
		return session.ErrLeaseLost
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	if l.consumed {
		if l.acked {
			l.mu.Unlock()
			return session.ErrLeaseLost
		}
		l.acked = true
		l.mu.Unlock()
		return nil
	}
	credentials := leaseCredentials{owner: l.owner, fence: l.fence, generation: l.generation}
	l.mu.Unlock()
	err := l.backend.watchSession(ctx, l.sessionID, func(tx *goredis.Tx) error {
		if validErr := l.backend.validateLease(ctx, tx, l.sessionID, credentials); validErr != nil {
			return validErr
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.Del(ctx, l.key)
			return nil
		})
		return pipeErr
	})
	if err != nil {
		return err
	}
	l.markConsumedAndAcked()
	return nil
}

type leaseReader interface {
	HMGet(context.Context, string, ...string) *goredis.SliceCmd
	PTTL(context.Context, string) *goredis.DurationCmd
}

func (b *Backend) validateLease(ctx context.Context, reader leaseReader, id string, credentials leaseCredentials) error {
	sessionPTTL, err := reader.PTTL(ctx, b.sessionKey(id)).Result()
	if err != nil {
		return err
	}
	leasePTTL, err := reader.PTTL(ctx, b.leaseKey(id)).Result()
	if err != nil {
		return err
	}
	if sessionPTTL <= 0 || leasePTTL <= 0 {
		return session.ErrLeaseLost
	}
	sessionGeneration, err := reader.HMGet(ctx, b.sessionKey(id), "generation").Result()
	if err != nil {
		return err
	}
	leaseFields, err := reader.HMGet(ctx, b.leaseKey(id), "owner", "fence", "generation").Result()
	if err != nil {
		return err
	}
	if len(sessionGeneration) != 1 || len(leaseFields) != 3 {
		return session.ErrLeaseLost
	}
	wantFence := strconv.FormatUint(credentials.fence, 10)
	if text, ok := redisText(sessionGeneration[0]); !ok || text != credentials.generation {
		return session.ErrLeaseLost
	}
	wants := []string{credentials.owner, wantFence, credentials.generation}
	for index, want := range wants {
		if text, ok := redisText(leaseFields[index]); !ok || text != want {
			return session.ErrLeaseLost
		}
	}
	return nil
}

func (b *Backend) ownedLease(candidate session.Lease, id string) (*refreshLease, leaseCredentials, bool) {
	owned, ok := candidate.(*refreshLease)
	if !ok || owned == nil || owned.backend != b || owned.sessionID != id || owned.key != b.leaseKey(id) {
		return nil, leaseCredentials{}, false
	}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if owned.consumed {
		return nil, leaseCredentials{}, false
	}
	return owned, leaseCredentials{owner: owned.owner, fence: owned.fence, generation: owned.generation}, true
}

func (l *refreshLease) markConsumed() {
	l.mu.Lock()
	l.consumed = true
	l.mu.Unlock()
}

func (l *refreshLease) markConsumedAndAcked() {
	l.mu.Lock()
	l.consumed = true
	l.acked = true
	l.mu.Unlock()
}

func (b *Backend) watchSession(ctx context.Context, id string, fn func(*goredis.Tx) error) error {
	err := b.client.Watch(ctx, fn, b.sessionKey(id), b.leaseKey(id))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, goredis.TxFailedErr):
		return session.ErrConflict
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired),
		errors.Is(err, session.ErrConflict), errors.Is(err, session.ErrLeaseLost),
		errors.Is(err, ErrFenceExhausted), errors.Is(err, ErrDecodeFailed):
		return err
	default:
		return backendError(err)
	}
}

func (b *Backend) deleteExpired(ctx context.Context, tx *goredis.Tx, id string) error {
	_, err := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
		pipe.Del(ctx, b.sessionKey(id), b.leaseKey(id))
		return nil
	})
	if err != nil {
		return err
	}
	return session.ErrExpired
}

func incrementFence(last string) (uint64, error) {
	current, err := strconv.ParseUint(last, 10, 64)
	if err != nil || strconv.FormatUint(current, 10) != last {
		return 0, ErrDecodeFailed
	}
	if current == math.MaxUint64 {
		return 0, errFenceOverflow
	}
	return current + 1, nil
}

func canonicalUint64(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && strconv.FormatUint(parsed, 10) == value
}

func (b *Backend) randomToken(size int) (string, error) {
	b.randomMu.Lock()
	value := make([]byte, size)
	_, err := io.ReadFull(b.random, value)
	b.randomMu.Unlock()
	if err != nil {
		clear(value)
		return "", ErrRandomSource
	}
	encoded := base64.RawURLEncoding.EncodeToString(value)
	clear(value)
	return encoded, nil
}

func (b *Backend) sessionKey(id string) string { return b.taggedKey("session", id) }
func (b *Backend) flowKey(id string) string    { return b.key("flow", id) }
func (b *Backend) leaseKey(id string) string   { return b.taggedKey("lease", id) }

func (b *Backend) taggedKey(kind, id string) string {
	return b.prefix + ":" + kind + ":{" + digest(id) + "}"
}

func (b *Backend) key(kind, id string) string { return b.prefix + ":" + kind + ":" + digest(id) }

func digest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func safePrefix(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > maxPrefixLength || prefix[0] == ':' || prefix[len(prefix)-1] == ':' {
		return false
	}
	previousColon := false
	for _, character := range []byte(prefix) {
		if character == ':' {
			if previousColon {
				return false
			}
			previousColon = true
			continue
		}
		previousColon = false
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validID(id string) bool { return strings.TrimSpace(id) != "" }

func validOpaqueToken(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return false
	}
	clear(decoded)
	return true
}

func validateReplacement(id string, expectedVersion uint64, next *session.Session) error {
	if !validID(id) || expectedVersion == 0 || expectedVersion == math.MaxUint64 || next == nil ||
		next.ID != id || next.Version != expectedVersion+1 || next.ExpiresAt.IsZero() || next.IdleExpiresAt.IsZero() {
		return ErrInvalidInput
	}
	return nil
}

func sessionTTL(item *session.Session, now time.Time) (time.Duration, error) {
	if item == nil || item.ExpiresAt.IsZero() || item.IdleExpiresAt.IsZero() {
		return 0, ErrInvalidInput
	}
	deadline := item.ExpiresAt
	if item.IdleExpiresAt.Before(deadline) {
		deadline = item.IdleExpiresAt
	}
	return deadlineTTL(deadline, now)
}

func deadlineTTL(deadline, now time.Time) (time.Duration, error) {
	if deadline.IsZero() {
		return 0, ErrInvalidInput
	}
	lifetime := deadline.Sub(now)
	if lifetime <= 0 {
		return 0, session.ErrExpired
	}
	return ceilMillisecond(lifetime), nil
}

func ceilMillisecond(duration time.Duration) time.Duration {
	const maxWholeMilliseconds = time.Duration(math.MaxInt64/int64(time.Millisecond)) * time.Millisecond
	if duration >= maxWholeMilliseconds {
		return maxWholeMilliseconds
	}
	milliseconds := duration / time.Millisecond
	if duration%time.Millisecond != 0 {
		milliseconds++
	}
	if milliseconds < 1 {
		milliseconds = 1
	}
	return milliseconds * time.Millisecond
}

func sessionExpired(item *session.Session, now time.Time) bool {
	return !item.ExpiresAt.After(now) || !item.IdleExpiresAt.After(now)
}

func encodeModel(codec Codec, value any) ([]byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, ErrEncodeFailed
	}
	encoded, err := codec.Seal(plaintext)
	clear(plaintext)
	if err != nil {
		return nil, ErrEncodeFailed
	}
	return encoded, nil
}

func decodeModel(codec Codec, encoded []byte, destination any) error {
	plaintext, err := codec.Open(encoded)
	if err != nil {
		return ErrDecodeFailed
	}
	defer clear(plaintext)
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	if err := decoder.Decode(destination); err != nil {
		return ErrDecodeFailed
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrDecodeFailed
	}
	return nil
}

func backendError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrBackendUnavailable
	}
}

func mapReadError(err error) error {
	if errors.Is(err, session.ErrNotFound) || errors.Is(err, ErrDecodeFailed) {
		return err
	}
	return backendError(err)
}

func contextError(ctx context.Context) error {
	if isNil(ctx) {
		return ErrInvalidInput
	}
	select {
	case <-ctx.Done():
		return backendError(ctx.Err())
	default:
		return nil
	}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

func redisText(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case []byte:
		return string(value), true
	default:
		return "", false
	}
}

func redisBytes(value any) ([]byte, bool) {
	switch value := value.(type) {
	case string:
		return []byte(value), true
	case []byte:
		return append([]byte(nil), value...), true
	default:
		return nil, false
	}
}

var _ session.Backend = (*Backend)(nil)
var _ session.Lease = (*refreshLease)(nil)
