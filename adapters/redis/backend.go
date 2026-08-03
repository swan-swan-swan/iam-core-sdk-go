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
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

var (
	ErrInvalidOptions     = errors.New("redis adapter: invalid options")
	ErrInvalidInput       = errors.New("redis adapter: invalid input")
	ErrEncodeFailed       = errors.New("redis adapter: encode failed")
	ErrDecodeFailed       = errors.New("redis adapter: decode failed")
	ErrRandomSource       = errors.New("redis adapter: random source failed")
	ErrFenceExhausted     = errors.New("redis adapter: fencing numbers exhausted")
	ErrBackendUnavailable = errors.New("redis adapter: backend unavailable")
)

const (
	maxPrefixLength       = 256
	ownerByteLength       = 32
	generationByteLength  = 32
	maxFenceGrantAttempts = 16
	maxLuaExactInteger    = int64(1<<53 - 1)
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
	return &Backend{
		client: client,
		prefix: options.Prefix,
		codec:  options.Codec,
		clock:  options.Clock,
		random: options.Random,
	}, nil
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
	status, err := flowPutScript.Run(
		ctx,
		b.client,
		[]string{b.flowKey(flow.ID)},
		payload,
		millisecondsText(ttl),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCreateStatus(status)
}

func (b *Backend) ConsumeFlow(ctx context.Context, id string) (*session.Flow, error) {
	if !validID(id) {
		return nil, ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	result, err := flowConsumeScript.Run(ctx, b.client, []string{b.flowKey(id)}).Result()
	if errors.Is(err, goredis.Nil) || (err == nil && result == nil) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, backendError(err)
	}
	payload, ok := redisBytes(result)
	if !ok {
		return nil, ErrDecodeFailed
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
	if item == nil || !validID(item.ID) || item.Version != 1 {
		return ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, item)
	if err != nil {
		return err
	}
	if _, err := b.Get(ctx, item.ID); err == nil {
		return session.ErrConflict
	} else if !errors.Is(err, session.ErrNotFound) && !errors.Is(err, session.ErrExpired) {
		return err
	}
	generation, err := b.randomToken(generationByteLength)
	if err != nil {
		return err
	}
	ttl, err := sessionTTL(item, b.clock.Now())
	if err != nil {
		return err
	}
	status, err := sessionCreateScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(item.ID), b.leaseKey(item.ID)},
		strconv.FormatUint(item.Version, 10),
		payload,
		generation,
		millisecondsText(ttl),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCreateStatus(status)
}

func (b *Backend) Get(ctx context.Context, id string) (*session.Session, error) {
	stored, err := b.getStored(ctx, id)
	if err != nil {
		return nil, err
	}
	return stored.item, nil
}

type storedSession struct {
	item        *session.Session
	versionText string
	payload     []byte
	generation  string
}

func (b *Backend) getStored(ctx context.Context, id string) (*storedSession, error) {
	if !validID(id) {
		return nil, ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	key := b.sessionKey(id)
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		values, err := b.client.HMGet(ctx, key, "version", "payload", "generation").Result()
		if err != nil {
			return nil, backendError(err)
		}
		if len(values) != 3 || values[0] == nil || values[1] == nil || values[2] == nil {
			return nil, session.ErrNotFound
		}
		versionText, ok := redisText(values[0])
		if !ok {
			return nil, ErrDecodeFailed
		}
		version, err := strconv.ParseUint(versionText, 10, 64)
		if err != nil || version == 0 {
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
		var item session.Session
		if err := decodeModel(b.codec, payload, &item); err != nil {
			return nil, err
		}
		if item.ID != id || !validID(item.ID) || item.Version != version || item.ExpiresAt.IsZero() {
			return nil, ErrDecodeFailed
		}
		if !sessionExpired(&item, b.clock.Now()) {
			return &storedSession{
				item:        &item,
				versionText: versionText,
				payload:     append([]byte(nil), payload...),
				generation:  generation,
			}, nil
		}
		status, err := sessionDeleteExpiredScript.Run(
			ctx,
			b.client,
			[]string{key, b.leaseKey(id)},
			versionText,
			payload,
			generation,
		).Int64()
		if err != nil {
			return nil, backendError(err)
		}
		switch status {
		case 1:
			return nil, session.ErrExpired
		case 0:
			continue
		default:
			return nil, ErrBackendUnavailable
		}
	}
}

func (b *Backend) CompareAndSwap(
	ctx context.Context,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
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
	if _, err := b.Get(ctx, id); err != nil {
		return err
	}
	status, err := sessionCompareAndSwapScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(id)},
		strconv.FormatUint(expectedVersion, 10),
		strconv.FormatUint(next.Version, 10),
		payload,
		millisecondsText(ttl),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCASStatus(status)
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

func (b *Backend) AcquireRefreshLease(
	ctx context.Context,
	sessionID string,
	duration time.Duration,
) (session.Lease, error) {
	if !validID(sessionID) || duration <= 0 {
		return nil, ErrInvalidInput
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	stored, err := b.getStored(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	owner, err := b.randomToken(ownerByteLength)
	if err != nil {
		return nil, err
	}
	now := b.clock.Now()
	remaining, err := sessionTTL(stored.item, now)
	if err != nil {
		return nil, err
	}
	ttl := ceilMillisecond(duration)
	if remaining < ttl {
		ttl = remaining
	}
	if !validLuaTTL(ttl) {
		return nil, ErrInvalidInput
	}
	expiresAt := now.Add(ttl)
	if !expiresAt.After(now) {
		return nil, ErrInvalidInput
	}
	for range maxFenceGrantAttempts {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		fence, err := b.nextFence(ctx)
		if err != nil {
			return nil, err
		}
		status, err := leaseAcquireScript.Run(
			ctx,
			b.client,
			[]string{b.sessionKey(sessionID), b.leaseKey(sessionID)},
			owner,
			strconv.FormatUint(fence, 10),
			stored.generation,
			millisecondsText(ttl),
		).Int64()
		if err != nil {
			return nil, backendError(err)
		}
		switch status {
		case 1:
			return &refreshLease{
				backend:    b,
				sessionID:  sessionID,
				key:        b.leaseKey(sessionID),
				owner:      owner,
				fence:      fence,
				generation: stored.generation,
				expiresAt:  expiresAt,
			}, nil
		case 0:
			return nil, session.ErrConflict
		case -1:
			return nil, session.ErrNotFound
		case -4:
			continue
		case -5:
			return nil, session.ErrConflict
		default:
			return nil, ErrBackendUnavailable
		}
	}
	return nil, session.ErrConflict
}

func (b *Backend) CompareAndSwapWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
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
	payload, err := encodeModel(b.codec, next)
	if err != nil {
		return err
	}
	if _, err := b.Get(ctx, id); err != nil {
		return err
	}
	now := b.clock.Now()
	if !credentials.expiresAt.After(now) {
		return session.ErrLeaseLost
	}
	ttl, err := sessionTTL(next, now)
	if err != nil {
		return err
	}
	if !validLuaTTL(ttl) {
		return ErrInvalidInput
	}
	status, err := sessionCompareAndSwapWithLeaseScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(id), b.leaseKey(id)},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		credentials.generation,
		strconv.FormatUint(expectedVersion, 10),
		strconv.FormatUint(next.Version, 10),
		payload,
		millisecondsText(ttl),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	mapped := mapFencedStatus(status)
	if mapped == nil {
		owned.markConsumed()
	}
	return mapped
}

func (b *Backend) DeleteWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
) error {
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
	if _, err := b.Get(ctx, id); err != nil {
		return err
	}
	if !credentials.expiresAt.After(b.clock.Now()) {
		return session.ErrLeaseLost
	}
	status, err := sessionDeleteWithLeaseScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(id), b.leaseKey(id)},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		credentials.generation,
		strconv.FormatUint(expectedVersion, 10),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	mapped := mapFencedStatus(status)
	if mapped == nil {
		owned.markConsumed()
	}
	return mapped
}

type refreshLease struct {
	mu sync.Mutex

	backend    *Backend
	sessionID  string
	key        string
	owner      string
	fence      uint64
	generation string
	expiresAt  time.Time
	consumed   bool
	acked      bool
}

type leaseCredentials struct {
	owner      string
	fence      uint64
	generation string
	expiresAt  time.Time
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
	credentials := leaseCredentials{owner: l.owner, fence: l.fence, generation: l.generation, expiresAt: l.expiresAt}
	sessionKey := l.backend.sessionKey(l.sessionID)
	key := l.key
	l.mu.Unlock()
	now := l.backend.clock.Now()
	if !credentials.expiresAt.After(now) {
		return false
	}
	status, err := leaseValidScript.Run(
		ctx,
		l.backend.client,
		[]string{sessionKey, key},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		credentials.generation,
	).Int64()
	return err == nil && status == 1
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
	credentials := leaseCredentials{owner: l.owner, fence: l.fence, generation: l.generation, expiresAt: l.expiresAt}
	sessionKey := l.backend.sessionKey(l.sessionID)
	key := l.key
	l.mu.Unlock()
	now := l.backend.clock.Now()
	if !credentials.expiresAt.After(now) {
		return session.ErrLeaseLost
	}
	status, err := leaseReleaseScript.Run(
		ctx,
		l.backend.client,
		[]string{sessionKey, key},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		credentials.generation,
	).Int64()
	if err != nil {
		return backendError(err)
	}
	if status != 1 {
		return session.ErrLeaseLost
	}
	l.markConsumedAndAcked()
	return nil
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
	return owned, leaseCredentials{
		owner: owned.owner, fence: owned.fence, generation: owned.generation, expiresAt: owned.expiresAt,
	}, true
}

func (b *Backend) nextFence(ctx context.Context) (uint64, error) {
	result, err := fenceNextScript.Run(ctx, b.client, []string{b.fenceKey()}).Text()
	if err != nil {
		return 0, backendError(err)
	}
	if result == "" {
		return 0, ErrFenceExhausted
	}
	fence, err := strconv.ParseUint(result, 10, 64)
	if err != nil || fence == 0 {
		return 0, ErrBackendUnavailable
	}
	return fence, nil
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
func (b *Backend) fenceKey() string            { return b.prefix + ":fence" }

func (b *Backend) taggedKey(kind, id string) string {
	return b.prefix + ":" + kind + ":{" + digest(id) + "}"
}

func (b *Backend) key(kind, id string) string {
	return b.prefix + ":" + kind + ":" + digest(id)
}

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
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validID(id string) bool {
	return strings.TrimSpace(id) != ""
}

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
	if !validID(id) || expectedVersion == 0 || expectedVersion == math.MaxUint64 ||
		next == nil || next.ID != id || next.Version != expectedVersion+1 {
		return ErrInvalidInput
	}
	return nil
}

func sessionTTL(item *session.Session, now time.Time) (time.Duration, error) {
	if item == nil || item.ExpiresAt.IsZero() {
		return 0, ErrInvalidInput
	}
	deadline := item.ExpiresAt
	if !item.IdleExpiresAt.IsZero() && item.IdleExpiresAt.Before(deadline) {
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
	return !item.ExpiresAt.After(now) ||
		(!item.IdleExpiresAt.IsZero() && !item.IdleExpiresAt.After(now))
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

func mapCreateStatus(status int64) error {
	switch status {
	case 1:
		return nil
	case 0:
		return session.ErrConflict
	case scriptStatusStorageFailed:
		return ErrBackendUnavailable
	default:
		return ErrBackendUnavailable
	}
}

func mapCASStatus(status int64) error {
	switch status {
	case 1:
		return nil
	case 0:
		return session.ErrConflict
	case -1:
		return session.ErrNotFound
	case scriptStatusStorageFailed:
		return ErrBackendUnavailable
	default:
		return ErrBackendUnavailable
	}
}

func mapFencedStatus(status int64) error {
	switch status {
	case 1:
		return nil
	case 0:
		return session.ErrConflict
	case -1:
		return session.ErrNotFound
	case -3:
		return session.ErrLeaseLost
	case scriptStatusStorageFailed:
		return ErrBackendUnavailable
	default:
		return ErrBackendUnavailable
	}
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

func millisecondsText(duration time.Duration) string {
	return strconv.FormatInt(duration.Milliseconds(), 10)
}

func validLuaTTL(duration time.Duration) bool {
	milliseconds := duration.Milliseconds()
	return duration > 0 && milliseconds > 0 && milliseconds <= maxLuaExactInteger
}

var _ session.Backend = (*Backend)(nil)
var _ session.Lease = (*refreshLease)(nil)
