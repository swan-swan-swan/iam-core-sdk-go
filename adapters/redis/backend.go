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
	maxPrefixLength = 256
	ownerByteLength = 32
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
	ttl, err := sessionTTL(item, b.clock.Now())
	if err != nil {
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
	status, err := sessionCreateScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(item.ID)},
		strconv.FormatUint(item.Version, 10),
		payload,
		millisecondsText(ttl),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCreateStatus(status)
}

func (b *Backend) Get(ctx context.Context, id string) (*session.Session, error) {
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
		values, err := b.client.HMGet(ctx, key, "version", "payload").Result()
		if err != nil {
			return nil, backendError(err)
		}
		if len(values) != 2 || values[0] == nil || values[1] == nil {
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
		var item session.Session
		if err := decodeModel(b.codec, payload, &item); err != nil {
			return nil, err
		}
		if item.ID != id || !validID(item.ID) || item.Version != version || item.ExpiresAt.IsZero() {
			return nil, ErrDecodeFailed
		}
		if !sessionExpired(&item, b.clock.Now()) {
			return &item, nil
		}
		status, err := sessionDeleteExpiredScript.Run(
			ctx,
			b.client,
			[]string{key, b.leaseKey(id)},
			versionText,
			payload,
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
	if _, err := b.Get(ctx, sessionID); err != nil {
		return nil, err
	}
	now := b.clock.Now()
	ttl := ceilMillisecond(duration)
	expiresAt := now.Add(ttl)
	nowText, ok := millisecondInstant(now)
	if !ok {
		return nil, ErrInvalidInput
	}
	expiresText, ok := millisecondInstant(expiresAt)
	if !ok || !expiresAt.After(now) {
		return nil, ErrInvalidInput
	}
	b.randomMu.Lock()
	ownerBytes := make([]byte, ownerByteLength)
	_, randomErr := io.ReadFull(b.random, ownerBytes)
	b.randomMu.Unlock()
	if randomErr != nil {
		return nil, ErrRandomSource
	}
	owner := base64.RawURLEncoding.EncodeToString(ownerBytes)
	clear(ownerBytes)
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
		expiresText,
		millisecondsText(ttl),
		nowText,
	).Int64()
	if err != nil {
		return nil, backendError(err)
	}
	switch status {
	case 1:
		return &refreshLease{
			backend:   b,
			sessionID: sessionID,
			key:       b.leaseKey(sessionID),
			owner:     owner,
			fence:     fence,
			expiresAt: expiresAt,
		}, nil
	case 0:
		return nil, session.ErrConflict
	case -1:
		return nil, session.ErrNotFound
	default:
		return nil, ErrBackendUnavailable
	}
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
	now := b.clock.Now()
	nowText, ok := millisecondInstant(now)
	if !ok {
		return ErrInvalidInput
	}
	if !credentials.expiresAt.After(now) {
		return session.ErrLeaseLost
	}
	ttl, err := sessionTTL(next, now)
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
	status, err := sessionCompareAndSwapWithLeaseScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(id), b.leaseKey(id)},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		strconv.FormatInt(credentials.expiresAt.UnixMilli(), 10),
		nowText,
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
	now := b.clock.Now()
	nowText, ok := millisecondInstant(now)
	if !ok {
		return ErrInvalidInput
	}
	if !credentials.expiresAt.After(now) {
		return session.ErrLeaseLost
	}
	if _, err := b.Get(ctx, id); err != nil {
		return err
	}
	status, err := sessionDeleteWithLeaseScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(id), b.leaseKey(id)},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		strconv.FormatInt(credentials.expiresAt.UnixMilli(), 10),
		nowText,
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

	backend   *Backend
	sessionID string
	key       string
	owner     string
	fence     uint64
	expiresAt time.Time
	consumed  bool
	acked     bool
}

type leaseCredentials struct {
	owner     string
	fence     uint64
	expiresAt time.Time
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
	credentials := leaseCredentials{owner: l.owner, fence: l.fence, expiresAt: l.expiresAt}
	key := l.key
	l.mu.Unlock()
	now := l.backend.clock.Now()
	if !credentials.expiresAt.After(now) {
		return false
	}
	nowText, ok := millisecondInstant(now)
	if !ok {
		return false
	}
	status, err := leaseValidScript.Run(
		ctx,
		l.backend.client,
		[]string{key},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		strconv.FormatInt(credentials.expiresAt.UnixMilli(), 10),
		nowText,
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
	credentials := leaseCredentials{owner: l.owner, fence: l.fence, expiresAt: l.expiresAt}
	key := l.key
	l.mu.Unlock()
	now := l.backend.clock.Now()
	if !credentials.expiresAt.After(now) {
		return session.ErrLeaseLost
	}
	nowText, ok := millisecondInstant(now)
	if !ok {
		return ErrInvalidInput
	}
	status, err := leaseReleaseScript.Run(
		ctx,
		l.backend.client,
		[]string{key},
		credentials.owner,
		strconv.FormatUint(credentials.fence, 10),
		strconv.FormatInt(credentials.expiresAt.UnixMilli(), 10),
		nowText,
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
	return owned, leaseCredentials{owner: owned.owner, fence: owned.fence, expiresAt: owned.expiresAt}, true
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

func millisecondInstant(value time.Time) (string, bool) {
	milliseconds := value.UnixMilli()
	truncated := time.UnixMilli(milliseconds)
	return strconv.FormatInt(milliseconds, 10), truncated.Equal(value.Truncate(time.Millisecond))
}

var _ session.Backend = (*Backend)(nil)
var _ session.Lease = (*refreshLease)(nil)
