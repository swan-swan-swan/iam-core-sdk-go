package redisstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/random"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

var (
	errInvalidInput       = errors.New("session redis: invalid input")
	errEncodeFailed       = errors.New("session redis: encode failed")
	errDecodeFailed       = errors.New("session redis: decode failed")
	errRandomFailed       = errors.New("session redis: random source failed")
	ErrBackendUnavailable = errors.New("session redis: backend unavailable")
)

const scriptStatusStorageFailure int64 = -2

type Options struct {
	Prefix string
	Codec  session.Codec
	Clock  session.Clock
	Random io.Reader
}

type Backend struct {
	client   goredis.UniversalClient
	prefix   string
	codec    session.Codec
	clock    session.Clock
	random   io.Reader
	randomMu sync.Mutex
}

func New(client goredis.UniversalClient, options Options) (*Backend, error) {
	prefix := normalizePrefix(options.Prefix)
	if isNilInterface(client) || isNilInterface(options.Codec) ||
		isNilInterface(options.Clock) || isNilInterface(options.Random) || prefix == "" {
		return nil, errInvalidInput
	}
	return &Backend{
		client: client,
		prefix: prefix,
		codec:  options.Codec,
		clock:  options.Clock,
		random: options.Random,
	}, nil
}

func (b *Backend) Create(ctx context.Context, item *session.Session) error {
	if item == nil || !validID(item.ID) || item.Version != 1 {
		return errInvalidInput
	}
	ttl, err := sessionTTL(item, b.clock.Now())
	if err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, item)
	if err != nil {
		return err
	}
	status, err := sessionCreateScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(item.ID)},
		strconv.FormatUint(item.Version, 10),
		payload,
		ttl.Milliseconds(),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCreateStatus(status)
}

func (b *Backend) Get(ctx context.Context, id string) (*session.Session, error) {
	if !validID(id) {
		return nil, errInvalidInput
	}
	key := b.sessionKey(id)
	values, err := b.client.HMGet(ctx, key, "version", "payload").Result()
	if err != nil {
		return nil, backendError(err)
	}
	if len(values) != 2 || values[0] == nil || values[1] == nil {
		return nil, session.ErrNotFound
	}
	versionText, versionOK := values[0].(string)
	payloadText, payloadOK := values[1].(string)
	if !versionOK || !payloadOK {
		return nil, errDecodeFailed
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 {
		return nil, errDecodeFailed
	}
	var item session.Session
	if err := decodeModel(b.codec, []byte(payloadText), &item); err != nil {
		return nil, err
	}
	if item.Version != version || item.ID != id || !validID(item.ID) || item.ExpiresAt.IsZero() {
		return nil, errDecodeFailed
	}
	if sessionExpired(&item, b.clock.Now()) {
		if _, err := b.client.Del(ctx, key).Result(); err != nil {
			return nil, backendError(err)
		}
		return nil, session.ErrExpired
	}
	return &item, nil
}

func (b *Backend) CompareAndSwap(
	ctx context.Context,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	if !validID(id) || expectedVersion == 0 || expectedVersion == ^uint64(0) ||
		next == nil || next.ID != id || next.Version != expectedVersion+1 {
		return errInvalidInput
	}
	ttl, err := sessionTTL(next, b.clock.Now())
	if err != nil {
		return err
	}
	payload, err := encodeModel(b.codec, next)
	if err != nil {
		return err
	}
	status, err := sessionCompareAndSwapScript.Run(
		ctx,
		b.client,
		[]string{b.sessionKey(id)},
		strconv.FormatUint(expectedVersion, 10),
		strconv.FormatUint(next.Version, 10),
		payload,
		ttl.Milliseconds(),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCASStatus(status)
}

func (b *Backend) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return errInvalidInput
	}
	if _, err := b.client.Del(ctx, b.sessionKey(id)).Result(); err != nil {
		return backendError(err)
	}
	return nil
}

func (b *Backend) PutFlow(ctx context.Context, flow *session.Flow) error {
	if flow == nil || !validID(flow.ID) || flow.ExpiresAt.IsZero() {
		return errInvalidInput
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
		ttl.Milliseconds(),
	).Int64()
	if err != nil {
		return backendError(err)
	}
	return mapCreateStatus(status)
}

func (b *Backend) ConsumeFlow(ctx context.Context, id string) (*session.Flow, error) {
	if !validID(id) {
		return nil, errInvalidInput
	}
	result, err := flowConsumeScript.Run(ctx, b.client, []string{b.flowKey(id)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, backendError(err)
	}
	payload, ok := result.(string)
	if !ok {
		return nil, errDecodeFailed
	}
	var flow session.Flow
	if err := decodeModel(b.codec, []byte(payload), &flow); err != nil {
		return nil, err
	}
	if flow.ID != id || !validID(flow.ID) || flow.ExpiresAt.IsZero() {
		return nil, errDecodeFailed
	}
	if !flow.ExpiresAt.After(b.clock.Now()) {
		return nil, session.ErrExpired
	}
	return &flow, nil
}

func (b *Backend) Lock(ctx context.Context, id string, duration time.Duration) (session.Lock, error) {
	if !validID(id) || duration <= 0 {
		return nil, errInvalidInput
	}
	ttl := ceilMillisecond(duration)
	b.randomMu.Lock()
	token, err := random.ID(b.random, 32)
	b.randomMu.Unlock()
	if err != nil {
		return nil, errRandomFailed
	}
	key := b.lockKey(id)
	status, err := lockAcquireScript.Run(
		ctx,
		b.client,
		[]string{key},
		token,
		ttl.Milliseconds(),
	).Int64()
	if err != nil {
		return nil, backendError(err)
	}
	if status != 1 {
		return nil, session.ErrLocked
	}
	return &ownedLock{client: b.client, key: key, token: token}, nil
}

type ownedLock struct {
	client goredis.UniversalClient
	key    string
	token  string
}

func (l *ownedLock) Valid(ctx context.Context) bool {
	status, err := lockValidScript.Run(ctx, l.client, []string{l.key}, l.token).Int64()
	return err == nil && status == 1
}

func (l *ownedLock) Unlock(ctx context.Context) error {
	status, err := lockUnlockScript.Run(ctx, l.client, []string{l.key}, l.token).Int64()
	if err != nil {
		return backendError(err)
	}
	if status != 1 {
		return session.ErrLockLost
	}
	return nil
}

func (b *Backend) sessionKey(id string) string { return b.key("session", id) }
func (b *Backend) flowKey(id string) string    { return b.key("flow", id) }
func (b *Backend) lockKey(id string) string    { return b.key("lock", id) }

func (b *Backend) key(kind, id string) string {
	sum := sha256.Sum256([]byte(id))
	return b.prefix + ":" + kind + ":" + hex.EncodeToString(sum[:])
}

func normalizePrefix(prefix string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(prefix), ":"))
}

func validID(id string) bool {
	return strings.TrimSpace(id) != ""
}

func sessionTTL(item *session.Session, now time.Time) (time.Duration, error) {
	if item == nil || item.ExpiresAt.IsZero() {
		return 0, errInvalidInput
	}
	deadline := item.ExpiresAt
	if !item.IdleExpiresAt.IsZero() && item.IdleExpiresAt.Before(deadline) {
		deadline = item.IdleExpiresAt
	}
	return deadlineTTL(deadline, now)
}

func deadlineTTL(deadline, now time.Time) (time.Duration, error) {
	if deadline.IsZero() {
		return 0, errInvalidInput
	}
	lifetime := deadline.Sub(now)
	if lifetime <= 0 {
		return 0, session.ErrExpired
	}
	return ceilMillisecond(lifetime), nil
}

func ceilMillisecond(duration time.Duration) time.Duration {
	const maxWholeMilliseconds = time.Duration((1<<63-1)/int64(time.Millisecond)) * time.Millisecond
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

func encodeModel(codec session.Codec, value any) ([]byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, errEncodeFailed
	}
	encoded, err := codec.Encode(plaintext)
	if err != nil {
		return nil, errEncodeFailed
	}
	return encoded, nil
}

func decodeModel(codec session.Codec, encoded []byte, destination any) error {
	plaintext, err := codec.Decode(encoded)
	if err != nil {
		return errDecodeFailed
	}
	if err := json.Unmarshal(plaintext, destination); err != nil {
		return errDecodeFailed
	}
	return nil
}

func mapCreateStatus(status int64) error {
	switch status {
	case 1:
		return nil
	case 0:
		return session.ErrVersionConflict
	case scriptStatusStorageFailure:
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
		return session.ErrVersionConflict
	case -1:
		return session.ErrNotFound
	case scriptStatusStorageFailure:
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

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
