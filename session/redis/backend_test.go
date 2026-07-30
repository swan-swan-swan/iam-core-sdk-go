package redisstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time { return c.now }

type recordingCodec struct {
	encoded []byte
}

func (c *recordingCodec) Encode(plaintext []byte) ([]byte, error) {
	c.encoded = append([]byte(nil), plaintext...)
	return append([]byte("encrypted:"), plaintext...), nil
}

func (c *recordingCodec) Decode(encoded []byte) ([]byte, error) {
	if !bytes.HasPrefix(encoded, []byte("encrypted:")) {
		return nil, errors.New("codec details")
	}
	return append([]byte(nil), encoded[len("encrypted:"):]...), nil
}

func validOptions() Options {
	return Options{
		Prefix: "iamcore",
		Codec:  &recordingCodec{},
		Clock:  fixedClock{now: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)},
		Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64)),
	}
}

func TestKeyNeverContainsRawIdentifier(t *testing.T) {
	backend := &Backend{prefix: "iamcore"}
	raw := "session-secret-id"
	got := backend.sessionKey(raw)
	sum := sha256.Sum256([]byte(raw))
	want := "iamcore:session:" + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	if strings.Contains(got, raw) {
		t.Fatal("raw identifier exposed")
	}
}

func TestAllRedisKeysHashRawIdentifiers(t *testing.T) {
	backend := &Backend{prefix: "iamcore"}
	raw := "shared-raw-secret"
	sum := sha256.Sum256([]byte(raw))
	digest := hex.EncodeToString(sum[:])
	for name, got := range map[string]string{
		"session": backend.sessionKey(raw),
		"flow":    backend.flowKey(raw),
		"lock":    backend.lockKey(raw),
	} {
		if strings.Contains(got, raw) {
			t.Fatalf("%s key exposed identifier", name)
		}
		if !strings.HasSuffix(got, digest) {
			t.Fatalf("%s key = %q, missing digest", name, got)
		}
	}
}

func TestNewValidatesDependenciesAndNormalizesPrefix(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })

	tests := []struct {
		name    string
		client  goredis.UniversalClient
		options Options
	}{
		{name: "nil client", options: validOptions()},
		{name: "typed nil client", client: (*goredis.Client)(nil), options: validOptions()},
		{name: "nil codec", client: client, options: func() Options {
			options := validOptions()
			options.Codec = nil
			return options
		}()},
		{name: "typed nil codec", client: client, options: func() Options {
			options := validOptions()
			options.Codec = (*recordingCodec)(nil)
			return options
		}()},
		{name: "nil clock", client: client, options: func() Options {
			options := validOptions()
			options.Clock = nil
			return options
		}()},
		{name: "nil random", client: client, options: func() Options {
			options := validOptions()
			options.Random = nil
			return options
		}()},
		{name: "empty prefix", client: client, options: func() Options {
			options := validOptions()
			options.Prefix = " :: "
			return options
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.client, test.options); err == nil {
				t.Fatal("expected constructor error")
			}
		})
	}

	options := validOptions()
	options.Prefix = "  iamcore:  "
	backend, err := New(client, options)
	if err != nil {
		t.Fatal(err)
	}
	if backend.prefix != "iamcore" {
		t.Fatalf("prefix = %q", backend.prefix)
	}
}

func TestExpiryTTLUsesEarlierDeadlineAndCeilsPositiveSubMillisecond(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		item *session.Session
		want time.Duration
	}{
		{
			name: "absolute expiry",
			item: &session.Session{ExpiresAt: now.Add(3 * time.Second)},
			want: 3 * time.Second,
		},
		{
			name: "idle expiry is earlier",
			item: &session.Session{
				ExpiresAt:     now.Add(3 * time.Second),
				IdleExpiresAt: now.Add(1500 * time.Millisecond),
			},
			want: 1500 * time.Millisecond,
		},
		{
			name: "sub millisecond is retained",
			item: &session.Session{ExpiresAt: now.Add(time.Nanosecond)},
			want: time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := sessionTTL(test.item, now)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ttl = %s, want %s", got, test.want)
			}
		})
	}
}

func TestExpiryTTLRejectsMissingAndNonfutureDeadlines(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	for _, item := range []*session.Session{
		{},
		{ExpiresAt: now},
		{ExpiresAt: now.Add(time.Second), IdleExpiresAt: now.Add(-time.Nanosecond)},
	} {
		_, err := sessionTTL(item, now)
		if err == nil {
			t.Fatal("expected expiry error")
		}
	}
}

func TestCeilMillisecondDoesNotOverflowMaximumDuration(t *testing.T) {
	got := ceilMillisecond(time.Duration(1<<63 - 1))
	if got <= 0 {
		t.Fatalf("rounded maximum duration overflowed: %s", got)
	}
	if got%time.Millisecond != 0 {
		t.Fatalf("rounded duration = %s, want whole milliseconds", got)
	}
}

func TestEncodeModelMarshalsJSONBeforeCodec(t *testing.T) {
	codec := &recordingCodec{}
	input := &session.Flow{
		ID:        "flow",
		State:     "state",
		ExpiresAt: time.Date(2026, 7, 30, 12, 1, 0, 0, time.UTC),
	}
	encoded, err := encodeModel(codec, input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"state"`)) && !bytes.HasPrefix(encoded, []byte("encrypted:")) {
		t.Fatal("persisted value was not passed through codec")
	}
	var decoded session.Flow
	if err := json.Unmarshal(codec.encoded, &decoded); err != nil {
		t.Fatalf("codec did not receive JSON: %v", err)
	}
	if decoded.ID != input.ID || decoded.State != input.State {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestStatusMappingPreservesSentinelsAndSanitizesBackendErrors(t *testing.T) {
	if err := mapCreateStatus(0); !errors.Is(err, session.ErrVersionConflict) {
		t.Fatalf("create status error = %v", err)
	}
	if err := mapCASStatus(-1); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("cas missing error = %v", err)
	}
	if err := mapCASStatus(0); !errors.Is(err, session.ErrVersionConflict) {
		t.Fatalf("cas conflict error = %v", err)
	}

	raw := errors.New("dial redis://user:password@host secret-key payload")
	err := backendError(raw)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("backend error = %v", err)
	}
	for _, secret := range []string{"user", "password", "host", "secret-key", "payload"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("backend error exposed %q: %v", secret, err)
		}
	}
}

func TestRandomFailureIsSanitized(t *testing.T) {
	options := validOptions()
	options.Random = io.LimitReader(strings.NewReader("short"), 5)
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })
	backend, err := New(client, options)
	if err != nil {
		t.Fatal(err)
	}
	secret := "raw-lock-identifier"
	_, err = backend.Lock(context.Background(), secret, time.Minute)
	if err == nil {
		t.Fatal("expected random error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "short") {
		t.Fatalf("error exposed secret: %v", err)
	}
}
