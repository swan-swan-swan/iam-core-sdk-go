package redis_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	redisadapter "github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis"
)

func TestCodecEncryptsVerifierAndTokens(t *testing.T) {
	codec, err := redisadapter.NewAESGCMCodec(
		redisadapter.Key{ID: "primary", Bytes: bytes.Repeat([]byte{1}, 32)},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"code_verifier":"verifier-secret","access_token":"access-secret"}`)
	sealed, err := codec.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("verifier-secret")) || bytes.Contains(sealed, []byte("access-secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	opened, err := codec.Open(sealed)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open did not round-trip: err=%v", err)
	}
}

func TestCodecValidatesKeyringWithoutLeakingKeyMaterial(t *testing.T) {
	valid := redisadapter.Key{ID: "primary.v1", Bytes: bytes.Repeat([]byte{1}, 32)}
	tests := []struct {
		name      string
		primary   redisadapter.Key
		fallbacks []redisadapter.Key
	}{
		{name: "missing ID", primary: redisadapter.Key{Bytes: valid.Bytes}},
		{name: "unsafe whitespace ID", primary: redisadapter.Key{ID: " primary", Bytes: valid.Bytes}},
		{name: "unsafe separator ID", primary: redisadapter.Key{ID: "primary:one", Bytes: valid.Bytes}},
		{name: "oversized ID", primary: redisadapter.Key{ID: strings.Repeat("a", 65), Bytes: valid.Bytes}},
		{name: "short key", primary: redisadapter.Key{ID: "primary", Bytes: []byte("key-secret")}},
		{name: "long key", primary: redisadapter.Key{ID: "primary", Bytes: bytes.Repeat([]byte{2}, 33)}},
		{name: "duplicate ID", primary: valid, fallbacks: []redisadapter.Key{{ID: valid.ID, Bytes: bytes.Repeat([]byte{2}, 32)}}},
		{name: "invalid fallback", primary: valid, fallbacks: []redisadapter.Key{{ID: "fallback", Bytes: []byte("fallback-secret")}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := redisadapter.NewAESGCMCodec(test.primary, test.fallbacks)
			if !errors.Is(err, redisadapter.ErrInvalidKeyring) {
				t.Fatal("invalid keyring returned the wrong error classification")
			}
			for _, secret := range []string{"key-secret", "fallback-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("keyring error exposed key material")
				}
			}
		})
	}
}

func TestCodecCopiesCallerOwnedKeys(t *testing.T) {
	primaryBytes := bytes.Repeat([]byte{3}, 32)
	fallbackBytes := bytes.Repeat([]byte{4}, 32)
	codec, err := redisadapter.NewAESGCMCodec(
		redisadapter.Key{ID: "new", Bytes: primaryBytes},
		[]redisadapter.Key{{ID: "old", Bytes: fallbackBytes}},
	)
	if err != nil {
		t.Fatal(err)
	}
	oldCodec, err := redisadapter.NewAESGCMCodec(
		redisadapter.Key{ID: "old", Bytes: append([]byte(nil), fallbackBytes...)},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldPayload, err := oldCodec.Seal([]byte("rotation-secret"))
	if err != nil {
		t.Fatal(err)
	}
	clear(primaryBytes)
	clear(fallbackBytes)

	opened, err := codec.Open(oldPayload)
	if err != nil || string(opened) != "rotation-secret" {
		t.Fatal("caller mutation changed codec keys")
	}
	sealed, err := codec.Seal([]byte("current-secret"))
	if err != nil {
		t.Fatal("caller mutation changed primary key")
	}
	envelope := decodeTestEnvelope(t, sealed)
	if envelope.KeyID != "new" {
		t.Fatalf("seal key ID = %q, want new", envelope.KeyID)
	}
}

func TestCodecRotationAndNonceRandomness(t *testing.T) {
	oldKey := redisadapter.Key{ID: "old", Bytes: bytes.Repeat([]byte{5}, 32)}
	newKey := redisadapter.Key{ID: "new", Bytes: bytes.Repeat([]byte{6}, 32)}
	oldCodec, err := redisadapter.NewAESGCMCodec(oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := redisadapter.NewAESGCMCodec(newKey, []redisadapter.Key{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	oldPayload, err := oldCodec.Seal([]byte("rotation-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := rotated.Open(oldPayload); err != nil || string(opened) != "rotation-secret" {
		t.Fatal("fallback key did not open old payload")
	}

	first, err := rotated.Seal([]byte("same-plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := rotated.Seal([]byte("same-plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("repeated seals reused a nonce")
	}
	if decodeTestEnvelope(t, first).KeyID != "new" {
		t.Fatal("rotated codec did not seal with primary key")
	}
}

func TestCodecRejectsTamperedUnknownMalformedAndTrailingEnvelopes(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{7}, 32)
	codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{ID: "primary", Bytes: keyBytes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := codec.Seal([]byte("plaintext-secret"))
	if err != nil {
		t.Fatal(err)
	}
	valid := decodeTestEnvelope(t, sealed)
	tamperedCiphertext, err := base64.RawURLEncoding.DecodeString(valid.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 1

	tests := map[string][]byte{
		"not JSON":           []byte("payload-secret"),
		"leading whitespace": append([]byte(" "), sealed...),
		"trailing data":      append(append([]byte(nil), sealed...), []byte(` {}`)...),
		"reordered fields": []byte(fmt.Sprintf(
			`{"key_id":%q,"version":1,"nonce":%q,"ciphertext":%q}`,
			valid.KeyID,
			valid.Nonce,
			valid.Ciphertext,
		)),
		"escaped field spelling": []byte(fmt.Sprintf(
			`{"versi\u006fn":1,"key_id":%q,"nonce":%q,"ciphertext":%q}`,
			valid.KeyID,
			valid.Nonce,
			valid.Ciphertext,
		)),
		"unknown field":      []byte(`{"version":1,"key_id":"primary","nonce":"AA","ciphertext":"AA","extra":true}`),
		"duplicate field":    []byte(`{"version":1,"version":1,"key_id":"primary","nonce":"AA","ciphertext":"AA"}`),
		"unknown version":    marshalTestEnvelope(t, testEnvelope{Version: 2, KeyID: valid.KeyID, Nonce: valid.Nonce, Ciphertext: valid.Ciphertext}),
		"unknown key":        marshalTestEnvelope(t, testEnvelope{Version: 1, KeyID: "unknown", Nonce: valid.Nonce, Ciphertext: valid.Ciphertext}),
		"noncanonical nonce": marshalTestEnvelope(t, testEnvelope{Version: 1, KeyID: valid.KeyID, Nonce: valid.Nonce + "=", Ciphertext: valid.Ciphertext}),
		"short nonce":        marshalTestEnvelope(t, testEnvelope{Version: 1, KeyID: valid.KeyID, Nonce: "AA", Ciphertext: valid.Ciphertext}),
		"short ciphertext":   marshalTestEnvelope(t, testEnvelope{Version: 1, KeyID: valid.KeyID, Nonce: valid.Nonce, Ciphertext: "AA"}),
		"tampered":           marshalTestEnvelope(t, testEnvelope{Version: 1, KeyID: valid.KeyID, Nonce: valid.Nonce, Ciphertext: base64.RawURLEncoding.EncodeToString(tamperedCiphertext)}),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			opened, err := codec.Open(input)
			if !errors.Is(err, redisadapter.ErrOpenFailed) {
				t.Fatal("invalid envelope returned the wrong error classification")
			}
			if opened != nil {
				t.Fatal("invalid envelope returned plaintext")
			}
			for _, secret := range []string{"plaintext-secret", "payload-secret", base64.RawURLEncoding.EncodeToString(keyBytes)} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("open error exposed sensitive input")
				}
			}
		})
	}
}

func TestCodecIsSafeForConcurrentUse(t *testing.T) {
	codec, err := redisadapter.NewAESGCMCodec(
		redisadapter.Key{ID: "primary", Bytes: bytes.Repeat([]byte{8}, 32)},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for i := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			plaintext := []byte{byte(i), 0, 1, 2, 3}
			sealed, err := codec.Seal(plaintext)
			if err != nil {
				errorsSeen <- err
				return
			}
			opened, err := codec.Open(sealed)
			if err != nil || !bytes.Equal(opened, plaintext) {
				errorsSeen <- errors.New("concurrent round trip failed")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
}

type testEnvelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func decodeTestEnvelope(t testing.TB, input []byte) testEnvelope {
	t.Helper()
	var envelope testEnvelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		t.Fatal("sealed payload was not a JSON envelope")
	}
	return envelope
}

func marshalTestEnvelope(t testing.TB, envelope testEnvelope) []byte {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
