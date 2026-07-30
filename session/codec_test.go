package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAESGCMCodecEncryptsWithFreshNonceAndRotatesKeys(t *testing.T) {
	oldKey := Key{ID: "old", Bytes: bytes.Repeat([]byte{1}, 32)}
	newKey := Key{ID: "new", Bytes: bytes.Repeat([]byte{2}, 32)}
	oldCodec, err := NewAESGCMCodec(oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"access_token":"secret"}`)
	first, err := oldCodec.Encode(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := oldCodec.Encode(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("encryptions reused nonce")
	}
	if bytes.Contains(first, []byte("secret")) {
		t.Fatal("ciphertext envelope contains plaintext")
	}

	rotated, err := NewAESGCMCodec(newKey, []Key{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := rotated.Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("plaintext = %q", decoded)
	}
	current, err := rotated.Encode(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(current, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "new" {
		t.Fatalf("key id = %q", envelope.KeyID)
	}
}

func TestAESGCMCodecRejectsInvalidKeyrings(t *testing.T) {
	valid := bytes.Repeat([]byte{1}, 32)
	cases := []struct {
		name      string
		primary   Key
		fallbacks []Key
	}{
		{name: "empty primary id", primary: Key{Bytes: valid}},
		{name: "whitespace primary id", primary: Key{ID: " ", Bytes: valid}},
		{name: "padded primary id", primary: Key{ID: " primary ", Bytes: valid}},
		{name: "short primary key", primary: Key{ID: "primary", Bytes: valid[:31]}},
		{name: "long primary key", primary: Key{ID: "primary", Bytes: append(valid, 1)}},
		{name: "empty fallback id", primary: Key{ID: "primary", Bytes: valid}, fallbacks: []Key{{Bytes: valid}}},
		{name: "invalid fallback length", primary: Key{ID: "primary", Bytes: valid}, fallbacks: []Key{{ID: "old", Bytes: valid[:31]}}},
		{name: "duplicate primary id", primary: Key{ID: "same", Bytes: valid}, fallbacks: []Key{{ID: "same", Bytes: valid}}},
		{name: "duplicate fallback id", primary: Key{ID: "primary", Bytes: valid}, fallbacks: []Key{{ID: "same", Bytes: valid}, {ID: "same", Bytes: valid}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAESGCMCodec(test.primary, test.fallbacks)
			if err == nil {
				t.Fatal("expected error")
			}
			for _, key := range append([]Key{test.primary}, test.fallbacks...) {
				if strings.TrimSpace(key.ID) != "" && strings.Contains(err.Error(), key.ID) {
					t.Fatalf("error exposes key id: %v", err)
				}
				if len(key.Bytes) != 0 && strings.Contains(err.Error(), string(key.Bytes)) {
					t.Fatalf("error exposes key material: %v", err)
				}
			}
		})
	}
}

func TestAESGCMCodecCopiesKeysAndInputs(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{7}, 32)
	primary := Key{ID: "primary", Bytes: keyBytes}
	codec, err := NewAESGCMCodec(primary, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes[0] = 8
	primary.Bytes[1] = 9

	plaintext := []byte("sensitive plaintext")
	original := append([]byte(nil), plaintext...)
	encoded, err := codec.Encode(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, original) {
		t.Fatal("encode mutated plaintext")
	}
	plaintext[0] = 'X'
	decoded, err := codec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q", decoded)
	}
	encoded[0] = 'X'
	if bytes.Equal(decoded, encoded) {
		t.Fatal("decode returned ciphertext alias")
	}
}

func TestAESGCMCodecCopiesFallbackKeyMaterial(t *testing.T) {
	oldBytes := bytes.Repeat([]byte{10}, 32)
	oldCodec, err := NewAESGCMCodec(Key{ID: "old", Bytes: append([]byte(nil), oldBytes...)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := oldCodec.Encode([]byte("fallback plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewAESGCMCodec(
		Key{ID: "new", Bytes: bytes.Repeat([]byte{11}, 32)},
		[]Key{{ID: "old", Bytes: oldBytes}},
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := range oldBytes {
		oldBytes[index] = 12
	}
	decoded, err := rotated.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "fallback plaintext" {
		t.Fatalf("plaintext = %q", decoded)
	}
}

func TestAESGCMCodecRejectsMalformedTamperedAndUnknownEnvelopes(t *testing.T) {
	key := Key{ID: "primary", Bytes: bytes.Repeat([]byte{3}, 32)}
	codec, err := NewAESGCMCodec(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("plaintext-must-stay-secret-x")
	valid, err := codec.Encode(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var original encryptedEnvelope
	if err := json.Unmarshal(valid, &original); err != nil {
		t.Fatal(err)
	}

	mutateBinary := func(value string) string {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 1
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	envelopeJSON := func(envelope encryptedEnvelope) []byte {
		value, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	cases := []struct {
		name  string
		value []byte
	}{
		{name: "empty", value: nil},
		{name: "malformed json", value: []byte(`{`)},
		{name: "trailing json", value: append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{name: "unknown field", value: []byte(`{"version":1,"key_id":"primary","nonce":"AA","ciphertext":"AA","extra":true}`)},
		{name: "case variant field", value: []byte(fmt.Sprintf(`{"Version":1,"key_id":%q,"nonce":%q,"ciphertext":%q}`, original.KeyID, original.Nonce, original.Ciphertext))},
		{name: "duplicate version", value: []byte(fmt.Sprintf(`{"version":1,"version":1,"key_id":%q,"nonce":%q,"ciphertext":%q}`, original.KeyID, original.Nonce, original.Ciphertext))},
		{name: "duplicate key id", value: []byte(fmt.Sprintf(`{"version":1,"key_id":%q,"key_id":%q,"nonce":%q,"ciphertext":%q}`, original.KeyID, original.KeyID, original.Nonce, original.Ciphertext))},
		{name: "duplicate nonce", value: []byte(fmt.Sprintf(`{"version":1,"key_id":%q,"nonce":%q,"nonce":%q,"ciphertext":%q}`, original.KeyID, original.Nonce, original.Nonce, original.Ciphertext))},
		{name: "duplicate ciphertext", value: []byte(fmt.Sprintf(`{"version":1,"key_id":%q,"nonce":%q,"ciphertext":%q,"ciphertext":%q}`, original.KeyID, original.Nonce, original.Ciphertext, original.Ciphertext))},
		{name: "missing version", value: []byte(`{"key_id":"primary","nonce":"AA","ciphertext":"AA"}`)},
		{name: "missing key id", value: []byte(`{"version":1,"nonce":"AA","ciphertext":"AA"}`)},
		{name: "missing nonce", value: []byte(`{"version":1,"key_id":"primary","ciphertext":"AA"}`)},
		{name: "missing ciphertext field", value: []byte(`{"version":1,"key_id":"primary","nonce":"AA"}`)},
		{name: "unknown version", value: envelopeJSON(func() encryptedEnvelope { value := original; value.Version++; return value }())},
		{name: "unknown key id", value: envelopeJSON(func() encryptedEnvelope { value := original; value.KeyID = "unknown"; return value }())},
		{name: "empty key id", value: envelopeJSON(func() encryptedEnvelope { value := original; value.KeyID = ""; return value }())},
		{name: "tampered key id aad", value: envelopeJSON(func() encryptedEnvelope { value := original; value.KeyID = "other"; return value }())},
		{name: "tampered nonce", value: envelopeJSON(func() encryptedEnvelope { value := original; value.Nonce = mutateBinary(value.Nonce); return value }())},
		{name: "short nonce", value: envelopeJSON(func() encryptedEnvelope { value := original; value.Nonce = "AA"; return value }())},
		{name: "invalid nonce base64", value: envelopeJSON(func() encryptedEnvelope { value := original; value.Nonce = "%%%"; return value }())},
		{name: "noncanonical nonce base64", value: envelopeJSON(func() encryptedEnvelope {
			value := original
			value.Nonce = value.Nonce[:1] + "\n" + value.Nonce[1:]
			return value
		}())},
		{name: "tampered ciphertext", value: envelopeJSON(func() encryptedEnvelope {
			value := original
			value.Ciphertext = mutateBinary(value.Ciphertext)
			return value
		}())},
		{name: "invalid ciphertext base64", value: envelopeJSON(func() encryptedEnvelope { value := original; value.Ciphertext = "%%%"; return value }())},
		{name: "noncanonical ciphertext base64", value: envelopeJSON(func() encryptedEnvelope {
			value := original
			value.Ciphertext = nonCanonicalRawURL(t, value.Ciphertext)
			return value
		}())},
		{name: "missing ciphertext", value: envelopeJSON(func() encryptedEnvelope { value := original; value.Ciphertext = ""; return value }())},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := codec.Decode(test.value)
			if err == nil {
				t.Fatalf("decoded unexpected plaintext %q", decoded)
			}
			if len(decoded) != 0 {
				t.Fatalf("partial plaintext returned: %q", decoded)
			}
			for _, secret := range []string{string(plaintext), key.ID, original.Nonce, original.Ciphertext, string(test.value)} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("error exposes sensitive input: %v", err)
				}
			}
		})
	}
}

func nonCanonicalRawURL(t *testing.T, canonical string) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, replacement := range alphabet {
		candidate := canonical[:len(canonical)-1] + string(replacement)
		if candidate == canonical {
			continue
		}
		candidateDecoded, err := base64.RawURLEncoding.DecodeString(candidate)
		if err == nil && bytes.Equal(candidateDecoded, decoded) {
			return candidate
		}
	}
	t.Fatal("test value has no noncanonical RawURL representation")
	return ""
}

func TestAESGCMCodecAuthenticatesVersionAndKeyID(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{4}, 32)
	codec, err := NewAESGCMCodec(
		Key{ID: "primary", Bytes: keyBytes},
		[]Key{{ID: "other", Bytes: append([]byte(nil), keyBytes...)}},
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := codec.Encode([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.KeyID = "other"
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(tampered); err == nil {
		t.Fatal("key id tamper passed authentication")
	}
}

func TestAESGCMCodecRejectsCiphertextFromDifferentKeyWithSameID(t *testing.T) {
	first, err := NewAESGCMCodec(Key{ID: "primary", Bytes: bytes.Repeat([]byte{5}, 32)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAESGCMCodec(Key{ID: "primary", Bytes: bytes.Repeat([]byte{6}, 32)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := first.Encode([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Decode(encoded); err == nil {
		t.Fatal("ciphertext decrypted with wrong key")
	}
}
