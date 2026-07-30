package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const encryptedEnvelopeVersion = 1

var (
	errInvalidKeyring = errors.New("session codec: invalid keyring")
	errEncodeFailed   = errors.New("session codec: encode failed")
	errDecodeFailed   = errors.New("session codec: decode failed")
)

type Codec interface {
	Encode([]byte) ([]byte, error)
	Decode([]byte) ([]byte, error)
}

type Key struct {
	ID    string
	Bytes []byte
}

type encryptedEnvelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type aesGCMCodec struct {
	primaryID string
	keys      map[string][]byte
}

func NewAESGCMCodec(primary Key, fallbacks []Key) (Codec, error) {
	keys := make(map[string][]byte, len(fallbacks)+1)
	all := make([]Key, 0, len(fallbacks)+1)
	all = append(all, primary)
	all = append(all, fallbacks...)
	for _, key := range all {
		if strings.TrimSpace(key.ID) == "" || strings.TrimSpace(key.ID) != key.ID || len(key.Bytes) != 32 {
			return nil, errInvalidKeyring
		}
		if _, exists := keys[key.ID]; exists {
			return nil, errInvalidKeyring
		}
		keys[key.ID] = append([]byte(nil), key.Bytes...)
	}
	return &aesGCMCodec{primaryID: primary.ID, keys: keys}, nil
}

func (c *aesGCMCodec) Encode(plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(c.keys[c.primaryID])
	if err != nil {
		return nil, errEncodeFailed
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errEncodeFailed
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, envelopeAAD(encryptedEnvelopeVersion, c.primaryID))
	envelope := encryptedEnvelope{
		Version:    encryptedEnvelopeVersion,
		KeyID:      c.primaryID,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, errEncodeFailed
	}
	return encoded, nil
}

func (c *aesGCMCodec) Decode(encoded []byte) ([]byte, error) {
	var envelope encryptedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errDecodeFailed
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errDecodeFailed
	}
	if envelope.Version != encryptedEnvelopeVersion || envelope.KeyID == "" ||
		envelope.Nonce == "" || envelope.Ciphertext == "" {
		return nil, errDecodeFailed
	}
	key, exists := c.keys[envelope.KeyID]
	if !exists {
		return nil, errDecodeFailed
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, errDecodeFailed
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, errDecodeFailed
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < gcm.Overhead() {
		return nil, errDecodeFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, envelopeAAD(envelope.Version, envelope.KeyID))
	if err != nil {
		return nil, errDecodeFailed
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func envelopeAAD(version int, keyID string) []byte {
	return []byte(strconv.Itoa(version) + "\x00" + keyID)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errDecodeFailed
		}
		return err
	}
	return nil
}
