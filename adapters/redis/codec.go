package redis

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
)

const (
	encryptedEnvelopeVersion = 1
	maxKeyIDLength           = 64
)

var (
	ErrInvalidKeyring = errors.New("redis adapter: invalid keyring")
	ErrSealFailed     = errors.New("redis adapter: seal failed")
	ErrOpenFailed     = errors.New("redis adapter: open failed")
)

type Key struct {
	ID    string
	Bytes []byte
}

type Codec interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
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
		if !safeKeyID(key.ID) || len(key.Bytes) != 32 {
			return nil, ErrInvalidKeyring
		}
		if _, exists := keys[key.ID]; exists {
			return nil, ErrInvalidKeyring
		}
		keys[key.ID] = append([]byte(nil), key.Bytes...)
	}
	return &aesGCMCodec{primaryID: primary.ID, keys: keys}, nil
}

func (c *aesGCMCodec) Seal(plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(c.keys[c.primaryID])
	if err != nil {
		return nil, ErrSealFailed
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrSealFailed
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, envelopeAAD(encryptedEnvelopeVersion, c.primaryID))
	encoded, err := json.Marshal(encryptedEnvelope{
		Version:    encryptedEnvelopeVersion,
		KeyID:      c.primaryID,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, ErrSealFailed
	}
	return encoded, nil
}

func (c *aesGCMCodec) Open(encoded []byte) ([]byte, error) {
	envelope, err := parseEncryptedEnvelope(encoded)
	if err != nil || envelope.Version != encryptedEnvelopeVersion || envelope.KeyID == "" ||
		envelope.Nonce == "" || envelope.Ciphertext == "" {
		return nil, ErrOpenFailed
	}
	key, exists := c.keys[envelope.KeyID]
	if !exists {
		return nil, ErrOpenFailed
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrOpenFailed
	}
	nonce, err := decodeCanonicalBase64(envelope.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, ErrOpenFailed
	}
	ciphertext, err := decodeCanonicalBase64(envelope.Ciphertext)
	if err != nil || len(ciphertext) < gcm.Overhead() {
		return nil, ErrOpenFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, envelopeAAD(envelope.Version, envelope.KeyID))
	if err != nil {
		return nil, ErrOpenFailed
	}
	return plaintext, nil
}

func safeKeyID(id string) bool {
	if len(id) == 0 || len(id) > maxKeyIDLength {
		return false
	}
	for _, character := range []byte(id) {
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

func parseEncryptedEnvelope(encoded []byte) (encryptedEnvelope, error) {
	var envelope encryptedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return encryptedEnvelope{}, ErrOpenFailed
	}
	seen := make(map[string]bool, 4)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return encryptedEnvelope{}, ErrOpenFailed
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return encryptedEnvelope{}, ErrOpenFailed
		}
		seen[name] = true
		switch name {
		case "version":
			err = decoder.Decode(&envelope.Version)
		case "key_id":
			err = decoder.Decode(&envelope.KeyID)
		case "nonce":
			err = decoder.Decode(&envelope.Nonce)
		case "ciphertext":
			err = decoder.Decode(&envelope.Ciphertext)
		default:
			return encryptedEnvelope{}, ErrOpenFailed
		}
		if err != nil {
			return encryptedEnvelope{}, ErrOpenFailed
		}
	}
	closeToken, err := decoder.Token()
	if err != nil || closeToken != json.Delim('}') {
		return encryptedEnvelope{}, ErrOpenFailed
	}
	for _, name := range []string{"version", "key_id", "nonce", "ciphertext"} {
		if !seen[name] {
			return encryptedEnvelope{}, ErrOpenFailed
		}
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return encryptedEnvelope{}, ErrOpenFailed
	}
	return envelope, nil
}

func decodeCanonicalBase64(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, ErrOpenFailed
	}
	return decoded, nil
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
