package random

import (
	"encoding/base64"
	"fmt"
	"io"
)

func ID(source io.Reader, byteCount int) (string, error) {
	if source == nil || byteCount < 16 {
		return "", fmt.Errorf("random source is nil or byte count is below 16")
	}
	value := make([]byte, byteCount)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
