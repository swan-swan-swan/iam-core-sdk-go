package client

import (
	"encoding/json"
	"fmt"
)

const redactedSensitiveString = "[REDACTED]"

// SensitiveString prevents a secret from being written by normal formatting,
// logging, or JSON encoding. Reveal is explicit and repeatable.
type SensitiveString struct{ value string }

// NewSensitiveString wraps value so it remains redacted unless explicitly
// revealed.
func NewSensitiveString(value string) SensitiveString {
	return SensitiveString{value: value}
}

// Reveal returns the wrapped value. It is explicit and repeatable.
func (s SensitiveString) Reveal() string {
	return s.value
}

func (SensitiveString) String() string {
	return redactedSensitiveString
}

func (SensitiveString) GoString() string {
	return redactedSensitiveString
}

// Format prevents every fmt verb from exposing the wrapped value.
func (SensitiveString) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte(redactedSensitiveString))
}

// MarshalJSON writes a redacted JSON string and never the wrapped value.
func (SensitiveString) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedSensitiveString)
}
