package client

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
)

const redactedSensitiveString = "[REDACTED]"

type sensitiveState struct {
	value    string
	revealed atomic.Bool
}

// SensitiveString prevents a secret from being written by normal formatting,
// logging, or JSON encoding. A value can be revealed exactly once.
type SensitiveString struct {
	value string
	state *sensitiveState
}

// NewSensitiveString wraps value so it remains redacted unless explicitly
// revealed once.
func NewSensitiveString(value string) SensitiveString {
	return SensitiveString{
		value: value,
		state: &sensitiveState{value: value},
	}
}

// Reveal returns the wrapped value only on its first call across all copies.
// The zero value has no value to reveal.
func (s SensitiveString) Reveal() string {
	if s.state == nil || !s.state.revealed.CompareAndSwap(false, true) {
		return ""
	}
	return s.state.value
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
