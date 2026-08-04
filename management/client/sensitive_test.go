package client

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

func TestSensitiveStringRedactsAllDefaultFormattingAndJSON(t *testing.T) {
	secret := NewSensitiveString("credential-that-must-not-leak")
	for _, got := range []string{
		fmt.Sprint(secret),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%#v", secret),
	} {
		if got != "[REDACTED]" {
			t.Errorf("formatted sensitive value = %q, want [REDACTED]", got)
		}
	}

	gotJSON, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	if string(gotJSON) != `"[REDACTED]"` {
		t.Errorf("json.Marshal() = %s, want redacted JSON string", gotJSON)
	}
}

func TestSensitiveStringRevealIsSingleUseAcrossCopies(t *testing.T) {
	value := NewSensitiveString("one-time-secret")
	copyOfValue := value
	if got := value.Reveal(); got != "one-time-secret" {
		t.Errorf("first Reveal() = %q, want secret", got)
	}
	if got := copyOfValue.Reveal(); got != "" {
		t.Errorf("Reveal() through copy = %q, want empty after first reveal", got)
	}
}

func TestSensitiveStringRevealIsConcurrentSafeAcrossCopies(t *testing.T) {
	value := NewSensitiveString("one-time-secret")
	const attempts = 32

	results := make(chan string, attempts)
	var group sync.WaitGroup
	for range attempts {
		copyOfValue := value
		group.Add(1)
		go func() {
			defer group.Done()
			results <- copyOfValue.Reveal()
		}()
	}
	group.Wait()
	close(results)

	count := 0
	for got := range results {
		if got == "one-time-secret" {
			count++
		} else if got != "" {
			t.Errorf("Reveal() = %q, want secret or empty", got)
		}
	}
	if count != 1 {
		t.Errorf("secret reveal count = %d, want 1", count)
	}
}
