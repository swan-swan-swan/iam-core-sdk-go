package client

import (
	"encoding/json"
	"fmt"
	"reflect"
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

func TestSensitiveStringHasExactSingleValueFieldLayout(t *testing.T) {
	typeOfSensitive := reflect.TypeOf(SensitiveString{})
	if typeOfSensitive.NumField() != 1 {
		t.Fatalf("SensitiveString field count = %d, want 1", typeOfSensitive.NumField())
	}
	field := typeOfSensitive.Field(0)
	if field.Name != "value" || field.Type.Kind() != reflect.String || field.PkgPath == "" {
		t.Errorf("SensitiveString field = %#v, want unexported string value", field)
	}
}

func TestSensitiveStringRevealIsRepeatableAcrossCopies(t *testing.T) {
	value := NewSensitiveString("repeatable-secret")
	copyOfValue := value
	if got := value.Reveal(); got != "repeatable-secret" {
		t.Errorf("first Reveal() = %q, want secret", got)
	}
	if got := value.Reveal(); got != "repeatable-secret" {
		t.Errorf("second Reveal() = %q, want secret", got)
	}
	if got := copyOfValue.Reveal(); got != "repeatable-secret" {
		t.Errorf("Reveal() through copy = %q, want secret", got)
	}
}

func TestSensitiveStringZeroValueIsAlwaysSafe(t *testing.T) {
	var value SensitiveString
	for _, got := range []string{
		fmt.Sprint(value),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
		value.String(),
		value.GoString(),
	} {
		if got != "[REDACTED]" {
			t.Errorf("zero-value formatting = %q, want [REDACTED]", got)
		}
	}
	gotJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	if string(gotJSON) != `"[REDACTED]"` {
		t.Errorf("json.Marshal() = %s, want redacted JSON string", gotJSON)
	}
	if got := value.Reveal(); got != "" {
		t.Errorf("first zero-value Reveal() = %q, want empty", got)
	}
	if got := value.Reveal(); got != "" {
		t.Errorf("second zero-value Reveal() = %q, want empty", got)
	}
}
