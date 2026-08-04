package random

import (
	"bytes"
	"testing"
)

func TestIDReturnsBase64URLWithoutPadding(t *testing.T) {
	got, err := ID(bytes.NewReader(make([]byte, 32)), 32)
	if err != nil {
		t.Fatal(err)
	}
	if got != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("ID() = %q", got)
	}
}
