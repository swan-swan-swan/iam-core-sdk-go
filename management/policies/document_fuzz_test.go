package policies

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzPolicyDocument(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`{}`), []byte(`{"Statement":[]}`), []byte(`[]`), []byte(`null`), []byte(`{"x":1} trailing`), nil} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		cloned, ok := cloneJSONObject(json.RawMessage(input))
		if !ok {
			return
		}
		trimmed := bytes.TrimSpace(cloned)
		if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(cloned) {
			t.Fatalf("accepted invalid object %q", cloned)
		}
		if len(input) > 0 {
			input[0] ^= 0xff
			if !json.Valid(cloned) {
				t.Fatal("clone aliases fuzz input")
			}
		}
	})
}
