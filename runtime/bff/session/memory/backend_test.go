package memory_test

import (
	"bytes"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/memory"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/sessiontest"
)

func TestMemoryBackendConformance(t *testing.T) {
	sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
		t.Helper()
		return memory.New(memory.Options{
			Clock:  clock,
			Random: bytes.NewReader(bytes.Repeat([]byte{1}, 4096)),
		})
	})
}
