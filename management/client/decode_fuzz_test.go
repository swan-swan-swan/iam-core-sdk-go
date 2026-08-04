package client

import "testing"

func FuzzDecodeEnvelope(f *testing.F) {
	for _, seed := range []string{
		`{"code":0,"message":"ok","data":null}`,
		`{"code":0,"message":"ok","data":{"nested":{"id":1}}}`,
		`{"code":7,"message":"failed","data":{"reason":"x"}}`,
		`{"code":0,"code":1,"message":"duplicate","data":null}`,
		`not-json`,
	} {
		f.Add([]byte(seed), 200, false)
	}

	f.Fuzz(func(t *testing.T, raw []byte, status int, withOutput bool) {
		if status < 100 || status > 599 {
			status = 200
		}
		if withOutput {
			var out any
			_, _ = decodeEnvelope(raw, status, "management.fuzz", &out)
			return
		}
		_, _ = decodeEnvelope(raw, status, "management.fuzz", nil)
	})
}
