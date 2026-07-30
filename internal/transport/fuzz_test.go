package transport

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzDecodeJSON(f *testing.F) {
	f.Add([]byte(`{"code":0,"message":"ok","data":{"allowed":true},"request_id":"req_1","trace_id":"trace_1"}`))
	f.Add([]byte(`{"error":"invalid_grant","error_description":"authorization code expired"}`))
	f.Add([]byte(`{"code":0,"data":`))
	f.Add([]byte(`{"allowed":true} {"allowed":false}`))
	f.Add([]byte(`{"message":"` + strings.Repeat("x", 64<<10) + `"}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		if int64(len(body)) > DefaultMaxBodyBytes {
			t.Skip()
		}
		var decoded any
		err := DecodeJSON(body, &decoded)
		if err == nil && !json.Valid(body) {
			t.Fatal("decoder accepted invalid JSON")
		}
		if err == nil {
			withTrailingValue := make([]byte, 0, len(body)+3)
			withTrailingValue = append(withTrailingValue, body...)
			withTrailingValue = append(withTrailingValue, '\n', '{', '}')
			var trailingDecoded any
			if err := DecodeJSON(withTrailingValue, &trailingDecoded); err == nil {
				t.Fatal("decoder accepted trailing JSON value")
			}
		}
	})
}
