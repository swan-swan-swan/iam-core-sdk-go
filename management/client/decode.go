package client

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

type envelope struct {
	Code      int             `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"request_id"`
	TraceID   string          `json:"trace_id"`
}

func decodeEnvelope(body []byte, statusCode int, operation string, out any) (Metadata, error) {
	if !utf8.Valid(body) || rejectDuplicateJSONKeys(body) != nil {
		return Metadata{}, protocolError(operation, statusCode)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return Metadata{}, protocolError(operation, statusCode)
	}
	for _, required := range []string{"code", "message", "data"} {
		if _, ok := fields[required]; !ok {
			return Metadata{}, protocolError(operation, statusCode)
		}
	}
	if rawJSONNull(fields["code"]) || !validEnvelopeData(fields["data"]) {
		return Metadata{}, protocolError(operation, statusCode)
	}
	for _, optionalString := range []string{"request_id", "trace_id"} {
		if value, present := fields[optionalString]; present && rawJSONNull(value) {
			return Metadata{}, protocolError(operation, statusCode)
		}
	}

	var decoded envelope
	if err := json.Unmarshal(body, &decoded); err != nil || strings.TrimSpace(decoded.Message) == "" || !safeCorrelationID(decoded.RequestID) || !safeCorrelationID(decoded.TraceID) {
		return Metadata{}, protocolError(operation, statusCode)
	}
	metadata := Metadata{RequestID: decoded.RequestID, TraceID: decoded.TraceID}

	if statusCode < 200 || statusCode > 299 {
		managementError := &Error{
			Kind:       kindForStatus(statusCode),
			Operation:  operation,
			StatusCode: statusCode,
			IAMCode:    decoded.Code,
			Retryable:  statusCode == 429 || statusCode >= 500,
			RequestID:  decoded.RequestID,
			TraceID:    decoded.TraceID,
		}
		if !bytes.Equal(bytes.TrimSpace(decoded.Data), []byte("null")) {
			managementError.Data = cloneErrorData(decoded.Data)
		}
		return metadata, managementError
	}

	if decoded.Code != 0 {
		return metadata, protocolErrorWithMetadata(operation, statusCode, decoded)
	}
	if bytes.Equal(bytes.TrimSpace(decoded.Data), []byte("null")) {
		if out != nil {
			return metadata, protocolErrorWithMetadata(operation, statusCode, decoded)
		}
		return metadata, nil
	}
	if out == nil {
		return metadata, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return metadata, protocolErrorWithMetadata(operation, statusCode, decoded)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return metadata, protocolErrorWithMetadata(operation, statusCode, decoded)
	}
	return metadata, nil
}

func rawJSONNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func validEnvelopeData(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	if bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	return len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return &json.SyntaxError{}
			}
			if _, duplicate := seen[key]; duplicate {
				return &duplicateJSONKeyError{}
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return &json.SyntaxError{}
	}
}

type duplicateJSONKeyError struct{}

func (*duplicateJSONKeyError) Error() string { return "duplicate JSON key" }

func requireJSONEOF(decoder *json.Decoder) error {
	_, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return &duplicateJSONKeyError{}
	}
	return err
}

func safeCorrelationID(id string) bool {
	if id == "" {
		return true
	}
	if len(id) > 128 {
		return false
	}
	for _, character := range id {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '-', '_', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func kindForStatus(statusCode int) Kind {
	switch statusCode {
	case 401:
		return KindUnauthenticated
	case 403:
		return KindForbidden
	case 404:
		return KindNotFound
	case 409:
		return KindConflict
	case 429:
		return KindRateLimited
	default:
		if statusCode >= 500 {
			return KindIAMUnavailable
		}
		return KindProtocol
	}
}

func protocolError(operation string, statusCode int) *Error {
	return &Error{Kind: KindProtocol, Operation: operation, StatusCode: statusCode}
}

func protocolErrorWithMetadata(operation string, statusCode int, decoded envelope) *Error {
	return &Error{
		Kind:       KindProtocol,
		Operation:  operation,
		StatusCode: statusCode,
		IAMCode:    decoded.Code,
		RequestID:  decoded.RequestID,
		TraceID:    decoded.TraceID,
	}
}
