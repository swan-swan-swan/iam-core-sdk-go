package httpauthz

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxDecisionResponseBytes int64 = 1 << 20

var errInvalidDecisionResponse = errors.New("invalid decision response")

type decisionEnvelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		DecisionID string `json:"decision_id"`
		Allowed    bool   `json:"allowed"`
		ReasonCode string `json:"reason_code"`
		Action     string `json:"action"`
	} `json:"data"`
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`
}

func decodeDecision(body []byte) (Decision, error) {
	if int64(len(body)) > maxDecisionResponseBytes || !utf8.Valid(body) || validateDecisionStructure(body) != nil {
		return Decision{}, errInvalidDecisionResponse
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return Decision{}, errInvalidDecisionResponse
	}
	var envelope decisionEnvelope
	if decodeRequired(root, "code", &envelope.Code) != nil || envelope.Code != 0 ||
		decodeRequiredString(root, "message", &envelope.Message, false) != nil {
		return Decision{}, errInvalidDecisionResponse
	}
	dataRaw, ok := root["data"]
	if !ok {
		return Decision{}, errInvalidDecisionResponse
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(dataRaw, &data) != nil || data == nil {
		return Decision{}, errInvalidDecisionResponse
	}
	if decodeRequiredString(data, "decision_id", &envelope.Data.DecisionID, false) != nil ||
		decodeRequiredBool(data, "allowed", &envelope.Data.Allowed) != nil ||
		decodeRequiredString(data, "reason_code", &envelope.Data.ReasonCode, false) != nil ||
		decodeOptionalString(data, "action", &envelope.Data.Action) != nil ||
		decodeOptionalString(root, "request_id", &envelope.RequestID) != nil ||
		decodeOptionalString(root, "trace_id", &envelope.TraceID) != nil {
		return Decision{}, errInvalidDecisionResponse
	}
	return Decision{
		ID:         envelope.Data.DecisionID,
		Allowed:    envelope.Data.Allowed,
		ReasonCode: envelope.Data.ReasonCode,
		Action:     envelope.Data.Action,
		RequestID:  envelope.RequestID,
		TraceID:    envelope.TraceID,
	}, nil
}

func validateDecisionStructure(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errInvalidDecisionResponse
	}
	if walkObject(decoder, rootDecisionFields, true) != nil {
		return errInvalidDecisionResponse
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidDecisionResponse
	}
	return nil
}

var rootDecisionFields = map[string]struct{}{
	"code": {}, "message": {}, "data": {}, "request_id": {}, "trace_id": {},
}

var dataDecisionFields = map[string]struct{}{
	"decision_id": {}, "allowed": {}, "reason_code": {}, "action": {},
}

func walkObject(decoder *json.Decoder, canonical map[string]struct{}, root bool) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return errInvalidDecisionResponse
		}
		key, ok := keyToken.(string)
		if !ok {
			return errInvalidDecisionResponse
		}
		if _, duplicate := seen[key]; duplicate || conflictingJSONKey(key, canonical) {
			return errInvalidDecisionResponse
		}
		seen[key] = struct{}{}
		if root && key == "data" {
			opening, err := decoder.Token()
			if err != nil || opening != json.Delim('{') || walkObject(decoder, dataDecisionFields, false) != nil {
				return errInvalidDecisionResponse
			}
			continue
		}
		if skipJSONValue(decoder) != nil {
			return errInvalidDecisionResponse
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errInvalidDecisionResponse
	}
	return nil
}

func conflictingJSONKey(key string, canonical map[string]struct{}) bool {
	if _, exact := canonical[key]; exact {
		return false
	}
	for known := range canonical {
		if strings.EqualFold(key, known) {
			return true
		}
	}
	return false
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidDecisionResponse
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return errInvalidDecisionResponse
			}
			if skipJSONValue(decoder) != nil {
				return errInvalidDecisionResponse
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidDecisionResponse
		}
	case '[':
		for decoder.More() {
			if skipJSONValue(decoder) != nil {
				return errInvalidDecisionResponse
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidDecisionResponse
		}
	default:
		return errInvalidDecisionResponse
	}
	return nil
}

func decodeRequired(fields map[string]json.RawMessage, name string, target any) error {
	raw, ok := fields[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, target) != nil {
		return errInvalidDecisionResponse
	}
	return nil
}

func decodeRequiredBool(fields map[string]json.RawMessage, name string, target *bool) error {
	raw, ok := fields[name]
	if !ok {
		return errInvalidDecisionResponse
	}
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		*target = true
	case "false":
		*target = false
	default:
		return errInvalidDecisionResponse
	}
	return nil
}

func decodeRequiredString(fields map[string]json.RawMessage, name string, target *string, allowEmpty bool) error {
	if decodeRequired(fields, name, target) != nil || (!allowEmpty && *target == "") || !safeEnvelopeString(*target) {
		return errInvalidDecisionResponse
	}
	return nil
}

func decodeOptionalString(fields map[string]json.RawMessage, name string, target *string) error {
	if _, ok := fields[name]; !ok {
		return nil
	}
	return decodeRequiredString(fields, name, target, true)
}

func safeEnvelopeString(value string) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && !strings.ContainsFunc(value, unicode.IsControl)
}
