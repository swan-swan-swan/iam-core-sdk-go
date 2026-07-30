package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const DefaultMaxBodyBytes int64 = 1 << 20

type Correlation struct {
	RequestID string
	TraceID   string
}

type Response struct {
	StatusCode  int
	Header      http.Header
	Body        []byte
	Correlation Correlation
}

type Client struct {
	HTTP         *http.Client
	MaxBodyBytes int64
}

func (c Client) Do(request *http.Request) (Response, error) {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	limit := c.MaxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}
	ApplyHeaders(request.Context(), request.Header)
	raw, err := httpClient.Do(request)
	if err != nil {
		return Response{}, fmt.Errorf("execute HTTP request: %w", err)
	}
	defer raw.Body.Close()
	mediaType, _, err := mime.ParseMediaType(raw.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return Response{}, fmt.Errorf("unexpected content type %q", raw.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(raw.Body, limit+1))
	if err != nil {
		return Response{}, fmt.Errorf("read HTTP response: %w", err)
	}
	if int64(len(body)) > limit {
		return Response{}, fmt.Errorf("HTTP response exceeds %d bytes", limit)
	}
	correlation := Correlation{RequestID: strings.TrimSpace(raw.Header.Get("X-Request-ID"))}
	var envelope struct {
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
	}
	_ = json.Unmarshal(body, &envelope)
	if correlation.RequestID == "" {
		correlation.RequestID = strings.TrimSpace(envelope.RequestID)
	}
	correlation.TraceID = strings.TrimSpace(envelope.TraceID)
	return Response{StatusCode: raw.StatusCode, Header: raw.Header.Clone(), Body: body, Correlation: correlation}, nil
}

func DecodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode JSON response: trailing JSON value")
	}
	return nil
}
