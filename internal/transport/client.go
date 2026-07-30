package transport

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
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
	// HTTP is optional. An injected client retains its caller-defined transport
	// and redirect behavior; Client.Do invokes it once without an SDK retry loop.
	HTTP         *http.Client
	MaxBodyBytes int64
}

func (c Client) Do(request *http.Request) (Response, error) {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = newDefaultHTTPClient()
	}
	limit := c.MaxBodyBytes
	if limit == 0 {
		limit = DefaultMaxBodyBytes
	}
	if limit < 0 || limit == math.MaxInt64 {
		return Response{}, sdkerr.New(sdkerr.KindInvalidConfig, "transport.configure", 0, false, nil)
	}
	ApplyHeaders(request.Context(), request.Header)
	raw, err := httpClient.Do(request)
	if err != nil {
		return Response{}, sdkerr.New(
			sdkerr.KindIAMUnavailable,
			"transport.request",
			http.StatusServiceUnavailable,
			true,
			nil,
		)
	}
	defer raw.Body.Close()
	response := Response{StatusCode: raw.StatusCode, Header: raw.Header.Clone()}
	body, err := io.ReadAll(io.LimitReader(raw.Body, limit+1))
	oversized := int64(len(body)) > limit
	if oversized {
		body = body[:int(limit)]
	}
	response.Body = body
	response.Correlation = responseCorrelation(response.Header, body)
	if err != nil {
		return response, sdkerr.New(
			sdkerr.KindIAMUnavailable,
			"transport.response",
			http.StatusServiceUnavailable,
			true,
			nil,
		)
	}
	if oversized {
		return response, sdkerr.New(sdkerr.KindProtocol, "transport.response", raw.StatusCode, false, nil)
	}
	if len(body) == 0 {
		return response, nil
	}
	mediaType, _, err := mime.ParseMediaType(raw.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return response, sdkerr.New(sdkerr.KindProtocol, "transport.response", raw.StatusCode, false, nil)
	}
	return response, nil
}

func responseCorrelation(header http.Header, body []byte) Correlation {
	correlation := Correlation{RequestID: strings.TrimSpace(header.Get("X-Request-ID"))}
	var envelope struct {
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
	}
	_ = json.Unmarshal(body, &envelope)
	if correlation.RequestID == "" {
		correlation.RequestID = strings.TrimSpace(envelope.RequestID)
	}
	correlation.TraceID = strings.TrimSpace(envelope.TraceID)
	return correlation
}

func newDefaultHTTPClient() *http.Client {
	// Disabling connection reuse keeps net/http out of its automatic
	// reused-connection replay path. HTTP/2 is disabled because it has its own
	// stream retry behavior.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableKeepAlives:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func DecodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return sdkerr.New(sdkerr.KindProtocol, "transport.decode_json", 0, false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return sdkerr.New(sdkerr.KindProtocol, "transport.decode_json", 0, false, nil)
	}
	return nil
}
