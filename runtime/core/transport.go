package core

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxResponseBodyBytes int64 = 1 << 20

var (
	errTransportUnavailable = errors.New("transport unavailable")
	errTransportProtocol    = errors.New("transport protocol error")
)

type transportClient struct {
	http *http.Client
}

type transportResponse struct {
	status int
	body   []byte
}

func newTransportClient(injected *http.Client) transportClient {
	client := injected
	if client == nil {
		client = defaultHTTPClient()
	}
	cloned := *client
	cloned.Jar = nil
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return transportClient{http: &cloned}
}

func defaultHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	return &http.Client{Transport: transport}
}

func (c transportClient) getJSON(ctxRequest *http.Request) (transportResponse, error) {
	ctxRequest.Header.Set("Accept", "application/json")
	raw, err := c.http.Do(ctxRequest)
	if err != nil {
		return transportResponse{}, errTransportUnavailable
	}
	defer raw.Body.Close()
	if raw.StatusCode != http.StatusOK {
		return transportResponse{status: raw.StatusCode}, nil
	}
	body, err := io.ReadAll(io.LimitReader(raw.Body, maxResponseBodyBytes+1))
	if err != nil {
		return transportResponse{status: raw.StatusCode}, errTransportUnavailable
	}
	if int64(len(body)) > maxResponseBodyBytes {
		return transportResponse{status: raw.StatusCode}, errTransportProtocol
	}
	if len(body) != 0 {
		mediaType, _, parseErr := mime.ParseMediaType(raw.Header.Get("Content-Type"))
		if parseErr != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
			return transportResponse{status: raw.StatusCode}, errTransportProtocol
		}
	}
	return transportResponse{status: raw.StatusCode, body: body}, nil
}

func decodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid json")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing json")
	}
	return nil
}
