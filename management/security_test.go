package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	managementclient "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

const (
	tokenMarker   = "TOKEN_MARKER_91c9"
	secretMarker  = "SECRET_MARKER_72ab"
	bodyMarker    = "RAW_BODY_MARKER_54de"
	queryMarker   = "QUERY_MARKER_83fa"
	authorization = "Bearer " + tokenMarker
)

type markerTokenSource struct{}

func (markerTokenSource) AccessToken(context.Context) (string, error) { return tokenMarker, nil }

type eventCollector struct {
	mu     sync.Mutex
	events []managementclient.Event
}

func (collector *eventCollector) Observe(_ context.Context, event managementclient.Event) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.events = append(collector.events, event)
}

func (collector *eventCollector) last(t *testing.T) managementclient.Event {
	t.Helper()
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if len(collector.events) == 0 {
		t.Fatal("observer received no event")
	}
	return collector.events[len(collector.events)-1]
}

func TestManagementOutputsNeverExposeSensitiveMarkers(t *testing.T) {
	statuses := []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests, http.StatusServiceUnavailable}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if got := request.Header.Get("Authorization"); got != authorization {
					t.Errorf("Authorization = %q, want marker credential", got)
				}
				if got := request.URL.Query().Get("filter"); got != queryMarker {
					t.Errorf("filter = %q, want marker query", got)
				}
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = fmt.Fprint(writer, `{"code":0,"message":"`+bodyMarker+`","data":{"ok":true},"request_id":"req-safe","trace_id":"trace-safe"}`)
					return
				}
				_, _ = fmt.Fprint(writer, `{"code":123,"message":"`+bodyMarker+`","data":{"secret":"`+secretMarker+`","authorization":"`+authorization+`","query":"`+queryMarker+`"},"request_id":"req-safe","trace_id":"trace-safe"}`)
			}))
			defer server.Close()

			observer := &eventCollector{}
			transport, err := managementclient.New(managementclient.Config{BaseURL: server.URL, TokenSource: markerTokenSource{}, Observer: observer})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			var output struct {
				OK bool `json:"ok"`
			}
			_, callErr := transport.Do(context.Background(), managementclient.Request{
				Operation: "management.security.marker_gate",
				Method:    http.MethodPost,
				Path:      "/api/v1/marker-gate",
				Query:     url.Values{"filter": {queryMarker}},
				Body:      map[string]string{"secret": secretMarker},
			}, &output)
			if status == http.StatusOK && callErr != nil {
				t.Fatalf("Do() error = %v", callErr)
			}
			if status != http.StatusOK && callErr == nil {
				t.Fatal("Do() error = nil, want status error")
			}

			event := observer.last(t)
			sensitive := managementclient.NewSensitiveString(secretMarker)
			jsonOutput, marshalErr := json.Marshal(struct {
				Error  error                            `json:"error,omitempty"`
				Event  managementclient.Event           `json:"event"`
				Secret managementclient.SensitiveString `json:"secret"`
			}{callErr, event, sensitive})
			if marshalErr != nil {
				t.Fatalf("json.Marshal() error = %v", marshalErr)
			}
			fmtOutput := fmt.Sprintf("error=%v error_go=%#v event=%+v secret=%v", callErr, callErr, event, sensitive)
			var logOutput bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logOutput, nil))
			logger.Info("management result", slog.Any("error", callErr), slog.Any("event", event), slog.Any("secret", sensitive))

			assertNoMarkers(t, "error formatting", fmtOutput)
			assertNoMarkers(t, "JSON", string(jsonOutput))
			assertNoMarkers(t, "slog", logOutput.String())
		})
	}
}

func assertNoMarkers(t *testing.T, surface, output string) {
	t.Helper()
	for _, marker := range []string{tokenMarker, authorization, secretMarker, bodyMarker, queryMarker} {
		if strings.Contains(output, marker) {
			t.Errorf("%s exposed sensitive marker %q in %q", surface, marker, output)
		}
	}
}
