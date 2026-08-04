package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	testApplicationOpenID = "op_app_0123456789abcdefghj"
	testRuleOpenID        = "op_lpr_0123456789abcdefghj"
	testSubjectOpenID     = "op_usr_0123456789abcdefghj"
)

func TestRunListsApplicationsWithoutWritingByDefault(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.RequestURI() != "/api/v1/applications" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.RequestURI())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer example-access-token" {
			t.Fatalf("Authorization = %q", got)
		}
		writeEnvelope(t, w, map[string]any{"items": []any{}})
	}))
	defer server.Close()

	var output strings.Builder
	err := run(context.Background(), environment(map[string]string{
		"IAMCORE_MANAGEMENT_BASE_URL":     server.URL,
		"IAMCORE_MANAGEMENT_ACCESS_TOKEN": "example-access-token",
	}), &output)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one read", requests)
	}
	if got := output.String(); got != "applications: 0\n" {
		t.Fatalf("output = %q", got)
	}
	if strings.Contains(output.String(), "example-access-token") {
		t.Fatal("output leaked the access token")
	}
}

func TestRunUpdatesAdmissionOnlyWithExplicitFlagAndRevision(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		mu.Unlock()
		if got := request.Header.Get("Authorization"); got != "Bearer example-access-token" {
			t.Fatalf("Authorization = %q", got)
		}
		switch request.Method {
		case http.MethodGet:
			writeEnvelope(t, w, map[string]any{"items": []any{}})
		case http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			want := map[string]any{
				"subject_type": "user", "subject_open_id": testSubjectOpenID,
				"effect": "allow", "login_policy_revision": float64(7),
			}
			if !reflect.DeepEqual(body, want) {
				t.Fatalf("request body = %#v, want %#v", body, want)
			}
			writeEnvelope(t, w, map[string]any{
				"rule": map[string]any{}, "login_policy_revision": 8, "login_policy_hash": "hash-8",
			})
		default:
			t.Fatalf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	var output strings.Builder
	err := run(context.Background(), environment(map[string]string{
		"IAMCORE_MANAGEMENT_BASE_URL":             server.URL,
		"IAMCORE_MANAGEMENT_ACCESS_TOKEN":         "example-access-token",
		"IAMCORE_EXAMPLE_APPLY_ADMISSION_UPDATE":  "true",
		"IAMCORE_APPLICATION_OPEN_ID":             testApplicationOpenID,
		"IAMCORE_ADMISSION_RULE_OPEN_ID":          testRuleOpenID,
		"IAMCORE_ADMISSION_SUBJECT_TYPE":          "user",
		"IAMCORE_ADMISSION_SUBJECT_OPEN_ID":       testSubjectOpenID,
		"IAMCORE_ADMISSION_EFFECT":                "allow",
		"IAMCORE_ADMISSION_LOGIN_POLICY_REVISION": "7",
	}), &output)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	wantRequests := []string{
		"GET /api/v1/applications",
		"PUT /api/v1/applications/" + testApplicationOpenID + "/login-admission-rules/" + testRuleOpenID,
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != len(wantRequests) {
		t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
	}
	for index := range wantRequests {
		if requests[index] != wantRequests[index] {
			t.Fatalf("request %d = %q, want %q", index, requests[index], wantRequests[index])
		}
	}
	if got := output.String(); got != "applications: 0\nadmission revision: 8\n" {
		t.Fatalf("output = %q", got)
	}
}

func environment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func writeEnvelope(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{"code": 0, "message": "ok", "data": data}); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
