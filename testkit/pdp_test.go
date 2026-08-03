package testkit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/testkit"
)

func TestPDPDefaultsToDeny(t *testing.T) {
	fake := testkit.NewPDP(t)
	defer fake.Close()
	response, err := http.Post(fake.URL()+"/authorization/v1/decisions", "application/json", strings.NewReader(`{"resource_server":"orders_api","resource":"orders","http_method":"GET"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			DecisionID string `json:"decision_id"`
			Allowed    bool   `json:"allowed"`
			ReasonCode string `json:"reason_code"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Allowed {
		t.Fatal("default fake PDP allowed")
	}
	if envelope.Code != 0 || envelope.Message != "success" || envelope.Data.DecisionID == "" || envelope.Data.ReasonCode != "default_deny" {
		t.Fatal("default fake PDP did not return a valid default-deny envelope")
	}
}

func TestFixedClockIsThreadSafe(t *testing.T) {
	clock := testkit.NewFixedClock(time.Unix(100, 0))
	clock.Advance(time.Second)
	if got := clock.Now(); !got.Equal(time.Unix(101, 0)) {
		t.Fatalf("now=%s", got)
	}
}

func TestFixedClockSupportsConcurrentAdvanceAndRead(t *testing.T) {
	clock := testkit.NewFixedClock(time.Unix(100, 123))
	const workers = 64
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			clock.Advance(time.Millisecond)
			_ = clock.Now()
		}()
	}
	wait.Wait()
	if got := clock.Now(); !got.Equal(time.Unix(100, 123).Add(workers * time.Millisecond)) {
		t.Fatalf("now=%s", got)
	}
}

func TestPDPQueuedDecisionsAreFIFOAndExposeEnvelopeVariants(t *testing.T) {
	fake := testkit.NewPDP(t)
	defer fake.Close()
	fake.Enqueue(testkit.HTTPDecision{
		HTTPStatus: http.StatusTeapot,
		Code:       17,
		Message:    "fixture_error",
		DecisionID: "decision-one",
		ReasonCode: "fixture_deny",
	})
	fake.Enqueue(testkit.HTTPDecision{
		HTTPStatus: http.StatusOK,
		Code:       0,
		Message:    "success",
		DecisionID: "decision-two",
		ReasonCode: "policy_allow",
		Allowed:    true,
	})

	first, err := requestDecision(t.Context(), fake, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := requestDecision(t.Context(), fake, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != http.StatusTeapot || first.Code != 17 || first.Message != "fixture_error" ||
		first.DecisionID != "decision-one" || first.ReasonCode != "fixture_deny" || first.Allowed {
		t.Fatal("first queued decision did not preserve the configured status and envelope")
	}
	if second.Status != http.StatusOK || second.Code != 0 || second.Message != "success" ||
		second.DecisionID != "decision-two" || second.ReasonCode != "policy_allow" || !second.Allowed {
		t.Fatal("second queued decision did not preserve FIFO order")
	}
}

func TestPDPRecordsExactCallsAndReturnsDefensiveCopies(t *testing.T) {
	fake := testkit.NewPDP(t)
	defer fake.Close()
	if _, err := requestDecision(t.Context(), fake, "Bearer call-capture-secret"); err != nil {
		t.Fatal(err)
	}

	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls=%d", len(calls))
	}
	call := calls[0]
	if call.Authorization != "Bearer call-capture-secret" {
		t.Fatal("recorded Authorization header differs")
	}
	if call.ResourceServer != "orders_api" || call.Resource != "orders" || call.HTTPMethod != http.MethodGet {
		t.Fatalf("recorded decision coordinates=%q/%q/%q", call.ResourceServer, call.Resource, call.HTTPMethod)
	}
	calls[0] = testkit.PDPCall{Resource: "mutated"}
	again := fake.Calls()
	if len(again) != 1 || again[0].Resource != "orders" || again[0].Authorization != "Bearer call-capture-secret" {
		t.Fatal("mutating Calls result changed PDP state")
	}
}

func TestPDPQueueAndCallsAreConcurrentSafe(t *testing.T) {
	fake := testkit.NewPDP(t)
	defer fake.Close()
	const workers = 40
	var enqueueWait sync.WaitGroup
	for index := range workers {
		enqueueWait.Add(1)
		go func() {
			defer enqueueWait.Done()
			fake.Enqueue(testkit.HTTPDecision{DecisionID: fmt.Sprintf("decision-%02d", index), Allowed: true, ReasonCode: "policy_allow"})
		}()
	}
	enqueueWait.Wait()

	results := make(chan decisionEnvelope, workers)
	errs := make(chan error, workers)
	var requestWait sync.WaitGroup
	for range workers {
		requestWait.Add(1)
		go func() {
			defer requestWait.Done()
			response, err := requestDecision(context.Background(), fake, "Bearer concurrent-secret")
			if err != nil {
				errs <- err
				return
			}
			results <- response
		}()
	}
	requestWait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[string]struct{}, workers)
	for response := range results {
		if !response.Allowed || response.ReasonCode != "policy_allow" || response.DecisionID == "" {
			t.Fatal("concurrent request received an unexpected decision")
		}
		seen[response.DecisionID] = struct{}{}
	}
	if len(seen) != workers || len(fake.Calls()) != workers {
		t.Fatalf("unique decisions/calls=%d/%d", len(seen), len(fake.Calls()))
	}
}

func TestPDPDelayHonorsRequestCancellation(t *testing.T) {
	fake := testkit.NewPDP(t)
	defer fake.Close()
	fake.Enqueue(testkit.HTTPDecision{Delay: time.Second, DecisionID: "delayed", ReasonCode: "default_deny"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := requestDecision(ctx, fake, "Bearer cancellation-secret")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request error type=%T, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("canceled delayed response took %s", elapsed)
	}
	if len(fake.Calls()) != 1 {
		t.Fatalf("calls=%d", len(fake.Calls()))
	}
}

func TestPDPCloseIsIdempotent(t *testing.T) {
	fake := testkit.NewPDP(t)
	fake.Close()
	fake.Close()
}

func TestPDPExposesOnlyThePOSTDecisionEndpoint(t *testing.T) {
	fake := testkit.NewPDP(t)
	defer fake.Close()
	wrongPath, err := http.Post(fake.URL()+"/not-decisions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongPath.Body.Close()
	if wrongPath.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong-path status=%d", wrongPath.StatusCode)
	}
	wrongMethod, err := http.Get(fake.URL() + "/authorization/v1/decisions")
	if err != nil {
		t.Fatal(err)
	}
	wrongMethod.Body.Close()
	if wrongMethod.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("wrong-method status=%d", wrongMethod.StatusCode)
	}
	if len(fake.Calls()) != 0 {
		t.Fatalf("calls=%d", len(fake.Calls()))
	}
}

type decisionEnvelope struct {
	Status     int
	Code       int
	Message    string
	DecisionID string
	ReasonCode string
	Allowed    bool
}

func requestDecision(ctx context.Context, fake *testkit.PDP, authorization string) (decisionEnvelope, error) {
	body := strings.NewReader(`{"resource_server":"orders_api","resource":"orders","http_method":"GET"}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fake.URL()+"/authorization/v1/decisions", body)
	if err != nil {
		return decisionEnvelope{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorization)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return decisionEnvelope{}, err
	}
	defer response.Body.Close()
	var wire struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			DecisionID string `json:"decision_id"`
			ReasonCode string `json:"reason_code"`
			Allowed    bool   `json:"allowed"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&wire); err != nil {
		return decisionEnvelope{}, err
	}
	return decisionEnvelope{
		Status: response.StatusCode, Code: wire.Code, Message: wire.Message,
		DecisionID: wire.Data.DecisionID, ReasonCode: wire.Data.ReasonCode, Allowed: wire.Data.Allowed,
	}, nil
}
