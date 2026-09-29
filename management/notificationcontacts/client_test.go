package notificationcontacts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"

	management "github.com/swan-swan-swan/iam-core-sdk-go/v3/management/client"
)

type captureTransport struct {
	requests []management.Request
	response any
}

func (transport *captureTransport) Do(_ context.Context, request management.Request, out any) (management.Metadata, error) {
	transport.requests = append(transport.requests, request)
	if transport.response != nil && out != nil {
		payload, err := json.Marshal(transport.response)
		if err != nil {
			return management.Metadata{}, err
		}
		if err := json.Unmarshal(payload, out); err != nil {
			return management.Metadata{}, err
		}
	}
	return management.Metadata{RequestID: "request-2"}, nil
}

func TestBatchResolveUsesExactContractAndPreservesDestinationSemantics(t *testing.T) {
	transport := &captureTransport{response: map[string]any{"items": []map[string]any{
		{
			"subject_id": "op_usr_a", "status": "active",
			"email":      map[string]any{"available": false},
			"sms":        map[string]any{"available": true, "value": "+8613800000000"},
			"feishu_app": map[string]any{"available": true, "tenant_key": "tenant", "app_id": "app", "open_id": "open"},
		},
		{"subject_id": "op_usr_b", "status": "inactive"},
	}}}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}
	input := BatchResolveInput{
		SubjectIDs: []string{"op_usr_a", "op_usr_b", "op_usr_a"},
		Channels:   []Channel{ChannelSMS, ChannelEmail, ChannelSMS, ChannelFeishuApp},
	}
	originalSubjects := append([]string(nil), input.SubjectIDs...)
	originalChannels := append([]Channel(nil), input.Channels...)

	items, metadata, err := client.BatchResolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RequestID != "request-2" {
		t.Fatalf("metadata=%#v", metadata)
	}
	if !reflect.DeepEqual(input.SubjectIDs, originalSubjects) || !reflect.DeepEqual(input.Channels, originalChannels) {
		t.Fatalf("caller input mutated: %#v", input)
	}
	want := []SubjectResult{
		{
			SubjectID: "op_usr_a", Status: SubjectStatusActive,
			Email: &Destination{Available: false},
			SMS:   &Destination{Available: true, Value: "+8613800000000"},
			FeishuApp: &FeishuDestination{
				Available: true, TenantKey: "tenant", AppID: "app", OpenID: "open",
			},
		},
		{SubjectID: "op_usr_b", Status: SubjectStatusInactive},
	}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("items=%#v want=%#v", items, want)
	}
	request := transport.requests[0]
	if request.Operation != "management.notificationcontacts.batch_resolve" || request.Method != http.MethodPost || request.Path != "/api/v1/notification-contacts:batch-resolve" {
		t.Fatalf("request=%#v", request)
	}
	body, err := json.Marshal(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"subject_ids":["op_usr_a","op_usr_b"],"channels":["sms","email","feishu_app"]}` {
		t.Fatalf("body=%s", body)
	}
}

func TestBatchResolveRejectsInvalidInputBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, _ := New(transport)
	tooMany := make([]string, 101)
	for index := range tooMany {
		tooMany[index] = "subject-" + string(rune(index+0x100))
	}

	checks := []BatchResolveInput{
		{},
		{SubjectIDs: []string{"op_usr_a"}},
		{SubjectIDs: []string{"op_usr_a"}, Channels: []Channel{"webhook"}},
		{SubjectIDs: []string{" bad"}, Channels: []Channel{ChannelEmail}},
		{SubjectIDs: tooMany, Channels: []Channel{ChannelEmail}},
	}
	for index, input := range checks {
		if _, _, err := client.BatchResolve(context.Background(), input); !errors.Is(err, management.ErrInvalidArgument) {
			t.Fatalf("check %d error=%v", index, err)
		}
	}
	if len(transport.requests) != 0 {
		t.Fatalf("requests=%d want=0", len(transport.requests))
	}
}

func TestNewRejectsNilNotificationContactTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error=%v", err)
		}
	}
}
