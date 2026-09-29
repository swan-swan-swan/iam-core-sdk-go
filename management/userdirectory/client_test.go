package userdirectory

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
	return management.Metadata{RequestID: "request-1"}, nil
}

func TestSearchUsesMinimalDirectoryContract(t *testing.T) {
	transport := &captureTransport{response: map[string]any{"items": []map[string]any{{
		"subject_id": "op_usr_0123456789abcdefghi", "username": "wuhaolai", "display_name": "吴昊来",
	}}}}
	client, err := New(transport)
	if err != nil {
		t.Fatal(err)
	}

	users, metadata, err := client.Search(context.Background(), "wu", 20)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RequestID != "request-1" || !reflect.DeepEqual(users, []User{{
		SubjectID: "op_usr_0123456789abcdefghi", Username: "wuhaolai", DisplayName: "吴昊来",
	}}) {
		t.Fatalf("users=%#v metadata=%#v", users, metadata)
	}
	request := transport.requests[0]
	if request.Operation != "management.userdirectory.search" || request.Method != http.MethodGet || request.Path != "/api/v1/user-directory/users" {
		t.Fatalf("request=%#v", request)
	}
	if got := request.Query.Encode(); got != "limit=20&query=wu" {
		t.Fatalf("query=%q", got)
	}
}

func TestBatchGetDeduplicatesSubjectsAndPreservesFirstOrder(t *testing.T) {
	transport := &captureTransport{response: map[string]any{"items": []map[string]any{
		{"subject_id": "op_usr_a", "status": "active", "username": "a", "display_name": "A"},
		{"subject_id": "op_usr_b", "status": "inactive"},
		{"subject_id": "op_usr_c", "status": "not_found"},
	}}}
	client, _ := New(transport)
	input := []string{"op_usr_a", "op_usr_b", "op_usr_a", "op_usr_c"}

	items, _, err := client.BatchGet(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input, []string{"op_usr_a", "op_usr_b", "op_usr_a", "op_usr_c"}) {
		t.Fatalf("caller input mutated: %#v", input)
	}
	want := []SubjectResult{
		{SubjectID: "op_usr_a", Status: UserStatusActive, Username: "a", DisplayName: "A"},
		{SubjectID: "op_usr_b", Status: UserStatusInactive},
		{SubjectID: "op_usr_c", Status: UserStatusNotFound},
	}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("items=%#v want=%#v", items, want)
	}
	body, err := json.Marshal(transport.requests[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"subject_ids":["op_usr_a","op_usr_b","op_usr_c"]}` {
		t.Fatalf("body=%s", body)
	}
}

func TestDirectoryRejectsInvalidInputBeforeTransport(t *testing.T) {
	transport := &captureTransport{}
	client, _ := New(transport)
	tooMany := make([]string, 101)
	for index := range tooMany {
		tooMany[index] = "op_usr_" + string(rune(index+33))
	}

	checks := []func() error{
		func() error { _, _, err := client.Search(context.Background(), " ", 10); return err },
		func() error { _, _, err := client.Search(context.Background(), "x", 0); return err },
		func() error { _, _, err := client.Search(context.Background(), "x", 51); return err },
		func() error {
			_, _, err := client.Search(context.Background(), string(make([]byte, 129)), 1)
			return err
		},
		func() error { _, _, err := client.BatchGet(context.Background(), nil); return err },
		func() error { _, _, err := client.BatchGet(context.Background(), []string{" bad"}); return err },
		func() error { _, _, err := client.BatchGet(context.Background(), tooMany); return err },
	}
	for index, check := range checks {
		if err := check(); !errors.Is(err, management.ErrInvalidArgument) {
			t.Fatalf("check %d error=%v", index, err)
		}
	}
	if len(transport.requests) != 0 {
		t.Fatalf("requests=%d want=0", len(transport.requests))
	}
}

func TestNewRejectsNilDirectoryTransport(t *testing.T) {
	var typedNil *captureTransport
	for _, transport := range []management.Transport{nil, typedNil} {
		if _, err := New(transport); !errors.Is(err, management.ErrInvalidConfig) {
			t.Fatalf("error=%v", err)
		}
	}
}
