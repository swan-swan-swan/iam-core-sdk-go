package userdirectory

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	management "github.com/swan-swan-swan/iam-core-sdk-go/v3/management/client"
)

const directoryPath = "/api/v1/user-directory/users"

// Client queries the minimal IAM user directory through the shared transport.
type Client struct {
	transport management.Transport
}

// New creates a minimal user directory client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// Search returns active users matching an account or display-name query.
func (client *Client) Search(ctx context.Context, query string, limit int) ([]User, management.Metadata, error) {
	const operation = "management.userdirectory.search"
	if limit < 1 || limit > 50 || utf8.RuneCountInString(query) > 128 || (query != "" && strings.TrimSpace(query) != query) {
		return nil, management.Metadata{}, invalidArgument(operation)
	}
	var response struct {
		Items []userWire `json:"items"`
	}
	metadata, err := client.transport.Do(ctx, management.Request{
		Operation: operation,
		Method:    http.MethodGet,
		Path:      directoryPath,
		Query:     url.Values{"query": {query}, "limit": {strconv.Itoa(limit)}},
	}, &response)
	if err != nil {
		return nil, metadata, err
	}
	items := make([]User, len(response.Items))
	for index := range response.Items {
		items[index] = response.Items[index].user()
	}
	return items, metadata, nil
}

// BatchGet validates explicit IAM subjects while preserving their first-seen order.
func (client *Client) BatchGet(ctx context.Context, subjectIDs []string) ([]SubjectResult, management.Metadata, error) {
	const operation = "management.userdirectory.batch_get"
	unique, ok := uniqueSubjects(subjectIDs)
	if !ok {
		return nil, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		SubjectIDs []string `json:"subject_ids"`
	}{SubjectIDs: unique}
	var response struct {
		Items []subjectResultWire `json:"items"`
	}
	metadata, err := client.transport.Do(ctx, management.Request{
		Operation: operation,
		Method:    http.MethodPost,
		Path:      directoryPath + ":batch-get",
		Body:      body,
	}, &response)
	if err != nil {
		return nil, metadata, err
	}
	items := make([]SubjectResult, len(response.Items))
	for index := range response.Items {
		items[index] = response.Items[index].result()
	}
	return items, metadata, nil
}

func uniqueSubjects(values []string) ([]string, bool) {
	if len(values) == 0 || len(values) > 100 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || len(value) > 64 || strings.TrimSpace(value) != value {
			return nil, false
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, true
}

func invalidArgument(operation string) error {
	return &management.Error{Kind: management.KindInvalidArgument, Operation: operation}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
