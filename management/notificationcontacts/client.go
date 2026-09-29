package notificationcontacts

import (
	"context"
	"net/http"
	"reflect"
	"strings"

	management "github.com/swan-swan-swan/iam-core-sdk-go/v3/management/client"
)

const batchResolvePath = "/api/v1/notification-contacts:batch-resolve"

// Client resolves notification destinations through the shared Management transport.
type Client struct {
	transport management.Transport
}

// New creates a notification contact client.
func New(transport management.Transport) (*Client, error) {
	if nilInterface(transport) {
		return nil, &management.Error{Kind: management.KindInvalidConfig}
	}
	return &Client{transport: transport}, nil
}

// BatchResolve resolves only the requested channels for explicit IAM subjects.
func (client *Client) BatchResolve(ctx context.Context, input BatchResolveInput) ([]SubjectResult, management.Metadata, error) {
	const operation = "management.notificationcontacts.batch_resolve"
	subjects, subjectsOK := uniqueSubjects(input.SubjectIDs)
	channels, channelsOK := uniqueChannels(input.Channels)
	if !subjectsOK || !channelsOK {
		return nil, management.Metadata{}, invalidArgument(operation)
	}
	body := struct {
		SubjectIDs []string  `json:"subject_ids"`
		Channels   []Channel `json:"channels"`
	}{SubjectIDs: subjects, Channels: channels}
	var response struct {
		Items []subjectResultWire `json:"items"`
	}
	metadata, err := client.transport.Do(ctx, management.Request{
		Operation: operation,
		Method:    http.MethodPost,
		Path:      batchResolvePath,
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

func uniqueChannels(values []Channel) ([]Channel, bool) {
	if len(values) == 0 {
		return nil, false
	}
	seen := make(map[Channel]struct{}, len(values))
	result := make([]Channel, 0, len(values))
	for _, value := range values {
		switch value {
		case ChannelEmail, ChannelSMS, ChannelFeishuApp:
		default:
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
