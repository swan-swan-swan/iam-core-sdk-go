// Package notificationcontacts resolves explicit IAM subjects to requested notification destinations.
package notificationcontacts

// Channel identifies one supported notification destination type.
type Channel string

const (
	// ChannelEmail requests the user's notification email.
	ChannelEmail Channel = "email"
	// ChannelSMS requests the user's mobile number for SMS.
	ChannelSMS Channel = "sms"
	// ChannelFeishuApp requests the application-scoped Feishu destination.
	ChannelFeishuApp Channel = "feishu_app"
)

// SubjectStatus describes the IAM user status associated with a resolve result.
type SubjectStatus string

const (
	// SubjectStatusActive identifies an active IAM user.
	SubjectStatusActive SubjectStatus = "active"
	// SubjectStatusInactive identifies a known but inactive IAM user.
	SubjectStatusInactive SubjectStatus = "inactive"
	// SubjectStatusNotFound identifies an unknown IAM subject.
	SubjectStatusNotFound SubjectStatus = "not_found"
)

// BatchResolveInput contains explicit subjects and the requested channels.
type BatchResolveInput struct {
	SubjectIDs []string
	Channels   []Channel
}

// Destination is an email or SMS destination.
type Destination struct {
	Available bool
	Value     string
}

// FeishuDestination is an application-scoped Feishu message destination.
type FeishuDestination struct {
	Available bool
	TenantKey string
	AppID     string
	OpenID    string
}

// SubjectResult contains independently resolved destinations for one IAM subject.
type SubjectResult struct {
	SubjectID string
	Status    SubjectStatus
	Email     *Destination
	SMS       *Destination
	FeishuApp *FeishuDestination
}

type destinationWire struct {
	Available bool   `json:"available"`
	Value     string `json:"value"`
}

func (wire *destinationWire) destination() *Destination {
	if wire == nil {
		return nil
	}
	return &Destination{Available: wire.Available, Value: wire.Value}
}

type feishuDestinationWire struct {
	Available bool   `json:"available"`
	TenantKey string `json:"tenant_key"`
	AppID     string `json:"app_id"`
	OpenID    string `json:"open_id"`
}

func (wire *feishuDestinationWire) destination() *FeishuDestination {
	if wire == nil {
		return nil
	}
	return &FeishuDestination{
		Available: wire.Available, TenantKey: wire.TenantKey,
		AppID: wire.AppID, OpenID: wire.OpenID,
	}
}

type subjectResultWire struct {
	SubjectID string                 `json:"subject_id"`
	Status    SubjectStatus          `json:"status"`
	Email     *destinationWire       `json:"email"`
	SMS       *destinationWire       `json:"sms"`
	FeishuApp *feishuDestinationWire `json:"feishu_app"`
}

func (wire subjectResultWire) result() SubjectResult {
	return SubjectResult{
		SubjectID: wire.SubjectID, Status: wire.Status,
		Email: wire.Email.destination(), SMS: wire.SMS.destination(),
		FeishuApp: wire.FeishuApp.destination(),
	}
}
