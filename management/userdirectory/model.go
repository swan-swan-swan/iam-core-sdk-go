// Package userdirectory exposes the minimal, non-sensitive IAM user directory.
package userdirectory

// UserStatus describes whether an explicitly requested IAM user can receive work.
type UserStatus string

const (
	// UserStatusActive identifies an active IAM user.
	UserStatusActive UserStatus = "active"
	// UserStatusInactive identifies a known but inactive IAM user.
	UserStatusInactive UserStatus = "inactive"
	// UserStatusNotFound identifies an unknown IAM subject.
	UserStatusNotFound UserStatus = "not_found"
)

// User is the non-sensitive directory projection returned by search.
type User struct {
	SubjectID   string
	Username    string
	DisplayName string
}

// SubjectResult is the existence and status projection for an explicit subject.
type SubjectResult struct {
	SubjectID   string
	Status      UserStatus
	Username    string
	DisplayName string
}

type userWire struct {
	SubjectID   string `json:"subject_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

func (wire userWire) user() User {
	return User{SubjectID: wire.SubjectID, Username: wire.Username, DisplayName: wire.DisplayName}
}

type subjectResultWire struct {
	SubjectID   string     `json:"subject_id"`
	Status      UserStatus `json:"status"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
}

func (wire subjectResultWire) result() SubjectResult {
	return SubjectResult{
		SubjectID: wire.SubjectID, Status: wire.Status,
		Username: wire.Username, DisplayName: wire.DisplayName,
	}
}
