package session

import (
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
)

type Session struct {
	ID                  string
	Version             uint64
	TokenSet            oidc.TokenSet
	Identity            oidc.Identity
	GrantedScopes       []string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastSeenAt          time.Time
	ExpiresAt           time.Time
	IdleExpiresAt       time.Time
	IdentityValidatedAt time.Time
}

type Flow struct {
	ID        string
	State     string
	Nonce     string
	ReturnTo  string
	CreatedAt time.Time
	ExpiresAt time.Time
}
