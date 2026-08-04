package session

import (
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

type Flow struct {
	ID           string
	State        string
	Nonce        string
	CodeVerifier string
	ClientID     string
	RedirectURL  string
	ReturnTo     string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type TokenSet struct {
	AccessToken       string
	TokenType         string
	RefreshToken      string
	IDToken           string
	AccessTokenExpiry time.Time
	GrantedScopes     []string
}

type Session struct {
	ID            string
	Version       uint64
	Tokens        TokenSet
	Auth          core.AuthContext
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}
