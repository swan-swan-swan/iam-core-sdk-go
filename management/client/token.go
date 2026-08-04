package client

import "context"

// TokenSource supplies the access token used for one management API request.
// Implementations must not assume that the client will cache or refresh tokens.
type TokenSource interface {
	AccessToken(context.Context) (string, error)
}
