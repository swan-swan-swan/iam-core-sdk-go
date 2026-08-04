package oidcclients

// CredentialOption configures one credential creation call.
type CredentialOption interface {
	applyCredential(*credentialOptions)
}

type credentialOptionFunc func(*credentialOptions)

func (option credentialOptionFunc) applyCredential(target *credentialOptions) {
	option(target)
}

type credentialOptions struct {
	idempotencyKey string
}

// WithIdempotencyKey supplies the caller-owned key for credential creation.
// The SDK never generates a key or retries the request.
func WithIdempotencyKey(value string) CredentialOption {
	return credentialOptionFunc(func(options *credentialOptions) {
		options.idempotencyKey = value
	})
}
