# Changelog

All notable changes follow [Semantic Versioning](https://semver.org/).

## Unreleased

- No changes yet.

## v0.1.0

### OIDC

- Added Discovery, Authorization Code login, token exchange/refresh, RS256 JWKS verification,
  UserInfo validation, and remote logout for Confidential Clients.

### Session

- Added pluggable Session Backend contracts, a single-process Memory Backend, Redis 6.2+ Backend,
  AES-256-GCM keyrings, atomic updates, one-time login flows, and fenced refresh locking.

### PDP

- Added explicit resource decisions, fail-closed error mapping, fresh per-request authorization, and
  Decision/Request/Trace correlation.

### net/http

- Added login, callback, logout, authentication, permission middleware, Context helpers, stable
  errors, propagation, timeouts, and observability Hooks.

### Gin

- Added a thin Gin adapter for authentication, permission decisions, Identity, and Decision access.

### Security

- Added state/nonce replay defenses, safe return-to validation, secure Cookie defaults,
  Cookie/Bearer conflict rejection, bounded response decoding, token-safe errors/logging, race tests,
  fuzz targets, and real Redis conformance tests.

### Known limitations

- PKCE and Public Clients are not supported.
- Organization is not a stable, strongly typed Claim.
- IAM Core management APIs and web framework adapters other than Gin are out of scope.
- Roles are identity metadata only and are never an authorization source.
