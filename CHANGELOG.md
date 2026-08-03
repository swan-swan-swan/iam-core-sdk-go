# Changelog

All notable changes follow [Semantic Versioning](https://semver.org/).

## Unreleased

- No changes yet.

## v0.2.0

### Breaking rewrite

- Removed the v0.1 root Client facade and the legacy `authn`, `authz`, `middleware`, `oidc`,
  root Session and in-tree framework/storage APIs.
- Removed no-PKCE, legacy roles profile, bare PDP decision and dual-credential compatibility behavior.
- Split public APIs into `core`, `bff`, `bff/session`, `httpauthz` and `testkit`; Gin and Redis are
  independently versioned adapter modules.

### IAM Core v1.8.1

- Added startup Discovery validation, RS256 JWKS/JWT verification, Client groups and actual granted
  scope modeling.
- Added server-side BFF login with mandatory PKCE S256, one-time state/nonce flows, strict return
  targets and explicit secure host-only cookies.
- Added atomic refresh rotation of TokenSet and identity data with fenced Session leases.
- Added distinct local and central logout handlers.

### HTTP authorization

- Added compiled Route Manifest and Binder validation at startup.
- Added strict v1.8.1 PDP envelope decoding and exactly one fail-closed PDP decision per protected
  request, with no PDP retry or post-401 credential refresh.
- Added thin `net/http` and optional Gin middleware entry points with defensive Context helpers.

### Storage, testing and release boundaries

- Added a separately installed Redis adapter that encrypts complete Flow/Session payloads and uses
  generation-bound, fenced, Redis server-time leases.
- Added a default-deny testkit and isolated Docker/Testcontainers Redis 6.2/7.4 conformance module.
- Kept Gin, go-redis, Docker, Moby and Testcontainers out of the root module dependency graph.
- Added v0.2 BFF, net/http, Gin and Redis examples plus release CI gates.

### Unsupported

- RPC and IAM management APIs are not included.
- Local PDP/RBAC fallback, authorization-result caching, plain/no PKCE and `roles` scope are not supported.

## v0.1.0

- Historical IAM Core v1.7.1-only SDK. See the migration guide before upgrading.
