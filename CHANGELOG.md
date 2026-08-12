# Changelog

All notable changes follow [Semantic Versioning](https://semver.org/).

## Unreleased

## v0.6.0

### HTTP authorization

- Added an optional canonical three-level `RouteSpec.Action`. The SDK sends it as
  `expected_action` and rejects an allowed decision when IAM Core omits or returns a
  different derived Action.
- Preserved v0.5 request compatibility when Action is empty and preserved denied
  decision reason codes while exposing IAM Core's derived Action.
- Aligned the in-process PDP testkit with IAM Core's strict three-level Action format.

## v0.5.0

### Redis adapter

- Replaced Lua evaluation with Redis 6.2+ native commands and transactions, including Redis Cluster
  support. This is an operationally breaking change for deployments running Redis 6.0 or older;
  applications continue to supply their own go-redis Client, FailoverClient, or ClusterClient.

## v0.4.1

### Security

- Updated `github.com/go-jose/go-jose/v4` to v4.1.4 to address the published JWE denial-of-service advisory.
- Updated the Gin-transitive HTTP/3 dependencies `github.com/quic-go/quic-go` to v0.59.1 and `github.com/quic-go/qpack` to v0.6.0 to address published QPACK denial-of-service advisories.

## v0.4.0

### Single-module delivery

- Consolidated Runtime, Management, Gin Adapter, and Redis Adapter into a single root Module while
  keeping all public import paths unchanged.
- Removed the nested Gin and Redis `go.mod` files. Consumers install every SDK package through
  `github.com/swan-swan-swan/iam-core-sdk-go@v0.4.0`.
- Simplified release automation: every `dev` push is merged into `main`, then the root tag from
  `VERSION` is created and pushed with `main` atomically.
- Kept Docker, Moby, and Testcontainers isolated in the unpublished integration test Module.

## v0.3.0

### Breaking module layout

- Renamed the repository and root Module to `github.com/swan-swan-swan/iam-core-sdk-go`.
- Moved the existing public Runtime packages under `runtime/` and moved the independently versioned
  Gin and Redis modules under `runtime/adapters/`; no deprecated import wrapper is provided.

### Management

- Added the six approved Management domains: `applications`, `oidcclients`, `admission`,
  `groupmappings`, `catalog`, and `policies`, covering the frozen 42-endpoint IAM Core v1.8.1 contract.
- Added an injected `TokenSource`, strict single-request Bearer transport, envelope metadata, bounded
  response decoding, stable error kinds, and one terminal Observer event.
- Management operations read one token and send at most one HTTP request; the SDK 不自动重试 and
  does not refresh tokens or generate idempotency keys.
- Modeled the credential-creation-only Secret with redacting `SensitiveString`; callers must invoke
  `Reveal()` explicitly and later credential reads do not expose the Secret.
- Added explicit revision/hash conflict models without local policy compilation, automatic
  provisioning, cross-domain orchestration, or Runtime dependencies.

### Delivery and unsupported surfaces

- Added a safe Management example, the v0.2-to-v0.3 migration guide, compatibility matrix, and
  three-module atomic release gate.
- RPC, users, organizations, global roles, Cloud Provider, admission/authorization audits, and
  automatic provisioning remain unsupported.

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
- Added finite configurable token, UserInfo and end-session operation timeouts, future-`iat`
  rejection, and response-lifetime capping for initial access tokens.
- Added atomic refresh rotation of TokenSet and identity data with fenced Session leases.
- Added distinct local and central logout handlers.

### HTTP authorization

- Added compiled Route Manifest and Binder validation at startup.
- Added strict v1.8.1 PDP envelope decoding and exactly one fail-closed PDP decision per protected
  request, with no PDP retry or post-401 credential refresh.
- Added sanitized low-cardinality Service outcome events and fail-closed conflict handling for
  Bearer plus malformed-but-present platform Session Cookies.
- Added thin `net/http` and optional Gin middleware entry points with defensive Context helpers.

### Storage, testing and release boundaries

- Added a separately installed Redis adapter that encrypts complete Flow/Session payloads and uses
  generation-bound, fenced, Redis server-time leases.
- Aligned Memory and Redis Session validation on initial version 1 and required idle expiry; Memory
  operations now preserve canceled and deadline contexts before mutation.
- Added a default-deny testkit and isolated Docker/Testcontainers Redis 6.2/7.4 conformance module.
- Kept Gin, go-redis, Docker, Moby and Testcontainers out of the root module dependency graph.
- Added v0.2 BFF, net/http, Gin and Redis examples plus release CI gates.

### Unsupported

- RPC and IAM management APIs are not included.
- Local PDP/RBAC fallback, authorization-result caching, plain/no PKCE and `roles` scope are not supported.

## v0.1.0

- Historical IAM Core v1.7.1-only SDK. See the migration guide before upgrading.
