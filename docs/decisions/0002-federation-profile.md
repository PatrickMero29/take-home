# ADR 0002 — a closed, purpose-specific OIDC federation profile

Status: accepted for Phase 0.

## Decision

Use Authorization Code Flow, mandatory S256 PKCE, nonce/state binding, and
`private_key_jwt` for confidential clients. Use RS256 with separate issuer and
client-authentication keys. Discovery and key retrieval are anchored to a
configured HTTPS issuer.

ID tokens have a single string audience matching the recipient client. Client
assertions have a single string audience matching the configured token endpoint.
JWT headers require the selected algorithm, expected type, and a registered
`kid`. Token-supplied keys, key URLs, and ambiguous multi-audience artifacts are
rejected by this profile.

The client assertion also requires `iat`, `exp`, and `jti`, though some of these
restrictions are optional in the underlying RFC. Its issuer and subject both
identify the authenticated client. Replay is client-scoped and durable.

## Why

These restrictions make cross-SP and cross-purpose substitution easier to
reason about and test. A client's key authorizes only that client's protocol
requests. The shared issuer public key grants verification capability, not
signing capability, to SPs.

Registration matching uses literal URI strings. The callback receiver checks
its configured origin/path, rejects repeated query parameters, and lets Authlib
check state before any federation network I/O. These are application policy
boundaries, not custom signing or cryptographic primitives.

## Consequences and open call

The profile is intentionally narrower than general OIDC interoperability.
Additional algorithms, token header extensions, endpoint layouts, or audience
forms require a deliberate policy update and negative tests.

Online authorization checks are planned for Phase 3 to make central revocation
effective. That favors containment over availability; temporary IDP outages
will block protected access while preserving valid persisted local state.

References: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[JWT BCP](https://www.rfc-editor.org/rfc/rfc8725.html).
