// SPDX-License-Identifier: Apache-2.0

//! The control-plane component (M14, karyos#708; quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md): the agent's API v1
//! relayed over the network, outside the default core graph (owner item
//! 43: "Remote access belongs in a separate control-plane component").
//!
//! - **Graph.** This crate holds the agent HTTP stack of its admission
//!   record (quantstratum-docs:
//!   karyos/reviews/dependency-admission-agent-http-stack.md, owner
//!   decision ACS 71206): `hyper`, `hyper-util`, `tokio`, `tokio-rustls`,
//!   `rustls` and `rustls-graviola`, `graviola` under it. It is not a
//!   default member of the workspace and nothing depends on it, so
//!   `karyos-agent`'s graph and the default build's are unchanged.
//! - **Transport.** HTTP/1.1 over TLS 1.3 only ([`tls`]). Without an
//!   issuer, every client presents a certificate that chains to the
//!   configured client CA (mutual TLS, item 43's service channels); a
//!   handshake without one, or with one of another CA, fails. With an
//!   issuer ([`server::Oidc`]), a client may connect without a certificate
//!   (a person's browser or console); one it presents must still chain to
//!   the client CA. At start the provider's CPU
//!   requirements are checked ([`cpu`]), and a CPU without them is a typed
//!   refusal, never a panic.
//! - **Who.** A service is known by its certificate, pinned in the
//!   configuration with its principal name ([`server::Service`]): a
//!   certificate of the right CA that is not pinned is authenticated but
//!   names no principal, and every request on it without a bearer token
//!   is answered `403`. A request with `Authorization: Bearer` (with an
//!   issuer configured) is a person's: the token alone decides, whatever
//!   certificate, pinned or not, the client presented, so a bearer token
//!   takes precedence over the certificate.
//! - **Roles.** None here. The component relays each request to the
//!   agent's local socket as `KARYOS-AGENT 1 relay PRINCIPAL REQUEST`
//!   ([`relay`]), from the uid the agent knows as a relay, and the agent
//!   gives the principal its role, per request, from its own table. Nothing
//!   a client sends (a header, a field, a role's name) reaches the agent
//!   but the request itself, so the component cannot grant a role.
//! - **API v1.** The request is a v1 request line's request, unchanged,
//!   and the answer is the agent's v1 JSON object, unchanged ([`server`]).
//! - **People.** With an issuer configured ([`server::Oidc`]), a person
//!   presents the issuer's agent-audience access token, which the console
//!   got through the authorization code flow with PKCE. The token is
//!   verified on every request ([`jwt`]) against the issuer's key set
//!   ([`jwks`]): issuer, audience, type, expiry, signature, scope and
//!   principal. The principal, never a role, is relayed. When no key set
//!   inside its lifetime can verify a token, the answer is `503`, never a
//!   grant; stale keys are never trusted (owner decision on
//!   quantstratum-docs#899).

pub mod b64;
pub mod cli;
pub mod cpu;
pub mod jwks;
pub mod jwt;
pub mod relay;
pub mod server;
pub mod tls;
