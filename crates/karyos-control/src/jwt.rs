// SPDX-License-Identifier: Apache-2.0

//! Agent-audience access token verification (owner item 43; the JWT
//! verification record, quantstratum-docs:
//! karyos/reviews/dependency-admission-jwt-verification.md, conditions 1
//! to 6; RFC 8725). A JWS compact token is checked in the record's order:
//! shape, algorithm, an unambiguous key that agrees with the algorithm,
//! the signature, issuer, audience, time, type, scope and principal. The
//! signature is verified before any claim is used (RFC 8725 §3.4).
//! Nothing of the token but the principal is ever relayed: the agent
//! gives it its role.

use std::time::Duration;

use graviola::hashing::Sha256;
use graviola::signing::ecdsa::{P256, VerifyingKey as EcKey};
use graviola::signing::eddsa::Ed25519VerifyingKey;
use graviola::signing::rsa::VerifyingKey as RsaKey;
use serde_json::{Map, Value};

use crate::b64;

/// The longest header segment, encoded, in bytes.
pub const MAX_HEADER: usize = 1024;
/// The longest claims segment, encoded, in bytes.
pub const MAX_CLAIMS: usize = 8 << 10;
/// The longest signature segment, encoded, in bytes.
pub const MAX_SIGNATURE: usize = 512;
/// The most keys a key set may hold.
pub const MAX_KEYS: usize = 64;
/// The largest clock leeway a policy may allow.
pub const MAX_LEEWAY: Duration = Duration::from_secs(60);
/// The access token type of RFC 9068.
pub const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// A signature algorithm this verifier takes (never `none`, never HMAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// ECDSA P-256 with SHA-256.
    Es256,
    /// RSA PKCS#1 v1.5 with SHA-256.
    Rs256,
    /// RSA PSS with SHA-256.
    Ps256,
    /// Ed25519.
    EdDsa,
}

impl Algorithm {
    /// The algorithm named `name` (`ES256`, `RS256`, `PS256`, `EdDSA`).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "ES256" => Self::Es256,
            "RS256" => Self::Rs256,
            "PS256" => Self::Ps256,
            "EdDSA" => Self::EdDsa,
            _ => return None,
        })
    }
}

/// A verification key's material.
enum Material {
    P256(Box<EcKey<P256>>),
    Rsa(Box<RsaKey>),
    Ed25519(Box<Ed25519VerifyingKey>),
    /// A key type or curve this verifier does not take: present so that
    /// its `kid` is counted, never selectable.
    Unsupported,
}

/// One key of a set.
struct Key {
    kid: String,
    material: Material,
    alg: Option<String>,
    /// `use` is absent or `sig`, `key_ops`, if present, has `verify`, and
    /// `alg`, if present, is a string: a present member of another type
    /// makes the key unusable, never unrestricted.
    for_verification: bool,
}

/// An issuer's key set, each key named by a distinct `kid`.
pub struct KeySet {
    keys: Vec<Key>,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.keys.iter().map(|key| &key.kid))
            .finish()
    }
}

/// Why a key set was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeySetError {
    /// Not a JWK set: bad JSON, no `keys` array, a key without a `kid`, or
    /// a key whose members do not decode.
    #[error("not a key set")]
    Malformed,
    /// More than [`MAX_KEYS`] keys.
    #[error("too many keys")]
    TooMany,
    /// Two keys with the same `kid`: selection would be ambiguous.
    #[error("duplicate kid")]
    DuplicateKid,
}

impl KeySet {
    /// The key set of JWK set document `json` (RFC 7517 §5).
    ///
    /// # Errors
    ///
    /// [`KeySetError`].
    pub fn parse(json: &[u8]) -> Result<Self, KeySetError> {
        let document: Value = serde_json::from_slice(json).map_err(|_| KeySetError::Malformed)?;
        let entries = document
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(KeySetError::Malformed)?;
        if entries.len() > MAX_KEYS {
            return Err(KeySetError::TooMany);
        }
        let mut keys: Vec<Key> = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.as_object().ok_or(KeySetError::Malformed)?;
            let key = Key::parse(entry).ok_or(KeySetError::Malformed)?;
            if keys.iter().any(|other| other.kid == key.kid) {
                return Err(KeySetError::DuplicateKid);
            }
            keys.push(key);
        }
        Ok(Self { keys })
    }

    /// Whether a key of this set carries `kid`.
    #[must_use]
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|key| key.kid == kid)
    }
}

/// The string member `name` of `object`, if it is one.
fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

/// The base64url member `name` of `object`, decoded.
fn bytes(object: &Map<String, Value>, name: &str) -> Option<Vec<u8>> {
    b64::decode(string(object, name)?)
}

impl Key {
    fn parse(object: &Map<String, Value>) -> Option<Self> {
        let kid = string(object, "kid")
            .filter(|kid| !kid.is_empty())?
            .to_owned();
        let material = match (string(object, "kty")?, string(object, "crv")) {
            ("EC", Some("P-256")) => {
                let (x, y) = (bytes(object, "x")?, bytes(object, "y")?);
                if x.len() != 32 || y.len() != 32 {
                    return None;
                }
                let mut point = Vec::with_capacity(65);
                point.push(4);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Material::P256(Box::new(
                    EcKey::<P256>::from_x962_uncompressed(&point).ok()?,
                ))
            }
            ("RSA", _) => {
                let der = rsa_public_der(&bytes(object, "n")?, &bytes(object, "e")?)?;
                Material::Rsa(Box::new(RsaKey::from_pkcs1_der(&der).ok()?))
            }
            ("OKP", Some("Ed25519")) => Material::Ed25519(Box::new(
                Ed25519VerifyingKey::from_bytes(&bytes(object, "x")?).ok()?,
            )),
            _ => Material::Unsupported,
        };
        let use_sig = match object.get("use") {
            None => true,
            Some(value) => value.as_str() == Some("sig"),
        };
        let ops_verify = match object.get("key_ops") {
            None => true,
            Some(value) => value
                .as_array()
                .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify"))),
        };
        let alg_valid = object.get("alg").is_none_or(serde_json::Value::is_string);
        Some(Self {
            kid,
            material,
            alg: string(object, "alg").map(str::to_owned),
            for_verification: use_sig && ops_verify && alg_valid,
        })
    }

    /// Whether this key may verify `alg` (the record's step 3).
    fn agrees(&self, alg: Algorithm, name: &str) -> bool {
        let material = matches!(
            (&self.material, alg),
            (Material::P256(_), Algorithm::Es256)
                | (Material::Rsa(_), Algorithm::Rs256 | Algorithm::Ps256)
                | (Material::Ed25519(_), Algorithm::EdDsa)
        );
        material && self.for_verification && self.alg.as_deref().is_none_or(|own| own == name)
    }

    fn verify(&self, alg: Algorithm, message: &[u8], signature: &[u8]) -> bool {
        match (&self.material, alg) {
            (Material::P256(key), Algorithm::Es256) => {
                key.verify::<Sha256>(&[message], signature).is_ok()
            }
            (Material::Rsa(key), Algorithm::Rs256) => {
                key.verify_pkcs1_sha256(signature, message).is_ok()
            }
            (Material::Rsa(key), Algorithm::Ps256) => {
                key.verify_pss_sha256(signature, message).is_ok()
            }
            (Material::Ed25519(key), Algorithm::EdDsa) => key.verify(signature, message).is_ok(),
            _ => false,
        }
    }
}

/// A DER length.
fn der_length(length: usize, out: &mut Vec<u8>) -> Option<()> {
    match length {
        0..=0x7f => out.push(u8::try_from(length).ok()?),
        0x80..=0xff => out.extend_from_slice(&[0x81, u8::try_from(length).ok()?]),
        0x100..=0xffff => {
            let [high, low] = u16::try_from(length).ok()?.to_be_bytes();
            out.extend_from_slice(&[0x82, high, low]);
        }
        _ => return None,
    }
    Some(())
}

/// A positive DER INTEGER of big-endian `value`.
fn der_integer(value: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let start = value.iter().position(|byte| *byte != 0)?;
    let value = value.get(start..)?;
    let pad = value.first().is_some_and(|byte| byte & 0x80 != 0);
    out.push(0x02);
    der_length(value.len().checked_add(usize::from(pad))?, out)?;
    if pad {
        out.push(0);
    }
    out.extend_from_slice(value);
    Some(())
}

/// The PKCS#1 `RSAPublicKey` of modulus `n` and exponent `e`.
fn rsa_public_der(n: &[u8], e: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(n.len().checked_add(16)?);
    der_integer(n, &mut body)?;
    der_integer(e, &mut body)?;
    let mut out = vec![0x30];
    der_length(body.len(), &mut out)?;
    out.extend_from_slice(&body);
    Some(out)
}

/// What a token must satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Policy {
    /// `iss`, byte for byte.
    pub issuer: String,
    /// The agent audience `aud` must contain.
    pub audience: String,
    /// The scope token `scope` must contain.
    pub scope: String,
    /// The algorithms taken.
    pub algorithms: Vec<Algorithm>,
    /// The header `typ` required, compared without case.
    pub token_type: String,
    /// The claim that names the principal.
    pub principal_claim: String,
    /// The clock leeway, at most [`MAX_LEEWAY`].
    pub leeway: Duration,
}

impl Policy {
    /// Tokens of `issuer` for `audience` with `scope`: `ES256` only, type
    /// [`ACCESS_TOKEN_TYPE`], principal `sub`, no leeway.
    #[must_use]
    pub fn new(issuer: &str, audience: &str, scope: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            scope: scope.to_owned(),
            algorithms: vec![Algorithm::Es256],
            token_type: ACCESS_TOKEN_TYPE.to_owned(),
            principal_claim: "sub".to_owned(),
            leeway: Duration::ZERO,
        }
    }

    /// The same, taking `algorithms`.
    #[must_use]
    pub fn with_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// The same, with `leeway`, at most [`MAX_LEEWAY`].
    #[must_use]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway.min(MAX_LEEWAY);
        self
    }

    /// The same, naming the principal by `claim`.
    #[must_use]
    pub fn with_principal_claim(mut self, claim: &str) -> Self {
        claim.clone_into(&mut self.principal_claim);
        self
    }
}

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// Not a bounded three-segment JWS of JSON objects.
    #[error("malformed")]
    Malformed,
    /// A header member that names or carries a key, or `crit`.
    #[error("forbidden header")]
    ForbiddenHeader,
    /// `alg` absent, `none`, or not in the policy's list.
    #[error("algorithm")]
    Algorithm,
    /// No `kid`, or no key of the set carries it.
    #[error("unknown key")]
    UnknownKey,
    /// The key's type, curve, `alg`, `use` or `key_ops` do not allow it.
    #[error("key mismatch")]
    KeyMismatch,
    /// The signature does not verify.
    #[error("signature")]
    Signature,
    /// `iss` is not the issuer.
    #[error("issuer")]
    Issuer,
    /// `aud` does not contain the audience.
    #[error("audience")]
    Audience,
    /// `exp` absent or passed.
    #[error("expired")]
    Expired,
    /// `nbf` in the future.
    #[error("not yet valid")]
    NotYetValid,
    /// `iat` in the future.
    #[error("issued in the future")]
    IssuedInFuture,
    /// `typ` is not the access token type.
    #[error("token type")]
    TokenType,
    /// `scope` does not contain the scope token.
    #[error("scope")]
    Scope,
    /// The principal claim is absent, empty or not a principal name.
    #[error("principal")]
    Principal,
}

impl TokenError {
    /// The reason's short name, as answered.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::ForbiddenHeader => "forbidden header",
            Self::Algorithm => "algorithm",
            Self::UnknownKey => "unknown key",
            Self::KeyMismatch => "key mismatch",
            Self::Signature => "signature",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not yet valid",
            Self::IssuedInFuture => "issued in the future",
            Self::TokenType => "token type",
            Self::Scope => "scope",
            Self::Principal => "principal",
        }
    }
}

/// A token's segments and its header, before any key is chosen.
#[derive(Debug)]
pub struct Parsed<'a> {
    signed: &'a str,
    claims: &'a str,
    signature: Vec<u8>,
    algorithm: Algorithm,
    algorithm_name: String,
    kid: String,
    token_type: Option<String>,
}

impl Parsed<'_> {
    /// The `kid` the header names.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

/// The header members that name or carry a key, or ask for extensions.
const FORBIDDEN_HEADER: [&str; 5] = ["jku", "x5u", "x5c", "jwk", "crit"];

/// A JSON object of base64url `segment`.
fn object(segment: &str) -> Option<Map<String, Value>> {
    match serde_json::from_slice(&b64::decode(segment)?).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Steps 1 and 2 of the record: `token`'s shape and header under `policy`.
///
/// # Errors
///
/// [`TokenError::Malformed`], [`TokenError::ForbiddenHeader`],
/// [`TokenError::Algorithm`] or [`TokenError::UnknownKey`] (no `kid`).
pub fn parse<'a>(token: &'a str, policy: &Policy) -> Result<Parsed<'a>, TokenError> {
    let mut segments = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(TokenError::Malformed);
    };
    if header.len() > MAX_HEADER || claims.len() > MAX_CLAIMS || signature.len() > MAX_SIGNATURE {
        return Err(TokenError::Malformed);
    }
    let signed_len = header
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_add(claims.len()))
        .ok_or(TokenError::Malformed)?;
    let signed = token.get(..signed_len).ok_or(TokenError::Malformed)?;
    let fields = object(header).ok_or(TokenError::Malformed)?;
    let signature = b64::decode(signature).ok_or(TokenError::Malformed)?;
    if FORBIDDEN_HEADER
        .iter()
        .any(|name| fields.contains_key(*name))
    {
        return Err(TokenError::ForbiddenHeader);
    }
    let algorithm_name = string(&fields, "alg").ok_or(TokenError::Algorithm)?;
    let algorithm = Algorithm::parse(algorithm_name)
        .filter(|algorithm| policy.algorithms.contains(algorithm))
        .ok_or(TokenError::Algorithm)?;
    let kid = string(&fields, "kid")
        .filter(|kid| !kid.is_empty())
        .ok_or(TokenError::UnknownKey)?;
    Ok(Parsed {
        signed,
        claims,
        signature,
        algorithm,
        algorithm_name: algorithm_name.to_owned(),
        kid: kid.to_owned(),
        token_type: string(&fields, "typ").map(str::to_owned),
    })
}

/// Seconds since the epoch of the number `name` of `claims`, if present.
fn seconds(claims: &Map<String, Value>, name: &str) -> Result<Option<u64>, TokenError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .or_else(|| {
                value
                    .as_f64()
                    .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                    .map(|seconds| seconds as u64)
            })
            .map(Some)
            .ok_or(TokenError::Malformed),
    }
}

/// Steps 3 to 10 of the record: the principal `parsed` names, verified
/// with `keys` under `policy` at `now` (seconds since the epoch).
///
/// # Errors
///
/// [`TokenError`], the first check that fails.
pub fn verify(
    parsed: &Parsed<'_>,
    keys: &KeySet,
    policy: &Policy,
    now: u64,
) -> Result<String, TokenError> {
    let key = keys
        .keys
        .iter()
        .find(|key| key.kid == parsed.kid)
        .ok_or(TokenError::UnknownKey)?;
    if !key.agrees(parsed.algorithm, &parsed.algorithm_name) {
        return Err(TokenError::KeyMismatch);
    }
    if !key.verify(
        parsed.algorithm,
        parsed.signed.as_bytes(),
        &parsed.signature,
    ) {
        return Err(TokenError::Signature);
    }
    let claims = object(parsed.claims).ok_or(TokenError::Malformed)?;
    if string(&claims, "iss") != Some(policy.issuer.as_str()) {
        return Err(TokenError::Issuer);
    }
    let audience = match claims.get("aud") {
        Some(Value::String(one)) => *one == policy.audience,
        Some(Value::Array(many)) => many
            .iter()
            .any(|one| one.as_str() == Some(policy.audience.as_str())),
        _ => false,
    };
    if !audience {
        return Err(TokenError::Audience);
    }
    let leeway = policy.leeway.min(MAX_LEEWAY).as_secs();
    let expiry = seconds(&claims, "exp")?.ok_or(TokenError::Expired)?;
    if expiry.saturating_add(leeway) <= now {
        return Err(TokenError::Expired);
    }
    if seconds(&claims, "nbf")?.is_some_and(|nbf| nbf > now.saturating_add(leeway)) {
        return Err(TokenError::NotYetValid);
    }
    if seconds(&claims, "iat")?.is_some_and(|iat| iat > now.saturating_add(leeway)) {
        return Err(TokenError::IssuedInFuture);
    }
    if !parsed
        .token_type
        .as_deref()
        .is_some_and(|typ| typ.eq_ignore_ascii_case(&policy.token_type))
    {
        return Err(TokenError::TokenType);
    }
    let scope = string(&claims, "scope")
        .is_some_and(|scope| scope.split(' ').any(|token| token == policy.scope));
    if !scope {
        return Err(TokenError::Scope);
    }
    string(&claims, &policy.principal_claim)
        .filter(|principal| crate::relay::valid_principal(principal))
        .map(str::to_owned)
        .ok_or(TokenError::Principal)
}

#[cfg(test)]
mod tests;
