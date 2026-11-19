// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use graviola::signing::ecdsa::SigningKey;
use graviola::signing::eddsa::Ed25519SigningKey;
use serde_json::json;

use super::*;

const ISSUER: &str = "https://issuer.example";
const NOW: u64 = 1_800_000_000;

fn policy() -> Policy {
    Policy::new(ISSUER, "karyos-agent", "karyos.api").with_algorithms(vec![
        Algorithm::Es256,
        Algorithm::Rs256,
        Algorithm::Ps256,
        Algorithm::EdDsa,
    ])
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": ["karyos-agent", "other"],
        "sub": "alice@example",
        "exp": NOW + 300,
        "iat": NOW - 10,
        "scope": "openid karyos.api",
        "role": "administrator",
    })
}

fn segment(value: &Value) -> String {
    b64::encode(serde_json::to_string(value).unwrap().as_bytes())
}

/// A signer and the JWK of its public key.
enum Signer {
    Ec(SigningKey<P256>),
    Ed(Ed25519SigningKey),
    Rsa(Box<graviola::signing::rsa::SigningKey>),
}

impl Signer {
    fn ec() -> Self {
        Self::Ec(SigningKey::<P256>::generate().unwrap())
    }

    fn rsa() -> Self {
        let der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-signing.der"
        ))
        .unwrap();
        Self::Rsa(Box::new(
            graviola::signing::rsa::SigningKey::from_pkcs1_der(&der).unwrap(),
        ))
    }

    fn jwk(&self, kid: &str) -> Value {
        match self {
            Self::Ec(key) => {
                let point = key.private_key.public_key_uncompressed();
                json!({"kty": "EC", "crv": "P-256", "kid": kid,
                       "x": b64::encode(&point[1..33]), "y": b64::encode(&point[33..])})
            }
            Self::Ed(key) => json!({"kty": "OKP", "crv": "Ed25519", "kid": kid,
                                    "x": b64::encode(&key.public_key().as_bytes())}),
            Self::Rsa(_) => {
                let text = std::fs::read_to_string(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/rsa-signing.jwk.json"
                ))
                .unwrap();
                let mut jwk: Value = serde_json::from_str(&text).unwrap();
                jwk["kid"] = json!(kid);
                jwk
            }
        }
    }

    fn sign(&self, alg: &str, message: &[u8]) -> Vec<u8> {
        match (self, alg) {
            (Self::Ec(key), _) => {
                let mut out = [0u8; 64];
                key.sign::<Sha256>(&[message], &mut out).unwrap().to_vec()
            }
            (Self::Ed(key), _) => key.sign(message).to_vec(),
            (Self::Rsa(key), "PS256") => {
                let mut out = [0u8; 256];
                key.sign_pss_sha256(&mut out, message).unwrap().to_vec()
            }
            (Self::Rsa(key), _) => {
                let mut out = [0u8; 256];
                key.sign_pkcs1_sha256(&mut out, message).unwrap().to_vec()
            }
        }
    }

    /// A token with `header` and `claims`, signed as `alg`.
    fn token(&self, header: &Value, claims: &Value) -> String {
        let signed = format!("{}.{}", segment(header), segment(claims));
        let alg = header["alg"].as_str().unwrap_or("ES256");
        let signature = self.sign(alg, signed.as_bytes());
        format!("{signed}.{}", b64::encode(&signature))
    }
}

fn header(alg: &str, kid: &str) -> Value {
    json!({"alg": alg, "kid": kid, "typ": "at+jwt"})
}

fn set(keys: &[Value]) -> KeySet {
    KeySet::parse(json!({ "keys": keys }).to_string().as_bytes()).unwrap()
}

fn check(token: &str, keys: &KeySet) -> Result<String, TokenError> {
    let policy = policy();
    verify(&parse(token, &policy)?, keys, &policy, NOW)
}

/// RFC 8037 §A.4: the Ed25519 JWS of the RFC verifies with its key, and a
/// changed payload does not.
#[test]
fn rfc_8037_ed25519_vector() {
    let keys = set(&[json!({"kty": "OKP", "crv": "Ed25519", "kid": "rfc",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})]);
    let key = &keys.keys[0];
    let signed = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    let signature = b64::decode(
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    )
    .unwrap();
    assert!(key.verify(Algorithm::EdDsa, signed.as_bytes(), &signature));
    assert!(!key.verify(Algorithm::EdDsa, b"eyJhbGciOiJFZERTQSJ9.e30", &signature));
    // The RFC's private key signs to the same bytes (Ed25519 is
    // deterministic).
    let seed = b64::decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
    let signer = Ed25519SigningKey::from_bytes(&seed).unwrap();
    assert_eq!(signer.sign(signed.as_bytes()).to_vec(), signature);
}

/// Each algorithm verifies with its key, and the principal comes back;
/// a role claim is not part of the answer.
#[test]
fn each_algorithm_verifies() {
    let ed = Signer::Ed(Ed25519SigningKey::from_bytes(&[7u8; 32]).unwrap());
    for (signer, alg) in [
        (Signer::ec(), "ES256"),
        (Signer::rsa(), "RS256"),
        (Signer::rsa(), "PS256"),
        (ed, "EdDSA"),
    ] {
        let keys = set(&[signer.jwk("k1")]);
        let token = signer.token(&header(alg, "k1"), &claims());
        assert_eq!(
            check(&token, &keys),
            Ok("alice@example".to_owned()),
            "{alg}"
        );
    }
}

/// The acceptance criteria's refusals: a wrong audience, an expired token,
/// a wrong issuer, and a key no longer in the set (revoked or rotated out).
#[test]
fn the_four_refusals() {
    let signer = Signer::ec();
    let keys = set(&[signer.jwk("k1")]);
    let refused = |claims: Value| check(&signer.token(&header("ES256", "k1"), &claims), &keys);
    let mut wrong = claims();
    wrong["aud"] = json!("another-agent");
    assert_eq!(refused(wrong), Err(TokenError::Audience));
    let mut wrong = claims();
    wrong["exp"] = json!(NOW);
    assert_eq!(refused(wrong), Err(TokenError::Expired));
    let mut wrong = claims();
    wrong["iss"] = json!("https://issuer.example/");
    assert_eq!(refused(wrong), Err(TokenError::Issuer));
    let rotated = set(&[Signer::ec().jwk("k2")]);
    let token = signer.token(&header("ES256", "k1"), &claims());
    assert_eq!(check(&token, &rotated), Err(TokenError::UnknownKey));
}

/// Cross-token confusion (RFC 8725 §3.12): an ID token, a token of
/// another type or without one, signed by the same key, is refused.
#[test]
fn another_kind_of_token_is_refused() {
    let signer = Signer::ec();
    let keys = set(&[signer.jwk("k1")]);
    for typ in [Some("JWT"), Some("logout+jwt"), Some("id_token"), None] {
        let mut header = header("ES256", "k1");
        match typ {
            Some(typ) => header["typ"] = json!(typ),
            None => drop(header.as_object_mut().unwrap().remove("typ")),
        }
        let mut claims = claims();
        claims["nonce"] = json!("n");
        let token = signer.token(&header, &claims);
        assert_eq!(check(&token, &keys), Err(TokenError::TokenType), "{typ:?}");
    }
    let mut header = header("ES256", "k1");
    header["typ"] = json!("AT+JWT");
    assert!(check(&signer.token(&header, &claims()), &keys).is_ok());
}

/// The algorithm and key checks (RFC 8725 §3.1): `none`, an algorithm
/// outside the list, a key of another type or curve, a key whose `alg`,
/// `use` or `key_ops` forbid it, a missing `kid`.
#[test]
fn algorithm_and_key_mismatches_are_refused() {
    let signer = Signer::ec();
    let claims = claims();
    let keys = set(&[signer.jwk("k1")]);
    let unsigned = format!(
        "{}.{}.",
        segment(&json!({"alg": "none", "kid": "k1"})),
        segment(&claims)
    );
    assert_eq!(check(&unsigned, &keys), Err(TokenError::Algorithm));
    let hmac = signer.token(&header("HS256", "k1"), &claims);
    assert_eq!(check(&hmac, &keys), Err(TokenError::Algorithm));
    let only_es = Policy::new(ISSUER, "karyos-agent", "karyos.api");
    let rs = Signer::rsa();
    let rs_token = rs.token(&header("RS256", "r1"), &claims);
    assert_eq!(
        parse(&rs_token, &only_es).err(),
        Some(TokenError::Algorithm)
    );
    // An EC key named by an RS256 token, an RSA key by an ES256 one.
    let both = set(&[signer.jwk("k1"), rs.jwk("r1")]);
    let mut forged = header("RS256", "k1");
    forged["kid"] = json!("k1");
    assert_eq!(
        check(&rs.token(&forged, &claims), &both),
        Err(TokenError::KeyMismatch)
    );
    assert_eq!(
        check(&signer.token(&header("ES256", "r1"), &claims), &both),
        Err(TokenError::KeyMismatch)
    );
    // The key's own alg, use and key_ops.
    for (member, value) in [
        ("alg", json!("ES384")),
        // A present `alg` that is not a string never makes the key
        // unrestricted.
        ("alg", json!(7)),
        ("alg", json!(null)),
        ("alg", json!(["ES256"])),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
    ] {
        let mut jwk = signer.jwk("k1");
        jwk[member] = value;
        let token = signer.token(&header("ES256", "k1"), &claims);
        assert_eq!(
            check(&token, &set(&[jwk])),
            Err(TokenError::KeyMismatch),
            "{member}"
        );
    }
    let mut jwk = signer.jwk("k1");
    jwk["alg"] = json!("ES256");
    jwk["use"] = json!("sig");
    jwk["key_ops"] = json!(["verify"]);
    assert!(check(&signer.token(&header("ES256", "k1"), &claims), &set(&[jwk])).is_ok());
    // A key of a type this verifier does not take is never selected.
    let other = set(&[json!({"kty": "oct", "kid": "k1", "k": "c2VjcmV0"})]);
    assert_eq!(
        check(&signer.token(&header("ES256", "k1"), &claims), &other),
        Err(TokenError::KeyMismatch)
    );
    let no_kid = signer.token(&json!({"alg": "ES256", "typ": "at+jwt"}), &claims);
    assert_eq!(check(&no_kid, &keys), Err(TokenError::UnknownKey));
}

/// A header that names or carries a key is refused before any key is
/// looked up (`jku`, `x5u`, `x5c`, `jwk`, `crit`).
#[test]
fn a_key_from_the_token_is_never_used() {
    let signer = Signer::ec();
    let keys = set(&[signer.jwk("k1")]);
    for member in FORBIDDEN_HEADER {
        let mut header = header("ES256", "k1");
        header[member] = json!("https://attacker.example/keys");
        let token = signer.token(&header, &claims());
        assert_eq!(
            check(&token, &keys),
            Err(TokenError::ForbiddenHeader),
            "{member}"
        );
    }
}

/// A key set with two keys of one `kid` is refused as a whole; a set past
/// its bound too.
#[test]
fn an_ambiguous_set_is_refused() {
    let (one, two) = (Signer::ec(), Signer::ec());
    let doubled = json!({"keys": [one.jwk("k1"), two.jwk("k1")]}).to_string();
    assert_eq!(
        KeySet::parse(doubled.as_bytes()).err(),
        Some(KeySetError::DuplicateKid)
    );
    let many: Vec<Value> = (0..=MAX_KEYS).map(|n| one.jwk(&format!("k{n}"))).collect();
    let many = json!({ "keys": many }).to_string();
    assert_eq!(
        KeySet::parse(many.as_bytes()).err(),
        Some(KeySetError::TooMany)
    );
    assert_eq!(
        KeySet::parse(b"{\"keys\":{}}").err(),
        Some(KeySetError::Malformed)
    );
}

/// Signature, time, scope and principal checks: a changed claim, a token
/// not yet valid or issued in the future, a scope prefix or substring,
/// a missing, empty or invalid principal.
#[test]
fn claims_are_checked_exactly() {
    let signer = Signer::ec();
    let keys = set(&[signer.jwk("k1")]);
    let token = signer.token(&header("ES256", "k1"), &claims());
    let mut parts: Vec<&str> = token.split('.').collect();
    let mut forged = claims();
    forged["sub"] = json!("mallory");
    let forged = segment(&forged);
    parts[1] = &forged;
    assert_eq!(check(&parts.join("."), &keys), Err(TokenError::Signature));
    let refused = |change: &dyn Fn(&mut Value)| {
        let mut claims = claims();
        change(&mut claims);
        check(&signer.token(&header("ES256", "k1"), &claims), &keys)
    };
    assert_eq!(
        refused(&|c| c["nbf"] = json!(NOW + 5)),
        Err(TokenError::NotYetValid)
    );
    assert_eq!(
        refused(&|c| c["iat"] = json!(NOW + 5)),
        Err(TokenError::IssuedInFuture)
    );
    assert_eq!(
        refused(&|c| drop(c.as_object_mut().unwrap().remove("exp"))),
        Err(TokenError::Expired)
    );
    for scope in [
        "karyos.api.admin",
        "karyos",
        "openid",
        "karyos.apiX openid",
        "",
    ] {
        assert_eq!(
            refused(&|c| c["scope"] = json!(scope)),
            Err(TokenError::Scope),
            "{scope}"
        );
    }
    assert_eq!(
        refused(&|c| drop(c.as_object_mut().unwrap().remove("scope"))),
        Err(TokenError::Scope)
    );
    for sub in [json!(""), json!("a b"), json!(42), json!("x".repeat(65))] {
        assert_eq!(
            refused(&|c| c["sub"] = sub.clone()),
            Err(TokenError::Principal),
            "{sub}"
        );
    }
    assert_eq!(
        refused(&|c| drop(c.as_object_mut().unwrap().remove("sub"))),
        Err(TokenError::Principal)
    );
    assert_eq!(
        refused(&|c| c["aud"] = json!(["a", "b"])),
        Err(TokenError::Audience)
    );
    // A leeway of at most 60 s.
    let mut claims = claims();
    claims["exp"] = json!(NOW - 30);
    let token = signer.token(&header("ES256", "k1"), &claims);
    let lenient = policy().with_leeway(Duration::from_secs(3600));
    assert_eq!(lenient.leeway, MAX_LEEWAY);
    assert!(verify(&parse(&token, &lenient).unwrap(), &keys, &lenient, NOW).is_ok());
    claims["exp"] = json!(NOW - 61);
    let token = signer.token(&header("ES256", "k1"), &claims);
    assert_eq!(
        verify(&parse(&token, &lenient).unwrap(), &keys, &lenient, NOW),
        Err(TokenError::Expired)
    );
}

/// Malformed shapes: not three segments, oversized, not base64url, not a
/// JSON object.
#[test]
fn malformed_tokens_are_refused() {
    let signer = Signer::ec();
    let keys = set(&[signer.jwk("k1")]);
    let token = signer.token(&header("ES256", "k1"), &claims());
    for bad in [
        String::new(),
        "a.b".to_owned(),
        format!("{token}.x"),
        format!("{}.e30.", "A".repeat(MAX_HEADER + 1)),
        "!!.e30.".to_owned(),
        format!("{}.e30.", b64::encode(b"[1]")),
    ] {
        assert_eq!(check(&bad, &keys), Err(TokenError::Malformed), "{bad}");
    }
}
