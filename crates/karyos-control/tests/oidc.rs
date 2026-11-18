// SPDX-License-Identifier: Apache-2.0

//! People's sign-in end to end (karyos#708): an issuer stand-in over TLS
//! serves its discovery document, its key set and the authorization code
//! flow with PKCE (S256); a person, played by the test as the console,
//! signs in, gets an agent-audience access token and is relayed as its
//! principal. A wrong audience, an expired token, a wrong issuer and a
//! revoked key are each refused. An issuer or key set endpoint that is
//! unreachable, or a key set past its lifetime, gives `503`, never a
//! grant. The agent is a stand-in on a Unix socket that records each line.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use graviola::hashing::{Hash, Sha256};
use graviola::signing::ecdsa::{P256, SigningKey};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use karyos_control::b64;
use karyos_control::jwks::{Budget, Issuer, Jwks};
use karyos_control::jwt::Policy;
use karyos_control::server::{Control, ControlConfig, Oidc, Service};
use karyos_control::tls;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};

const ANSWER: &str = "{\"agent\":\"stand-in\"}\n";
const AUDIENCE: &str = "karyos-agent";
const SCOPE: &str = "karyos.api";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---- The agent stand-in. ----

fn agent(name: &str) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let dir = std::env::temp_dir().join(format!("karyos-oidc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap() == 1 {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            seen.lock().unwrap().push(String::from_utf8(line).unwrap());
            stream.write_all(ANSWER.as_bytes()).unwrap();
        }
    });
    (socket, lines)
}

// ---- The issuer stand-in. ----

/// A signing key and its `kid`.
struct Signer {
    kid: String,
    key: SigningKey<P256>,
}

impl Signer {
    fn new(kid: &str) -> Self {
        Self {
            kid: kid.to_owned(),
            key: SigningKey::<P256>::generate().unwrap(),
        }
    }

    fn jwk(&self) -> Value {
        let point = self.key.private_key.public_key_uncompressed();
        json!({"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig", "alg": "ES256",
               "x": b64::encode(&point[1..33]), "y": b64::encode(&point[33..])})
    }

    fn token(&self, typ: &str, claims: &Value) -> String {
        let header = json!({"alg": "ES256", "kid": self.kid, "typ": typ});
        let signed = format!(
            "{}.{}",
            b64::encode(header.to_string().as_bytes()),
            b64::encode(claims.to_string().as_bytes())
        );
        let mut out = [0u8; 64];
        let signature = self
            .key
            .sign::<Sha256>(&[signed.as_bytes()], &mut out)
            .unwrap();
        format!("{signed}.{}", b64::encode(signature))
    }
}

/// What the issuer serves, changed by each test.
struct IssuerState {
    url: String,
    /// The signer of new tokens.
    signer: Signer,
    /// The keys its set publishes.
    published: Vec<Value>,
    cache_control: String,
    age: Option<String>,
    /// Whether it answers; when not, every route answers 503.
    up: bool,
    /// The challenge of each code given.
    codes: HashMap<String, String>,
    /// Key set fetches served.
    fetches: usize,
}

type Shared = Arc<Mutex<IssuerState>>;

impl IssuerState {
    fn claims(&self, subject: &str) -> Value {
        json!({"iss": self.url, "aud": AUDIENCE, "sub": subject, "scope": format!("openid {SCOPE}"),
               "exp": now() + 300, "iat": now(), "groups": ["administrators"]})
    }
}

fn text(status: StatusCode, body: String) -> Response<ReplyBody> {
    let mut response = Response::new(ReplyBody(Some(body.into())));
    *response.status_mut() = status;
    response
}

/// The issuer's body type (the component's `Reply` is not constructible
/// with content from here).
struct ReplyBody(Option<hyper::body::Bytes>);

impl hyper::body::Body for ReplyBody {
    type Data = hyper::body::Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Infallible>>> {
        std::task::Poll::Ready(
            self.get_mut()
                .0
                .take()
                .map(|data| Ok(hyper::body::Frame::data(data))),
        )
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.0.as_ref().map_or(0, |data| data.len() as u64))
    }
}

async fn body(request: Request<Incoming>) -> String {
    let mut body = request.into_body();
    let mut out = Vec::new();
    while let Some(Ok(frame)) =
        std::future::poll_fn(|cx| hyper::body::Body::poll_frame(std::pin::Pin::new(&mut body), cx))
            .await
    {
        if let Ok(data) = frame.into_data() {
            out.extend_from_slice(&data);
        }
    }
    String::from_utf8(out).unwrap()
}

fn form(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

async fn issuer_route(state: Shared, request: Request<Incoming>) -> Response<ReplyBody> {
    let path = request.uri().path().to_owned();
    let query = form(request.uri().query().unwrap_or(""));
    if !state.lock().unwrap().up {
        return text(StatusCode::SERVICE_UNAVAILABLE, String::new());
    }
    match path.as_str() {
        "/.well-known/openid-configuration" => {
            let url = state.lock().unwrap().url.clone();
            text(
                StatusCode::OK,
                json!({"issuer": url, "jwks_uri": format!("{url}/jwks"),
                       "code_challenge_methods_supported": ["S256"]})
                .to_string(),
            )
        }
        "/jwks" => {
            let mut state = state.lock().unwrap();
            state.fetches += 1;
            let mut response = text(StatusCode::OK, json!({"keys": state.published}).to_string());
            let headers = response.headers_mut();
            let _ = headers.insert("cache-control", state.cache_control.parse().unwrap());
            if let Some(age) = &state.age {
                let _ = headers.insert("age", age.parse().unwrap());
            }
            response
        }
        // The authorization endpoint, after the person signed in: the
        // code, bound to the PKCE challenge (S256 only).
        "/authorize" => {
            if query.get("code_challenge_method").map(String::as_str) != Some("S256") {
                return text(StatusCode::BAD_REQUEST, String::new());
            }
            let code = format!("code-{}", state.lock().unwrap().codes.len());
            let challenge = query.get("code_challenge").cloned().unwrap_or_default();
            let _ = state.lock().unwrap().codes.insert(code.clone(), challenge);
            text(StatusCode::OK, json!({"code": code}).to_string())
        }
        // The token endpoint: the code and the verifier whose S256 is its
        // challenge give an agent-audience access token, once.
        "/token" => {
            let fields = form(&body(request).await);
            let mut state = state.lock().unwrap();
            let code = fields.get("code").cloned().unwrap_or_default();
            let verifier = fields.get("code_verifier").cloned().unwrap_or_default();
            let challenge = b64::encode(Sha256::hash(verifier.as_bytes()).as_ref());
            if state.codes.get(&code) != Some(&challenge) {
                return text(
                    StatusCode::BAD_REQUEST,
                    json!({"error": "invalid_grant"}).to_string(),
                );
            }
            let _ = state.codes.remove(&code);
            let subject = fields
                .get("login_hint")
                .cloned()
                .unwrap_or("alice@example".to_owned());
            let claims = state.claims(&subject);
            let token = state.signer.token("at+jwt", &claims);
            let id_token = state.signer.token("JWT", &claims);
            text(
                StatusCode::OK,
                json!({"access_token": token, "token_type": "Bearer", "id_token": id_token})
                    .to_string(),
            )
        }
        _ => text(StatusCode::NOT_FOUND, String::new()),
    }
}

/// The issuer stand-in on a thread of its own: its state.
fn issuer() -> Shared {
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                tls::certificates(&fixture("server.pem")).unwrap(),
                tls::private_key(&fixture("server.key")).unwrap(),
            )
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let signer = Signer::new("k1");
    let state = Arc::new(Mutex::new(IssuerState {
        url: String::new(),
        published: vec![signer.jwk()],
        signer,
        cache_control: "max-age=300".to_owned(),
        age: None,
        up: true,
        codes: HashMap::new(),
        fetches: 0,
    }));
    let (sender, receiver) = std::sync::mpsc::channel();
    let shared = Arc::clone(&state);
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            sender.send(listener.local_addr().unwrap()).unwrap();
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (acceptor, state) = (acceptor.clone(), Arc::clone(&shared));
                drop(tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(move |request| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, Infallible>(issuer_route(state, request).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                }));
            }
        });
    });
    let address = receiver.recv().unwrap();
    state.lock().unwrap().url = format!("https://localhost:{}", address.port());
    state
}

// ---- The component and its clients. ----

/// The component taking `issuer_url`'s tokens and serving `svc.ops` by its
/// certificate, relaying to `socket`, with `budget`.
fn control(issuer_url: &str, socket: PathBuf, budget: Budget) -> SocketAddr {
    let config = tls::server_config(
        tls::certificates(&fixture("server.pem")).unwrap(),
        tls::private_key(&fixture("server.key")).unwrap(),
        tls::certificates(&fixture("ca.pem")).unwrap(),
        tls::ClientAuth::Optional,
    )
    .unwrap();
    let pinned = tls::certificates(&fixture("svc-ops.pem"))
        .unwrap()
        .remove(0);
    let services = vec![Service::new("svc.ops", pinned).unwrap()];
    let issuer =
        Issuer::new(issuer_url, tls::certificates(&fixture("ca.pem")).unwrap()).with_budget(budget);
    let oidc = Oidc::new(
        Policy::new(issuer_url, AUDIENCE, SCOPE),
        Jwks::new(issuer).unwrap(),
    );
    let config = ControlConfig::new(config, services, socket).with_oidc(oidc);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let control = Control::bind("127.0.0.1:0".parse().unwrap(), config)
                .await
                .unwrap();
            sender.send(control.local_addr().unwrap()).unwrap();
            control.serve().await.unwrap();
        });
    });
    receiver.recv().unwrap()
}

fn client(identity: Option<&str>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for root in tls::certificates(&fixture("ca.pem")).unwrap() {
        roots.add(root).unwrap();
    }
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
    Arc::new(match identity {
        None => builder.with_no_client_auth(),
        Some(name) => builder
            .with_client_auth_cert(
                tls::certificates(&fixture(&format!("{name}.pem"))).unwrap(),
                tls::private_key(&fixture(&format!("{name}.key"))).unwrap(),
            )
            .unwrap(),
    })
}

/// `request` over TLS to `address`: the status and the body.
fn exchange(address: SocketAddr, config: Arc<ClientConfig>, request: &str) -> (u16, String) {
    let connection =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    let tcp = TcpStream::connect(address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut stream = StreamOwned::new(connection, tcp);
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").expect("a response");
    (
        head.split(' ').nth(1).unwrap().parse().unwrap(),
        body.to_owned(),
    )
}

fn view(token: &str) -> String {
    format!("GET /v1/view HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n")
}

fn issuer_address(state: &Shared) -> SocketAddr {
    let url = state.lock().unwrap().url.clone();
    let port = url.rsplit(':').next().unwrap().parse().unwrap();
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The console's side of the authorization code flow with PKCE: the code
/// for the challenge of `verifier`, then its exchange with `verifier`.
fn sign_in(state: &Shared, verifier: &str, presented: &str) -> (u16, Value) {
    let address = issuer_address(state);
    let challenge = b64::encode(Sha256::hash(verifier.as_bytes()).as_ref());
    let (status, body) = exchange(
        address,
        client(None),
        &format!(
            "GET /authorize?response_type=code&client_id=console&code_challenge={challenge}\
             &code_challenge_method=S256 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ),
    );
    assert_eq!(status, 200);
    let code: Value = serde_json::from_str(&body).unwrap();
    let form = format!(
        "grant_type=authorization_code&code={}&code_verifier={presented}",
        code["code"].as_str().unwrap()
    );
    let (status, body) = exchange(
        address,
        client(None),
        &format!(
            "POST /token HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\r\n{form}",
            form.len()
        ),
    );
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn quick() -> Budget {
    Budget::new(Duration::ZERO, Duration::ZERO)
}

/// A person signs in through the issuer with PKCE and presents the access
/// token: relayed as its principal, the role being the agent's (a groups
/// claim is not relayed); a wrong verifier gets no token, and the ID token
/// of the same sign-in is no access token.
#[test]
fn a_person_signs_in_with_pkce() {
    let state = issuer();
    let url = state.lock().unwrap().url.clone();
    let (socket, lines) = agent("pkce");
    let address = control(&url, socket, quick());
    let (status, _) = sign_in(
        &state,
        VERIFIER,
        "the-wrong-verifier-of-forty-three-characters",
    );
    assert_eq!(status, 400);
    let (status, tokens) = sign_in(&state, VERIFIER, VERIFIER);
    assert_eq!(status, 200);
    let token = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        exchange(address, client(None), &view(token)),
        (200, ANSWER.to_owned())
    );
    let body = "guard-close /d 3 drill";
    let post = format!(
        "POST /v1/request HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\
         X-Karyos-Role: administrator\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    assert_eq!(exchange(address, client(None), &post).0, 200);
    let id_token = tokens["id_token"].as_str().unwrap();
    let (status, answer) = exchange(address, client(None), &view(id_token));
    assert_eq!(status, 401);
    assert!(answer.contains("\"reason\":\"token type\""), "{answer}");
    assert_eq!(
        *lines.lock().unwrap(),
        [
            "KARYOS-AGENT 1 relay alice@example view\n",
            "KARYOS-AGENT 1 relay alice@example guard-close /d 3 drill\n",
        ]
    );
    // No token and no certificate: not authenticated; a service's
    // certificate still works beside people's tokens.
    let plain = "GET /v1/view HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert_eq!(exchange(address, client(None), plain).0, 401);
    assert_eq!(exchange(address, client(Some("svc-ops")), plain).0, 200);
}

/// `token`'s answer: its status and refusal reason, if any.
fn refused(address: SocketAddr, token: &str) -> (u16, String) {
    let (status, body) = exchange(address, client(None), &view(token));
    let reason: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    (status, reason["reason"].as_str().unwrap_or("").to_owned())
}

/// A wrong audience, an expired token, a wrong issuer: each refused with
/// its reason, nothing relayed.
#[test]
fn wrong_audience_expired_and_wrong_issuer_are_refused() {
    let state = issuer();
    let url = state.lock().unwrap().url.clone();
    let (socket, lines) = agent("claims");
    let address = control(&url, socket, quick());
    let mint = |change: &dyn Fn(&mut Value)| {
        let state = state.lock().unwrap();
        let mut claims = state.claims("alice@example");
        change(&mut claims);
        state.signer.token("at+jwt", &claims)
    };
    let audience = mint(&|claims| claims["aud"] = json!("another-agent"));
    assert_eq!(refused(address, &audience), (401, "audience".to_owned()));
    let expired = mint(&|claims| claims["exp"] = json!(now() - 1));
    assert_eq!(refused(address, &expired), (401, "expired".to_owned()));
    let issuer = mint(&|claims| claims["iss"] = json!("https://localhost:1"));
    assert_eq!(refused(address, &issuer), (401, "issuer".to_owned()));
    assert!(lines.lock().unwrap().is_empty());
}

/// A key the issuer revoked (rotated out of its set) no longer verifies,
/// from the fetch that removed it; the new key does.
#[test]
fn a_revoked_key_is_refused() {
    let state = issuer();
    let url = state.lock().unwrap().url.clone();
    let (socket, lines) = agent("revoked");
    let address = control(&url, socket, quick());
    // Every set is fresh for no time: each token fetches the set.
    state.lock().unwrap().cache_control = "max-age=0".to_owned();
    let old = {
        let state = state.lock().unwrap();
        state.signer.token("at+jwt", &state.claims("alice@example"))
    };
    assert_eq!(refused(address, &old), (200, String::new()));
    {
        let mut state = state.lock().unwrap();
        state.signer = Signer::new("k2");
        state.published = vec![state.signer.jwk()];
    }
    assert_eq!(refused(address, &old), (401, "unknown key".to_owned()));
    let new = {
        let state = state.lock().unwrap();
        state.signer.token("at+jwt", &state.claims("alice@example"))
    };
    assert_eq!(refused(address, &new), (200, String::new()));
    assert_eq!(lines.lock().unwrap().len(), 2);
}

/// An issuer that cannot be reached at start: every token is refused with
/// 503, nothing relayed; services over mutual TLS keep working.
#[test]
fn an_unreachable_issuer_refuses_every_token() {
    let state = issuer();
    let token = {
        let state = state.lock().unwrap();
        state.signer.token("at+jwt", &state.claims("alice@example"))
    };
    // Nothing listens on this port.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://localhost:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let (socket, lines) = agent("unreachable");
    let address = control(&url, socket, quick());
    let (status, body) = exchange(address, client(None), &view(&token));
    assert_eq!(
        (status, body.as_str()),
        (503, "{\"error\":\"token keys unavailable\"}\n")
    );
    let plain = "GET /v1/view HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert_eq!(exchange(address, client(Some("svc-ops")), plain).0, 200);
    assert_eq!(
        *lines.lock().unwrap(),
        ["KARYOS-AGENT 1 relay svc.ops view\n"]
    );
}

/// The key set endpoint fails after a good fetch: a set inside its
/// lifetime keeps verifying; one past it (by `max-age`, `Age`, `no-cache`
/// or no metadata) never does, and the answer is 503, never a grant.
#[test]
fn an_expired_set_is_never_used() {
    for (cache_control, age, usable) in [
        ("max-age=300", None, true),
        ("max-age=300", Some("300"), false),
        ("max-age=0", None, false),
        ("max-age=300, no-cache", None, false),
        ("max-age=300, must-revalidate", None, true),
        ("", None, false),
    ] {
        let state = issuer();
        let url = state.lock().unwrap().url.clone();
        let (socket, lines) = agent("expired");
        let address = control(&url, socket, quick());
        {
            let mut state = state.lock().unwrap();
            state.cache_control = cache_control.to_owned();
            state.age = age.map(str::to_owned);
        }
        let token = {
            let state = state.lock().unwrap();
            state.signer.token("at+jwt", &state.claims("alice@example"))
        };
        // The fetch it triggers verifies the first token, whatever the set's
        // lifetime.
        assert_eq!(refused(address, &token).0, 200, "{cache_control} {age:?}");
        state.lock().unwrap().up = false;
        let expected = if usable { 200 } else { 503 };
        assert_eq!(
            refused(address, &token).0,
            expected,
            "{cache_control} {age:?}"
        );
        assert_eq!(lines.lock().unwrap().len(), if usable { 2 } else { 1 });
    }
}

/// A set's lifetime passing while the issuer is down: 503 from then on;
/// the fetch budget never extends a lifetime (a set past it is not used
/// while the budget forbids a fetch, the issuer up or not).
#[test]
fn neither_time_nor_the_budget_extends_trust() {
    let state = issuer();
    let url = state.lock().unwrap().url.clone();
    let (socket, _) = agent("lifetime");
    let address = control(&url, socket, quick());
    state.lock().unwrap().cache_control = "max-age=1".to_owned();
    let token = {
        let state = state.lock().unwrap();
        state.signer.token("at+jwt", &state.claims("alice@example"))
    };
    assert_eq!(refused(address, &token).0, 200);
    state.lock().unwrap().up = false;
    assert_eq!(refused(address, &token).0, 200);
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(refused(address, &token).0, 503);
    state.lock().unwrap().up = true;
    assert_eq!(refused(address, &token).0, 200);

    // A budget of one fetch a minute: the set of no lifetime verifies the
    // token of its fetch, then no other until the budget allows a fetch.
    let state = issuer();
    let url = state.lock().unwrap().url.clone();
    let (socket, _) = agent("budget");
    let address = control(
        &url,
        socket,
        Budget::new(Duration::from_secs(60), Duration::from_secs(60)),
    );
    state.lock().unwrap().cache_control = "max-age=0".to_owned();
    let token = {
        let state = state.lock().unwrap();
        state.signer.token("at+jwt", &state.claims("alice@example"))
    };
    assert_eq!(refused(address, &token).0, 200);
    assert_eq!(refused(address, &token).0, 503);
    assert_eq!(state.lock().unwrap().fetches, 1);
}

/// A key set with two keys of one `kid` is refused as a whole: 503.
#[test]
fn an_ambiguous_set_is_refused() {
    let state = issuer();
    let url = state.lock().unwrap().url.clone();
    let (socket, lines) = agent("ambiguous");
    let address = control(&url, socket, quick());
    let token = {
        let mut state = state.lock().unwrap();
        let other = Signer::new("k1");
        state.published.push(other.jwk());
        state.signer.token("at+jwt", &state.claims("alice@example"))
    };
    assert_eq!(refused(address, &token).0, 503);
    assert!(lines.lock().unwrap().is_empty());
}
