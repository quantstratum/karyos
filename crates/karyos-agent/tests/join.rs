// SPDX-License-Identifier: Apache-2.0

//! The join metadata registry over API v1 (Linux; karyos#736): a registrar
//! puts versioned entries, a collector of any role reads them and the
//! version in force at an instant, each bound is refused by name, and an
//! incarnation change of the driver leaves the registry as it was.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_agent::server::{ApiConfig, Role, Served, Server};
use karyos_agent::{Agent, AgentConfig};
use karyos_client::{Client, Context, CounterKind, IdleStrategy};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_sys::term_bytes::SharedTerms;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-join-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn driver(dir: &Path) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 4,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: 4,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Runs `work` on another thread while this one serves `driver`.
fn serving<R: Send>(driver: &mut IpcDriver, work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

fn own() -> u32 {
    karyos_sys::ipc::own_uid()
}

/// Sends `request` from another thread and serves it.
fn ask(server: &mut Server, agent: &mut Agent, request: &str) -> (String, Vec<Served>) {
    let path = server.path().to_path_buf();
    std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer).unwrap();
            answer
        });
        let mut served = Vec::new();
        let start = Instant::now();
        while served.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10), "never served");
            served = server.poll(agent).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        (client.join().unwrap(), served)
    })
}

/// A server for one role, in its own directory.
fn server(dir: &Path, name: &str, role: Role) -> Server {
    Server::bind(ApiConfig::new(dir.join(name), vec![(own(), role)])).unwrap()
}

/// The numbers after each `"field":` in `text`, in order.
fn numbers(text: &str, field: &str) -> Vec<u64> {
    let key = format!("\"{field}\":");
    text.match_indices(&key)
        .filter_map(|(at, _)| {
            let rest = &text[at + key.len()..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse().ok()
        })
        .collect()
}

/// A product registers versioned entries and a collector reads them
/// through the agent: the version in force at an instant before the new
/// one is the old one; what the agent observes of a trace point and an
/// application counter is given, and of a stream nothing; a viewer may
/// not write; the view of API v1 is unchanged.
#[test]
fn a_registrar_writes_and_a_collector_joins_against_the_right_version() {
    let _serial = serial();
    let dir = dir("versions");
    let mut driver = driver(&dir.join("driver"));
    let mut agent = Agent::new(
        AgentConfig::new(vec![dir.join("driver")]).with_attach_timeout(Duration::from_secs(5)),
    );
    let context = Context::builder()
        .dir(dir.join("driver"))
        .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
        .build()
        .unwrap();
    // A client holding a trace point and an application counter.
    let (_client, _point, _counter) = serving(&mut driver, || {
        let mut client = Client::connect(context).unwrap();
        let point = client.add_trace_point("md.tick").unwrap();
        let counter = client.add_counter("orders", CounterKind::Event).unwrap();
        (client, point, counter)
    });
    serving(&mut driver, || agent.refresh());
    let registrar = &mut server(&dir, "api-registrar", Role::Registrar);
    let driver_dir = dir.join("driver").display().to_string();

    let (answer, served) = ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-put {driver_dir} point md.tick venue=xnas instrument=aapl\n"),
    );
    assert_eq!(served, [Served::Registered]);
    let generation = numbers(&answer, "generation")[0];
    assert_eq!(
        answer,
        format!(
            "{{\"registered\":{{\"driver\":\"{driver_dir}\",\"kind\":\"point\",\"key\":\"md.tick\",\"version\":1,\"generation\":{generation}}}}}\n"
        )
    );
    std::thread::sleep(Duration::from_millis(2));
    let (answer, _) = ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-put {driver_dir} point md.tick venue=xnys instrument=aapl\n"),
    );
    assert!(answer.contains("\"version\":2"), "{answer}");
    ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-put {driver_dir} counter orders desk=a\n"),
    );
    ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-put {driver_dir} stream 7 feed=itch\n"),
    );

    // A collector with the viewer role reads the list, then the version
    // in force just before the second put.
    let viewer = &mut server(&dir, "api-viewer", Role::Viewer);
    let (list, served) = ask(
        viewer,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-list {driver_dir}\n"),
    );
    assert_eq!(served, [Served::Join]);
    assert!(
        list.contains(&format!("\"generation\":{generation},")),
        "{list}"
    );
    // Key order: streams, then points, then counters.
    let stream_at = list.find("\"kind\":\"stream\"").unwrap();
    let point_at = list.find("\"kind\":\"point\"").unwrap();
    let counter_at = list.find("\"kind\":\"counter\"").unwrap();
    assert!(stream_at < point_at && point_at < counter_at, "{list}");
    assert!(
        list.contains(r#""kind":"stream","key":"7","present":null,"holders":null,"shared":null,"#),
        "{list}"
    );
    assert!(
        list.contains(
            r#""kind":"point","key":"md.tick","present":true,"holders":1,"shared":false,"#
        ),
        "{list}"
    );
    assert!(
        list.contains(
            r#""kind":"counter","key":"orders","present":true,"holders":1,"shared":false,"#
        ),
        "{list}"
    );
    assert!(list.ends_with("\"more\":false}}\n"), "{list}");
    let point = &list[point_at..counter_at];
    let from = numbers(point, "valid_from");
    assert_eq!(from.len(), 2, "{point}");
    assert!(from[0] < from[1]);
    let (old, served) = ask(
        viewer,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 join-get {driver_dir} point md.tick {}\n",
            from[1] - 1
        ),
    );
    assert_eq!(served, [Served::Join]);
    assert!(
        old.contains(&format!(
            "\"version\":{{\"number\":1,\"registered_by\":{},\"valid_from\":{},\"valid_to\":{},\"attributes\":{{\"venue\":\"xnas\",\"instrument\":\"aapl\"}}}}",
            own(),
            from[0],
            from[1]
        )),
        "{old}"
    );
    let (now, _) = ask(
        viewer,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-get {driver_dir} point md.tick\n"),
    );
    assert!(now.contains("\"number\":2,"), "{now}");
    assert!(now.contains("\"valid_to\":null"), "{now}");
    // Before the first version: nothing in force, and no history lost.
    let (before, _) = ask(
        viewer,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 join-get {driver_dir} point md.tick {}\n",
            from[0] - 1
        ),
    );
    assert!(
        before.contains("\"version\":null,\"history_dropped\":0,\"before_history\":false"),
        "{before}"
    );

    // A viewer may read, never write.
    let (answer, served) = ask(
        viewer,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-put {driver_dir} point md.tick venue=x\n"),
    );
    assert_eq!(served, [Served::Refused]);
    assert_eq!(answer, "{\"error\":\"forbidden\"}\n");
    let (answer, _) = ask(
        viewer,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-retire {driver_dir} point md.tick\n"),
    );
    assert_eq!(answer, "{\"error\":\"forbidden\"}\n");

    // The retire ends the current version; a second one finds none.
    let (answer, served) = ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-retire {driver_dir} counter orders\n"),
    );
    assert_eq!(served, [Served::Registered]);
    assert!(answer.starts_with("{\"retired\":"), "{answer}");
    let (answer, _) = ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-retire {driver_dir} counter orders\n"),
    );
    assert_eq!(answer, "{\"error\":\"no such entry\"}\n");

    // The view of API v1 carries nothing of the registry.
    let (view, _) = ask(viewer, &mut agent, "KARYOS-AGENT 1 view\n");
    assert!(view.starts_with("{\"version\":1,\"drivers\":["), "{view}");
    assert!(!view.contains("join"), "{view}");
}

/// Each bound and each malformed request is refused by name over the
/// socket, an unknown driver too, and nothing is kept.
#[test]
fn registry_requests_are_refused_by_bound_and_shape() {
    let _serial = serial();
    let dir = dir("bounds");
    let mut agent = Agent::new(AgentConfig::new(vec![dir.join("driver")]));
    let registrar = &mut server(&dir, "api", Role::Registrar);
    let driver_dir = dir.join("driver").display().to_string();
    let put = |rest: &str| format!("KARYOS-AGENT 1 join-put {driver_dir} {rest}\n");
    let many = (0..=16)
        .map(|index| format!("a{index}=x"))
        .collect::<Vec<_>>()
        .join(" ");
    let rows = [
        (
            put(&format!("point p {many}")),
            "{\"error\":\"above bound\",\"dimension\":\"join.attributes_per_entry\",\"bound\":16}\n"
                .to_owned(),
        ),
        (
            put(&format!("point p n={}", "v".repeat(65))),
            "{\"error\":\"above bound\",\"dimension\":\"join.value_bytes\",\"bound\":64}\n"
                .to_owned(),
        ),
        (
            put(&format!("point p {}=v", "n".repeat(33))),
            "{\"error\":\"above bound\",\"dimension\":\"join.name_bytes\",\"bound\":32}\n"
                .to_owned(),
        ),
        (
            put(&format!("point {} n=v", "k".repeat(65))),
            "{\"error\":\"above bound\",\"dimension\":\"join.key_bytes\",\"bound\":64}\n"
                .to_owned(),
        ),
        (
            put(&format!("point p n={}", "v ".repeat(600))),
            "{\"error\":\"above bound\",\"dimension\":\"join.request_bytes\",\"bound\":1024}\n"
                .to_owned(),
        ),
        (
            put("point p Name=v"),
            "{\"error\":\"bad arguments\",\"request\":\"join-put\",\"detail\":\"attribute name\"}\n"
                .to_owned(),
        ),
        (
            put("stream 07 n=v"),
            "{\"error\":\"bad arguments\",\"request\":\"join-put\",\"detail\":\"key\"}\n"
                .to_owned(),
        ),
        (
            put("table p n=v"),
            "{\"error\":\"bad arguments\",\"request\":\"join-put\"}\n".to_owned(),
        ),
        (
            put("point p"),
            "{\"error\":\"bad arguments\",\"request\":\"join-put\"}\n".to_owned(),
        ),
        (
            "KARYOS-AGENT 1 join-put /no/such/driver point p n=v\n".to_owned(),
            "{\"error\":\"unknown driver\"}\n".to_owned(),
        ),
        (
            format!("KARYOS-AGENT 1 join-get {driver_dir} point p soon\n"),
            "{\"error\":\"bad arguments\",\"request\":\"join-get\"}\n".to_owned(),
        ),
        (
            format!("KARYOS-AGENT 1 join-list {driver_dir} point\n"),
            "{\"error\":\"bad arguments\",\"request\":\"join-list\"}\n".to_owned(),
        ),
        (
            format!("KARYOS-AGENT 1 join-retire {driver_dir} point p extra\n"),
            "{\"error\":\"bad arguments\",\"request\":\"join-retire\"}\n".to_owned(),
        ),
        // Another request as long as a join-put may be is still refused.
        (
            format!("KARYOS-AGENT 1 view {}\n", "x".repeat(300)),
            "{\"error\":\"bad request\"}\n".to_owned(),
        ),
    ];
    for (request, expected) in rows {
        let (answer, served) = ask(registrar, &mut agent, &request);
        assert_eq!(served, [Served::Refused], "{request}");
        assert_eq!(answer, expected, "{request}");
    }
    let (list, _) = ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-list {driver_dir}\n"),
    );
    assert!(list.contains("\"entries\":[]"), "{list}");
}

/// A driver's restart, a new incarnation, leaves the registry as it was:
/// its keys are names, not the old instance's ids, so every version and
/// the generation stand, and what the agent observes follows the new
/// instance (here nothing holds the point, so it is absent).
#[test]
fn an_incarnation_change_leaves_the_registry_as_it_was() {
    let _serial = serial();
    let dir = dir("incarnation");
    let mut driver = driver(&dir.join("driver"));
    let mut agent = Agent::new(
        AgentConfig::new(vec![dir.join("driver")]).with_attach_timeout(Duration::from_secs(5)),
    );
    serving(&mut driver, || agent.refresh());
    let registrar = &mut server(&dir, "api", Role::Registrar);
    let driver_dir = dir.join("driver").display().to_string();
    ask(
        registrar,
        &mut agent,
        &format!("KARYOS-AGENT 1 join-put {driver_dir} point md.tick venue=xnas\n"),
    );
    let get = format!("KARYOS-AGENT 1 join-get {driver_dir} point md.tick\n");
    let (before, _) = ask(registrar, &mut agent, &get);
    let instance = driver.instance();
    drop(driver);
    agent.refresh();
    let mut driver = self::driver(&dir.join("driver"));
    serving(&mut driver, || agent.refresh());
    assert_ne!(driver.instance(), instance);
    let (after, _) = ask(registrar, &mut agent, &get);
    let strip_at = |text: &str| {
        let at = text.find("\"at\":").unwrap();
        let end = at + text[at..].find(',').unwrap();
        format!("{}{}", &text[..at], &text[end..])
    };
    assert_eq!(strip_at(&before), strip_at(&after));
    assert!(
        after.contains("\"present\":false,\"holders\":0,\"shared\":false"),
        "{after}"
    );
    assert!(after.contains("\"number\":1,"), "{after}");
}
