// SPDX-License-Identifier: Apache-2.0

//! The admission of encrypted channels (ADR-0114 sections 4a and 11)
//! through the real admission paths, and an encrypted unicast channel end
//! to end over loopback: both drivers' agents, their bindings and the
//! conductor's key duty.

use super::*;

use karyos_client::OfferOutcome;
use karyos_protocol::channel::EncryptedChannel;
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::log_buffer::Role;

/// The encrypted channel key id.
const ENC_CHANNEL: u32 = 13;
/// The encrypted pairwise key id.
const ENC_PAIRWISE: u32 = 19;

/// A `profile_id=16` channel key file of `stream_id`.
fn enc_channel_key(stream_id: i32) -> String {
    format!(
        "format=karyos-wire-key-v1\nkey_id={ENC_CHANNEL}\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={}\nchannel_id=7\nstream_id={stream_id}\n",
        "33".repeat(32)
    )
}

/// A `profile_id=16` pairwise key file of receiver 77.
fn enc_pairwise_key() -> String {
    format!(
        "format=karyos-wire-key-v1\nkey_id={ENC_PAIRWISE}\nfile_epoch=1\npurpose=pairwise\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={}\nreceiver_id={RECEIVER}\npublisher_id=5\n",
        "44".repeat(32)
    )
}

/// The files both ends of the encrypted channel hold.
fn enc_files() -> Vec<(&'static str, String)> {
    vec![
        ("13-1.key", enc_channel_key(STREAM)),
        ("19-1.key", enc_pairwise_key()),
    ]
}

/// The configured `channel_id` of the encrypted channel.
const CHANNEL_ID: u64 = 7;
/// The configured `publisher_id` of its publishing driver.
const PUBLISHER_ID: u64 = 5;

fn enc(channel_key_id: u32, pairwise_key_id: u32) -> Security {
    Security::Encrypted(EncryptedChannel {
        channel_key_id,
        pairwise_key_id,
        receiver_id: RECEIVER,
        channel_id: CHANNEL_ID,
        publisher_id: PUBLISHER_ID,
    })
}

fn encrypted() -> Security {
    enc(ENC_CHANNEL, ENC_PAIRWISE)
}

fn publish(driver: &mut EmbeddedDriver, to: Destination, security: Security) -> DriverError {
    driver
        .add_network_publication(aggregate(STREAM), &udp(to, security))
        .unwrap_err()
}

fn subscribe(driver: &mut EmbeddedDriver, channel: &UdpConfig, receiver_id: u64) -> DriverError {
    driver
        .add_network_subscription_as(STREAM, channel, identity(receiver_id))
        .unwrap_err()
}

fn nothing_created(driver: &EmbeddedDriver) {
    let net = driver.net.as_ref().unwrap();
    assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
}

fn unicast() -> Destination {
    Destination::Unicast(SocketAddr::new(LOOPBACK, 9))
}

/// An encrypted channel is refused, typed, by both roles of a driver with
/// no key store; nothing is created.
#[test]
fn encrypted_admission_needs_a_key_store() {
    let mut driver = driver_with(64);
    assert_eq!(
        publish(&mut driver, unicast(), encrypted()),
        refused(AuthRefusal::NoKeyStore)
    );
    let channel = udp(Destination::Unicast(ANY_PORT), encrypted());
    assert_eq!(
        subscribe(&mut driver, &channel, RECEIVER),
        refused(AuthRefusal::NoKeyStore)
    );
    nothing_created(&driver);
}

/// A key id with no valid `profile_id=16` file of its purpose and scope
/// refuses admission, typed, on each role.
#[test]
fn encrypted_admission_refuses_a_missing_key_typed() {
    // No pairwise file: the publisher cannot serve its receiver.
    let (mut publisher, _) = keyed(&[("13-1.key", enc_channel_key(STREAM).as_str())]);
    assert_eq!(
        publish(&mut publisher, unicast(), encrypted()),
        refused(AuthRefusal::PairwiseKey)
    );
    nothing_created(&publisher);
    // A channel file of another stream only.
    let other = enc_channel_key(STREAM + 1);
    let pairwise = enc_pairwise_key();
    let (mut subscriber, _) = keyed(&[
        ("13-1.key", other.as_str()),
        ("19-1.key", pairwise.as_str()),
    ]);
    let channel = udp(Destination::Unicast(ANY_PORT), encrypted());
    assert_eq!(
        subscribe(&mut subscriber, &channel, RECEIVER),
        refused(AuthRefusal::ChannelKey)
    );
    nothing_created(&subscriber);
    // A key id the store does not hold at all.
    let (mut publisher, _) = keyed(&borrowed(&enc_files()));
    assert_eq!(
        publish(
            &mut publisher,
            unicast(),
            enc(ENC_CHANNEL + 1, ENC_PAIRWISE)
        ),
        refused(AuthRefusal::ChannelKey)
    );
    nothing_created(&publisher);
}

/// One class per file (ADR-0114 section 4a): an encrypted channel naming
/// `profile_id=1` files, valid as they are for the authenticated class, is
/// refused, typed, on each role.
#[test]
fn an_encrypted_channel_naming_a_profile_1_file_is_refused() {
    let files = [
        ("3-1.key", channel_key(3, STREAM)),
        ("9-1.key", PAIRWISE.to_owned()),
    ];
    let (mut publisher, _) = keyed(&borrowed(&files));
    assert_eq!(
        publish(&mut publisher, unicast(), enc(3, 9)),
        refused(AuthRefusal::KeyClass)
    );
    nothing_created(&publisher);
    // The channel file of the right class, the pairwise one of the other.
    let mixed = [
        ("13-1.key", enc_channel_key(STREAM)),
        ("9-1.key", PAIRWISE.to_owned()),
    ];
    let (mut subscriber, _) = keyed(&borrowed(&mixed));
    let channel = udp(Destination::Unicast(ANY_PORT), enc(ENC_CHANNEL, 9));
    assert_eq!(
        subscribe(&mut subscriber, &channel, RECEIVER),
        refused(AuthRefusal::KeyClass)
    );
    nothing_created(&subscriber);
}

/// One class per file (ADR-0114 section 4a), the other way: an
/// authenticated channel naming `profile_id=16` files, valid as they are
/// for the encrypted class, is refused, typed, and nothing is created:
/// the authenticated class sees no `profile_id=1` channel file of that
/// key id ([`AuthRefusal::ChannelKey`]).
#[test]
fn an_authenticated_channel_naming_a_profile_16_file_is_refused() {
    let (mut publisher, _) = keyed(&borrowed(&enc_files()));
    let security = Security::Authenticated(AuthenticatedChannel {
        channel_key_id: ENC_CHANNEL,
        pairwise_key_id: ENC_PAIRWISE,
        ..auth(None)
    });
    assert_eq!(
        publish(&mut publisher, unicast(), security),
        refused(AuthRefusal::ChannelKey)
    );
    nothing_created(&publisher);
}

/// Anything but one unicast receiver is ambiguous and refused, typed:
/// several destinations, multicast, another receiver identity.
#[test]
fn encrypted_admission_refuses_multicast_and_ambiguous_configurations() {
    let (mut publisher, _) = keyed(&borrowed(&enc_files()));
    let destinations = Destination::MultiDestination {
        destinations: vec![SocketAddr::new(LOOPBACK, 9), SocketAddr::new(LOOPBACK, 10)],
        control: None,
        mode: karyos_protocol::channel::ControlMode::Manual,
    };
    let multicast = Destination::Multicast {
        group: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)), 4000),
        ttl: None,
    };
    // Several destinations and multicast are unsupported operations,
    // refused typed by name (fail closed; ADR-0035, ADR-0076).
    for (destination, operation) in [
        (
            destinations,
            crate::error::AuthUnsupported::MultiDestination,
        ),
        (multicast.clone(), crate::error::AuthUnsupported::Multicast),
    ] {
        assert_eq!(
            publish(&mut publisher, destination, encrypted()),
            refused(AuthRefusal::Unsupported { operation })
        );
    }
    nothing_created(&publisher);
    let (mut subscriber, _) = keyed(&borrowed(&enc_files()));
    let channel = udp(Destination::Unicast(ANY_PORT), encrypted());
    assert_eq!(
        subscribe(&mut subscriber, &channel, RECEIVER + 1),
        refused(AuthRefusal::Ambiguous)
    );
    assert_eq!(
        subscribe(&mut subscriber, &udp(multicast, encrypted()), RECEIVER),
        refused(AuthRefusal::Unsupported {
            operation: crate::error::AuthUnsupported::Multicast,
        })
    );
    nothing_created(&subscriber);
}

/// An etf declaration is refused, typed and counted, on both roles.
#[test]
fn an_etf_declaration_is_refused_on_an_encrypted_channel() {
    use karyos_protocol::channel::EtfDeclaration;

    let declared = |destination| UdpConfig {
        etf: Some(EtfDeclaration {
            priority: 3,
            delta: Duration::from_nanos(100_000),
        }),
        ..udp(destination, encrypted())
    };
    let (mut publisher, _) = keyed(&borrowed(&enc_files()));
    assert_eq!(
        publisher
            .add_network_publication(aggregate(STREAM), &declared(unicast()))
            .unwrap_err(),
        refused(AuthRefusal::Unsupported {
            operation: crate::error::AuthUnsupported::Etf,
        })
    );
    let (mut subscriber, _) = keyed(&borrowed(&enc_files()));
    assert_eq!(
        subscribe(
            &mut subscriber,
            &declared(Destination::Unicast(ANY_PORT)),
            RECEIVER
        ),
        refused(AuthRefusal::Unsupported {
            operation: crate::error::AuthUnsupported::Etf,
        })
    );
    for driver in [&publisher, &subscriber] {
        assert_eq!(driver.wire_key_counters().unwrap().etf_refused, 1);
        nothing_created(driver);
    }
}

/// ADR-0114 end to end: an encrypted unicast publication admitted through
/// production admission establishes with an encrypted subscription and
/// delivers every message in order over loopback; an encrypted publication
/// of the same stream to a trusted subscriber gives it nothing.
#[test]
fn an_encrypted_unicast_channel_delivers_and_a_trusted_subscriber_gets_nothing() {
    const COUNT: u32 = 64;

    let (mut subscriber, _sub_keys) = keyed(&borrowed(&enc_files()));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), encrypted()),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _pub_keys) = keyed(&borrowed(&enc_files()));
    let handle = publisher
        .add_network_publication(
            aggregate(STREAM),
            &udp(Destination::Unicast(to), encrypted()),
        )
        .unwrap();
    let mut image = None;
    assert!(
        pump(&mut [&mut publisher, &mut subscriber], |drivers| {
            image = drivers[1].network_image(STREAM, 1);
            image.is_some()
        }),
        "the encrypted channel never established"
    );
    let mut reader = subscriber
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lane = publisher
        .publication(handle.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0_u32, 0_u32);
    let budget = Budget {
        work: 256,
        bytes: 1 << 22,
    };
    let delivered = pump(&mut [&mut publisher, &mut subscriber], |_| {
        while sent < COUNT {
            let mut payload = [0_u8; 200];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            budget,
        );
        seen == COUNT
    });
    assert!(delivered, "{seen} of {COUNT} delivered");

    let mut trusted = driver_with(64);
    trusted
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), Security::Trusted),
            identity(RECEIVER),
        )
        .unwrap();
    let to = trusted.network_subscription_address(STREAM).unwrap();
    let (mut other, _) = keyed(&borrowed(&enc_files()));
    let handle = other
        .add_network_publication(
            aggregate(STREAM),
            &udp(Destination::Unicast(to), encrypted()),
        )
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let _ = other.do_work().unwrap();
        let _ = trusted.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(200));
    }
    assert!(trusted.network_images(STREAM).is_empty());
    assert!(
        !other
            .net
            .as_ref()
            .unwrap()
            .publication_established(handle.registration())
    );
}

/// The frame lengths of one sealed datagram's plaintext, each frame at a
/// 32-byte boundary.
fn frame_lengths(frames: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut at = 0;
    while at + 4 <= frames.len() {
        let length = i32::from_le_bytes(frames[at..at + 4].try_into().unwrap());
        let length = usize::try_from(length).unwrap();
        lengths.push(length);
        at += length.max(32).next_multiple_of(32);
    }
    lengths
}

/// An established encrypted unicast channel through production admission
/// (`mtu` 1408): see [`enc_run`].
fn enc_mtu_run(batches: &[Vec<usize>]) -> Vec<Vec<usize>> {
    enc_run(1408, batches)
}

/// An established encrypted unicast channel through production admission
/// at channel `mtu`: each batch of message lengths is offered at once and
/// delivered; returns the frame lengths of every domain 1 datagram sealed
/// meanwhile, after checking that none exceeds `mtu` bytes on the wire
/// (`mtu - 84` inner bytes). Every SETUP the publisher sealed states the
/// whole datagram's `mtu`, and the receiver's image log takes the inner
/// budget, derived locally (H8-13).
fn enc_run(mtu: u32, batches: &[Vec<usize>]) -> Vec<Vec<usize>> {
    enc_run_traced(mtu, batches, false)
}

/// [`enc_run`], each message traced when `traced`: every fragment
/// carries the 64-byte `EXT` frame extension (ADR-0035).
fn enc_run_traced(mtu: u32, batches: &[Vec<usize>], traced: bool) -> Vec<Vec<usize>> {
    use karyos_protocol::network::encrypted::{EncSetup, decode_setup};
    use karyos_protocol::protection::aes_gcm_siv::{Domain, ENVELOPE_LEN};

    let wire = usize::try_from(mtu).unwrap();
    crate::wire_enc::record_seals();
    let (mut subscriber, _sub_keys) = keyed(&borrowed(&enc_files()));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), encrypted()),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _pub_keys) = keyed(&borrowed(&enc_files()));
    let mut config = aggregate(STREAM);
    config.stream.buffer.mtu = mtu;
    let handle = publisher
        .add_network_publication(config, &udp(Destination::Unicast(to), encrypted()))
        .unwrap();
    let mut image = None;
    assert!(
        pump(&mut [&mut publisher, &mut subscriber], |drivers| {
            image = drivers[1].network_image(STREAM, 1);
            image.is_some()
        }),
        "the encrypted channel never established"
    );
    let image = image.unwrap();
    // The SETUPs advertise the whole datagram (ADR-0114 section 11).
    let setups: Vec<u32> = crate::wire_enc::take_seals()
        .iter()
        .filter(|record| record.context.domain == Domain::Setup)
        .map(|record| match decode_setup(&record.frames).unwrap() {
            EncSetup::Announce(announce) => announce.term.mtu,
            EncSetup::Answer(answer) => answer.answer.term.mtu,
        })
        .collect();
    assert!(!setups.is_empty());
    assert!(
        setups.iter().all(|advertised| *advertised == mtu),
        "{setups:?}"
    );
    // Each side sizes its log at the inner budget, locally.
    for (driver, handle) in [(&publisher, &handle), (&subscriber, &image)] {
        let stream = handle.streams().next().unwrap();
        assert_eq!(
            driver.stream_ref(stream).unwrap().config.mtu,
            mtu - 84,
            "the log's inner budget"
        );
    }
    let mut reader = subscriber
        .subscribe_aggregate(&image, Role::Required)
        .unwrap();
    let mut lane = publisher
        .publication(handle.lane(Lane::ZERO).unwrap())
        .unwrap();
    let budget = Budget {
        work: 256,
        bytes: 1 << 22,
    };
    crate::wire_enc::record_seals();
    let sealed = || -> Vec<Vec<usize>> {
        crate::wire_enc::take_seals()
            .iter()
            .filter(|record| record.context.domain == Domain::Sender)
            .map(|record| {
                assert!(
                    record.frames.len() + ENVELOPE_LEN <= wire,
                    "a {}-byte datagram",
                    record.frames.len() + ENVELOPE_LEN
                );
                frame_lengths(&record.frames)
            })
            .collect()
    };
    let mut delivered: Vec<Vec<u8>> = Vec::new();
    let mut offered: Vec<Vec<u8>> = Vec::new();
    for messages in batches {
        for (index, length) in messages.iter().enumerate() {
            let payload: Vec<u8> = (0..*length)
                .map(|at| u8::try_from((at * 31 + index) % 251).unwrap())
                .collect();
            offered.push(payload.clone());
            let outcome = if traced {
                let decision =
                    karyos_client::TraceDecision::traced(karyos_protocol::frame::TraceExtension {
                        extension_flags: 0,
                        trace_id: [7, u64::try_from(index).unwrap() + 1],
                        span_id: 3,
                        parent_span_id: 0,
                        message_id: u64::try_from(offered.len()).unwrap(),
                    });
                assert!(decision.is_traced());
                lane.offer_with_trace(&payload, &decision).unwrap()
            } else {
                lane.offer(&payload).unwrap()
            };
            assert!(matches!(outcome, OfferOutcome::Accepted { .. }));
        }
        let want = delivered.len() + messages.len();
        let done = pump(&mut [&mut publisher, &mut subscriber], |_| {
            let _ = reader.poll(|bytes, _, _| delivered.push(bytes.to_vec()), budget);
            delivered.len() == want
        });
        if !done {
            let data: Vec<Vec<usize>> = sealed()
                .into_iter()
                .filter(|lengths| lengths.iter().any(|length| *length > 96))
                .collect();
            panic!(
                "{} of {want} delivered; DATA sealed: {data:?}",
                delivered.len()
            );
        }
    }
    assert!(delivered == offered, "a message was not delivered intact");
    sealed()
}

/// Gate H11 (manifest section 7; ADR-0114 section 11; ADR-0035
/// Validation), through production admission at `mtu` 1408 (`E` = 84,
/// inner budget 1324, `c` = 1280): a 1280-byte message leaves as one full
/// DATA frame of 1312 bytes, a 1396-byte datagram (W4); 40 messages of 32
/// bytes offered at once leave in datagrams of at most floor(1324 / 64) =
/// 20 frames of 64 bytes, and one holds exactly 20 (W5). Every message is
/// delivered, and no sealed datagram exceeds 1408 bytes on the wire.
#[test]
fn an_encrypted_publication_fills_the_mtu_and_never_exceeds_it() {
    let data = enc_mtu_run(&[vec![1280], vec![32; 40]]);
    assert!(
        data.iter().flatten().any(|length| *length == 32 + 1280),
        "W4: {data:?}"
    );
    let batched = data
        .iter()
        .filter(|lengths| !lengths.is_empty() && lengths.iter().all(|length| *length == 64))
        .map(Vec::len)
        .max();
    assert_eq!(batched, Some(20), "W5: {data:?}");
}

/// Gate H11 (ADR-0114 section 11): through production admission at
/// `mtu` 1408 the encrypted log keeps the inner budget of 1324 bytes, so
/// a message that needs fragments is cut at `c` = 1280: 3000 bytes leave
/// as 1280, 1280 and 440, and a single message of 1293 bytes, one over
/// the largest unfragmented payload of 1292, as 1280 and 13. Each
/// fragment is one datagram of at most 1408 bytes, and both messages are
/// delivered intact.
#[test]
fn an_encrypted_message_is_fragmented_at_c_1280() {
    let data = enc_mtu_run(&[vec![3000], vec![1293]]);
    let fragments: Vec<usize> = data.into_iter().flatten().collect();
    let data: Vec<usize> = fragments
        .iter()
        .copied()
        .filter(|length| *length > 96)
        .collect();
    assert_eq!(data, vec![32 + 1280, 32 + 1280, 32 + 440, 32 + 1280]);
    assert_eq!(
        fragments
            .iter()
            .filter(|length| **length == 32 + 13)
            .count(),
        1,
        "the 13-byte last fragment: {fragments:?}"
    );
}

/// PR #1286 review (P2): the 1408-byte encrypted ceiling (ADR-0114
/// section 11) holds at admission whatever set the channel MTU: a typed
/// publication above it is refused, typed, and nothing is created; 1408
/// is admitted.
#[test]
fn a_typed_encrypted_publication_above_the_mtu_ceiling_is_refused_typed() {
    let (mut publisher, _keys) = keyed(&borrowed(&enc_files()));
    let mut config = aggregate(STREAM);
    config.stream.buffer.mtu = karyos_protocol::channel::MAX_ENCRYPTED_MTU + 1;
    assert_eq!(
        publisher
            .add_network_publication(config, &udp(unicast(), encrypted()))
            .unwrap_err(),
        refused(AuthRefusal::Mtu)
    );
    nothing_created(&publisher);
    let mut config = aggregate(STREAM);
    config.stream.buffer.mtu = karyos_protocol::channel::MAX_ENCRYPTED_MTU;
    assert!(
        publisher
            .add_network_publication(config, &udp(unicast(), encrypted()))
            .is_ok()
    );
}

/// PR #1286 review (P2), the client path: an encrypted channel URI with
/// no `mtu` takes the driver's network default; a default above the
/// 1408-byte ceiling is refused at admission and nothing is created,
/// rather than admitting DATA frames above the AEAD plaintext bound.
#[test]
fn an_encrypted_uri_without_an_mtu_above_the_ceiling_by_default_is_refused() {
    use karyos_client::Outcome;

    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.mtu = karyos_protocol::channel::MAX_ENCRYPTED_MTU + 64;
    let mut publisher = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let (keys, state) = dirs(&borrowed(&enc_files()));
    let report = publisher
        .start_wire_keys_at(Box::new(keys) as Dir, Box::new(state) as Dir, wall)
        .unwrap();
    assert!(!report.alarm(), "{report:?}");
    let mut client = publisher.connect().unwrap();
    let uri = format!(
        "karyos:udp?endpoint=127.0.0.1:{}|interface=127.0.0.1|security=encrypted|channel-key={ENC_CHANNEL}|pairwise-key={ENC_PAIRWISE}|receiver-id={RECEIVER}|channel-id={CHANNEL_ID}|publisher-id={PUBLISHER_ID}",
        crate::test_ports::test_port()
    );
    let sequence = client.add_network_publication(&uri, STREAM, true).unwrap();
    let mut outcome = None;
    assert!(pump(&mut [&mut publisher], |_| {
        let _ = client.poll(usize::MAX, |completion| {
            if completion.sequence == sequence {
                outcome = Some(completion.outcome);
            }
        });
        outcome.is_some()
    }));
    assert!(
        matches!(outcome, Some(Outcome::Refused { .. })),
        "{outcome:?}"
    );
    nothing_created(&publisher);
}

/// H8-13 (ADR-0114 section 11): the 256-byte floor applies to the
/// channel MTU, the whole datagram. 255 is refused, typed, and nothing is
/// created; 256 and 288 (inner budgets of 172 and 204 bytes) are admitted.
#[test]
fn an_encrypted_channel_below_the_mtu_floor_is_refused_typed() {
    let (mut publisher, _keys) = keyed(&borrowed(&enc_files()));
    let mut config = aggregate(STREAM);
    config.stream.buffer.mtu = 255;
    assert_eq!(
        publisher
            .add_network_publication(config, &udp(unicast(), encrypted()))
            .unwrap_err(),
        refused(AuthRefusal::Mtu)
    );
    nothing_created(&publisher);
    for mtu in [256, 288] {
        let (mut publisher, _keys) = keyed(&borrowed(&enc_files()));
        let mut config = aggregate(STREAM);
        config.stream.buffer.mtu = mtu;
        assert!(
            publisher
                .add_network_publication(config, &udp(unicast(), encrypted()))
                .is_ok(),
            "{mtu}"
        );
    }
}

/// H8-13 (ADR-0114 section 11) at the 256-byte floor, end to end through
/// production admission: the SETUPs advertise 256, both logs take the
/// 172-byte inner budget (`c` = 128), the channel establishes and every
/// message is delivered intact in datagrams of at most 256 bytes: one of
/// 128 bytes whole, one of 300 cut as 128, 128 and 44.
#[test]
fn an_encrypted_channel_at_the_mtu_floor_interoperates() {
    let data = enc_run(256, &[vec![128], vec![300]]);
    let lengths: Vec<usize> = data
        .into_iter()
        .flatten()
        .filter(|length| *length > 96)
        .collect();
    assert_eq!(lengths, vec![32 + 128, 32 + 128, 32 + 128], "{lengths:?}");
}

/// H8-03 (wire-key-files.md 2.2): admission uses a channel file only for
/// the configured `channel_id` (and, on the publisher too, its stream),
/// and a pairwise file only for the configured `publisher_id`. Each
/// mismatched field alone refuses admission, typed, on each role that
/// checks it, and creates nothing.
#[test]
fn encrypted_admission_checks_every_scope_field_of_its_files() {
    let channel_of = |channel_id: u64, stream_id: i32| {
        enc_channel_key(stream_id).replace("channel_id=7", &format!("channel_id={channel_id}"))
    };
    let pairwise_of = |publisher_id: u64| {
        enc_pairwise_key().replace("publisher_id=5", &format!("publisher_id={publisher_id}"))
    };
    let channel = udp(Destination::Unicast(ANY_PORT), encrypted());
    for (channel_file, pairwise_file, refusal) in [
        (
            channel_of(CHANNEL_ID + 1, STREAM),
            pairwise_of(PUBLISHER_ID),
            AuthRefusal::ChannelKey,
        ),
        (
            channel_of(CHANNEL_ID, STREAM),
            pairwise_of(PUBLISHER_ID + 1),
            AuthRefusal::PairwiseKey,
        ),
    ] {
        let files = [
            ("13-1.key", channel_file.as_str()),
            ("19-1.key", pairwise_file.as_str()),
        ];
        let (mut publisher, _) = keyed(&files);
        assert_eq!(
            publish(&mut publisher, unicast(), encrypted()),
            refused(refusal)
        );
        nothing_created(&publisher);
        let (mut subscriber, _) = keyed(&files);
        assert_eq!(
            subscribe(&mut subscriber, &channel, RECEIVER),
            refused(refusal)
        );
        nothing_created(&subscriber);
    }
    // The publication's own stream: a channel file of another stream.
    let other = channel_of(CHANNEL_ID, STREAM + 1);
    let pairwise = pairwise_of(PUBLISHER_ID);
    let (mut publisher, _) = keyed(&[
        ("13-1.key", other.as_str()),
        ("19-1.key", pairwise.as_str()),
    ]);
    assert_eq!(
        publish(&mut publisher, unicast(), encrypted()),
        refused(AuthRefusal::ChannelKey)
    );
    nothing_created(&publisher);
}

/// H8-03 (wire-key-files.md 2.2, ADM-2): encrypted admission registers
/// its scopes as the authenticated class does, so a reload whose successor
/// file differs from the admitted scope in one field, each field on its
/// own (the channel key's `channel_id` and `stream_id`, the pairwise
/// key's `receiver_id` and `publisher_id`), never reaches the roles: the
/// view the agents apply holds no file of it, on the publisher and on the
/// subscriber. (Its `not_before` is past the predecessor's overlap, so the
/// store retires the predecessor at once and the channel stops, fail
/// closed.) A successor of the admitted scope does reach them.
#[test]
fn an_encrypted_reload_refuses_a_successor_of_another_scope() {
    let successor = |channel_id: u64, stream_id: i32| {
        enc_channel_key(stream_id)
            .replace("file_epoch=1", "file_epoch=2")
            .replace("channel_id=7", &format!("channel_id={channel_id}"))
            .replace(&"33".repeat(32), &"35".repeat(32))
    };
    let pair_successor = |receiver_id: u64, publisher_id: u64| {
        enc_pairwise_key()
            .replace("file_epoch=1", "file_epoch=2")
            .replace(
                &format!("receiver_id={RECEIVER}"),
                &format!("receiver_id={receiver_id}"),
            )
            .replace("publisher_id=5", &format!("publisher_id={publisher_id}"))
            .replace(&"44".repeat(32), &"46".repeat(32))
    };
    let cases = [
        (
            "channel_id",
            ENC_CHANNEL,
            successor(CHANNEL_ID + 1, STREAM),
            false,
        ),
        (
            "stream_id",
            ENC_CHANNEL,
            successor(CHANNEL_ID, STREAM + 1),
            false,
        ),
        (
            "receiver_id",
            ENC_PAIRWISE,
            pair_successor(RECEIVER + 1, PUBLISHER_ID),
            false,
        ),
        (
            "publisher_id",
            ENC_PAIRWISE,
            pair_successor(RECEIVER, PUBLISHER_ID + 1),
            false,
        ),
        (
            "same scope",
            ENC_CHANNEL,
            successor(CHANNEL_ID, STREAM),
            true,
        ),
        (
            "same pair",
            ENC_PAIRWISE,
            pair_successor(RECEIVER, PUBLISHER_ID),
            true,
        ),
    ];
    for (field, key_id, text, reaches) in cases {
        let (mut subscriber, sub_keys) = keyed(&borrowed(&enc_files()));
        subscriber
            .add_network_subscription_as(
                STREAM,
                &udp(Destination::Unicast(ANY_PORT), encrypted()),
                identity(RECEIVER),
            )
            .unwrap();
        let (mut publisher, pub_keys) = keyed(&borrowed(&enc_files()));
        publisher
            .add_network_publication(aggregate(STREAM), &udp(unicast(), encrypted()))
            .unwrap();
        for keys in [&sub_keys, &pub_keys] {
            keys.put(&format!("{key_id}-2.key"), &text);
        }
        advance(RELOAD_INTERVAL_S);
        for _ in 0..20 {
            let _ = subscriber.do_work().unwrap();
            let _ = publisher.do_work().unwrap();
        }
        for driver in [&subscriber, &publisher] {
            let wire = driver.net.as_ref().unwrap().wire_keys().unwrap();
            let epochs: Vec<u32> = crate::wire_auth::KeySet::verifying(&*wire.view, key_id)
                .into_iter()
                .flatten()
                .map(|file| file.file_epoch)
                .collect();
            let want: Vec<u32> = if reaches { vec![2] } else { Vec::new() };
            assert_eq!(epochs, want, "{field}");
        }
    }
}

/// The frames of each sealed DATA datagram longer than `above` bytes
/// (heartbeats and pads aside), datagrams without one dropped.
fn enc_message_frames(data: &[Vec<usize>], above: usize) -> Vec<Vec<usize>> {
    data.iter()
        .map(|frames| {
            frames
                .iter()
                .copied()
                .filter(|length| *length > above)
                .collect::<Vec<usize>>()
        })
        .filter(|frames| !frames.is_empty())
        .collect()
}

/// Gate H11, W9 at the MTU boundary (manifest 6.1 and 7; ADR-0114 section
/// 11; ADR-0035 Validation), through production admission at `mtu` 1408
/// (inner budget 1324, a frame of at most 1312): the encrypted sender
/// emits `EXT` frames. A traced frame's header is 32 + 64 bytes, so the
/// largest traced message left whole is 1312 - 96 = 1216 bytes, one frame
/// of 1312 in a datagram of 1396; one byte more fragments as 1216 and 1,
/// each fragment carrying its `EXT`; 21 traced 32-byte messages pack at
/// most floor(1324 / 128) = 10 per datagram. Every message is delivered
/// intact and no sealed datagram exceeds 1408 bytes (checked by the run).
#[test]
fn h11_w9_encrypted_ext_frames_fill_the_mtu_and_never_exceed_it() {
    let full = enc_run_traced(1408, &[vec![1216]], true);
    let frames: Vec<usize> = enc_message_frames(&full, 96)
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(frames, vec![96 + 1216], "{full:?}");
    let over = enc_run_traced(1408, &[vec![1217]], true);
    let frames: Vec<usize> = enc_message_frames(&over, 96)
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(frames, vec![96 + 1216, 96 + 1], "{over:?}");
    let batched = enc_run_traced(1408, &[vec![32; 21]], true);
    let packed = enc_message_frames(&batched, 96);
    assert!(
        packed.iter().all(|frames| frames.len() <= 10),
        "{batched:?}"
    );
    assert_eq!(packed.iter().map(Vec::len).max(), Some(10), "{batched:?}");
    assert_eq!(packed.iter().map(Vec::len).sum::<usize>(), 21);
}

/// Gate H11, W6 (manifest 6.1, "the datagram count of 6.1 under each
/// profile"; ADR-0114 section 11): a 6000-byte message under the
/// encrypted envelope leaves in exactly ceil(6000 / 1280) = 5 datagrams,
/// four fragments of 1280 and one of 880, each alone in its datagram,
/// and arrives intact. Traced (`c` = 1216) it is still 5: four of 1216
/// and one of 1136.
#[test]
fn h11_w6_an_encrypted_6000_byte_message_takes_five_datagrams() {
    let data = enc_mtu_run(&[vec![6000]]);
    let datagrams = enc_message_frames(&data, 96);
    assert_eq!(datagrams.len(), 6000_usize.div_ceil(1280), "{data:?}");
    assert_eq!(
        datagrams,
        vec![
            vec![32 + 1280],
            vec![32 + 1280],
            vec![32 + 1280],
            vec![32 + 1280],
            vec![32 + 880]
        ],
        "{data:?}"
    );
    let traced = enc_run_traced(1408, &[vec![6000]], true);
    let datagrams = enc_message_frames(&traced, 96);
    assert_eq!(
        datagrams,
        vec![
            vec![96 + 1216],
            vec![96 + 1216],
            vec![96 + 1216],
            vec![96 + 1216],
            vec![96 + 1136]
        ],
        "{traced:?}"
    );
}
