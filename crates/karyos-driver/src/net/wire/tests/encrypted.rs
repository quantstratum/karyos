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

fn enc(channel_key_id: u32, pairwise_key_id: u32) -> Security {
    Security::Encrypted(EncryptedChannel {
        channel_key_id,
        pairwise_key_id,
        receiver_id: RECEIVER,
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
