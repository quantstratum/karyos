// SPDX-License-Identifier: Apache-2.0

//! H8 round 5 (karyos#648): the evidence findings R5-07 to R5-09 raised
//! to the agents' production paths: both network agents, their rings, the
//! real intakes, the production mark store and the driver's key store.
//! Each test names its `INV-` id in the invariant list.

use super::*;

use crate::wire_keys::store::{FileError, Files};

/// A [`Files`] directory shared with the test whose writes can fail: the
/// production [`crate::remote_guard::GuardMarks`] runs over it.
#[derive(Clone, Default)]
struct FlakyDir {
    files: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    fail_writes: Arc<Mutex<bool>>,
}

impl FlakyDir {
    fn put(&self, name: &str, text: &str) {
        self.files
            .lock()
            .unwrap()
            .insert(name.to_owned(), text.as_bytes().to_vec());
    }

    fn text(&self, name: &str) -> Option<String> {
        self.files
            .lock()
            .unwrap()
            .get(name)
            .map(|bytes| String::from_utf8(bytes.clone()).unwrap())
    }

    fn fail_writes(&self, fail: bool) {
        *self.fail_writes.lock().unwrap() = fail;
    }
}

impl Files for FlakyDir {
    fn names(&self) -> Result<Vec<String>, FileError> {
        Ok(self.files.lock().unwrap().keys().cloned().collect())
    }

    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError> {
        let files = self.files.lock().unwrap();
        let bytes = files.get(name).ok_or(FileError::NotFound)?;
        if bytes.len() >= buf.len() {
            return Err(FileError::Refused);
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError> {
        if *self.fail_writes.lock().unwrap() {
            return Err(FileError::Refused);
        }
        self.files
            .lock()
            .unwrap()
            .insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn lock(&self) -> Result<(), FileError> {
        Ok(())
    }
}

/// The production mark file of guard 11.
const MARK_11: &str = "guard-11";

/// [`guarded_over`], the follower's marks in the production
/// [`crate::remote_guard::GuardMarks`] over `dir`.
fn guarded_on(
    dir: &FlakyDir,
    authority: Option<Arc<karyos_client::HeapWords>>,
) -> (Rig, SocketAddr, crate::authority::Ed25519Signer) {
    use karyos_sys::applied_epoch::AppliedEpoch;

    use crate::authority::Ed25519Signer;
    use crate::guard_authority::{AuthorityGuard, GuardAuthority};
    use crate::remote_guard::{GuardMarks, RemoteGuard};
    use crate::signed_control::Authority;

    let mirror = guard_word(1, false);
    let (mut rig, b) = Rig::new(Setup {
        remote_guard: Some(crate::agents::data::GuardSpec {
            word: Arc::clone(&mirror) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            epoch: 0,
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
        }),
        ..Setup::default()
    });
    let a = rig.publisher;
    let a_at = rig.endpoints.local_address(a).unwrap();
    let b_at = rig.endpoints.local_address(b).unwrap();
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let receiver = &mut rig.agents.receiver.role;
    receiver.trust_authorities(
        vec![Authority::of(10, signer.verifier(), 10, &[11], false)],
        0,
    );
    let guard = RemoteGuard::load(10, 11, &GuardMarks::new(dir.clone()));
    receiver.follow_guard(
        guard,
        66,
        a,
        b_at,
        Box::new(GuardMarks::new(dir.clone())),
        Some(mirror),
    );
    if let Some(word) = authority {
        let guards = vec![AuthorityGuard {
            guard_id: 11,
            word: word as Arc<dyn karyos_client::SharedWords>,
            lifetime_ms: 5_000,
            receivers: vec![(66, a_at)],
        }];
        receiver.set_guard_authority(
            Some(
                GuardAuthority::new(
                    10,
                    10,
                    Ed25519Signer::from_seed(&[9; 32]),
                    guards,
                    Box::new(MemoryMarks::default()),
                    0,
                )
                .unwrap(),
            ),
            &[b],
        );
    }
    (rig, b_at, signer)
}

/// INV-GRD-8, the failed-latch arm (ADR-0107 d6; ADR-0118 (c)), end to
/// end over the production mark store: the durable mark is 4 and the
/// store refuses every write. The authority's recovery STATUS at 2 is
/// below the mark, so the guard latches; the latch cannot be stored (the
/// file still says `latched=0`) but holds in memory: the publication is
/// never admitted, and stays so when the authority later answers at 6,
/// above the mark.
#[test]
fn inv_r6_a_latch_that_cannot_be_stored_still_latches_in_memory() {
    use crate::remote_guard::Phase;

    let dir = FlakyDir::default();
    let stored = "karyos-guard-mark-v2\nepoch=4\nlatched=0\n";
    dir.put(MARK_11, stored);
    dir.fail_writes(true);
    let authority = guard_word(2, true);
    let (mut rig, _b_at, _signer) = guarded_on(&dir, Some(Arc::clone(&authority)));
    rig.until(true, |rig| {
        rig.agents.receiver.role.guard_phase(11, rig.now) == Some(Phase::Latched)
    });
    assert_eq!(dir.text(MARK_11).as_deref(), Some(stored), "not stored");
    set_word(&authority, 6, true);
    for _ in 0..1500 {
        rig.round(true);
    }
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Latched)
    );
    assert_eq!(rig.agents.sender.role.registered_sessions(), (0, 1));
    assert_eq!(send_one(&mut rig, 100), 0);
    assert!(pending(&rig));
}

/// INV-GRD-9 (ADR-0086 section 7), end to end over the production mark
/// store. A mark file of an unknown format leaves the guard latched
/// closed (fail closed): the authority's answer at 2 admits nothing, and
/// the file is never rewritten. A readable store: the guard opens at 2,
/// the authority's close at 3 raises the stored mark to 3, a later STATE
/// at 2 is refused and leaves it at 3, and a follower restarted over the
/// same store with the authority back at 2 latches and never admits: the
/// mark never went down.
#[test]
fn inv_r6_marks_only_rise_and_an_unknown_format_fails_closed() {
    use crate::remote_guard::Phase;

    let unknown = "karyos-guard-mark-v9\nepoch=1\nlatched=0\n";
    let dir = FlakyDir::default();
    dir.put(MARK_11, unknown);
    {
        let (mut rig, _b_at, _signer) = guarded_on(&dir, Some(guard_word(2, true)));
        for _ in 0..1500 {
            rig.round(true);
        }
        assert_eq!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Latched)
        );
        assert_eq!(send_one(&mut rig, 100), 0);
        assert!(pending(&rig));
    }
    assert_eq!(dir.text(MARK_11).as_deref(), Some(unknown), "untouched");

    let dir = FlakyDir::default();
    let authority = guard_word(2, true);
    {
        let (mut rig, b_at, signer) = guarded_on(&dir, Some(Arc::clone(&authority)));
        let _slot = established(&mut rig);
        rig.until(true, |rig| {
            matches!(
                rig.agents.receiver.role.guard_phase(11, rig.now),
                Some(Phase::Open { epoch: 2, .. })
            )
        });
        set_word(&authority, 3, false);
        inject_at_a(&mut rig, b_at, &signed_state(&signer, 3, 0));
        assert_eq!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Closed)
        );
        assert_eq!(
            dir.text(MARK_11).as_deref(),
            Some("karyos-guard-mark-v2\nepoch=3\nlatched=0\n")
        );
        let refused = rig.agents.receiver.counters().guard_refused;
        inject_at_a(&mut rig, b_at, &signed_state(&signer, 2, 1));
        assert_eq!(rig.agents.receiver.counters().guard_refused, refused + 1);
        assert!(dir.text(MARK_11).unwrap().contains("epoch=3\n"));
    }
    let (mut rig, _b_at, _signer) = guarded_on(&dir, Some(guard_word(2, true)));
    rig.until(true, |rig| {
        rig.agents.receiver.role.guard_phase(11, rig.now) == Some(Phase::Latched)
    });
    assert_eq!(send_one(&mut rig, 100), 0);
    assert!(pending(&rig));
    assert_eq!(
        dir.text(MARK_11).as_deref(),
        Some("karyos-guard-mark-v2\nepoch=3\nlatched=1\n"),
        "the mark never went down; the latch is stored with it"
    );
}

/// INV-BUD-9 (ADR-0086 section 6), the digest cache's whole lifecycle at
/// the receiver's real signed intake under allocation counting, with an
/// abort that applies: the genuine in-scope SESSION_ABORT is verified,
/// applied (the image closes) and its digest inserted; the identical
/// datagram again is a cache hit, answered with the ACK resend and no
/// verification; past the retention it is verified again and its entry
/// replaces the expired one, so the cache holds one entry. No intake
/// step allocates, nor do the agents' duties after the hit and the
/// expiry; the receiver duties right after the first application, which
/// close and retire the aborted image, are outside the cache and not
/// asserted here.
#[test]
fn inv_r6_the_digest_cache_inserts_hits_and_replaces_without_allocating() {
    use crate::signed_control::CACHE_RETENTION_NS;
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, _slot) = abort_rig(Some(scope));
    assert!(send_one(&mut rig, 200) >= 1);
    rig.agents.receiver.role.reserve_test_logs();
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let genuine = signed_abort(10, 11, GUARD_CLOSED);
    let inject = |rig: &mut Rig| -> (u64, u64, [u64; 3]) {
        rig.now += 300 * MS;
        for _ in 0..3 {
            let _ = counted_round(rig);
        }
        let opens = crate::wire_auth::crypto_opens();
        let now = rig.now;
        let receiver = &mut rig.agents.receiver;
        let ((), allocations) = karyos_sys::alloc_count::count(|| {
            receiver
                .role
                .inject_datagram(&receiver.sessions, b, source, &genuine, now);
        });
        let opens = crate::wire_auth::crypto_opens() - opens;
        let mut around = [0; 3];
        for _ in 0..20 {
            for (total, n) in around.iter_mut().zip(counted_round(rig)) {
                *total += n;
            }
        }
        (allocations, opens, around)
    };
    // Insertion, with the abort applied.
    let (allocations, opens, _closing) = inject(&mut rig);
    let receiver = rig.agents.receiver.counters();
    assert_eq!(receiver.images_closed_aborted, 1, "{receiver:?}");
    assert_eq!(rig.agents.receiver.role.signed_cached(), 1);
    assert_eq!((allocations, opens), (0, 1), "insertion");
    // A hit: the ACK again, nothing verified.
    let resent = receiver.abort_acks_resent;
    let (allocations, opens, around) = inject(&mut rig);
    assert_eq!(around, [0; 3], "the duties after a hit allocated");
    assert_eq!(
        rig.agents.receiver.counters().abort_acks_resent,
        resent + 1,
        "a hit resends the ACK"
    );
    assert_eq!((allocations, opens), (0, 0), "hit");
    // Expiry: verified again; the expired entry is replaced in place.
    rig.now += CACHE_RETENTION_NS;
    let (allocations, opens, around) = inject(&mut rig);
    assert_eq!(around, [0; 3], "the duties after an expiry allocated");
    assert_eq!((allocations, opens), (0, 1), "expiry");
    assert!(rig.agents.receiver.role.signed_cached() <= 1);
    assert_eq!(rig.agents.receiver.counters().images_closed_aborted, 1);
}

/// A signed SESSION_ABORT envelope of the rig's alias whose every fixed
/// field is valid (declared length equal to its length, version 1, flags
/// 0, frame type 0x20, `profile_id` 4, a 64-byte signature, domain 3,
/// the alias, authority key 10) but whose body is `body` bytes.
fn signed_envelope(body: usize) -> Vec<u8> {
    use karyos_protocol::protection::hmac_sha256::FRAME_TYPE;

    let length = 32 + body + 64;
    let mut bytes = vec![0x5au8; length];
    bytes[..4].copy_from_slice(&i32::try_from(length).unwrap().to_le_bytes());
    bytes[4] = 1;
    bytes[5] = 0;
    bytes[6..8].copy_from_slice(&FRAME_TYPE.to_le_bytes());
    bytes[8] = 4;
    bytes[9] = 64;
    bytes[10] = 3;
    bytes[11] = 0;
    bytes[12..16].copy_from_slice(&alias().session_id.to_le_bytes());
    bytes[16..20].copy_from_slice(&alias().stream_id.to_le_bytes());
    bytes[20..24].copy_from_slice(&10u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&7u64.to_le_bytes());
    bytes
}

/// INV-BUD-10 (ADR-0086 section 2), with the crypto work counted (every
/// envelope open and signature verification the driver attempts):
///
/// - checked by the protocol intake: a signed SESSION_ABORT whose fixed
///   fields are all valid and bound to the image's alias and trusted
///   authority, but whose body is above the 160 bytes the profile allows,
///   is refused at the receiver's signed intake before its budget, its
///   digest or any verification; the same envelope at the largest valid
///   size is verified (the counter sees signature work when it happens);
/// - bounded by the socket: a DATA envelope sealed under the session's
///   own key, valid in every field and tag, but longer than the
///   endpoint's `max_datagram` (the 1408-byte default), sent to the
///   receiver's socket, is dropped by the endpoint (counted as a backend
///   drop) and never reaches the intake: no MAC work, no commit.
#[test]
fn inv_r6_oversized_well_formed_envelopes_cost_no_crypto_work() {
    use crate::wire_auth::Sealer;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, channel) = {
        let (rig, b, _slot) = abort_rig(Some(scope));
        let (channel, _) = auth_keys(77);
        (rig, b, channel)
    };
    assert!(send_one(&mut rig, 200) >= 1);
    let party = bound_party(&rig).unwrap();
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.sender_stopped = true;
    rig.now += 300 * MS;
    rig.round(true);
    let before = rig.agents.receiver.counters();
    let opens = crate::wire_auth::crypto_opens();
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_datagram(
        &receiver.sessions,
        b,
        source,
        &signed_envelope(161),
        rig.now,
    );
    assert_eq!(crate::wire_auth::crypto_opens(), opens, "no signature work");
    let after = rig.agents.receiver.counters();
    assert_eq!(after.images_closed_aborted, before.images_closed_aborted);
    // The largest valid body is verified (and refused: its signature).
    rig.now += 300 * MS;
    rig.round(true);
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_datagram(
        &receiver.sessions,
        b,
        source,
        &signed_envelope(160),
        rig.now,
    );
    assert_eq!(crate::wire_auth::crypto_opens(), opens + 1, "verified");

    // A well-formed sealed DATA datagram above the endpoint's limit, on
    // the real socket.
    let mut sealer = Sealer::new(&channel, party, alias()).unwrap();
    sealer.jump_to(0, 1 << 20);
    let oversized = sealed(&mut sealer, &stale_frame(9, 1 << 12, 1500));
    assert!(oversized.len() > 1408);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = rig.endpoints.local_address(b).unwrap();
    let before = rig.agents.receiver.counters();
    let opens = crate::wire_auth::crypto_opens();
    socket.send_to(&oversized, to).unwrap();
    let mut dropped = false;
    for _ in 0..200 {
        rig.round(true);
        if rig.agents.receiver.counters().backend_drops > before.backend_drops {
            dropped = true;
            break;
        }
    }
    assert!(dropped, "the endpoint dropped it");
    let after = rig.agents.receiver.counters();
    assert_eq!(crate::wire_auth::crypto_opens(), opens, "no MAC work");
    assert_eq!(after.data_committed, before.data_committed);
    assert_eq!(after.auth_rejected, before.auth_rejected);
}

/// INV-ABT-17 (H8 R1 #2; ACS 6), with a nonzero repair budget: two DATA
/// datagrams are lost, the budget serves one repair per duty, so a repair
/// is handed to the backend (sent and delivered: the receiver commits
/// it) while another stays pending; the guard then closes. The abort
/// cancels the pending job and serves no later NAK, and what was already
/// handed over is not taken back: the delivered repair stays committed,
/// and no transmit datagram is discarded (the endpoint owns each
/// datagram's storage from submission to its send; the sender keeps no
/// lease on it that cancellation could release).
#[test]
fn inv_r6_an_abort_keeps_what_the_backend_holds_and_cancels_the_rest() {
    use karyos_sys::log_buffer::AppendOptions;

    let jobs = |rig: &Rig| {
        *rig.agents
            .sender
            .role
            .outbound(0)
            .and_then(|outbound| outbound.repair())
            .unwrap()
            .parts()
            .1
            .counts()
    };
    let (mut rig, word) = guarded_abort_rig(false, true);
    // One 900-byte frame of repair per duty at most.
    rig.agents.sender.role.set_repair_bytes(1000);
    rig.agents.receiver.role.drop_data(&[1, 2]);
    for i in 0..4u8 {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    let committed = rig.agents.receiver.counters().data_committed;
    rig.until(true, |rig| rig.agents.sender.role.counters().repairs >= 1);
    let handed = rig.agents.sender.role.counters().repairs;
    let discarded = karyos_io::sockets::endpoint::tx_discarded_on_drop();
    close_guard(&mut rig, &word);
    rig.until(true, |rig| rig.agents.sender.role.pending_aborts() == 1);
    for _ in 0..50 {
        rig.round(true);
    }
    let after = jobs(&rig);
    let sender = rig.agents.sender.role.counters();
    assert!(handed >= 1);
    assert!(
        rig.agents.receiver.counters().data_committed > committed,
        "the handed repair was delivered"
    );
    assert_eq!(sender.repairs_cancelled, after.cancelled, "{sender:?}");
    assert_eq!(
        karyos_io::sockets::endpoint::tx_discarded_on_drop(),
        discarded,
        "nothing the backend held was discarded"
    );
    let created = after.created;
    for _ in 0..20 {
        rig.round(true);
    }
    assert_eq!(jobs(&rig).created, created, "no job after the abort");
}

/// A CHALLENGE of receiver 77 for the publication's alias naming
/// `identity`, sealed under `file`'s RSP_SETUP proof.
fn rsp_challenge_of(
    file: &crate::wire_keys::KeyFile,
    identity: Identity,
    boot: [u64; 2],
    nonce: [u64; 2],
) -> Vec<u8> {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind};
    use karyos_protocol::network::{ChallengeBlock, Control, RspChallenge};

    let proof = Proof::new(
        ProofKind::RspSetup { receiver_id: 77 },
        alias(),
        Some(file),
        [file],
        file.file_epoch,
    )
    .unwrap();
    let control = Control::Challenge(RspChallenge {
        alias: alias(),
        identity,
        challenge: ChallengeBlock {
            receiver_boot_id: boot,
            nonce,
        },
    });
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = control.encode(&mut bytes).unwrap();
    let length = proof.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    bytes
}

/// INV-EST-5 (ADR-0118 (d); ADR-0086 section 4), at the publisher's real
/// RSP_SETUP intake: a CHALLENGE that verifies under the pair's current
/// RSP_SETUP proof but names another incarnation of the publication, with
/// a boot id the publisher never saw, is refused (`Inner`) after its tag
/// and before the boot table: a new boot id reaching the table would have
/// bound, yet the installed key and the establishment are unchanged and
/// delivery goes on.
#[test]
fn inv_r6_a_challenge_of_another_incarnation_binds_nothing() {
    use crate::agents::roles::receive_auth::AuthReason;

    let (mut rig, b, _channel, _previous, current) = lifecycle_rig();
    let _slot = established(&mut rig);
    let b_at = rig.endpoints.local_address(b).unwrap();
    assert!(send_one(&mut rig, 200) >= 1);
    let state = key_state(&rig);
    let before = refused_for(&rig, AuthReason::Inner);
    let other = Identity {
        incarnation: identity().incarnation + 1,
        ..identity()
    };
    challenge_a(
        &mut rig,
        b_at,
        &rsp_challenge_of(&current, other, [0xE5, 1], [5, 5]),
        50,
    );
    assert_eq!(refused_for(&rig, AuthReason::Inner), before + 1);
    assert_eq!(key_state(&rig), state, "nothing bound");
    assert!(send_one(&mut rig, 200) >= 1, "delivery goes on");
}

/// INV-EST-9, the epoch-reset arm (ADR-0086 section 7), through the
/// driver's key store and both agents: under pairwise file epoch 1,
/// receiver-only restarts bind until the retired-boot table is full, and
/// the next is refused `Full`. The store then admits pairwise and channel
/// epoch 2 and its view is applied to both agents, as the conductor does:
/// the waiting receiver's next CHALLENGE, proved under the new current
/// epoch, binds its new boot id.
#[test]
fn inv_r6_a_full_boot_table_binds_again_at_the_next_file_epoch() {
    use crate::agents::roles::receive_auth::AuthReason;
    use crate::wire_auth::MAX_RETIRED_BOOTS;

    let (mut wire, keys_dir) = store_of(&[("3-1.key", C1), ("9-1.key", P1)]);
    let (mut rig, _b, _channel) = authenticated_rig();
    let _slot = established(&mut rig);
    reload_and_apply(&mut rig, &mut wire, 0);
    assert!(send_one(&mut rig, 200) >= 1);
    let mut rebinds = 0;
    loop {
        let last = bound_party(&rig);
        if !restart_and_rebind(&mut rig, last) {
            break;
        }
        rebinds += 1;
        assert!(rebinds <= MAX_RETIRED_BOOTS + 1, "never refused");
    }
    assert!(refused_for(&rig, AuthReason::Full) >= 1);
    let last = bound_party(&rig);
    keys_dir.put("3-2.key", C2);
    keys_dir.put("9-2.key", P2);
    let reload_s = u64::try_from(crate::wire_keys::store::RELOAD_INTERVAL_S).unwrap();
    reload_and_apply(&mut rig, &mut wire, reload_s);
    let mut bound = false;
    for _ in 0..20_000 {
        rig.round(true);
        if bound_party(&rig).is_some() && bound_party(&rig) != last {
            bound = true;
            break;
        }
    }
    assert!(bound, "the new boot id bound under epoch 2");
    let Some(crate::wire_auth::Party::Sender {
        receiver_boot_id, ..
    }) = bound_party(&rig)
    else {
        panic!("bound");
    };
    assert_eq!(receiver_boot_id, rig.agents.receiver.role.boot_id());
}

thread_local! {
    /// What [`skewed_monotonic`] adds to the production monotonic clock.
    static SKEW_NS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The production monotonic clock of an image's verifier
/// (`receive_auth::monotonic_ns`), moved on by [`SKEW_NS`].
fn skewed_monotonic() -> u64 {
    crate::agents::roles::receive_auth::monotonic_ns() + SKEW_NS.with(std::cell::Cell::get)
}

/// Injects DATA sealed by `sealer` at fresh `offset` on B from `source`;
/// returns whether it opened (committed) or was refused, never neither.
fn probe(
    rig: &mut Rig,
    b: EndpointId,
    source: SocketAddr,
    sealer: &mut crate::wire_auth::Sealer,
    offset: u32,
) -> bool {
    let before = rig.agents.receiver.counters();
    let bytes = sealed(sealer, &stale_frame(9, offset, 32));
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &bytes, rig.now);
    let after = rig.agents.receiver.counters();
    let opened = after.data_committed > before.data_committed;
    assert!(
        opened || after.auth_rejected > before.auth_rejected,
        "neither opened nor refused: {after:?}"
    );
    opened
}

/// INV-ROT-5 (H8 R1 #7), at the receiver's real intake, on the image
/// verifier's own clock: the production monotonic clock, moved on by a
/// skew (it is never the wall clock). The publication's domain 1 sealer
/// moves to in-band epoch 1 at 75% (moved there; 2^47 seals are not run)
/// and the image follows. DATA sealed at the previous in-band epoch 0, at
/// fresh sequences, opens 12 hours on, and is refused once its 24-hour
/// overlap has passed, and stays refused.
#[test]
fn inv_r6_the_previous_in_band_epoch_stops_at_the_end_of_its_overlap() {
    use crate::wire_auth::{IN_BAND_OVERLAP_NS, ROTATE_AT, Sealer};

    let (mut rig, b, channel) = authenticated_rig();
    let slot = established(&mut rig);
    rig.agents
        .receiver
        .role
        .set_image_auth_clock(slot, skewed_monotonic);
    assert!(send_one(&mut rig, 200) >= 1);
    let party = bound_party(&rig).unwrap();
    rig.agents
        .sender
        .role
        .outbound_mut(0)
        .unwrap()
        .jump_sealer(0, ROTATE_AT - 2);
    for _ in 0..3 {
        assert!(send_one(&mut rig, 100) >= 1);
    }
    assert_eq!(
        rig.agents
            .sender
            .role
            .outbound(0)
            .unwrap()
            .sealer_keys()
            .map(|keys| keys.0),
        Some(1)
    );
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let mut previous = Sealer::new(&channel, party, alias()).unwrap();
    previous.jump_to(0, ROTATE_AT - 500);
    SKEW_NS.with(|skew| skew.set(IN_BAND_OVERLAP_NS / 2));
    assert!(
        probe(&mut rig, b, source, &mut previous, 1 << 12),
        "in the overlap"
    );
    SKEW_NS.with(|skew| skew.set(IN_BAND_OVERLAP_NS + 1_000 * MS));
    assert!(
        !probe(&mut rig, b, source, &mut previous, (1 << 12) + 64),
        "past it"
    );
    SKEW_NS.with(|skew| skew.set(IN_BAND_OVERLAP_NS + 2_000 * MS));
    assert!(
        !probe(&mut rig, b, source, &mut previous, (1 << 12) + 128),
        "for good"
    );
}
