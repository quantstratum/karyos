// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

/// What the test service saw, in order: the entry's index and what.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Command(u64, u64),
    Timer(u64, u64),
    Configuration(u64, Vec<u8>),
}

/// A deterministic service: command `[0, v..8]` appends `v` and replies
/// with the count; `[1, id..8, after..8]` schedules timer `id` at the log
/// time plus `after`; `[2, id..8]` cancels it; `[3]` replies past any
/// buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Register {
    values: Vec<u64>,
    seen: Vec<Seen>,
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

impl ClusteredService for Register {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        self.seen.push(Seen::Command(context.index(), client));
        match command[0] {
            0 => {
                self.values.push(word(&command[1..]));
                let count = (self.values.len() as u64).to_le_bytes();
                reply.get_mut(..8)?.copy_from_slice(&count);
                Some(8)
            }
            1 => {
                let deadline = context.log_time() + word(&command[9..]);
                context.schedule(word(&command[1..]), deadline).ok()?;
                Some(0)
            }
            2 => Some(usize::from(context.cancel(word(&command[1..])))),
            _ => None,
        }
    }

    fn on_timer(&mut self, context: &mut Context<'_>, timer: u64) {
        self.seen.push(Seen::Timer(context.index(), timer));
    }

    fn on_configuration(&mut self, context: &mut Context<'_>, configuration: &[u8]) {
        self.seen
            .push(Seen::Configuration(context.index(), configuration.to_vec()));
    }
}

fn config() -> ContainerConfig {
    ContainerConfig::default()
        .with_dedup(
            DedupConfig::default()
                .with_sessions(4)
                .with_window(4)
                .with_response_bytes(16)
                .with_ttl(1000),
        )
        .with_timers(2)
}

fn container() -> ServiceContainer<Register> {
    ServiceContainer::new(Register::default(), config()).unwrap()
}

fn entry(index: u64, event_time: u64, envelope: Envelope<'_>) -> Entry {
    Entry {
        index,
        term: 1,
        event_time,
        payload: envelope.to_vec().unwrap(),
    }
}

/// Client 7's request `sequence`, counted from 1 (the table's from 0).
fn request(sequence: u64, command: &[u8]) -> Envelope<'_> {
    Envelope::Request {
        request: Request::new(7, 1, sequence - 1, sequence - 1),
        command,
    }
}

fn append(value: u64) -> Vec<u8> {
    let mut command = vec![0];
    command.extend_from_slice(&value.to_le_bytes());
    command
}

fn schedule(timer: u64, after: u64) -> Vec<u8> {
    let mut command = vec![1];
    command.extend_from_slice(&timer.to_le_bytes());
    command.extend_from_slice(&after.to_le_bytes());
    command
}

/// Client 7 registered at index 1, epoch 1.
fn registered() -> ServiceContainer<Register> {
    let mut container = container();
    let applied = container
        .apply(&entry(1, 0, Envelope::Register { client: 7 }))
        .unwrap();
    assert!(matches!(applied, Applied::Registered(Ok(r)) if r.epoch == 1));
    container
}

#[test]
fn test_envelope_round_trips_every_template() {
    let command = [9, 8, 7];
    let largest = vec![0xA5; MAX_COMMAND];
    let configuration = vec![0x5A; MAX_CONFIGURATION];
    for (envelope, template, length) in [
        (Envelope::Register { client: 3 }, 1, 20),
        (
            Envelope::Close {
                client: 3,
                epoch: 11,
            },
            2,
            28,
        ),
        (
            Envelope::Request {
                request: Request::new(3, 11, 5, 4),
                command: &command,
            },
            3,
            12 + 32 + 2 + 3,
        ),
        (
            Envelope::Request {
                request: Request::new(3, 11, 5, 6),
                command: &[],
            },
            3,
            12 + 32 + 2,
        ),
        (
            Envelope::Request {
                request: Request::new(3, 11, u64::MAX, u64::MAX),
                command: &largest,
            },
            3,
            65581,
        ),
        (
            Envelope::TimerFired {
                timer: 2,
                deadline: 900,
            },
            4,
            28,
        ),
        (Envelope::Configuration(&command), 5, 12 + 2 + 3),
        (Envelope::Configuration(&configuration), 5, 4110),
    ] {
        let bytes = envelope.to_vec().unwrap();
        assert_eq!(bytes.len(), length, "{template}");
        // The ADR-0036 envelope: schema 2, the template, version 1.
        assert_eq!(&bytes[..6], &[2, 0, template, 0, 1, 0], "{template}");
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize,
            length
        );
        assert_eq!(Envelope::decode(&bytes), Ok(envelope));
    }
}

#[test]
fn test_envelope_refuses_what_schema_2_refuses() {
    let out_of_range = |field| Err(CodecError::ValueOutOfRange { field });
    // Value rules, encoding and decoding.
    for (envelope, field) in [
        (Envelope::Register { client: 0 }, "client"),
        (
            Envelope::Close {
                client: 0,
                epoch: 1,
            },
            "client",
        ),
        (
            Envelope::Close {
                client: 1,
                epoch: 0,
            },
            "epoch",
        ),
        (
            Envelope::Request {
                request: Request::new(0, 1, 0, 0),
                command: &[],
            },
            "client",
        ),
        (
            Envelope::Request {
                request: Request::new(1, 0, 0, 0),
                command: &[],
            },
            "epoch",
        ),
        (
            Envelope::Request {
                request: Request::new(1, 1, 5, 7),
                command: &[],
            },
            "lowest_unanswered",
        ),
    ] {
        assert_eq!(envelope.to_vec(), out_of_range(field), "{envelope:?}");
    }
    let mut zero_client = Envelope::Register { client: 1 }.to_vec().unwrap();
    zero_client[12] = 0;
    assert_eq!(
        Envelope::decode(&zero_client),
        Err(CodecError::ValueOutOfRange { field: "client" })
    );
    let mut past = Envelope::Request {
        request: Request::new(1, 1, 5, 6),
        command: &[],
    }
    .to_vec()
    .unwrap();
    past[36] = 7;
    assert_eq!(
        Envelope::decode(&past),
        Err(CodecError::ValueOutOfRange {
            field: "lowest_unanswered"
        })
    );
    // Length bounds of the variable fields.
    let too_long = vec![0; MAX_CONFIGURATION + 1];
    assert!(matches!(
        Envelope::Configuration(&too_long).to_vec(),
        Err(CodecError::LengthOutOfRange {
            field: "configuration",
            ..
        })
    ));
    assert!(matches!(
        Envelope::Configuration(&[]).to_vec(),
        Err(CodecError::LengthOutOfRange {
            field: "configuration",
            min: 1,
            ..
        })
    ));
    let command = vec![0; MAX_COMMAND + 1];
    assert!(matches!(
        Envelope::Request {
            request: Request::new(1, 1, 0, 0),
            command: &command,
        }
        .to_vec(),
        Err(CodecError::LengthOutOfRange {
            field: "command",
            ..
        })
    ));
    // The envelope: another schema, version or template, a block of
    // another length, a length that is not the input's.
    let good = Envelope::Close {
        client: 3,
        epoch: 4,
    }
    .to_vec()
    .unwrap();
    for (at, value) in [(0, 1u8), (4, 2), (2, 9)] {
        let mut bytes = good.clone();
        bytes[at] = value;
        assert!(
            matches!(
                Envelope::decode(&bytes),
                Err(CodecError::UnsupportedSchema { .. })
            ),
            "byte {at}"
        );
    }
    let mut block = good.clone();
    block[6] = 8;
    assert!(matches!(
        Envelope::decode(&block),
        Err(CodecError::UnsupportedSchema { .. })
    ));
    let mut longer = good.clone();
    longer.push(0);
    assert!(matches!(
        Envelope::decode(&longer),
        Err(CodecError::MessageLength { .. })
    ));
    assert!(Envelope::decode(&good[..good.len() - 1]).is_err());
}

/// karyos#797: a payload that is not a schema 2 message stops every
/// replica at the same index, for the same reason, and none applies past
/// it: a safety stop.
#[test]
fn test_container_a_payload_not_schema_2_stops_every_replica_at_the_same_index() {
    let bad = Entry {
        index: 3,
        term: 1,
        event_time: 0,
        payload: vec![1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    let log = [
        entry(1, 0, Envelope::Register { client: 7 }),
        entry(2, 0, request(1, &append(5))),
        bad,
        entry(4, 0, request(2, &append(6))),
    ];
    let stops: Vec<_> = (0..3)
        .map(|_| {
            let mut container = container();
            let mut stop = None;
            for entry in &log {
                if let Err(error) = container.apply(entry) {
                    stop = Some((entry.index, error));
                    break;
                }
            }
            (
                stop,
                container.applied(),
                container.service().values.clone(),
            )
        })
        .collect();
    assert!(stops.windows(2).all(|pair| pair[0] == pair[1]), "{stops:?}");
    let (stop, applied, values) = &stops[0];
    assert!(matches!(
        stop,
        Some((
            3,
            ApplyError::Envelope(CodecError::UnsupportedSchema { .. })
        ))
    ));
    assert_eq!(*applied, Some(2), "nothing past the stop");
    assert_eq!(values, &[5]);
}

#[test]
fn test_container_a_request_runs_once_and_a_retry_gets_its_retained_reply() {
    let mut container = registered();
    let command = append(42);
    let first = entry(2, 10, request(1, &command));
    let Applied::Answered { outcome, .. } = container.apply(&first).unwrap() else {
        panic!("not answered");
    };
    assert_eq!(outcome, Outcome::Applied(&1u64.to_le_bytes()));
    // The retry is a new entry with the same client, epoch and sequence.
    let retry = entry(3, 11, request(1, &command));
    let Applied::Answered { outcome, .. } = container.apply(&retry).unwrap() else {
        panic!("not answered");
    };
    assert_eq!(outcome, Outcome::Retained(&1u64.to_le_bytes()));
    assert_eq!(container.service().values, [42]);
    assert_eq!(container.service().seen, [Seen::Command(2, 7)]);
}

#[test]
fn test_container_a_reply_too_large_keeps_its_effects() {
    let mut container = registered();
    let Applied::Answered { outcome, .. } =
        container.apply(&entry(2, 0, request(1, &[3]))).unwrap()
    else {
        panic!("not answered");
    };
    assert_eq!(outcome, Outcome::ReplyTooLarge);
    assert_eq!(container.service().seen, [Seen::Command(2, 7)]);
}

#[test]
fn test_container_refuses_an_entry_out_of_order_or_not_an_envelope() {
    let mut container = registered();
    assert_eq!(
        container.apply(&entry(3, 0, Envelope::Register { client: 8 })),
        Err(ApplyError::OutOfOrder {
            index: 3,
            last: Some(1)
        })
    );
    let bad = Entry {
        index: 2,
        term: 1,
        event_time: 0,
        payload: vec![2, 1],
    };
    assert_eq!(
        container.apply(&bad),
        Err(ApplyError::Envelope(CodecError::Truncated {
            needed: 12,
            available: 2
        }))
    );
    assert_eq!(container.applied(), Some(1), "nothing was applied");
}

#[test]
fn test_container_the_first_entry_must_be_index_1() {
    let mut container = container();
    assert_eq!(
        container.apply(&entry(2, 0, Envelope::Register { client: 7 })),
        Err(ApplyError::OutOfOrder {
            index: 2,
            last: None
        })
    );
    // An entry 1 that is not an envelope stops the container: entry 2 is
    // not applied past it.
    let bad = Entry {
        index: 1,
        term: 1,
        event_time: 0,
        payload: vec![1, 9],
    };
    assert_eq!(
        container.apply(&bad),
        Err(ApplyError::Envelope(CodecError::Truncated {
            needed: 12,
            available: 2
        }))
    );
    assert_eq!(
        container.apply(&entry(2, 0, Envelope::Register { client: 7 })),
        Err(ApplyError::OutOfOrder {
            index: 2,
            last: None
        })
    );
    assert_eq!(container.applied(), None);
}

#[test]
fn test_container_a_core_entry_delivers_nothing_but_moves_the_log_time() {
    let mut container = registered();
    let empty = Entry {
        index: 2,
        term: 2,
        event_time: 1000,
        payload: Vec::new(),
    };
    assert_eq!(container.apply(&empty), Ok(Applied::Nothing));
    assert_eq!(container.sessions().log_time(), 1000);
    // The session expired at that entry, a TTL after its registration.
    let command = append(1);
    let Applied::Answered { outcome, .. } =
        container.apply(&entry(3, 0, request(1, &command))).unwrap()
    else {
        panic!("not answered");
    };
    assert_eq!(outcome, Outcome::SessionExpired);
    assert!(container.service().seen.is_empty());
}

#[test]
fn test_container_a_timer_fires_only_through_its_entry_and_once() {
    let mut container = registered();
    let command = schedule(5, 100);
    let _ = container
        .apply(&entry(2, 50, request(1, &command)))
        .unwrap();
    assert_eq!(container.timer(5), Some(150));
    assert_eq!(container.due(149).count(), 0, "not due before its deadline");
    let due: Vec<_> = container.due(150).collect();
    assert_eq!(
        due,
        [Envelope::TimerFired {
            timer: 5,
            deadline: 150
        }]
    );
    // Due at the leader, it is delivered only when its entry applies.
    assert_eq!(container.service().seen, [Seen::Command(2, 7)]);
    assert_eq!(
        container.apply(&entry(3, 150, due[0])),
        Ok(Applied::Fired { timer: 5 })
    );
    // A second leader's proposal of the same firing is a no-op.
    assert_eq!(
        container.apply(&entry(4, 160, due[0])),
        Ok(Applied::Nothing)
    );
    assert_eq!(
        container.service().seen,
        [Seen::Command(2, 7), Seen::Timer(3, 5)]
    );
    assert_eq!(container.timer(5), None);
}

#[test]
fn test_container_a_stale_or_early_firing_is_a_no_op() {
    let mut container = registered();
    let first = schedule(5, 100);
    let _ = container.apply(&entry(2, 0, request(1, &first))).unwrap();
    // Rescheduled to 300: the firing for 100 is stale.
    let again = schedule(5, 300);
    let _ = container.apply(&entry(3, 0, request(2, &again))).unwrap();
    let stale = Envelope::TimerFired {
        timer: 5,
        deadline: 100,
    };
    assert_eq!(container.apply(&entry(4, 200, stale)), Ok(Applied::Nothing));
    // At its deadline, but the log time is not there yet.
    let early = Envelope::TimerFired {
        timer: 5,
        deadline: 300,
    };
    assert_eq!(container.apply(&entry(5, 250, early)), Ok(Applied::Nothing));
    assert_eq!(container.timer(5), Some(300));
    assert_eq!(
        container.apply(&entry(6, 300, early)),
        Ok(Applied::Fired { timer: 5 })
    );
}

#[test]
fn test_container_timers_are_bounded() {
    let mut container = registered();
    for (sequence, timer) in [(1, 1), (2, 2), (3, 3)] {
        let command = schedule(timer, 10);
        let _ = container
            .apply(&entry(sequence + 1, 0, request(sequence, &command)))
            .unwrap();
    }
    assert_eq!(container.timer(2), Some(10));
    assert_eq!(container.timer(3), None, "the third did not fit two slots");
}

/// The bound is the configured one, whatever capacity the allocator
/// gave the vector, so every replica refuses the same timer.
#[test]
fn test_container_the_timer_bound_is_the_configured_one() {
    for bound in [1u32, 3, 5, 7] {
        let mut container =
            ServiceContainer::new(Register::default(), config().with_timers(bound)).unwrap();
        let _ = container
            .apply(&entry(1, 0, Envelope::Register { client: 7 }))
            .unwrap();
        for timer in 1..=u64::from(bound) + 1 {
            let command = schedule(timer, 10);
            let _ = container
                .apply(&entry(timer + 1, 0, request(timer, &command)))
                .unwrap();
        }
        let scheduled = (1..=u64::from(bound) + 1)
            .filter(|&timer| container.timer(timer).is_some())
            .count();
        assert_eq!(scheduled, bound as usize, "bound {bound}");
    }
}

#[test]
fn test_container_a_configuration_change_is_delivered_at_its_entry() {
    let mut container = registered();
    let command = append(1);
    let _ = container.apply(&entry(2, 0, request(1, &command))).unwrap();
    assert_eq!(
        container.apply(&entry(3, 0, Envelope::Configuration(b"five nodes"))),
        Ok(Applied::Configured)
    );
    let _ = container.apply(&entry(4, 0, request(2, &command))).unwrap();
    assert_eq!(
        container.service().seen,
        [
            Seen::Command(2, 7),
            Seen::Configuration(3, b"five nodes".to_vec()),
            Seen::Command(4, 7)
        ]
    );
}

/// karyos#686, condition 1: the service is a function of the log. The
/// same entries, applied by 3 and by 5 replicas, give every replica the
/// same state and the same replies.
#[test]
fn test_container_the_same_log_gives_every_replica_the_same_state_and_replies() {
    let mut log = vec![
        entry(1, 0, Envelope::Register { client: 7 }),
        entry(2, 5, Envelope::Register { client: 8 }),
    ];
    let commands: Vec<Vec<u8>> = vec![append(10), schedule(1, 20), append(30), append(10)];
    for (offset, command) in commands.iter().enumerate() {
        let sequence = offset as u64 + 1;
        let index = log.len() as u64 + 1;
        log.push(entry(index, 10 * index, request(sequence, command)));
    }
    log.push(entry(
        7,
        100,
        Envelope::TimerFired {
            timer: 1,
            deadline: 60,
        },
    ));
    log.push(entry(8, 100, request(1, &commands[0])));
    log.push(entry(9, 110, Envelope::Configuration(b"c")));
    for replicas in [3, 5] {
        let runs: Vec<_> = (0..replicas)
            .map(|_| {
                let mut container = container();
                let replies: Vec<String> = log
                    .iter()
                    .map(|entry| format!("{:?}", container.apply(entry).unwrap()))
                    .collect();
                (
                    container.service().clone(),
                    container.sessions().encode(),
                    replies,
                )
            })
            .collect();
        assert!(
            runs.windows(2).all(|pair| pair[0] == pair[1]),
            "{replicas} replicas"
        );
        assert_eq!(runs[0].0.values, [10, 30, 10]);
    }
}
