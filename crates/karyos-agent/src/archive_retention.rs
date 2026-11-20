// SPDX-License-Identifier: Apache-2.0

//! The agent's retention backend over a running Archive (ADR-0088,
//! Proposed; karyos#967): [`ArchiveRetention`] implements
//! [`RetentionBackend`] with the Archive's control templates 6 to 9 and
//! 104, through `karyos_archive::client::retention`.
//!
//! - **One connection per operation.** Each call connects to the driver
//!   that hosts the Archive, opens its control streams, sends the one
//!   request, waits for its answer within [`ArchiveRetention::deadline`],
//!   and closes, as a guard operation's one-command client does: the agent
//!   holds no client slot between operations. The calls run on
//!   [`crate::retention`]'s worker, never on the polling thread.
//! - **Verbatim.** A refusal carries the Archive's wire code and its
//!   message; a range carries the verifier's outcome and reason names. A
//!   hold answered code 6 or 7 is done without evidence.
//! - **Purges.** The request id is the agent's operation id. The codec
//!   names an operator of 0 no operator, so a purge for uid 0 (root) is
//!   refused here, code 4 (`invalid request`), and never sent.
//! - **A verification the Archive refuses** has no ranges to report:
//!   [`RetentionBackend::verify`] then answers `None`, as for no answer.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
use karyos_archive::client::retention::{RetentionPoll, RetentionRequest, RetentionRequester};
use karyos_archive::control::ResponseCode;
use karyos_client::{Client, Context};

use crate::catalog::ArchiveStreams;
use crate::retention::{RangeOutcome, RetentionBackend, RetentionReply};

/// The correlation ids' client id of the retention requests: apart from
/// the catalog lister's.
pub const RETENTION_CLIENT_ID: u32 = 0x4b52_5452;
/// The default wait for one operation's answer, connection included.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);
/// How long it sleeps between polls while it waits.
const TICK: Duration = Duration::from_millis(1);

/// The wire code a refusal of the agent's own carries: invalid request.
const INVALID_REQUEST: u64 = 4;

/// The Archive hosted by the driver in `dir`, reached on `streams`.
#[derive(Debug, Clone)]
pub struct ArchiveRetention {
    dir: PathBuf,
    streams: ArchiveStreams,
    deadline: Duration,
}

impl ArchiveRetention {
    /// The Archive of the driver in `dir`, on its control `streams`.
    #[must_use]
    pub fn new(dir: PathBuf, streams: ArchiveStreams) -> Self {
        Self {
            dir,
            streams,
            deadline: DEFAULT_DEADLINE,
        }
    }

    /// With `deadline` for each operation.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Its deadline per operation.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Sends `request` on a connection of its own and waits for the answer
    /// within the deadline: `None` when none came.
    fn ask(&self, request: RetentionRequest) -> Option<RetentionPoll> {
        let start = Instant::now();
        let context = Context::builder()
            .dir(&self.dir)
            .timeout(self.deadline)
            .build()
            .ok()?;
        let mut client = Client::connect(context).ok()?;
        let connection = ArchiveConnection::open(
            &mut client,
            ControlStreams::new(self.streams.requests, self.streams.responses),
        )
        .ok()?;
        let (requests, responses) = connection.into_transports();
        let mut requester = RetentionRequester::new(RETENTION_CLIENT_ID, requests, responses);
        requester.start(request);
        let answer = loop {
            let _ = client.poll();
            match requester.poll() {
                RetentionPoll::Pending => {}
                done => break Some(done),
            }
            if start.elapsed() >= self.deadline {
                break None;
            }
            std::thread::sleep(TICK);
        };
        let (requests, responses) = requester.into_transports();
        requests.close(&mut client);
        responses.close(&mut client);
        answer
    }

    fn reply(&self, request: RetentionRequest) -> RetentionReply {
        match self.ask(request) {
            Some(RetentionPoll::Answered { code, message, .. }) => match code {
                ResponseCode::Ok => RetentionReply::Done { evidenced: true },
                ResponseCode::HeldWithoutEvidence | ResponseCode::HeldInMemoryOnly => {
                    RetentionReply::Done { evidenced: false }
                }
                code => RetentionReply::Refused {
                    code: u64::from(code.code()),
                    reason: message,
                },
            },
            Some(RetentionPoll::Invalid) => RetentionReply::Refused {
                code: INVALID_REQUEST,
                reason: "the request does not encode".to_owned(),
            },
            _ => RetentionReply::NoAnswer,
        }
    }
}

impl RetentionBackend for ArchiveRetention {
    fn hold(&mut self, recording: u64, _operation: u64, _operator: u32) -> RetentionReply {
        self.reply(RetentionRequest::Hold { recording })
    }

    fn release(&mut self, recording: u64, _operation: u64, _operator: u32) -> RetentionReply {
        self.reply(RetentionRequest::Release { recording })
    }

    fn purge(
        &mut self,
        recording: u64,
        before: u64,
        operation: u64,
        operator: u32,
    ) -> RetentionReply {
        if operator == 0 || operation == 0 {
            return RetentionReply::Refused {
                code: INVALID_REQUEST,
                reason: "operator 0 cannot be named to the Archive".to_owned(),
            };
        }
        self.reply(RetentionRequest::Purge {
            recording,
            before,
            request_id: operation,
            operator: u64::from(operator),
        })
    }

    fn verify(&mut self, recording: u64) -> Option<Vec<RangeOutcome>> {
        match self.ask(RetentionRequest::Verify { recording })? {
            RetentionPoll::Verified { ranges, .. } => Some(
                ranges
                    .iter()
                    .map(|range| RangeOutcome {
                        start: range.start,
                        end: range.end,
                        outcome: range.outcome.name().to_owned(),
                        reasons: range.reason_names().map(str::to_owned).collect(),
                    })
                    .collect(),
            ),
            _ => None,
        }
    }
}
