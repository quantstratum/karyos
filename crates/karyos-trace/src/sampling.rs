// SPDX-License-Identifier: Apache-2.0

//! Trace sampling (SPEC.md §7.3; design in `quantstratum-docs: karyos/design/trace-sampling.md`).
//!
//! A publication decides once per logical message whether to trace it; the
//! decision is the presence of `EXT`, which every downstream observer
//! follows without sampling again. Roots (messages with no incoming trace
//! context) follow the policy's cadence; children of a traced message keep
//! the incoming choice unless the publication's policy is `Off`.
//!
//! The sampler allocates nothing. Identifiers that must be unique beyond
//! one publication (trace and span ids) come from the owner's [`IdSource`],
//! called only for messages decided traced, once per identifier, never
//! retried. The message id is the publication's own counter.

use core::num::NonZeroU32;

use crate::record::TraceIds;

/// A publication's sampling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    /// Trace nothing this publication creates.
    Off,
    /// Trace the first root and then one root in `n`; `Sampled(1)` behaves
    /// like `All`.
    Sampled(NonZeroU32),
    /// Trace every root.
    All,
}

/// Bounded source of random identifiers, owned by the sampler's owner.
///
/// Both methods run on the publication path: they must not allocate, block,
/// make system calls or reseed (for example, read from a buffer refilled off
/// the path). Outputs must be independent and uniform across every source,
/// publication and driver restart; copying, resetting or replaying a
/// generator's state voids the collision bounds of the design.
pub trait IdSource {
    /// A fresh 128-bit trace id, or `None` when none is available now.
    fn trace_id(&mut self) -> Option<[u64; 2]>;
    /// A fresh 64-bit span id, or `None` when none is available now.
    fn span_id(&mut self) -> Option<u64>;
}

/// The outcome of one sampling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Not traced: publish without `EXT`.
    Untraced,
    /// Traced: publish with these ids in `EXT`, on every fragment and every
    /// retry of this message.
    Traced(TraceIds),
    /// Selected, but the id source had no usable identifier (unavailable,
    /// zero, or a child span equal to its parent's): published untraced.
    IdsUnavailable,
    /// The publication's message ids are exhausted: no further message is
    /// traced.
    MessageIdsExhausted,
}

/// Per-publication sampler: the policy, the cadence residue and the message
/// id counter.
#[derive(Debug, Clone)]
pub struct Sampler {
    policy: Sampling,
    /// Root decisions since the policy was set, modulo `n`.
    residue: u32,
    /// The next message id; starts at 1 and never repeats.
    next_message: u64,
}

impl Sampler {
    /// A sampler for a new publication incarnation.
    #[must_use]
    pub fn new(policy: Sampling) -> Self {
        Self {
            policy,
            residue: 0,
            next_message: 1,
        }
    }

    /// A sampler that continues an incarnation from its message-id
    /// high-water mark (the next message id it may assign, at least 1).
    /// Owner precondition: one sampler owns an incarnation's counter at a
    /// time.
    #[must_use]
    pub fn resume(policy: Sampling, next_message: u64) -> Self {
        Self {
            policy,
            residue: 0,
            next_message: next_message.max(1),
        }
    }

    /// The next message id this sampler may assign (its high-water mark).
    #[must_use]
    pub fn next_message_id(&self) -> u64 {
        self.next_message
    }

    /// The current policy.
    #[must_use]
    pub fn policy(&self) -> Sampling {
        self.policy
    }

    /// Sets the policy for later decisions. Decisions already made keep
    /// their outcome; the cadence restarts (its first root is traced unless
    /// the policy is `Off`); the message-id counter is kept.
    pub fn set_policy(&mut self, policy: Sampling) {
        self.policy = policy;
        self.residue = 0;
    }

    /// Decides one logical message, created now. `incoming` is the trace
    /// context of the message that caused it, if any; a context with a zero
    /// `trace_id` is no context. Call once per message and reuse the result
    /// for every fragment and retry.
    pub fn decide(&mut self, incoming: Option<TraceIds>, ids: &mut impl IdSource) -> Decision {
        match incoming.filter(|context| context.trace_id != [0, 0]) {
            Some(parent) => self.child(parent, ids),
            None => self.root(ids),
        }
    }

    /// Whether the cadence selects this root; consumes its slot.
    fn select_root(&mut self) -> bool {
        match self.policy {
            Sampling::Off => false,
            Sampling::All => true,
            Sampling::Sampled(n) => {
                let selected = self.residue == 0;
                self.residue = (self.residue + 1) % n.get();
                selected
            }
        }
    }

    /// Takes the next message id, if any is left.
    fn message_id(&mut self) -> Option<u64> {
        let id = self.next_message;
        self.next_message = id.checked_add(1)?;
        Some(id)
    }

    fn root(&mut self, ids: &mut impl IdSource) -> Decision {
        if !self.select_root() {
            return Decision::Untraced;
        }
        if self.next_message.checked_add(1).is_none() {
            return Decision::MessageIdsExhausted;
        }
        let Some(trace_id) = ids.trace_id().filter(|id| *id != [0, 0]) else {
            return Decision::IdsUnavailable;
        };
        let Some(span_id) = ids.span_id().filter(|id| *id != 0) else {
            return Decision::IdsUnavailable;
        };
        match self.message_id() {
            Some(message_id) => Decision::Traced(TraceIds {
                trace_id,
                span_id,
                parent_span_id: 0,
                message_id,
            }),
            None => Decision::MessageIdsExhausted,
        }
    }

    fn child(&mut self, parent: TraceIds, ids: &mut impl IdSource) -> Decision {
        if self.policy == Sampling::Off {
            return Decision::Untraced;
        }
        if self.next_message.checked_add(1).is_none() {
            return Decision::MessageIdsExhausted;
        }
        let Some(span_id) = ids
            .span_id()
            .filter(|id| *id != 0 && (parent.span_id == 0 || *id != parent.span_id))
        else {
            return Decision::IdsUnavailable;
        };
        match self.message_id() {
            Some(message_id) => Decision::Traced(TraceIds {
                trace_id: parent.trace_id,
                span_id,
                parent_span_id: parent.span_id,
                message_id,
            }),
            None => Decision::MessageIdsExhausted,
        }
    }
}

#[cfg(test)]
mod tests;
