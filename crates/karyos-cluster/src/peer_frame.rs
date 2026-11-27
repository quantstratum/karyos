// SPDX-License-Identifier: Apache-2.0

//! The peer frame (quantstratum-docs: karyos/adr/0123-cluster-identity.md,
//! decision 3): the envelope every message between a cluster's peers
//! travels in, carrying the sender's cluster identity so a node drops a
//! frame of another cluster before its core sees it. The core's messages
//! are the payload, unchanged.
//!
//! The header, little endian, 48 bytes, then the encoded message:
//!
//! | Bytes | Field |
//! | --- | --- |
//! | 0..4 | magic `KRPF` |
//! | 4..6 | version, 1 |
//! | 6..8 | zero |
//! | 8..40 | the sender's cluster identity |
//! | 40..48 | the sender's node id |
//!
//! [`PeerGate`] is the check a node driver runs before `Core::step`: a
//! frame of another identity, magic or version is dropped and counted,
//! and the first drop of each (sender, identity) is reported once for its
//! log line.

use std::collections::BTreeSet;

use crate::cluster_identity::ClusterId;

/// The header's length.
pub const PEER_HEADER_LEN: usize = 48;
const MAGIC: [u8; 4] = *b"KRPF";
const VERSION: u16 = 1;
/// The (sender, identity) pairs remembered for logging: past it a drop
/// is still counted but not logged, so foreign frames cannot grow it.
pub const LOGGED_PAIRS: usize = 64;

/// The header of a frame from `node` of `cluster`.
#[must_use]
pub fn encode_header(cluster: ClusterId, node: u64) -> [u8; PEER_HEADER_LEN] {
    let mut header = [0u8; PEER_HEADER_LEN];
    let (magic, rest) = header.split_at_mut(4);
    magic.copy_from_slice(&MAGIC);
    let (version, rest) = rest.split_at_mut(2);
    version.copy_from_slice(&VERSION.to_le_bytes());
    let (_, rest) = rest.split_at_mut(2);
    let (identity, sender) = rest.split_at_mut(32);
    identity.copy_from_slice(&cluster.0);
    sender.copy_from_slice(&node.to_le_bytes());
    header
}

/// A frame as read: its sender and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The sender's cluster identity.
    pub cluster: ClusterId,
    /// The sender's node id.
    pub node: u64,
    /// The encoded message.
    pub payload: &'a [u8],
}

/// Why a frame was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameProblem {
    /// Shorter than the header.
    Short,
    /// Another magic, version, or a nonzero reserved field.
    Foreign,
}

/// Reads the header of `bytes`.
///
/// # Errors
///
/// [`FrameProblem`] for bytes that are not a version 1 frame.
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, FrameProblem> {
    let (header, payload) = bytes
        .split_first_chunk::<PEER_HEADER_LEN>()
        .ok_or(FrameProblem::Short)?;
    let (magic, rest) = header.split_at(4);
    let (version, rest) = rest.split_at(2);
    let (reserved, rest) = rest.split_at(2);
    let (identity, sender) = rest.split_at(32);
    if magic != MAGIC || version != VERSION.to_le_bytes() || reserved != [0, 0] {
        return Err(FrameProblem::Foreign);
    }
    let cluster = ClusterId(identity.try_into().map_err(|_| FrameProblem::Short)?);
    let node = u64::from_le_bytes(sender.try_into().map_err(|_| FrameProblem::Short)?);
    Ok(Frame {
        cluster,
        node,
        payload,
    })
}

/// What [`PeerGate::admit`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The frame is of this cluster: step the core with it.
    Admit,
    /// Dropped; the first drop of this (sender, identity), to log.
    DroppedFirst,
    /// Dropped, as before.
    Dropped,
}

/// A node's check of its peers' frames.
#[derive(Debug, Clone)]
pub struct PeerGate {
    own: ClusterId,
    dropped: u64,
    logged: BTreeSet<(u64, ClusterId)>,
}

impl PeerGate {
    /// The gate of a node of `own`.
    #[must_use]
    pub const fn new(own: ClusterId) -> Self {
        Self {
            own,
            dropped: 0,
            logged: BTreeSet::new(),
        }
    }

    /// The node's own identity, which its frames carry.
    #[must_use]
    pub const fn own(&self) -> ClusterId {
        self.own
    }

    /// Whether a frame from `node` carrying `cluster` reaches the core.
    pub fn admit(&mut self, node: u64, cluster: ClusterId) -> Admission {
        if cluster == self.own {
            return Admission::Admit;
        }
        self.dropped = self.dropped.saturating_add(1);
        if self.logged.len() < LOGGED_PAIRS && self.logged.insert((node, cluster)) {
            Admission::DroppedFirst
        } else {
            Admission::Dropped
        }
    }

    /// Whether the frame `bytes` reaches the core, and its payload if so.
    /// A frame that does not decode is dropped and counted too.
    pub fn admit_frame<'a>(&mut self, bytes: &'a [u8]) -> (Admission, Option<Frame<'a>>) {
        match decode(bytes) {
            Ok(frame) => match self.admit(frame.node, frame.cluster) {
                Admission::Admit => (Admission::Admit, Some(frame)),
                other => (other, None),
            },
            Err(_) => {
                self.dropped = self.dropped.saturating_add(1);
                (Admission::Dropped, None)
            }
        }
    }

    /// The frames dropped so far.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: ClusterId = ClusterId([0x11; 32]);
    const REBUILD: ClusterId = ClusterId([0x33; 32]);

    #[test]
    fn a_frame_round_trips_and_its_header_is_the_adr_layout() {
        let header = encode_header(LIVE, 0x0102_0304_0506_0708);
        assert_eq!(&header[..8], b"KRPF\x01\x00\x00\x00");
        assert_eq!(&header[8..40], &[0x11; 32]);
        assert_eq!(&header[40..], &[8, 7, 6, 5, 4, 3, 2, 1]);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(b"msg");
        assert_eq!(
            decode(&bytes),
            Ok(Frame {
                cluster: LIVE,
                node: 0x0102_0304_0506_0708,
                payload: b"msg",
            })
        );
    }

    #[test]
    fn a_frame_not_of_version_1_is_refused() {
        let header = encode_header(LIVE, 1);
        assert_eq!(decode(&header[..47]), Err(FrameProblem::Short));
        for at in [0, 4, 6] {
            let mut bad = header;
            bad[at] ^= 0x40;
            assert_eq!(decode(&bad), Err(FrameProblem::Foreign), "byte {at}");
        }
    }

    #[test]
    fn a_frame_of_another_cluster_is_dropped_counted_and_logged_once() {
        let mut gate = PeerGate::new(LIVE);
        assert_eq!(gate.admit(2, LIVE), Admission::Admit);
        assert_eq!(gate.admit(2, REBUILD), Admission::DroppedFirst);
        assert_eq!(gate.admit(2, REBUILD), Admission::Dropped);
        assert_eq!(gate.admit(3, REBUILD), Admission::DroppedFirst);
        assert_eq!(gate.dropped(), 3);
        let foreign = encode_header(REBUILD, 4);
        assert_eq!(gate.admit_frame(&foreign), (Admission::DroppedFirst, None));
        assert_eq!(gate.admit_frame(b"short"), (Admission::Dropped, None));
        assert_eq!(gate.dropped(), 5);
        let own = encode_header(LIVE, 4);
        assert_eq!(gate.admit_frame(&own).0, Admission::Admit);
    }

    #[test]
    fn the_logged_pairs_are_bounded() {
        let mut gate = PeerGate::new(LIVE);
        for node in 0..200 {
            let _ = gate.admit(node, REBUILD);
        }
        assert_eq!(gate.dropped(), 200);
        assert_eq!(gate.logged.len(), LOGGED_PAIRS);
        assert_eq!(gate.admit(500, REBUILD), Admission::Dropped);
    }
}
