// SPDX-License-Identifier: Apache-2.0

//! The configured receiver roles of a network publication and the receiver
//! identity of a subscription (MC-1, MC-2; owner decisions of 2026-10-21,
//! item 7): what the embedded driver, the client and the CnC command that
//! carries them share (`quantstratum-docs:
//! karyos/design/multicast-flow-control.md`). `karyos_driver::membership`
//! re-exports them.

/// How the optional contribution to a lane's edge is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// The slowest live member's edge (the default).
    Min,
    /// The fastest live member's edge: optional members may lose data.
    Max,
    /// The slowest live member configured with this tag (not 0).
    Tagged(u64),
}

/// A publication's configured receiver roles (MC-1): its strategy, the
/// required `receiver_id`s and the `(receiver_id, tag)` pairs, owned and
/// handed to the sender agent with the publication
/// (`EmbeddedDriver::add_network_publication_with_roles`; owner
/// item 7). Its strategy must be the channel's `fc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRoles {
    /// The strategy.
    pub strategy: Strategy,
    /// The required `receiver_id`s.
    pub required: Vec<u64>,
    /// `(receiver_id, tag)` pairs; a receiver absent here has tag 0.
    pub tags: Vec<(u64, u64)>,
}

impl PublicationRoles {
    /// Whether the roles are well formed: every required `receiver_id`
    /// nonzero and distinct, every tagged `receiver_id` nonzero and
    /// distinct among the pairs, every tag nonzero, and a tagged strategy's
    /// group nonzero. A client checks it before sending
    /// (`cnc`, `AddNetworkPublicationWithRoles`): the CnC decoder refuses a
    /// zero, and the driver a repeat once it has bounded the counts; how
    /// many receivers a membership holds is the driver's check. Each list
    /// is sorted in a copy, so the check is O(n log n).
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let distinct_nonzero = |mut ids: Vec<u64>| {
            ids.sort_unstable();
            ids.first() != Some(&0) && !ids.windows(2).any(|pair| matches!(pair, [a, b] if a == b))
        };
        self.strategy != Strategy::Tagged(0)
            && self.tags.iter().all(|&(_, tag)| tag != 0)
            && distinct_nonzero(self.required.clone())
            && distinct_nonzero(self.tags.iter().map(|&(id, _)| id).collect())
    }

    /// The borrowed roles `Membership::new` takes.
    #[must_use]
    pub fn roles(&self) -> Roles<'_> {
        Roles {
            required: &self.required,
            tags: &self.tags,
        }
    }
}

/// A subscription's receiver identity (MC-1, MC-2): the configured
/// `receiver_id` its images name in every RB block, stable across
/// restarts, and the `group_tag` their SMs declare (0 for none). Without
/// one an image names a `receiver_id` derived from its slot
/// (`EmbeddedDriver::add_network_subscription_as`; owner item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverIdentity {
    /// The configured receiver id.
    pub receiver_id: core::num::NonZeroU64,
    /// The declared group tag.
    pub group_tag: u64,
}

/// The configured roles and tags of an incarnation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Roles<'a> {
    /// The required `receiver_id`s.
    pub required: &'a [u64],
    /// `(receiver_id, tag)` pairs; a receiver absent here has tag 0.
    pub tags: &'a [(u64, u64)],
}
