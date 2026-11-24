// SPDX-License-Identifier: Apache-2.0

//! Endpoint configuration, its provisional defaults and the capability
//! snapshot (`quantstratum-docs: karyos/design/sockets-backend.md` 3.8,
//! 5.1 and 8.1).
//!
//! The defaults are the section 5.1 values, the RX budget of 64 datagrams
//! and the multicast TTL of 1; decision O-4 made them provisional and
//! configurable, so every one is a field of [`SocketsConfig`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use crate::backend::{
    BackendEpoch, Budget, Capability, CapabilityState, ClockDomain, ClockEpoch, InstanceId,
    OpenError, PathId, Reason,
};

/// `NonZeroU16` from a literal of these constants; never zero.
const fn nz16(value: u16) -> NonZeroU16 {
    match NonZeroU16::new(value) {
        Some(value) => value,
        None => NonZeroU16::MIN,
    }
}

/// `NonZeroU32` from a literal of these constants; never zero.
const fn nz32(value: u32) -> NonZeroU32 {
    match NonZeroU32::new(value) {
        Some(value) => value,
        None => NonZeroU32::MIN,
    }
}

/// The largest `max_batch`: the length of the stack arrays of one flush.
pub const SOCKETS_MAX_BATCH: u16 = 64;
/// [`SOCKETS_MAX_BATCH`] as an array length. A `const` cannot call
/// `usize::from`, and SPEC §14 rules out an `as` cast, so both literals are
/// pinned to the same value at compile time below.
pub(crate) const SOCKETS_MAX_BATCH_LEN: usize = 64;
const _: () = assert!(SOCKETS_MAX_BATCH == 64 && SOCKETS_MAX_BATCH_LEN == 64);
/// The smallest `max_datagram`: the syntax floor of the channel `mtu`.
pub const MIN_DATAGRAM: u16 = 256;
/// The largest `max_datagram`: the jumbo channel `mtu`.
pub const MAX_DATAGRAM: u16 = 8192;
/// The largest `tx_slots`.
pub const MAX_TX_SLOTS: u16 = 4096;
/// The largest `max_queues` and `max_routes`.
pub const MAX_TABLE_ENTRIES: u16 = 1024;
/// The largest `send_buffer` and `recv_buffer` request: `SO_SNDBUF` and
/// `SO_RCVBUF` take a C `int` on Linux and macOS, so a larger request
/// cannot reach the kernel and is refused by [`SocketsConfig::validate`]
/// rather than set to some other size. Equal to `c_int::MAX`, pinned
/// below without a cast.
pub const MAX_BUFFER_REQUEST: u32 = 0x7FFF_FFFF;
const _: () = assert!(std::ffi::c_int::MAX == 0x7FFF_FFFF);

/// Provisional default `max_datagram` (O-4): the default channel `mtu`.
pub const DEFAULT_MAX_DATAGRAM: NonZeroU16 = nz16(1408);
/// Provisional default `tx_slots` (O-4).
pub const DEFAULT_TX_SLOTS: NonZeroU16 = nz16(256);
/// Provisional default `max_queues` (O-4).
pub const DEFAULT_MAX_QUEUES: NonZeroU16 = nz16(64);
/// Provisional default `max_routes` (O-4).
pub const DEFAULT_MAX_ROUTES: NonZeroU16 = nz16(64);
/// Provisional default `max_batch` (O-4).
pub const DEFAULT_MAX_BATCH: NonZeroU16 = nz16(32);
/// Provisional default send buffer request, 1 MiB (O-4).
pub const DEFAULT_SEND_BUFFER: NonZeroU32 = nz32(1 << 20);
/// Provisional default receive buffer request, 4 MiB (O-4).
pub const DEFAULT_RECV_BUFFER: NonZeroU32 = nz32(4 << 20);
/// Provisional default datagrams of one `poll_rx` call (O-4).
pub const DEFAULT_RX_BUDGET_DATAGRAMS: u32 = 64;
/// Provisional default multicast TTL or hop limit (O-4).
pub const DEFAULT_MULTICAST_TTL: u8 = 1;
/// Provisional default memory cap of the endpoint's pools, 16 MiB. Section
/// 4.5 checks the pools against "the configured memory cap" but 5.1 gives
/// no default, so this value is a proposal like the O-4 defaults: it holds
/// the default pool (360,448 bytes) and a jumbo pool of 256 slots (2 MiB)
/// with room to spare, and makes the largest pool (4096 slots of 8192
/// bytes, 32 MiB) an explicit choice.
pub const DEFAULT_MEMORY_CAP: NonZeroU64 = match NonZeroU64::new(16 << 20) {
    Some(value) => value,
    None => NonZeroU64::MIN,
};

/// The protection profile of the endpoint's datagrams (5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protection {
    /// The trusted profile of ADR-0035: the UDP payload is exactly the
    /// Karyos frames. The only profile this backend opens.
    #[default]
    Trusted,
    /// An authenticated envelope. Fails with
    /// [`OpenError::ProtectionUnavailable`] until decision 5 defines the
    /// envelope and its accounting.
    Authenticated,
}

/// The interface of a multicast membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceSel {
    /// An IPv4 interface address.
    Address(Ipv4Addr),
    /// An interface index (IPv4 or IPv6).
    Index(u32),
}

/// One multicast group of the endpoint (one per endpoint, 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastConfig {
    /// The group; it must be a multicast address of the local family.
    pub group: IpAddr,
    /// The interface that joins and sends.
    pub interface: InterfaceSel,
    /// TTL (IPv4) or hop limit (IPv6) of sent datagrams.
    pub ttl: u8,
    /// Whether this host's own sends loop back to its receivers.
    pub loopback: bool,
}

impl MulticastConfig {
    /// `group` on `interface` with the default TTL of
    /// [`DEFAULT_MULTICAST_TTL`] and loopback off.
    #[must_use]
    pub const fn new(group: IpAddr, interface: InterfaceSel) -> Self {
        Self {
            group,
            interface,
            ttl: DEFAULT_MULTICAST_TTL,
            loopback: false,
        }
    }
}

/// A set of [`Capability`] values: the capabilities a configuration
/// requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CapabilitySet(u16);

/// Every capability, in declaration order; its position is its bit.
const ALL_CAPABILITIES: [Capability; 14] = [
    Capability::DontFragment,
    Capability::TxBatch,
    Capability::RxBatch,
    Capability::Gso,
    Capability::Gro,
    Capability::KernelStamps,
    Capability::HardwareStamps,
    Capability::BusyPoll,
    Capability::UserObservations,
    Capability::SendBuffer,
    Capability::RecvBuffer,
    Capability::PathMtu,
    Capability::UringRing,
    Capability::XdpSocket,
];

const fn bit(capability: Capability) -> u16 {
    let shift = match capability {
        Capability::DontFragment => 0,
        Capability::TxBatch => 1,
        Capability::RxBatch => 2,
        Capability::Gso => 3,
        Capability::Gro => 4,
        Capability::KernelStamps => 5,
        Capability::HardwareStamps => 6,
        Capability::BusyPoll => 7,
        Capability::UserObservations => 8,
        Capability::SendBuffer => 9,
        Capability::RecvBuffer => 10,
        Capability::PathMtu => 11,
        Capability::UringRing => 12,
        Capability::XdpSocket => 13,
    };
    1 << shift
}

impl CapabilitySet {
    /// No capability.
    pub const EMPTY: Self = Self(0);

    /// This set plus `capability`.
    #[must_use]
    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | bit(capability))
    }

    /// Whether the set holds `capability`.
    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & bit(capability) != 0
    }

    /// The capabilities of the set, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        ALL_CAPABILITIES
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }
}

/// The configuration of one sockets endpoint (3.8). Every bound of 5.1 is
/// fixed at `open`; [`SocketsConfig::new`] gives the provisional defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketsConfig {
    /// The local address to bind; port 0 lets the kernel choose.
    pub local: SocketAddr,
    /// The receiving path named in every received datagram.
    pub path: PathId,
    /// Karyos frame bytes per datagram: the channel `mtu`, 256..=8192.
    pub max_datagram: NonZeroU16,
    /// TX slots, 1..=4096.
    pub tx_slots: NonZeroU16,
    /// TX queues, 1..=1024.
    pub max_queues: NonZeroU16,
    /// Routes, 1..=1024.
    pub max_routes: NonZeroU16,
    /// Datagrams of one exposure, 1..=[`SOCKETS_MAX_BATCH`].
    pub max_batch: NonZeroU16,
    /// Bytes the TX pool (`tx_slots * max_datagram`) and the RX buffer
    /// (`max_datagram + 1`) may take together (4.5); provisional default
    /// [`DEFAULT_MEMORY_CAP`].
    pub memory_cap: NonZeroU64,
    /// The `SO_SNDBUF` request, if any, up to [`MAX_BUFFER_REQUEST`].
    pub send_buffer: Option<NonZeroU32>,
    /// The `SO_RCVBUF` request, if any, up to [`MAX_BUFFER_REQUEST`].
    pub recv_buffer: Option<NonZeroU32>,
    /// The multicast group, if any.
    pub multicast: Option<MulticastConfig>,
    /// Whether `poll_rx` reads the host monotonic clock after each receive.
    pub rx_observation: bool,
    /// The epoch the driver records for `host_monotonic_ns`, carried by
    /// every observation (3.7).
    pub clock_epoch: ClockEpoch,
    /// Datagrams of the RX budget [`SocketsConfig::rx_budget`] builds.
    pub rx_budget_datagrams: u32,
    /// Capabilities whose absence fails `open`, `reopen` or, for
    /// [`Capability::PathMtu`], `add_route`.
    pub require: CapabilitySet,
    /// The protection profile; [`Protection::Trusted`] only (5.2).
    pub protection: Protection,
    /// The endpoint carries etf queues (ADR-0109 point 5): its socket sets
    /// `SO_REUSEPORT` before it binds, so each etf queue's socket can join
    /// its port. Unicast only: refused with a multicast group.
    pub etf_route: bool,
}

impl SocketsConfig {
    /// A configuration binding `local` with the provisional defaults (O-4).
    #[must_use]
    pub const fn new(local: SocketAddr) -> Self {
        Self {
            local,
            path: PathId::new(0),
            max_datagram: DEFAULT_MAX_DATAGRAM,
            tx_slots: DEFAULT_TX_SLOTS,
            max_queues: DEFAULT_MAX_QUEUES,
            max_routes: DEFAULT_MAX_ROUTES,
            max_batch: DEFAULT_MAX_BATCH,
            memory_cap: DEFAULT_MEMORY_CAP,
            send_buffer: Some(DEFAULT_SEND_BUFFER),
            recv_buffer: Some(DEFAULT_RECV_BUFFER),
            multicast: None,
            rx_observation: false,
            clock_epoch: ClockEpoch::new(0),
            rx_budget_datagrams: DEFAULT_RX_BUDGET_DATAGRAMS,
            require: CapabilitySet::EMPTY,
            protection: Protection::Trusted,
            etf_route: false,
        }
    }

    /// One `poll_rx` budget: `rx_budget_datagrams` datagrams, as many ops
    /// and room for that many datagrams of `max_datagram` bytes. The byte
    /// count is a checked product; `None` when it does not fit `u64`, which
    /// a `u32` count of `u16` sized datagrams (below 2^48) never reaches.
    #[must_use]
    pub fn rx_budget(&self) -> Option<Budget> {
        let bytes =
            u64::from(self.rx_budget_datagrams).checked_mul(u64::from(self.max_datagram.get()))?;
        Some(Budget::new(
            self.rx_budget_datagrams,
            bytes,
            self.rx_budget_datagrams,
        ))
    }

    /// Bytes of the TX pool and the RX buffer, checked (4.5, 5.1).
    fn pool_bytes(&self) -> Option<u64> {
        let datagram = u64::from(self.max_datagram.get());
        let tx = u64::from(self.tx_slots.get()).checked_mul(datagram)?;
        let rx = datagram.checked_add(1)?;
        tx.checked_add(rx)
    }

    /// Checks every bound of 5.1 and the protection profile (5.2), in
    /// field order, then the protection. The pools are checked against
    /// `memory_cap` with checked arithmetic (4.5).
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::InvalidConfig`] with the first field out of
    /// range, or [`OpenError::ProtectionUnavailable`]. For `memory_cap`
    /// the value is the bytes the pools need, which exceed the cap
    /// (`u64::MAX` if that sum overflows, which `u16` sizes cannot reach).
    pub fn validate(&self) -> Result<(), OpenError> {
        let invalid = |field: &'static str, value: u64| OpenError::InvalidConfig { field, value };
        let max_datagram = self.max_datagram.get();
        if !(MIN_DATAGRAM..=MAX_DATAGRAM).contains(&max_datagram) {
            return Err(invalid("max_datagram", u64::from(max_datagram)));
        }
        if self.tx_slots.get() > MAX_TX_SLOTS {
            return Err(invalid("tx_slots", u64::from(self.tx_slots.get())));
        }
        if self.max_queues.get() > MAX_TABLE_ENTRIES {
            return Err(invalid("max_queues", u64::from(self.max_queues.get())));
        }
        if self.max_routes.get() > MAX_TABLE_ENTRIES {
            return Err(invalid("max_routes", u64::from(self.max_routes.get())));
        }
        if self.max_batch.get() > SOCKETS_MAX_BATCH {
            return Err(invalid("max_batch", u64::from(self.max_batch.get())));
        }
        // The TX pool, checked so its size fits `usize` (4.5).
        let pool = usize::from(self.tx_slots.get()).checked_mul(usize::from(max_datagram));
        if pool.is_none() {
            return Err(invalid("tx_slots", u64::from(self.tx_slots.get())));
        }
        match self.pool_bytes() {
            Some(bytes) if bytes <= self.memory_cap.get() => {}
            needed => return Err(invalid("memory_cap", needed.unwrap_or(u64::MAX))),
        }
        // A request the C `int` of the socket option cannot carry. Section
        // 8.3 covers an effective size below a request the kernel took;
        // this request cannot be made at all, so it is a configuration
        // error, not a `BelowRequest` fallback.
        let buffers = [
            ("send_buffer", self.send_buffer),
            ("recv_buffer", self.recv_buffer),
        ];
        for (field, request) in buffers {
            if let Some(request) = request
                && request.get() > MAX_BUFFER_REQUEST
            {
                return Err(invalid(field, u64::from(request.get())));
            }
        }
        if let Some(multicast) = self.multicast {
            let same_family = multicast.group.is_ipv4() == self.local.is_ipv4();
            if !multicast.group.is_multicast() || !same_family {
                return Err(invalid("multicast.group", 0));
            }
            // Multicast delivery is not decided by the reuseport
            // selection that keeps inbound datagrams off the etf socket.
            if self.etf_route {
                return Err(invalid("etf_route", 1));
            }
        }
        if self.protection != Protection::Trusted {
            return Err(OpenError::ProtectionUnavailable);
        }
        Ok(())
    }
}

/// The platform of the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux, through `rustix`.
    Linux,
    /// macOS, through `std::net`.
    MacOs,
}

impl Platform {
    /// The platform of this build.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::MacOs
        }
    }
}

/// The copy mode of the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMode {
    /// Copied staging: C1 to C5 of SPEC.md §16.7.
    Staged,
}

/// How NIC queues are assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueAssignment {
    /// Sockets do not choose NIC queues.
    KernelSelected,
}

/// The observation points an endpoint supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationPoints {
    /// Userspace, after a send call returned. `false` for sockets: no TX
    /// path produces a `SendReturn` observation yet.
    pub send_return: bool,
    /// Userspace, after a receive call returned.
    pub recv_return: bool,
}

/// The clock of the endpoint's observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockInfo {
    /// The clock domain.
    pub domain: ClockDomain,
    /// The clock epoch the driver recorded.
    pub epoch: ClockEpoch,
    /// The reading granularity in ns, at least 1; the `uncertainty_ns` of
    /// every observation. A placeholder of 1 until S3 probes the clock.
    pub granularity_ns: u64,
}

/// A kernel buffer size request and its read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferSize {
    /// The requested size, if any.
    pub requested: Option<NonZeroU32>,
    /// The effective size read back, when the platform reports it.
    pub effective: Option<u32>,
    /// `Active` when the effective size meets the request.
    pub state: CapabilityState,
}

impl BufferSize {
    /// No request: `NotRequested`, size unknown.
    pub const NOT_REQUESTED: Self = Self {
        requested: None,
        effective: None,
        state: CapabilityState::NotRequested,
    };
}

/// The joined multicast group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership {
    /// The group.
    pub group: IpAddr,
    /// The interface that joined.
    pub interface: InterfaceSel,
}

/// The effective capabilities of one epoch (8.1), built at `open` and
/// `reopen` and immutable for the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySnapshot {
    /// The endpoint instance.
    pub instance: InstanceId,
    /// The backend epoch, which is also the capability epoch (A-6).
    pub epoch: BackendEpoch,
    /// Linux or macOS.
    pub platform: Platform,
    /// Staged: C1 to C5.
    pub copy_mode: CopyMode,
    /// The bound local address.
    pub local: SocketAddr,
    /// Index of the interface owning `local`; `None` for a wildcard.
    pub interface: Option<u32>,
    /// Sockets do not choose NIC queues: `KernelSelected`.
    pub queue_assignment: QueueAssignment,
    /// The datagram limit in bytes.
    pub max_datagram: u16,
    /// The points the endpoint observes: `RecvReturn` only in the
    /// baseline (see [`ObservationPoints`]).
    pub observation_points: ObservationPoints,
    /// Domain, epoch and reading granularity of the observation clock.
    pub clock: ClockInfo,
    /// Don't fragment.
    pub dont_fragment: CapabilityState,
    /// TX batching.
    pub tx_batch: CapabilityState,
    /// RX batching.
    pub rx_batch: CapabilityState,
    /// UDP segmentation offload.
    pub gso: CapabilityState,
    /// UDP receive coalescing.
    pub gro: CapabilityState,
    /// Kernel stamps.
    pub kernel_stamps: CapabilityState,
    /// Hardware stamps.
    pub hardware_stamps: CapabilityState,
    /// Busy polling.
    pub busy_poll: CapabilityState,
    /// Userspace observations.
    pub user_observations: CapabilityState,
    /// The send buffer.
    pub send_buffer: BufferSize,
    /// The receive buffer.
    pub recv_buffer: BufferSize,
    /// The joined group.
    pub multicast: Option<Membership>,
    /// `false`: `IP_RECVERR` is not set, so local `ENOBUFS` drops are not
    /// reported (S-9).
    pub enobufs_reported: bool,
}

/// The `LibraryApi` capabilities of the baseline (4.6, decision O-3).
const LIBRARY_API: CapabilityState = CapabilityState::Unavailable(Reason::LibraryApi);

impl CapabilitySnapshot {
    /// Builds the snapshot of `epoch` from the socket's probes.
    pub(crate) fn build(
        config: &SocketsConfig,
        instance: InstanceId,
        epoch: BackendEpoch,
        probes: &super::super::ops::SocketProbes,
    ) -> Self {
        Self {
            instance,
            epoch,
            platform: Platform::current(),
            copy_mode: CopyMode::Staged,
            local: probes.local,
            interface: probes.interface,
            queue_assignment: QueueAssignment::KernelSelected,
            max_datagram: config.max_datagram.get(),
            // No TX path of the baseline reads the clock around a send, so
            // no `SendReturn` observation exists; `RecvReturn` is read when
            // `rx_observation` is set (4.4).
            observation_points: ObservationPoints {
                send_return: false,
                recv_return: true,
            },
            clock: ClockInfo {
                domain: ClockDomain::HostMonotonic,
                epoch: config.clock_epoch,
                // Placeholder: 1 ns until S3 probes the host clock's
                // reading granularity; RX observations carry the same
                // value as `uncertainty_ns`.
                granularity_ns: 1,
            },
            dont_fragment: probes.dont_fragment,
            tx_batch: probes.tx_batch,
            rx_batch: LIBRARY_API,
            gso: LIBRARY_API,
            gro: LIBRARY_API,
            kernel_stamps: LIBRARY_API,
            hardware_stamps: LIBRARY_API,
            busy_poll: LIBRARY_API,
            user_observations: CapabilityState::Active,
            send_buffer: probes.send_buffer,
            recv_buffer: probes.recv_buffer,
            multicast: probes.multicast,
            enobufs_reported: false,
        }
    }

    /// The state of `capability`. [`Capability::PathMtu`] is per route
    /// ([`super::RouteInfo`]); here it is `NotRequested`.
    #[must_use]
    pub const fn state(&self, capability: Capability) -> CapabilityState {
        match capability {
            Capability::DontFragment => self.dont_fragment,
            Capability::TxBatch => self.tx_batch,
            Capability::RxBatch => self.rx_batch,
            Capability::Gso => self.gso,
            Capability::Gro => self.gro,
            Capability::KernelStamps => self.kernel_stamps,
            Capability::HardwareStamps => self.hardware_stamps,
            Capability::BusyPoll => self.busy_poll,
            Capability::UserObservations => self.user_observations,
            Capability::SendBuffer => self.send_buffer.state,
            Capability::RecvBuffer => self.recv_buffer.state,
            Capability::PathMtu => CapabilityState::NotRequested,
            // The sockets backend has no ring.
            Capability::UringRing => CapabilityState::NotRequested,
            Capability::XdpSocket => CapabilityState::NotRequested,
        }
    }

    /// Checks that every capability `require` names, except the per route
    /// path MTU, is `Active` (8.3).
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::RequiredCapability`] for the first required
    /// capability, in declaration order, that is not `Active`.
    pub fn check_required(&self, require: CapabilitySet) -> Result<(), OpenError> {
        for capability in require.iter() {
            if capability == Capability::PathMtu {
                continue;
            }
            let state = self.state(capability);
            if state != CapabilityState::Active {
                return Err(OpenError::RequiredCapability { capability, state });
            }
        }
        Ok(())
    }
}
