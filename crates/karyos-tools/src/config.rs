// SPDX-License-Identifier: Apache-2.0

//! The configuration file of `karyosd` (`--config <path>`): the `[io]`
//! table of Karyos SPEC 16.9 and the extension point through which a
//! backend adds its own `[io.<backend>]` table (R-CORE-43;
//! `quantstratum-docs: karyos/design/karyosd-configuration.md`).
//!
//! ```toml
//! [io]
//! backend = "sockets"            # sockets | io_uring | af_xdp | ef_vi | dpdk
//! require = ["kernel-stamps"]    # an endpoint lacking one fails to open
//!
//! [io.sockets]
//! tx_slots = 1024
//! max_queues = 256
//! max_routes = 128
//! ```
//!
//! The file holds only `[io]` and its backend tables; any other key or
//! table is refused, by name. `backend` defaults to `sockets`. A backend is
//! selectable when it is registered in the [`IoSchema`] the driver binary
//! builds: `karyosd` registers [`SocketsBackend`]; `karyosd-native`
//! registers its own backends through [`IoSchema::register`] and reads
//! their tables with [`IoConfig::table`], with no parser of its own. A
//! selection this build does not register is refused, never replaced by
//! another backend: [`ConfigError::UnsupportedBackend`] for a name of SPEC
//! 16.9 ([`Unsupported::NotBuilt`] for `io_uring` and `af_xdp`,
//! [`Unsupported::NativeOnly`] for `ef_vi` and `dpdk`), and
//! [`ConfigError::UnknownBackend`] for any other.
//!
//! Every `[io.<name>]` table of a registered backend is parsed and
//! validated, selected or not, so a mistake in an unused table is found at
//! startup. A table for a backend this build does not register is refused.
//!
//! Running a backend other than sockets needs a daemon generic over its
//! backend (R-CORE-27); until then `karyosd-native` can register and
//! validate its tables, and select nothing else at run time.
//!
//! [`serde`] and [`toml`] are re-exported, so that a backend derives its
//! table against the versions this crate parses with. They are part of
//! this crate's public API: a major version of either is a breaking change
//! of `karyos-tools`. Versioning the schema is R-CORE-33, not this module.

use std::any::Any;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

pub use serde;
pub use toml;

/// The backend names of SPEC 16.9 with what a build that does not
/// register them says of them.
const SPEC_BACKENDS: [(&str, Unsupported); 5] = [
    ("sockets", Unsupported::NotBuilt),
    ("io_uring", Unsupported::NotBuilt),
    ("af_xdp", Unsupported::NotBuilt),
    ("ef_vi", Unsupported::NativeOnly),
    ("dpdk", Unsupported::NativeOnly),
];

/// The keys of `[io]` that are not backend tables.
const IO_KEYS: [&str; 2] = ["backend", "require"];

/// The backend selected when the file names none.
pub const DEFAULT_BACKEND: &str = "sockets";

/// A backend's `[io.<name>]` table: what it registers in an [`IoSchema`].
pub trait IoBackend: 'static {
    /// The table's name under `[io]`, and the value of `backend` that
    /// selects it: lowercase ASCII letters, digits and `_`, starting with a
    /// letter, and neither `backend` nor `require`.
    const NAME: &'static str;

    /// The table, deserialized from `[io.<name>]`. A backend uses
    /// `#[serde(deny_unknown_fields, rename_all = "snake_case")]` (Karyos
    /// SPEC §14), so an unknown key is refused by name.
    type Table: DeserializeOwned + fmt::Debug + PartialEq + Send + Sync + 'static;

    /// Validates a deserialized table beyond its types.
    ///
    /// # Errors
    ///
    /// A [`TableError`] whose key is relative to the table (`max_batch`),
    /// reported as `io.<name>.max_batch`.
    fn validate(table: &Self::Table) -> Result<(), TableError>;

    /// The capability names `[io] require` may hold when this backend is
    /// selected.
    fn capabilities() -> &'static [&'static str];
}

/// A validation failure of one key of a backend table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableError {
    /// The key, relative to the table.
    pub key: String,
    /// What is wrong with its value.
    pub message: String,
}

impl TableError {
    /// A failure of `key`.
    #[must_use]
    pub fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }
}

/// Why a backend name of SPEC 16.9 is not available in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// It is not built into this driver (`io_uring`, `af_xdp`).
    NotBuilt,
    /// It is built only into `karyosd-native` (`ef_vi`, `dpdk`; ADR-0050).
    NativeOnly,
}

/// A configuration file refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file could not be read.
    Read {
        /// The path as given.
        path: String,
        /// The operating system's reason.
        reason: String,
    },
    /// The file is not valid TOML.
    Syntax {
        /// The parser's message, with its line and column.
        message: String,
    },
    /// A key or table the schema does not know (`net`, `io.foo`).
    UnknownKey {
        /// Its path.
        key: String,
    },
    /// A key of `[io]` with a value of the wrong type.
    InvalidValue {
        /// Its path.
        key: String,
        /// The type it needs.
        expected: &'static str,
    },
    /// `backend` names no backend of SPEC 16.9 and none registered.
    UnknownBackend {
        /// The name.
        name: String,
        /// The backends this build has.
        available: Vec<&'static str>,
    },
    /// `backend` or a table names a backend of SPEC 16.9 this build does
    /// not have.
    UnsupportedBackend {
        /// The name.
        name: String,
        /// Why it is missing.
        reason: Unsupported,
        /// The backends this build has.
        available: Vec<&'static str>,
    },
    /// `require` names a capability the selected backend does not know.
    UnknownCapability {
        /// The selected backend.
        backend: String,
        /// The name.
        name: String,
    },
    /// A backend's table did not deserialize or validate.
    Table {
        /// The key's path (`io.sockets.tx_slots`), or the table's when the
        /// failure is in its types (the message then shows the key).
        key: String,
        /// What is wrong.
        message: String,
    },
    /// The file or the command line configures `[io]` while the network
    /// is off: nothing would read it.
    NetworkOff,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, reason } => write!(f, "cannot read {path}: {reason}"),
            Self::Syntax { message } => write!(f, "invalid TOML: {message}"),
            Self::UnknownKey { key } => write!(f, "unknown key {key}"),
            Self::InvalidValue { key, expected } => write!(f, "{key} must be {expected}"),
            Self::UnknownBackend { name, available } => write!(
                f,
                "unknown io backend {name:?}; this driver has {}",
                available.join(", ")
            ),
            Self::UnsupportedBackend {
                name,
                reason,
                available,
            } => {
                let why = match reason {
                    Unsupported::NotBuilt => "is not built into this driver",
                    Unsupported::NativeOnly => "needs karyosd-native",
                };
                write!(
                    f,
                    "io backend {name:?} {why}; this driver has {}",
                    available.join(", ")
                )
            }
            Self::UnknownCapability { backend, name } => {
                write!(
                    f,
                    "io.require: backend {backend} knows no capability {name:?}"
                )
            }
            Self::Table { key, message } => write!(f, "{key}: {message}"),
            Self::NetworkOff => write!(f, "the io configuration needs --network on"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A backend refused by [`IoSchema::register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// A backend of that name is registered already.
    Duplicate(&'static str),
    /// The name is not a valid table name, or is a key of `[io]`.
    InvalidName(&'static str),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(f, "io backend {name:?} is registered twice"),
            Self::InvalidName(name) => write!(f, "{name:?} is not a valid io backend name"),
        }
    }
}

impl std::error::Error for RegisterError {}

/// One registered backend.
#[derive(Clone, Copy)]
struct Registered {
    name: &'static str,
    capabilities: fn() -> &'static [&'static str],
    load: fn(&str) -> Result<Option<LoadedTable>, ConfigError>,
}

/// The backends a driver binary has, whose tables a configuration file
/// may hold.
#[derive(Clone)]
pub struct IoSchema {
    backends: Vec<Registered>,
}

impl fmt::Debug for IoSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.backends.iter().map(|backend| backend.name))
            .finish()
    }
}

impl IoSchema {
    /// No backend: [`IoSchema::register`] adds them.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            backends: Vec::new(),
        }
    }

    /// The core's backends: [`SocketsBackend`].
    #[must_use]
    pub fn core() -> Self {
        Self {
            backends: vec![registered::<SocketsBackend>()],
        }
    }

    /// Adds backend `B`.
    ///
    /// # Errors
    ///
    /// [`RegisterError::InvalidName`] for a name that is not lowercase
    /// ASCII letters, digits and `_` starting with a letter, or is
    /// `backend` or `require`; [`RegisterError::Duplicate`] for a name
    /// registered already.
    pub fn register<B: IoBackend>(&mut self) -> Result<(), RegisterError> {
        if !valid_name(B::NAME) {
            return Err(RegisterError::InvalidName(B::NAME));
        }
        if self.backends.iter().any(|backend| backend.name == B::NAME) {
            return Err(RegisterError::Duplicate(B::NAME));
        }
        self.backends.push(registered::<B>());
        Ok(())
    }

    /// The registered backend names, in registration order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.backends.iter().map(|backend| backend.name).collect()
    }

    /// Reads and checks the configuration file at `path`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] when it cannot be read; otherwise as
    /// [`IoSchema::load`].
    pub fn read(&self, path: &std::path::Path) -> Result<IoConfig, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        self.load(&text)
    }

    /// Checks the configuration file `text`: its keys, the selected
    /// backend and its required capabilities, and every backend table.
    ///
    /// # Errors
    ///
    /// The first [`ConfigError`] found.
    pub fn load(&self, text: &str) -> Result<IoConfig, ConfigError> {
        let document: toml::Table = toml::from_str(text).map_err(|error| ConfigError::Syntax {
            message: error.to_string().trim_end().to_owned(),
        })?;
        let mut config = IoConfig::default();
        for (key, value) in &document {
            if key != "io" {
                return Err(ConfigError::UnknownKey { key: key.clone() });
            }
            let Some(io) = value.as_table() else {
                return Err(ConfigError::InvalidValue {
                    key: "io".to_owned(),
                    expected: "a table",
                });
            };
            for (key, value) in io {
                match key.as_str() {
                    "backend" => {
                        config.backend = value
                            .as_str()
                            .ok_or(ConfigError::InvalidValue {
                                key: "io.backend".to_owned(),
                                expected: "a string",
                            })?
                            .to_owned();
                    }
                    "require" => config.require = Some(require(value)?),
                    name => {
                        if !self.backends.iter().any(|backend| backend.name == name) {
                            return Err(self.missing(name, format!("io.{name}")));
                        }
                    }
                }
            }
        }
        for backend in &self.backends {
            if let Some(table) = (backend.load)(text)? {
                config.tables.push(table);
            }
        }
        self.check(&config)?;
        Ok(config)
    }

    /// Checks `config`'s selection and required capabilities against the
    /// backends: [`IoSchema::load`] does on the file, and the daemon again
    /// after the command line overrides them.
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnknownBackend`], [`ConfigError::UnsupportedBackend`]
    /// or [`ConfigError::UnknownCapability`].
    pub fn check(&self, config: &IoConfig) -> Result<(), ConfigError> {
        let Some(backend) = self
            .backends
            .iter()
            .find(|backend| backend.name == config.backend)
        else {
            return Err(self.missing(&config.backend, config.backend.clone()));
        };
        let known = (backend.capabilities)();
        if let Some(name) = config
            .require()
            .iter()
            .find(|name| !known.contains(&name.as_str()))
        {
            return Err(ConfigError::UnknownCapability {
                backend: config.backend.clone(),
                name: name.clone(),
            });
        }
        Ok(())
    }

    /// The error for a backend `name` this schema does not register, met
    /// at `key`: unsupported for a name of SPEC 16.9, unknown otherwise.
    fn missing(&self, name: &str, key: String) -> ConfigError {
        let available = self.names();
        match SPEC_BACKENDS.iter().find(|(spec, _)| *spec == name) {
            Some(&(_, reason)) => ConfigError::UnsupportedBackend {
                name: name.to_owned(),
                reason,
                available,
            },
            None if key.starts_with("io.") => ConfigError::UnknownKey { key },
            None => ConfigError::UnknownBackend {
                name: name.to_owned(),
                available,
            },
        }
    }
}

/// `[io] require`: an array of strings.
fn require(value: &toml::Value) -> Result<Vec<String>, ConfigError> {
    let invalid = || ConfigError::InvalidValue {
        key: "io.require".to_owned(),
        expected: "an array of strings",
    };
    value
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|name| name.as_str().map(str::to_owned).ok_or_else(invalid))
        .collect()
}

/// Whether `name` may name a backend table.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !IO_KEYS.contains(&name)
}

fn registered<B: IoBackend>() -> Registered {
    Registered {
        name: B::NAME,
        capabilities: B::capabilities,
        load: load_table::<B>,
    }
}

/// Deserializes and validates `[io.<B::NAME>]` of `text`, if present. The
/// whole document is deserialized, every other key skipped, so that an
/// error carries its line and column.
fn load_table<B: IoBackend>(text: &str) -> Result<Option<LoadedTable>, ConfigError> {
    let table_key = format!("io.{}", B::NAME);
    let Only(table) = toml::from_str::<Only<B>>(text).map_err(|error| ConfigError::Table {
        key: table_key.clone(),
        message: error.to_string().trim_end().to_owned(),
    })?;
    let Some(table) = table else {
        return Ok(None);
    };
    B::validate(&table).map_err(|error| ConfigError::Table {
        key: format!("{table_key}.{}", error.key),
        message: error.message,
    })?;
    Ok(Some(LoadedTable {
        name: B::NAME,
        value: Arc::new(table),
    }))
}

/// The document deserialized for `[io.<B::NAME>]` alone.
struct Only<B: IoBackend>(Option<B::Table>);

impl<'de, B: IoBackend> Deserialize<'de> for Only<B> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(Pick::<B>(Level::Document, PhantomData))
    }
}

/// Where [`Pick`] is: the document, or `[io]`.
#[derive(Clone, Copy)]
enum Level {
    Document,
    Io,
}

/// Visits a map and deserializes only the key that leads to
/// `[io.<B::NAME>]`.
struct Pick<B: IoBackend>(Level, PhantomData<B>);

impl<'de, B: IoBackend> Visitor<'de> for Pick<B> {
    type Value = Only<B>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a table")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = None;
        while let Some(key) = map.next_key::<String>()? {
            match (self.0, key.as_str()) {
                (Level::Document, "io") => found = map.next_value::<IoOnly<B>>()?.0.0,
                (Level::Io, name) if name == B::NAME => found = Some(map.next_value()?),
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Only(found))
    }
}

/// `[io]` deserialized for `[io.<B::NAME>]` alone.
struct IoOnly<B: IoBackend>(Only<B>);

impl<'de, B: IoBackend> Deserialize<'de> for IoOnly<B> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_map(Pick::<B>(Level::Io, PhantomData))
            .map(IoOnly)
    }
}

/// A backend table, type-erased so that the configuration stays a value.
trait ErasedTable: Any + fmt::Debug + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn equals(&self, other: &dyn ErasedTable) -> bool;
}

impl<T: Any + fmt::Debug + PartialEq + Send + Sync> ErasedTable for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equals(&self, other: &dyn ErasedTable) -> bool {
        other.as_any().downcast_ref::<T>() == Some(self)
    }
}

/// One deserialized and validated backend table.
#[derive(Debug, Clone)]
struct LoadedTable {
    name: &'static str,
    value: Arc<dyn ErasedTable>,
}

impl PartialEq for LoadedTable {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.value.equals(other.value.as_ref())
    }
}

impl Eq for LoadedTable {}

/// A checked configuration: the selected backend, the required
/// capabilities and the backend tables the file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoConfig {
    backend: String,
    require: Option<Vec<String>>,
    tables: Vec<LoadedTable>,
}

impl Default for IoConfig {
    /// No file: [`DEFAULT_BACKEND`], nothing required, no table.
    fn default() -> Self {
        Self {
            backend: DEFAULT_BACKEND.to_owned(),
            require: None,
            tables: Vec::new(),
        }
    }
}

impl IoConfig {
    /// The selected backend.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// The capabilities every endpoint must have active: an endpoint that
    /// lacks one fails to open, at startup or at the first add that opens
    /// it.
    #[must_use]
    pub fn require(&self) -> &[String] {
        self.require.as_deref().unwrap_or_default()
    }

    /// Backend `B`'s table, if the file holds it.
    #[must_use]
    pub fn table<B: IoBackend>(&self) -> Option<&B::Table> {
        self.tables
            .iter()
            .find(|table| table.name == B::NAME)
            .and_then(|table| table.value.as_any().downcast_ref::<B::Table>())
    }

    /// Selects `backend` (`--io-backend`).
    pub fn set_backend(&mut self, backend: String) {
        self.backend = backend;
    }

    /// Replaces the required capabilities (`--io-require`).
    pub fn set_require(&mut self, require: Vec<String>) {
        self.require = Some(require);
    }

    /// Whether it configures anything beyond the defaults: a table, a
    /// backend other than the default or a `require` list.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.backend != DEFAULT_BACKEND || self.require.is_some() || !self.tables.is_empty()
    }
}

/// The core's sockets backend (SPEC 16.6), registered by
/// [`IoSchema::core`].
#[derive(Debug, Clone, Copy)]
pub struct SocketsBackend;

/// `[io.sockets]`: the tables of every endpoint the driver opens
/// (`NetworkConfig::endpoint_tables`); an absent key keeps its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SocketsTable {
    /// TX slots, 1 to 4096.
    pub tx_slots: Option<u16>,
    /// TX queues, 1 to 1024.
    pub max_queues: Option<u16>,
    /// Routes, 1 to 1024.
    pub max_routes: Option<u16>,
}

/// The capability names of the sockets backend, in the order of
/// `karyos_io::backend::Capability`.
const SOCKETS_CAPABILITIES: [&str; 12] = [
    "dont-fragment",
    "tx-batch",
    "rx-batch",
    "gso",
    "gro",
    "kernel-stamps",
    "hardware-stamps",
    "busy-poll",
    "user-observations",
    "send-buffer",
    "recv-buffer",
    "path-mtu",
];

impl IoBackend for SocketsBackend {
    const NAME: &'static str = "sockets";
    type Table = SocketsTable;

    fn validate(table: &SocketsTable) -> Result<(), TableError> {
        for (key, value, max) in [
            ("tx_slots", table.tx_slots, 4096),
            ("max_queues", table.max_queues, 1024),
            ("max_routes", table.max_routes, 1024),
        ] {
            if let Some(value) = value
                && !(1..=max).contains(&value)
            {
                return Err(TableError::new(
                    key,
                    format!("{value} is outside 1 to {max}"),
                ));
            }
        }
        Ok(())
    }

    fn capabilities() -> &'static [&'static str] {
        &SOCKETS_CAPABILITIES
    }
}

/// The capability a sockets capability name stands for.
#[must_use]
pub fn sockets_capability(name: &str) -> Option<karyos_io::backend::Capability> {
    use karyos_io::backend::Capability;

    let capability = match name {
        "dont-fragment" => Capability::DontFragment,
        "tx-batch" => Capability::TxBatch,
        "rx-batch" => Capability::RxBatch,
        "gso" => Capability::Gso,
        "gro" => Capability::Gro,
        "kernel-stamps" => Capability::KernelStamps,
        "hardware-stamps" => Capability::HardwareStamps,
        "busy-poll" => Capability::BusyPoll,
        "user-observations" => Capability::UserObservations,
        "send-buffer" => Capability::SendBuffer,
        "recv-buffer" => Capability::RecvBuffer,
        "path-mtu" => Capability::PathMtu,
        _ => return None,
    };
    Some(capability)
}

#[cfg(test)]
mod tests;
