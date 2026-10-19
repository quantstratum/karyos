// SPDX-License-Identifier: Apache-2.0

//! API v1 over a local Unix socket (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M7; owner item 51,
//! interims 1 to 3: a local socket with the peer's uid checked, a uid to
//! role table, JSON written by hand).
//!
//! - **Where.** `agent.sock` ([`SOCKET_NAME`]) in the API directory, which
//!   is created with mode `0700` or must already be a private directory of
//!   this uid; the socket has mode `0600`. A stale socket (one that
//!   refuses connections) is replaced; a live agent's never is.
//! - **Who.** The peer's uid (`SO_PEERCRED`) is looked up in the role
//!   table; a uid not in it is answered `not authorized`. Every v1 request
//!   reads, so every role may make it; the roles bound the operations M10
//!   adds.
//! - **Exchange.** One request per connection: a line `KARYOS-AGENT
//!   <version> <request>`, at most [`MAX_REQUEST`] bytes. The answer is one
//!   JSON object and a newline, then the agent closes the connection. A
//!   version other than [`API_VERSION`] is answered with the versions
//!   supported (`{"error":"unsupported version","supported":[1]}`), so a
//!   client learns what to ask for. Requests: `view` (the whole
//!   [`AgentView`](crate::api::AgentView)).
//! - **Bounds.** Each connection is served on the calling thread with
//!   [`IO_TIMEOUT`] on its reads and writes, so a slow client delays the
//!   others by that much at most.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::api::API_VERSION;
use crate::{Agent, json};

/// The API socket's name in its directory.
pub const SOCKET_NAME: &str = "agent.sock";
/// The first word of every request.
pub const PROTOCOL: &str = "KARYOS-AGENT";
/// The longest request line, in bytes.
pub const MAX_REQUEST: usize = 256;
/// The read and write timeout of each connection.
pub const IO_TIMEOUT: Duration = Duration::from_millis(100);

/// What an operator may do (SPEC §11, access control). Every API v1
/// request reads, which every role may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// Reads.
    Viewer,
    /// Reads and operates (guards, M10).
    Operator,
    /// An operator who may also reopen guards (M10).
    RiskOfficer,
    /// Everything, the configuration included.
    Administrator,
}

impl Role {
    /// The role named `name`: `viewer`, `operator`, `risk-officer` or
    /// `administrator`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "viewer" => Self::Viewer,
            "operator" => Self::Operator,
            "risk-officer" => Self::RiskOfficer,
            "administrator" => Self::Administrator,
            _ => return None,
        })
    }
}

/// Where the API listens and who may use it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApiConfig {
    /// The API socket's directory.
    pub dir: PathBuf,
    /// The role of each uid allowed to connect.
    pub roles: Vec<(u32, Role)>,
}

impl ApiConfig {
    /// Listening in `dir` for the uids of `roles`.
    #[must_use]
    pub fn new(dir: PathBuf, roles: Vec<(u32, Role)>) -> Self {
        Self { dir, roles }
    }
}

/// Why the API could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The directory is not a private directory of this uid, or its socket
    /// path holds something other than an API socket of this uid.
    #[error("{0}")]
    NotPrivate(&'static str),
    /// Another agent is serving in this directory.
    #[error("a live agent holds {}", .0.display())]
    Live(PathBuf),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What a connection was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Served {
    /// The view.
    View,
    /// A refusal: a uid without a role, a version not served, or a
    /// request not understood.
    Refused,
    /// The client went away, or its request never came within the timeout.
    Dropped,
}

/// The API socket, serving an [`Agent`]'s view.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    roles: Vec<(u32, Role)>,
}

impl Server {
    /// Listens in `config.dir` (see the module).
    ///
    /// # Errors
    ///
    /// [`ServeError`] for a directory that is not private, a live agent's
    /// socket, or a call that fails.
    pub fn bind(config: ApiConfig) -> Result<Self, ServeError> {
        use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
        match std::fs::DirBuilder::new().mode(0o700).create(&config.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let uid = karyos_sys::ipc::own_uid();
        let dir = std::fs::symlink_metadata(&config.dir)?;
        if !dir.is_dir() || dir.uid() != uid || dir.mode() & 0o777 != 0o700 {
            return Err(ServeError::NotPrivate(
                "the API directory is not a private directory of this uid",
            ));
        }
        let path = config.dir.join(SOCKET_NAME);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != uid
                    || metadata.mode() & 0o777 != 0o600
                {
                    return Err(ServeError::NotPrivate(
                        "the API socket path holds something other than an API socket",
                    ));
                }
                match UnixStream::connect(&path) {
                    Ok(_) => return Err(ServeError::Live(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(&path)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path,
            roles: config.roles,
        })
    }

    /// The socket's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serves every pending connection from `agent`'s current view;
    /// returns how each was answered. Never waits for a connection.
    ///
    /// # Errors
    ///
    /// The operating system's error when `accept` fails.
    pub fn poll(&mut self, agent: &Agent) -> Result<Vec<Served>, ServeError> {
        let mut served = Vec::new();
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => served.push(self.serve(stream, agent)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(served)
    }

    /// Answers one connection.
    fn serve(&self, stream: UnixStream, agent: &Agent) -> Served {
        let ready = stream.set_nonblocking(false).is_ok()
            && stream.set_read_timeout(Some(IO_TIMEOUT)).is_ok()
            && stream.set_write_timeout(Some(IO_TIMEOUT)).is_ok();
        if !ready {
            return Served::Dropped;
        }
        let role = karyos_sys::ipc::peer_credentials(stream.as_fd())
            .ok()
            .and_then(|peer| {
                let uid = peer.uid.as_raw();
                self.roles
                    .iter()
                    .find(|(allowed, _)| *allowed == uid)
                    .map(|(_, role)| *role)
            });
        let Some(line) = read_request(&stream) else {
            return Served::Dropped;
        };
        let (answer, served) = match (role, parse(&line)) {
            (None, _) => (json::error("not authorized", None), Served::Refused),
            (Some(_), Request::View) => (json::view(&agent.view()), Served::View),
            (Some(_), Request::Version) => (
                json::error("unsupported version", Some(&[API_VERSION])),
                Served::Refused,
            ),
            (Some(_), Request::Bad) => (json::error("bad request", None), Served::Refused),
        };
        let mut stream = stream;
        let written = stream
            .write_all(answer.as_bytes())
            .and_then(|()| stream.write_all(b"\n"))
            .and_then(|()| stream.flush());
        if written.is_err() {
            return Served::Dropped;
        }
        served
    }
}

impl Drop for Server {
    /// Removes the socket file, so the next agent finds none.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A request line, as the agent understood it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    View,
    /// A well-formed request of another version.
    Version,
    Bad,
}

/// Reads one request line, up to [`MAX_REQUEST`] bytes; `None` when the
/// client sent none in time or closed first.
fn read_request(stream: &UnixStream) -> Option<String> {
    let limit = u64::try_from(MAX_REQUEST).ok()?.checked_add(1)?;
    let mut reader = BufReader::new(stream.take(limit));
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
}

/// `KARYOS-AGENT <version> <request>`, with or without its newline.
fn parse(line: &str) -> Request {
    if line.len() > MAX_REQUEST {
        return Request::Bad;
    }
    let mut words = line.trim_end_matches(['\n', '\r']).split(' ');
    let (Some(PROTOCOL), Some(version), Some(request), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        return Request::Bad;
    };
    match version.parse::<u32>() {
        Ok(API_VERSION) => match request {
            "view" => Request::View,
            _ => Request::Bad,
        },
        Ok(_) => Request::Version,
        Err(_) => Request::Bad,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_strictly() {
        assert_eq!(parse("KARYOS-AGENT 1 view\n"), Request::View);
        assert_eq!(parse("KARYOS-AGENT 1 view"), Request::View);
        assert_eq!(parse("KARYOS-AGENT 2 view\n"), Request::Version);
        assert_eq!(parse("KARYOS-AGENT 1 drop\n"), Request::Bad);
        assert_eq!(parse("KARYOS-AGENT 1 view extra\n"), Request::Bad);
        assert_eq!(parse("karyos-agent 1 view\n"), Request::Bad);
        assert_eq!(parse("KARYOS-AGENT x view\n"), Request::Bad);
        assert_eq!(parse(""), Request::Bad);
        let long = format!("KARYOS-AGENT 1 {}", "v".repeat(MAX_REQUEST));
        assert_eq!(parse(&long), Request::Bad);
    }

    #[test]
    fn roles_parse_by_name() {
        assert_eq!(Role::parse("viewer"), Some(Role::Viewer));
        assert_eq!(Role::parse("risk-officer"), Some(Role::RiskOfficer));
        assert_eq!(Role::parse("root"), None);
    }
}
