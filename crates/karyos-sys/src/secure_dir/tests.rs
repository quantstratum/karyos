// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use super::*;

/// A fresh base directory, mode `0755`, owned by this process.
fn base(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-secure-dir-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("keys")).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(dir.join("keys"), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn put(dir: &Path, name: &str, bytes: &[u8], mode: u32) {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

fn me() -> u32 {
    effective_uid()
}

#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn a_checked_directory_reads_writes_and_lists() {
    let base = base("ok");
    put(&base.join("keys"), "1-1.key", b"abc\n", 0o600);
    let dir = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    let mut buf = [0_u8; 4097];
    assert_eq!(dir.read("1-1.key", &mut buf).unwrap(), 4);
    assert_eq!(buf.get(..4).unwrap(), b"abc\n");
    dir.write_atomic("state", b"one").unwrap();
    dir.write_atomic("state", b"two").unwrap();
    assert_eq!(dir.read("state", &mut buf).unwrap(), 3);
    assert_eq!(buf.get(..3).unwrap(), b"two");
    let mut names = dir.names().unwrap();
    names.sort();
    assert_eq!(names, ["1-1.key", "state"]);
    assert_eq!(dir.read("missing", &mut buf), Err(SecureDirError::NotFound));
    fs::remove_dir_all(&base).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn the_descriptor_survives_a_rename_of_the_path() {
    let base = base("rename");
    let dir = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    fs::rename(base.join("keys"), base.join("moved")).unwrap();
    fs::create_dir(base.join("keys")).unwrap();
    dir.write_atomic("state", b"x").unwrap();
    assert!(base.join("moved/state").exists());
    assert!(!base.join("keys/state").exists());
    fs::remove_dir_all(&base).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn symbolic_links_and_wide_directories_are_refused() {
    let base = base("dirs");
    symlink(base.join("keys"), base.join("link")).unwrap();
    assert_eq!(
        SecureDir::open_beneath(&base, Path::new("link"), me()).unwrap_err(),
        SecureDirError::Symlink
    );
    fs::set_permissions(base.join("keys"), fs::Permissions::from_mode(0o720)).unwrap();
    assert_eq!(
        SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap_err(),
        SecureDirError::Mode
    );
    fs::set_permissions(base.join("keys"), fs::Permissions::from_mode(0o700)).unwrap();
    // A group-writable ancestor fails as well.
    fs::create_dir(base.join("keys/inner")).unwrap();
    fs::set_permissions(base.join("keys"), fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        SecureDir::open_beneath(&base, Path::new("keys/inner"), me()).unwrap_err(),
        SecureDirError::Mode
    );
    fs::set_permissions(base.join("keys"), fs::Permissions::from_mode(0o700)).unwrap();
    // Another owner: no process owns uid `u32::MAX - 1`.
    assert_eq!(
        SecureDir::open_beneath(&base, Path::new("keys"), u32::MAX - 1).unwrap_err(),
        SecureDirError::Owner
    );
    assert_eq!(
        SecureDir::open(Path::new("relative"), me()).unwrap_err(),
        SecureDirError::Path
    );
    assert_eq!(
        SecureDir::open_beneath(&base, Path::new("keys/.."), me()).unwrap_err(),
        SecureDirError::Path
    );
    fs::remove_dir_all(&base).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn files_are_refused_by_link_type_mode_and_size() {
    let base = base("files");
    let keys = base.join("keys");
    put(&keys, "wide.key", b"x\n", 0o640);
    put(&keys, "max.key", &[b'a'; 4096], 0o600);
    put(&keys, "big.key", &[b'a'; 4096 + 1], 0o600);
    put(&keys, "target", b"x\n", 0o600);
    symlink(keys.join("target"), keys.join("link.key")).unwrap();
    fs::create_dir(keys.join("sub.key")).unwrap();
    let dir = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    let mut buf = [0_u8; 4097];
    assert_eq!(dir.read("wide.key", &mut buf), Err(SecureDirError::Mode));
    assert_eq!(dir.read("max.key", &mut buf), Ok(4096));
    assert_eq!(dir.read("big.key", &mut buf), Err(SecureDirError::TooLarge));
    assert_eq!(dir.read("link.key", &mut buf), Err(SecureDirError::Symlink));
    assert_eq!(dir.read("sub.key", &mut buf), Err(SecureDirError::FileType));
    assert_eq!(dir.read("../x", &mut buf), Err(SecureDirError::Name));
    assert_eq!(dir.write_atomic("", b""), Err(SecureDirError::Name));
    fs::remove_dir_all(&base).unwrap();
}

/// karyos#1067: opening and locking the directory again and again while
/// other threads spawn children is never refused as `Locked`: a child's
/// fork-to-exec window holds a closed descriptor's lock for a moment, and
/// the lock outlasts it.
#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn relocks_raced_against_spawns_are_never_refused_as_locked() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let base = base("spawn");
    let stop = Arc::new(AtomicBool::new(false));
    let spawners: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                }
            })
        })
        .collect();
    let (mut locked, mut tries) = (0u32, 0u32);
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(2) {
        let dir = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
        match dir.lock_exclusive() {
            Ok(()) => {}
            Err(SecureDirError::Locked) => locked += 1,
            Err(error) => panic!("{error:?}"),
        }
        tries += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for spawner in spawners {
        spawner.join().unwrap();
    }
    assert!(tries > 0);
    assert_eq!(locked, 0, "{locked} of {tries} relocks refused as Locked");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn the_exclusive_lock_admits_one_opener_until_it_drops() {
    let base = base("lock");
    let first = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    let second = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    first.lock_exclusive().unwrap();
    assert_eq!(second.lock_exclusive(), Err(SecureDirError::Locked));
    drop(first);
    second.lock_exclusive().unwrap();
    fs::remove_dir_all(&base).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn overlapping_writers_stage_under_their_own_names_and_leave_none_behind() {
    let base = base("stage");
    let one = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    let two = SecureDir::open_beneath(&base, Path::new("keys"), me()).unwrap();
    // A staging file left by another writer under the old fixed name, or
    // under any other name, is neither reused nor removed.
    put(&base.join("keys"), ".state.tmp", b"theirs", 0o600);
    one.write_atomic("state", b"one").unwrap();
    two.write_atomic("state", b"two").unwrap();
    let mut buf = [0_u8; 16];
    assert_eq!(one.read(".state.tmp", &mut buf).unwrap(), 6);
    let mut names = one.names().unwrap();
    names.sort();
    assert_eq!(names, [".state.tmp", "state"]);
    // A failed write removes its own staging file: a name that is a
    // directory makes the rename fail.
    fs::create_dir(base.join("keys").join("busy")).unwrap();
    fs::write(base.join("keys").join("busy").join("x"), b"").unwrap();
    assert!(one.write_atomic("busy", b"x").is_err());
    let mut names = one.names().unwrap();
    names.sort();
    assert_eq!(names, [".state.tmp", "busy", "state"]);
    fs::remove_dir_all(&base).unwrap();
}
