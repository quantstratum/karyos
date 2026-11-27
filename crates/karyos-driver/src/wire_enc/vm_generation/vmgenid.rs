// SPDX-License-Identifier: Apache-2.0

//! Detection of the Linux VM Generation ID device (`drivers/virt/vmgenid.c`)
//! through sysfs, for ADR-0114 section 10 (implementation item 3).
//!
//! What Linux exposes, checked against the 7.0 module (`vmgenid.ko`,
//! xaskar, `CONFIG_VMGENID=m`): the device is an ACPI device with `_HID`
//! `VMGENCTR` or `_CID` `VM_GEN_COUNTER` (QEMU: `QEMUVGID` with `_CID`
//! `VM_Gen_Counter`; Hyper-V: `Hyper_V_Gen_Counter_V1`), or, since 6.10, a
//! devicetree node compatible with `microsoft,vmgenid` bound to the
//! `vmgenid` platform driver (the node is a platform device whether or not
//! the driver is loaded or bound). The driver reads the 128-bit id from guest
//! memory and hands it to the kernel's random number generator only: it
//! creates no sysfs attribute (the id is not readable from user space on
//! any mainline kernel), and the `NEW_VMGENID=1` uevent of ad6bcdad2b67
//! (6.8) was reverted by 3aadf100f93d (6.9, Cc stable), the 7.0 module
//! has no such string. So the device's presence is observable, a change
//! is not: a host with the device is a virtual machine whose generation
//! can change without the process seeing it, and the deployment rule of
//! section 10 alone protects it. [`detect`] tells the three cases apart
//! so that the driver states which one holds; a sysfs it cannot read, or
//! a root that is no sysfs (no `bus` directory), is never taken for "no
//! device".

use std::io::ErrorKind;
use std::path::Path;

/// The sysfs root of a Linux host.
pub const SYSFS: &str = "/sys";

/// What sysfs says about the VM Generation ID device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmGenIdDevice {
    /// No device is visible in a readable sysfs: bare metal, a hypervisor
    /// that offers none, or a guest that hides it. This is no evidence
    /// that the generation cannot change: a hypervisor without the device
    /// can still restore a snapshot unseen, which the deployment rule of
    /// section 10 alone covers.
    Absent,
    /// A device is present: the host is a virtual machine whose
    /// generation can change, and Linux gives user space no signal of it.
    Present,
    /// sysfs could not be observed (the root or its `bus` directory is
    /// missing or unreadable, or an entry could not be read): a device may
    /// be present. It is reported as such, never as
    /// [`VmGenIdDevice::Absent`].
    Unreadable,
}

/// ACPI hardware and compatible ids the `vmgenid` driver binds to, matched
/// without regard to case (QEMU and Hyper-V spell the `_CID` in mixed
/// case).
const ACPI_IDS: [&str; 2] = ["VMGENCTR", "VM_GEN_COUNTER"];
/// The platform driver's name (ACPI since 6.10, devicetree).
const DRIVER: &str = "vmgenid";
/// The devicetree compatible string the driver matches.
const COMPATIBLE: &str = "microsoft,vmgenid";

/// What sysfs under `root` says about the VM Generation ID device: an ACPI
/// device whose `hid` or `modalias` names one of the driver's ids, a
/// platform device whose devicetree node is compatible with
/// `microsoft,vmgenid` (bound or not), or a device bound to the `vmgenid`
/// platform driver. A missing bus directory means no such bus only once
/// the root is shown to be a sysfs: a missing or unreadable root, or one
/// without a readable `bus` directory, is [`VmGenIdDevice::Unreadable`].
#[must_use]
pub fn detect(root: &Path) -> VmGenIdDevice {
    if std::fs::read_dir(root.join("bus")).is_err() {
        return VmGenIdDevice::Unreadable;
    }
    let probes = [
        acpi_device(&root.join("bus/acpi/devices")),
        devicetree_device(&root.join("bus/platform/devices")),
        bound_device(&root.join("bus/platform/drivers").join(DRIVER)),
    ];
    if probes.contains(&Some(true)) {
        VmGenIdDevice::Present
    } else if probes.iter().all(|probe| *probe == Some(false)) {
        VmGenIdDevice::Absent
    } else {
        VmGenIdDevice::Unreadable
    }
}

/// Whether an ACPI device names a `vmgenid` id; `None` if unreadable. A
/// missing directory (no ACPI) is `Some(false)`.
fn acpi_device(devices: &Path) -> Option<bool> {
    let entries = match std::fs::read_dir(devices) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let mut readable = true;
    for entry in entries {
        let Ok(entry) = entry else {
            readable = false;
            continue;
        };
        for file in ["hid", "modalias"] {
            match std::fs::read_to_string(entry.path().join(file)) {
                Ok(text) if names_vmgenid(&text) => return Some(true),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_) => readable = false,
            }
        }
    }
    readable.then_some(false)
}

/// Whether `text` (a `hid`, or a `modalias` such as
/// `acpi:QEMUVGID:VM_Gen_Counter:`) names one of the driver's ids.
fn names_vmgenid(text: &str) -> bool {
    text.trim()
        .trim_start_matches("acpi:")
        .split(':')
        .any(|id| ACPI_IDS.iter().any(|known| id.eq_ignore_ascii_case(known)))
}

/// Whether a platform device's devicetree node is compatible with
/// `microsoft,vmgenid`, read from its `of_node/compatible` or its
/// `modalias`, independently of any driver binding; `None` if unreadable.
/// A missing directory (no platform bus) is `Some(false)`.
fn devicetree_device(devices: &Path) -> Option<bool> {
    let entries = match std::fs::read_dir(devices) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let mut readable = true;
    for entry in entries {
        let Ok(entry) = entry else {
            readable = false;
            continue;
        };
        let path = entry.path();
        match std::fs::read(path.join("of_node/compatible")) {
            Ok(bytes) if compatible_names_vmgenid(&bytes) => return Some(true),
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => readable = false,
        }
        match std::fs::read_to_string(path.join("modalias")) {
            Ok(text) if of_modalias_names_vmgenid(&text) => return Some(true),
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => readable = false,
        }
    }
    readable.then_some(false)
}

/// Whether a devicetree `compatible` property (NUL-separated strings)
/// lists `microsoft,vmgenid`.
fn compatible_names_vmgenid(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| *byte == 0)
        .any(|name| name == COMPATIBLE.as_bytes())
}

/// Whether a devicetree `modalias` (`of:N<name>T<type>C<compatible>...`,
/// each compatible after a `C`) lists `microsoft,vmgenid`.
fn of_modalias_names_vmgenid(text: &str) -> bool {
    let Some(text) = text.trim().strip_prefix("of:") else {
        return false;
    };
    let tag = format!("C{COMPATIBLE}");
    text.match_indices(&tag).any(|(at, _)| {
        text.get(at + tag.len()..)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('C'))
    })
}

/// Whether the platform driver directory holds a bound device (a link
/// other than the driver's own `bind`, `unbind`, `uevent` and `module`);
/// `None` if unreadable. A missing directory (module not loaded, or no
/// device ever probed) is `Some(false)`.
fn bound_device(driver: &Path) -> Option<bool> {
    let entries = match std::fs::read_dir(driver) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let mut readable = true;
    for entry in entries {
        let Ok(entry) = entry else {
            readable = false;
            continue;
        };
        let name = entry.file_name();
        if !matches!(
            name.to_str(),
            Some("bind" | "unbind" | "uevent" | "module" | "new_id" | "remove_id")
        ) {
            return Some(true);
        }
    }
    readable.then_some(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use std::ops::Deref;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A fake sysfs directory under the system temp directory, removed
    /// when dropped, also when the test fails: permissions a test took
    /// away are restored first, so nothing is left behind (not even under
    /// a root-owned run in a container).
    struct FakeRoot(PathBuf);

    impl Deref for FakeRoot {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for FakeRoot {
        fn drop(&mut self) {
            restore(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Makes `path` and everything under it readable and writable again.
    fn restore(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return;
            };
            let mode = if meta.is_dir() { 0o755 } else { 0o644 };
            if !meta.file_type().is_symlink() {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
            }
            if meta.is_dir()
                && let Ok(entries) = std::fs::read_dir(path)
            {
                for entry in entries.flatten() {
                    restore(&entry.path());
                }
            }
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    /// A fresh fake sysfs root, with its `bus` directory and no bus in it.
    fn root(name: &str) -> FakeRoot {
        let root = bare(name);
        std::fs::create_dir_all(root.join("bus")).unwrap();
        root
    }

    /// A fresh empty directory under the system temp directory, unique to
    /// this process and call.
    fn bare(name: &str) -> FakeRoot {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "karyos-vmgenid-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        FakeRoot(root)
    }

    /// A platform device `name` (its `of_node` and `modalias`, as Linux
    /// creates them whether or not a driver binds it).
    fn platform(root: &Path, name: &str, compatible: &[u8], modalias: &str) -> PathBuf {
        let dir = root.join("bus/platform/devices").join(name);
        std::fs::create_dir_all(dir.join("of_node")).unwrap();
        std::fs::write(dir.join("of_node/compatible"), compatible).unwrap();
        std::fs::write(dir.join("modalias"), format!("{modalias}\n")).unwrap();
        dir
    }

    fn acpi(root: &Path, device: &str, hid: &str, modalias: &str) -> PathBuf {
        let dir = root.join("bus/acpi/devices").join(device);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hid"), format!("{hid}\n")).unwrap();
        std::fs::write(dir.join("modalias"), format!("{modalias}\n")).unwrap();
        dir
    }

    /// A missing sysfs, or a root without its `bus` directory, is no
    /// observation: unreadable, never absent.
    #[test]
    fn a_missing_sysfs_is_unreadable_not_absent() {
        let root = bare("missing");
        assert_eq!(detect(&root.join("missing")), VmGenIdDevice::Unreadable);
        assert_eq!(detect(&root), VmGenIdDevice::Unreadable, "no bus");
        std::fs::write(root.join("bus"), "").unwrap();
        assert_eq!(
            detect(&root),
            VmGenIdDevice::Unreadable,
            "bus not a directory"
        );
        std::fs::remove_file(root.join("bus")).unwrap();
        std::fs::create_dir(root.join("bus")).unwrap();
        assert_eq!(
            detect(&root),
            VmGenIdDevice::Absent,
            "a sysfs without these buses"
        );
    }

    #[test]
    fn no_device_is_absent() {
        let root = root("absent");
        assert_eq!(detect(&root), VmGenIdDevice::Absent);
        platform(
            &root,
            "serial@9000000",
            b"arm,pl011\0arm,primecell\0",
            "of:Npl011T(null)Carm,pl011Carm,primecell",
        );
        assert_eq!(
            detect(&root),
            VmGenIdDevice::Absent,
            "other devicetree devices"
        );
        acpi(&root, "PNP0A08:00", "PNP0A08", "acpi:PNP0A08:PNP0A03:");
        assert_eq!(detect(&root), VmGenIdDevice::Absent);
        let driver = root.join("bus/platform/drivers/vmgenid");
        std::fs::create_dir_all(&driver).unwrap();
        for file in ["bind", "unbind", "uevent"] {
            std::fs::write(driver.join(file), "").unwrap();
        }
        assert_eq!(detect(&root), VmGenIdDevice::Absent, "loaded, unbound");
    }

    #[test]
    fn every_id_the_driver_binds_to_is_detected() {
        for (hid, modalias) in [
            ("VMGENCTR", "acpi:VMGENCTR:"),
            ("QEMUVGID", "acpi:QEMUVGID:VM_Gen_Counter:"),
            (
                "Hyper_V_Gen_Counter_V1",
                "acpi:Hyper_V_Gen_Counter_V1:VM_Gen_Counter:",
            ),
        ] {
            let root = root(hid);
            acpi(&root, "PNP0A08:00", "PNP0A08", "acpi:PNP0A08:PNP0A03:");
            acpi(&root, &format!("{hid}:00"), hid, modalias);
            assert_eq!(detect(&root), VmGenIdDevice::Present, "{hid}");
        }
    }

    #[test]
    fn a_device_bound_to_the_platform_driver_is_detected() {
        let root = root("devicetree");
        let driver = root.join("bus/platform/drivers/vmgenid");
        std::fs::create_dir_all(driver.join("vmgenid@0")).unwrap();
        std::fs::write(driver.join("bind"), "").unwrap();
        assert_eq!(detect(&root), VmGenIdDevice::Present);
    }

    /// A devicetree node compatible with `microsoft,vmgenid` is detected
    /// with the driver neither loaded nor bound, from its `compatible` or
    /// from its `modalias` alone.
    #[test]
    fn an_unbound_devicetree_device_is_detected() {
        let root = root("unbound");
        let device = platform(
            &root,
            "vmgenid@1000",
            b"microsoft,vmgenid\0",
            "of:NvmgenidT(null)Cmicrosoft,vmgenid",
        );
        assert!(!root.join("bus/platform/drivers/vmgenid").exists());
        assert_eq!(detect(&root), VmGenIdDevice::Present, "both");
        std::fs::remove_file(device.join("modalias")).unwrap();
        assert_eq!(detect(&root), VmGenIdDevice::Present, "compatible alone");
        std::fs::remove_dir_all(device.join("of_node")).unwrap();
        std::fs::write(
            device.join("modalias"),
            "of:NvmgenidT(null)Cvendor,otherCmicrosoft,vmgenid\n",
        )
        .unwrap();
        assert_eq!(detect(&root), VmGenIdDevice::Present, "modalias alone");
        std::fs::write(
            device.join("modalias"),
            "of:NvmgenidT(null)Cmicrosoft,vmgenid-v2\n",
        )
        .unwrap();
        assert_eq!(detect(&root), VmGenIdDevice::Absent, "another compatible");
    }

    /// Unreadable sysfs is reported as such, never as no device. Needs a
    /// user that permissions bind (root reads everything: skipped).
    #[cfg(unix)]
    #[test]
    fn an_unreadable_sysfs_is_never_taken_for_no_device() {
        use std::os::unix::fs::PermissionsExt;

        let root = root("unreadable");
        let device = acpi(
            &root,
            "QEMUVGID:00",
            "QEMUVGID",
            "acpi:QEMUVGID:VM_Gen_Counter:",
        );
        for file in ["hid", "modalias"] {
            std::fs::set_permissions(device.join(file), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        let probe = std::fs::read_to_string(device.join("hid")).is_ok();
        if !probe {
            assert_eq!(
                detect(&root),
                VmGenIdDevice::Unreadable,
                "unreadable id files"
            );
        }
        let devices = root.join("bus/acpi/devices");
        std::fs::set_permissions(&devices, std::fs::Permissions::from_mode(0o000)).unwrap();
        if !probe {
            assert_eq!(
                detect(&root),
                VmGenIdDevice::Unreadable,
                "unreadable directory"
            );
        }
        std::fs::set_permissions(&devices, std::fs::Permissions::from_mode(0o755)).unwrap();
        for file in ["hid", "modalias"] {
            std::fs::set_permissions(device.join(file), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        assert_eq!(detect(&root), VmGenIdDevice::Present, "readable again");
    }

    /// The device appearing (hot-added, or a host moved under a hypervisor
    /// that offers one) and going is seen on the next detection.
    #[test]
    fn detection_follows_the_device() {
        let root = root("follows");
        assert_eq!(detect(&root), VmGenIdDevice::Absent);
        let device = acpi(&root, "VMGENCTR:00", "VMGENCTR", "acpi:VMGENCTR:");
        assert_eq!(detect(&root), VmGenIdDevice::Present);
        std::fs::remove_dir_all(device).unwrap();
        assert_eq!(detect(&root), VmGenIdDevice::Absent);
    }
}
