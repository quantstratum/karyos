// SPDX-License-Identifier: Apache-2.0

//! Detection of the Linux VM Generation ID device (`drivers/virt/vmgenid.c`)
//! through sysfs, for ADR-0114 section 10 (implementation item 3).
//!
//! What Linux exposes, checked against the 7.0 module (`vmgenid.ko`,
//! xaskar, `CONFIG_VMGENID=m`): the device is an ACPI device with `_HID`
//! `VMGENCTR` or `_CID` `VM_GEN_COUNTER` (QEMU: `QEMUVGID` with `_CID`
//! `VM_Gen_Counter`; Hyper-V: `Hyper_V_Gen_Counter_V1`), or, since 6.10, a
//! devicetree node compatible with `microsoft,vmgenid` bound to the
//! `vmgenid` platform driver. The driver reads the 128-bit id from guest
//! memory and hands it to the kernel's random number generator only: it
//! creates no sysfs attribute (the id is not readable from user space on
//! any mainline kernel), and the `NEW_VMGENID=1` uevent of ad6bcdad2b67
//! (6.8) was reverted by 3aadf100f93d (6.9, Cc stable), the 7.0 module
//! has no such string. So the device's presence is observable, a change
//! is not: a host with the device is a virtual machine whose generation
//! can change without the process seeing it, and the deployment rule of
//! section 10 alone protects it. [`detect`] tells the three cases apart
//! so that the driver states which one holds; a sysfs it cannot read is
//! never taken for "no device".

use std::io::ErrorKind;
use std::path::Path;

/// The sysfs root of a Linux host.
pub const SYSFS: &str = "/sys";

/// What sysfs says about the VM Generation ID device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmGenIdDevice {
    /// No device: bare metal, or a hypervisor that offers none (or not
    /// Linux). A generation change cannot happen unseen by the platform's
    /// own interface, and none is signalled.
    Absent,
    /// A device is present: the host is a virtual machine whose
    /// generation can change, and Linux gives user space no signal of it.
    Present,
    /// sysfs exists but could not be read: a device may be present. It is
    /// reported as such, never as [`VmGenIdDevice::Absent`].
    Unreadable,
}

/// ACPI hardware and compatible ids the `vmgenid` driver binds to, matched
/// without regard to case (QEMU and Hyper-V spell the `_CID` in mixed
/// case).
const ACPI_IDS: [&str; 2] = ["VMGENCTR", "VM_GEN_COUNTER"];
/// The platform driver's name (ACPI since 6.10, devicetree).
const DRIVER: &str = "vmgenid";

/// What sysfs under `root` says about the VM Generation ID device: an ACPI
/// device whose `hid` or `modalias` names one of the driver's ids, or a
/// device bound to the `vmgenid` platform driver.
#[must_use]
pub fn detect(root: &Path) -> VmGenIdDevice {
    let acpi = acpi_device(&root.join("bus/acpi/devices"));
    let platform = bound_device(&root.join("bus/platform/drivers").join(DRIVER));
    match (acpi, platform) {
        (Some(true), _) | (_, Some(true)) => VmGenIdDevice::Present,
        (Some(false), Some(false)) => VmGenIdDevice::Absent,
        _ => VmGenIdDevice::Unreadable,
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

    use std::path::PathBuf;

    use super::*;

    /// A fresh fake sysfs root under the target directory.
    fn root(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/vmgenid-fake-sysfs")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn acpi(root: &Path, device: &str, hid: &str, modalias: &str) -> PathBuf {
        let dir = root.join("bus/acpi/devices").join(device);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hid"), format!("{hid}\n")).unwrap();
        std::fs::write(dir.join("modalias"), format!("{modalias}\n")).unwrap();
        dir
    }

    #[test]
    fn no_sysfs_and_no_device_are_absent() {
        let root = root("absent");
        assert_eq!(detect(&root.join("missing")), VmGenIdDevice::Absent);
        assert_eq!(detect(&root), VmGenIdDevice::Absent);
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
