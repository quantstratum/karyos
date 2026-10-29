// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use super::*;

/// A backend registered through the public extension point, as
/// `karyosd-native` registers its own.
struct TestBackend;

#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct TestTable {
    queues: u16,
    mode: Option<String>,
}

impl IoBackend for TestBackend {
    const NAME: &'static str = "test_nic";
    type Table = TestTable;

    fn validate(table: &TestTable) -> Result<(), TableError> {
        if table.queues == 0 {
            return Err(TableError::new("queues", "must be above zero"));
        }
        Ok(())
    }

    fn capabilities() -> &'static [&'static str] {
        &["hw-rx-timestamp"]
    }
}

fn schema() -> IoSchema {
    let mut schema = IoSchema::core();
    schema.register::<TestBackend>().unwrap();
    schema
}

#[test]
fn an_empty_file_selects_sockets_with_nothing_required() {
    let config = IoSchema::core().load("").unwrap();
    assert_eq!(config, IoConfig::default());
    assert_eq!(config.backend(), "sockets");
    assert!(config.require().is_empty());
    assert!(!config.is_configured());
}

#[test]
fn the_io_table_selects_requires_and_sizes_the_sockets_backend() {
    let config = IoSchema::core()
        .load(
            r#"
[io]
backend = "sockets"
require = ["kernel-stamps", "gso"]

[io.sockets]
tx_slots = 512
max_routes = 32
"#,
        )
        .unwrap();
    assert_eq!(config.backend(), "sockets");
    assert_eq!(config.require(), ["kernel-stamps", "gso"]);
    assert_eq!(
        config.table::<SocketsBackend>(),
        Some(&SocketsTable {
            tx_slots: Some(512),
            max_queues: None,
            max_routes: Some(32),
        })
    );
    assert!(config.is_configured());
}

#[test]
fn a_registered_backend_reads_its_own_table() {
    let config = schema()
        .load(
            r#"
[io]
backend = "test_nic"
require = ["hw-rx-timestamp"]

[io.test_nic]
queues = 2
mode = "isolated"
"#,
        )
        .unwrap();
    assert_eq!(config.backend(), "test_nic");
    assert_eq!(
        config.table::<TestBackend>(),
        Some(&TestTable {
            queues: 2,
            mode: Some("isolated".to_owned()),
        })
    );
    assert_eq!(config.table::<SocketsBackend>(), None);
}

#[test]
fn an_invalid_backend_table_is_refused_with_its_key_named() {
    let refused = schema().load("[io.test_nic]\nqueues = 0\n");
    assert_eq!(
        refused,
        Err(ConfigError::Table {
            key: "io.test_nic.queues".to_owned(),
            message: "must be above zero".to_owned(),
        })
    );
    let refused = IoSchema::core().load("[io.sockets]\nmax_queues = 2000\n");
    assert_eq!(
        refused,
        Err(ConfigError::Table {
            key: "io.sockets.max_queues".to_owned(),
            message: "2000 is outside 1 to 1024".to_owned(),
        })
    );
}

#[test]
fn a_backend_table_of_the_wrong_type_is_refused_at_its_line() {
    let Err(ConfigError::Table { key, message }) =
        schema().load("[io]\nbackend = \"sockets\"\n\n[io.test_nic]\nqueues = \"two\"\n")
    else {
        panic!("not refused");
    };
    assert_eq!(key, "io.test_nic");
    assert!(message.contains("line 5"), "{message}");
    assert!(message.contains("queues = \"two\""), "{message}");
    assert!(message.contains("expected u16"), "{message}");
}

#[test]
fn an_unknown_key_of_a_backend_table_is_refused_by_name() {
    let Err(ConfigError::Table { key, message }) =
        IoSchema::core().load("[io.sockets]\ntx_slot = 8\n")
    else {
        panic!("not refused");
    };
    assert_eq!(key, "io.sockets");
    assert!(message.contains("unknown field `tx_slot`"), "{message}");
}

#[test]
fn an_unselected_table_is_validated_too() {
    assert!(matches!(
        schema().load("[io]\nbackend = \"sockets\"\n[io.test_nic]\nqueues = 0\n"),
        Err(ConfigError::Table { .. })
    ));
}

#[test]
fn a_missing_required_key_of_a_backend_table_is_refused() {
    let Err(ConfigError::Table { message, .. }) = schema().load("[io.test_nic]\nmode = \"a\"\n")
    else {
        panic!("not refused");
    };
    assert!(message.contains("missing field `queues`"), "{message}");
}

#[test]
fn a_backend_of_spec_16_9_not_built_here_is_refused_and_sockets_stays() {
    for (name, reason) in [
        ("io_uring", Unsupported::NotBuilt),
        ("af_xdp", Unsupported::NotBuilt),
        ("ef_vi", Unsupported::NativeOnly),
        ("dpdk", Unsupported::NativeOnly),
    ] {
        assert_eq!(
            IoSchema::core().load(&format!("[io]\nbackend = \"{name}\"\n")),
            Err(ConfigError::UnsupportedBackend {
                name: name.to_owned(),
                reason,
                available: vec!["sockets"],
            }),
            "{name}"
        );
    }
    // A native table in the core build is refused the same way.
    assert_eq!(
        IoSchema::core().load("[io.dpdk]\ndevices = [\"0000:3b:00.0\"]\n"),
        Err(ConfigError::UnsupportedBackend {
            name: "dpdk".to_owned(),
            reason: Unsupported::NativeOnly,
            available: vec!["sockets"],
        })
    );
    assert!(
        IoSchema::core()
            .load("[io]\nbackend = \"sockets\"\n")
            .is_ok()
    );
}

#[test]
fn an_unknown_backend_is_refused() {
    assert_eq!(
        schema().load("[io]\nbackend = \"rdma\"\n"),
        Err(ConfigError::UnknownBackend {
            name: "rdma".to_owned(),
            available: vec!["sockets", "test_nic"],
        })
    );
}

#[test]
fn an_unknown_key_or_table_is_refused_by_name() {
    for (text, key) in [
        ("[net]\nport = 1\n", "net"),
        ("threads = 2\n", "threads"),
        ("[io.foo]\nx = 1\n", "io.foo"),
        ("[io]\nbackends = \"sockets\"\n", "io.backends"),
    ] {
        assert_eq!(
            IoSchema::core().load(text),
            Err(ConfigError::UnknownKey {
                key: key.to_owned()
            }),
            "{text}"
        );
    }
}

#[test]
fn a_key_of_io_with_the_wrong_type_is_refused() {
    for (text, key, expected) in [
        ("io = 1\n", "io", "a table"),
        ("[io]\nbackend = 1\n", "io.backend", "a string"),
        (
            "[io]\nrequire = \"gso\"\n",
            "io.require",
            "an array of strings",
        ),
        ("[io]\nrequire = [1]\n", "io.require", "an array of strings"),
    ] {
        assert_eq!(
            IoSchema::core().load(text),
            Err(ConfigError::InvalidValue {
                key: key.to_owned(),
                expected,
            }),
            "{text}"
        );
    }
}

#[test]
fn a_capability_the_selected_backend_does_not_know_is_refused() {
    assert_eq!(
        schema().load("[io]\nrequire = [\"hw-rx-timestamp\"]\n"),
        Err(ConfigError::UnknownCapability {
            backend: "sockets".to_owned(),
            name: "hw-rx-timestamp".to_owned(),
        })
    );
    assert!(
        schema()
            .load("[io]\nbackend = \"test_nic\"\nrequire = [\"hw-rx-timestamp\"]\n[io.test_nic]\nqueues = 1\n")
            .is_ok()
    );
}

#[test]
fn invalid_toml_is_refused_with_its_position() {
    let Err(ConfigError::Syntax { message }) = IoSchema::core().load("[io\nbackend =") else {
        panic!("not refused");
    };
    assert!(message.contains("line 1, column 4"), "{message}");
}

#[test]
fn an_unreadable_file_is_refused_with_its_path() {
    let path = std::path::Path::new("/nonexistent/karyos/karyosd.toml");
    let Err(ConfigError::Read { path: shown, .. }) = IoSchema::core().read(path) else {
        panic!("not refused");
    };
    assert_eq!(shown, path.display().to_string());
}

#[test]
fn a_backend_registered_twice_or_badly_named_is_refused() {
    let mut schema = schema();
    assert_eq!(
        schema.register::<TestBackend>(),
        Err(RegisterError::Duplicate("test_nic"))
    );
    assert_eq!(
        schema.register::<SocketsBackend>(),
        Err(RegisterError::Duplicate("sockets"))
    );
    macro_rules! named {
        ($ident:ident, $name:literal) => {
            struct $ident;
            impl IoBackend for $ident {
                const NAME: &'static str = $name;
                type Table = SocketsTable;
                fn validate(_: &SocketsTable) -> Result<(), TableError> {
                    Ok(())
                }
                fn capabilities() -> &'static [&'static str] {
                    &[]
                }
            }
        };
    }
    named!(Empty, "");
    named!(Upper, "Dpdk");
    named!(Dotted, "a.b");
    named!(Digit, "1nic");
    named!(Backend, "backend");
    named!(Require, "require");
    for refused in [
        schema.register::<Empty>(),
        schema.register::<Upper>(),
        schema.register::<Dotted>(),
        schema.register::<Digit>(),
        schema.register::<Backend>(),
        schema.register::<Require>(),
    ] {
        assert!(
            matches!(refused, Err(RegisterError::InvalidName(_))),
            "{refused:?}"
        );
    }
    assert_eq!(schema.names(), ["sockets", "test_nic"]);
}

#[test]
fn the_overrides_are_checked_as_the_file_is() {
    let schema = schema();
    let mut config = schema.load("").unwrap();
    config.set_backend("dpdk".to_owned());
    assert!(matches!(
        schema.check(&config),
        Err(ConfigError::UnsupportedBackend { .. })
    ));
    config.set_backend("sockets".to_owned());
    config.set_require(vec!["path-mtu".to_owned()]);
    assert_eq!(schema.check(&config), Ok(()));
    config.set_require(vec!["teleport".to_owned()]);
    assert!(matches!(
        schema.check(&config),
        Err(ConfigError::UnknownCapability { .. })
    ));
}

#[test]
fn every_sockets_capability_name_maps_to_its_capability() {
    for name in SOCKETS_CAPABILITIES {
        assert!(sockets_capability(name).is_some(), "{name}");
    }
    assert_eq!(sockets_capability("teleport"), None);
}

#[test]
fn every_error_displays_one_line() {
    let errors = [
        ConfigError::Read {
            path: "a".to_owned(),
            reason: "b".to_owned(),
        },
        ConfigError::Syntax {
            message: "m".to_owned(),
        },
        ConfigError::UnknownKey {
            key: "k".to_owned(),
        },
        ConfigError::InvalidValue {
            key: "k".to_owned(),
            expected: "e",
        },
        ConfigError::UnknownBackend {
            name: "n".to_owned(),
            available: vec!["sockets"],
        },
        ConfigError::UnsupportedBackend {
            name: "dpdk".to_owned(),
            reason: Unsupported::NativeOnly,
            available: vec!["sockets"],
        },
        ConfigError::UnknownCapability {
            backend: "b".to_owned(),
            name: "n".to_owned(),
        },
        ConfigError::Table {
            key: "k".to_owned(),
            message: "m".to_owned(),
        },
        ConfigError::NetworkOff,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
    assert!(!RegisterError::Duplicate("x").to_string().is_empty());
    assert!(!RegisterError::InvalidName("x").to_string().is_empty());
}
