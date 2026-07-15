use std::fs;
use std::path::Path;

fn source(name: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name))
        .unwrap_or_else(|error| panic!("cannot read {name}: {error}"))
}

#[test]
fn installed_supervised_startup_has_no_production_v3_self_authorization_path() {
    // Given
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let library = source("lib.rs");
    let installed = source("installed_cli.rs");
    let loader = source("supervisor_bootstrap_io.rs");
    let stdio = source("supervisor_stdio.rs");

    // When
    let legacy_files = [
        "supervisor_bootstrap.rs",
        "supervisor_bootstrap_codec.rs",
        "supervisor_bootstrap_codec_tests.rs",
    ];

    // Then
    assert!(!library.contains("mod supervisor_bootstrap;"));
    assert!(!library.contains("mod supervisor_bootstrap_codec;"));
    assert!(!library.contains("mod supervisor_bootstrap_codec_tests;"));
    assert!(
        legacy_files
            .into_iter()
            .all(|name| !source_dir.join(name).exists())
    );
    assert!(!installed.contains("supervisor_bootstrap::"));
    assert!(!loader.contains("SupervisorBootstrap::from_bytes"));
    assert!(loader.contains("UnverifiedSupervisorBootstrapV4::from_bytes"));
    assert!(stdio.contains("startup: AuthorizedStartup"));
}

#[test]
fn installed_startup_authorizes_before_stdio_or_journal_attachment() {
    // Given
    let installed = source("installed_cli.rs");
    let boundary = source("installed_startup_io.rs");
    let startup = source("installed_startup.rs");

    // When
    let authorized = installed
        .find("authorize_installed_startup()?")
        .expect("authorization call");
    let stdin = authorized
        + installed[authorized..]
            .find("io::stdin()")
            .expect("supervised stdin");
    let trust = boundary
        .find("load_installed_trust_store()")
        .expect("trust");
    let bootstrap = boundary
        .find("load_inherited_supervisor_bootstrap_v4()")
        .expect("bootstrap");
    let executable = boundary
        .find("measure_running_executable()")
        .expect("executable");
    let clock = boundary.find("system_now_millis()?").expect("clock");
    let pure_authorization = boundary
        .find("authorize_loaded_startup(")
        .expect("pure authorization");
    let binding = startup.find(".durability_binding()").expect("binding");
    let journal = startup
        .find("open_inherited_journal_channels()")
        .expect("journal");

    // Then
    assert!(authorized < stdin);
    assert!(trust < bootstrap && bootstrap < executable);
    assert!(executable < clock && clock < pure_authorization);
    assert_eq!(boundary.matches("system_now_millis()?").count(), 1);
    assert!(binding < journal);
}

#[test]
fn installed_trust_is_a_fixed_local_root_without_runtime_override() {
    // Given
    let trust = source("installed_trust.rs");

    // When
    let fixed_path = trust
        .contains("const INSTALLED_TRUST_PATH: &str = \"/etc/faultloom/gateway-trust-v1.json\";");

    // Then
    assert!(fixed_path);
    assert!(!trust.contains("std::env"));
    assert!(!trust.contains("var_os("));
}
