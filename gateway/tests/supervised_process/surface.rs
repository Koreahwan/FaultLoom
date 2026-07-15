use std::process::{Command, Stdio};

#[test]
fn installed_binary_documents_an_authenticated_supervised_surface_without_a_target_url() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_faultloom-gateway"));
    command
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = command.output().expect("gateway help process");

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 gateway help");
    assert!(help.contains("--supervised-stdio --bootstrap-fd 3"));
    assert!(!help.to_ascii_lowercase().contains("url"));
}
