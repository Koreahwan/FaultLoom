use std::io::{self, Write};
use std::process::ExitCode;

use super::supervisor_install::{
    SUPERVISOR_BOOTSTRAP_FD, SUPERVISOR_JOURNAL_READ_FD, SUPERVISOR_JOURNAL_WRITE_FD,
};

const RUNTIME_FAILURE_CODE: u8 = 1;
const INVALID_ARGUMENTS_CODE: u8 = 2;

enum InstalledMode {
    FailClosed,
    Help,
    Supervised,
}

/// Runs the installed gateway through its fixed process and inherited-FD boundary.
pub fn run_installed_cli() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    run_with(
        &arguments,
        || super::run_fail_closed_stdio(io::stdin().lock(), io::stdout()),
        || {
            writeln!(
                io::stdout(),
                "faultloom-gateway\n\nAuthenticated mode:\n  faultloom-gateway --supervised-stdio --bootstrap-fd {SUPERVISOR_BOOTSTRAP_FD} --journal-write-fd {SUPERVISOR_JOURNAL_WRITE_FD} --journal-read-fd {SUPERVISOR_JOURNAL_READ_FD}"
            )
        },
        || {
            let startup = super::installed_startup::authorize_installed_startup()?;
            let input = io::stdin();
            super::supervisor_stdio::run_supervised_stdio(input.lock(), io::stdout(), startup)
        },
    )
}

fn run_with(
    arguments: &[String],
    fail_closed: impl FnOnce() -> io::Result<()>,
    help: impl FnOnce() -> io::Result<()>,
    supervised: impl FnOnce() -> io::Result<()>,
) -> ExitCode {
    let result = match parse_mode(arguments) {
        Ok(InstalledMode::FailClosed) => fail_closed(),
        Ok(InstalledMode::Help) => help(),
        Ok(InstalledMode::Supervised) => supervised(),
        Err(()) => return ExitCode::from(INVALID_ARGUMENTS_CODE),
    };
    result.map_or_else(
        |_| ExitCode::from(RUNTIME_FAILURE_CODE),
        |()| ExitCode::SUCCESS,
    )
}

fn parse_mode(arguments: &[String]) -> Result<InstalledMode, ()> {
    match arguments {
        [] => Ok(InstalledMode::FailClosed),
        [help] if help == "--help" => Ok(InstalledMode::Help),
        [
            mode,
            bootstrap_flag,
            bootstrap_fd,
            write_flag,
            write_fd,
            read_flag,
            read_fd,
        ] if mode == "--supervised-stdio"
            && bootstrap_flag == "--bootstrap-fd"
            && bootstrap_fd == SUPERVISOR_BOOTSTRAP_FD
            && write_flag == "--journal-write-fd"
            && write_fd == SUPERVISOR_JOURNAL_WRITE_FD
            && read_flag == "--journal-read-fd"
            && read_fd == SUPERVISOR_JOURNAL_READ_FD =>
        {
            Ok(InstalledMode::Supervised)
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn help_exits_successfully_without_entering_supervised_runtime() {
        let mut output = Vec::new();
        let status = run_with(
            &arguments(&["--help"]),
            || panic!("help must not enter fail-closed runtime"),
            || output.write_all(b"--bootstrap-fd 3"),
            || panic!("help must not enter supervised runtime"),
        );

        assert_eq!(status, ExitCode::SUCCESS);
        assert!(
            String::from_utf8(output)
                .expect("UTF-8 help")
                .contains("--bootstrap-fd 3")
        );
    }

    #[test]
    fn exact_supervised_arguments_enter_the_private_runtime() {
        let mut output = Vec::new();
        let status = run_with(
            &arguments(&[
                "--supervised-stdio",
                "--bootstrap-fd",
                "3",
                "--journal-write-fd",
                "4",
                "--journal-read-fd",
                "5",
            ]),
            || panic!("supervised mode must not enter fail-closed runtime"),
            || panic!("supervised mode must not print help"),
            || output.write_all(b"supervised"),
        );

        assert_eq!(status, ExitCode::SUCCESS);
        assert_eq!(output, b"supervised");
    }

    #[test]
    fn invalid_arguments_exit_two_without_entering_a_runtime() {
        let status = run_with(
            &arguments(&["--supervised-stdio", "--bootstrap-fd", "9"]),
            || panic!("invalid arguments must not enter fail-closed runtime"),
            || panic!("invalid arguments must not print help"),
            || panic!("invalid arguments must not enter supervised runtime"),
        );

        assert_eq!(status, ExitCode::from(INVALID_ARGUMENTS_CODE));
    }

    #[test]
    fn runtime_failure_exits_one() {
        let status = run_with(
            &arguments(&[
                "--supervised-stdio",
                "--bootstrap-fd",
                "3",
                "--journal-write-fd",
                "4",
                "--journal-read-fd",
                "5",
            ]),
            || panic!("supervised mode must not enter fail-closed runtime"),
            || panic!("supervised mode must not print help"),
            || Err(io::Error::other("supervised failure")),
        );

        assert_eq!(status, ExitCode::from(RUNTIME_FAILURE_CODE));
    }
}
