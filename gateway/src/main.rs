use std::io;

fn main() {
    if faultloom_gateway::run_fail_closed_stdio(io::stdin().lock(), io::stdout().lock()).is_err() {
        std::process::exit(1);
    }
}
