#[cfg(test)]
use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use crate::Digest;
use crate::ipc::{ActionKind, DispatchOutcome, EgressPlane};
use crate::policy::CompiledAction;
use crate::transport::{
    CancellationDisposition, DispatchCancellation, DispatchLimits, TargetTransport,
    TcpTargetTransport,
};

fn large_action(target: std::net::SocketAddr) -> CompiledAction {
    CompiledAction {
        intent_digest: Digest::of(b"attempt-5 cancellation intent"),
        action_kind: ActionKind::SemanticHttpV1,
        target,
        egress_plane: EgressPlane::TargetGateway,
        semantic_action_digest: Digest::of(b"attempt-5 cancellation semantics"),
        resolution_digest: Digest::of(b"attempt-5 cancellation resolution"),
        request_binding_digest: Digest::of(b"attempt-5 cancellation binding"),
        effect_digest: crate::policy::target_effect_digest(
            ActionKind::SemanticHttpV1,
            EgressPlane::TargetGateway,
            Digest::of(b"attempt-5 cancellation resolution"),
            Digest::of(&vec![b'X'; 16 * 1024 * 1024]),
        ),
        bytes: vec![b'X'; 16 * 1024 * 1024],
    }
}

#[test]
fn active_tcp_cancellation_never_acknowledges_a_target_stable_byte_boundary() {
    // Given: the target has observed one byte, then deliberately stops reading
    // while the transport fills the sender's kernel buffer.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("owned listener address");
    let (first_byte_tx, first_byte_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let (final_count_tx, final_count_rx) = mpsc::sync_channel(0);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("transport connection");
        let mut first = [0_u8; 1];
        stream.read_exact(&mut first).expect("first target byte");
        first_byte_tx.send(()).expect("first-byte signal");
        release_rx.recv().expect("post-cancel release");

        let mut total = 1_u64;
        let mut buffer = [0_u8; 65_536];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => total += u64::try_from(count).expect("buffer count fits u64"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("unexpected target read error: {error}"),
            }
        }
        final_count_tx.send(total).expect("final byte count");
    });

    let cancellation = DispatchCancellation::new();
    let worker_cancellation = cancellation.clone();
    let worker = thread::spawn(move || {
        TcpTargetTransport::new().dispatch_cancellable(
            &large_action(target),
            &worker_cancellation,
            DispatchLimits {
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
                maximum_response_bytes: 65_536,
            },
        )
    });
    first_byte_rx.recv().expect("target observed first byte");

    // When: cancellation reports whether it acknowledges a stable target-byte
    // boundary, before the target is allowed to drain queued bytes.
    let disposition = cancellation.cancel().expect("cancellation request");
    release_tx.send(()).expect("release target reader");
    let final_count = final_count_rx.recv().expect("final target byte count");
    let observation = worker.join().expect("transport worker");
    server.join().expect("owned target worker");

    // Then: an active generic TCP cancellation must be non-acknowledged and
    // terminally unknown; otherwise the target-visible count must be stable.
    assert_eq!(observation.outcome, DispatchOutcome::UnknownOutcome);
    assert_eq!(
        disposition,
        CancellationDisposition::TargetOutcomeUnknown,
        "active TCP cancellation falsely claimed stability after the target eventually observed {final_count} bytes"
    );
}
