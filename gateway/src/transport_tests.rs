#[cfg(test)]
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use super::*;
use crate::Digest;
use crate::ipc::{ActionKind, DispatchOutcome, EgressPlane};

fn action(target: std::net::SocketAddr) -> CompiledAction {
    CompiledAction {
        intent_digest: Digest::of(b"transport cancellation intent"),
        action_kind: ActionKind::SemanticHttpV1,
        target,
        egress_plane: EgressPlane::TargetGateway,
        semantic_action_digest: Digest::of(b"transport cancellation semantics"),
        resolution_digest: Digest::of(b"transport cancellation resolution"),
        request_binding_digest: Digest::of(b"transport cancellation binding"),
        effect_digest: crate::policy::target_effect_digest(
            ActionKind::SemanticHttpV1,
            EgressPlane::TargetGateway,
            Digest::of(b"transport cancellation resolution"),
            Digest::of(b"PING"),
        ),
        bytes: b"PING".to_vec(),
    }
}

fn limits() -> DispatchLimits {
    DispatchLimits {
        deadline: Instant::now() + Duration::from_secs(10),
        maximum_response_bytes: MAX_RESPONSE_BYTES,
    }
}

#[test]
fn cancellation_before_dispatch_never_opens_a_target_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let cancellation = DispatchCancellation::new();
    assert_eq!(
        cancellation.cancel(),
        Ok(CancellationDisposition::StableNoEgress),
        "pre-dispatch cancellation has a stable no-egress boundary"
    );

    let observation = TcpTargetTransport::new().dispatch_cancellable(
        &action(listener.local_addr().expect("listener address")),
        &cancellation,
        limits(),
    );
    assert_eq!(observation.outcome, DispatchOutcome::Failed);
    assert_eq!(observation.bytes_sent, 0);
    assert_eq!(
        listener
            .accept()
            .expect_err("cancelled dispatch cannot connect")
            .kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn cancellation_disposition_not_local_byte_count_drives_the_outcome() {
    assert_eq!(
        after_cancellation(Vec::new(), 0, CancellationDisposition::TargetOutcomeUnknown,).outcome,
        DispatchOutcome::UnknownOutcome,
        "target egress cannot be downgraded to failed merely because no local write completed"
    );
    assert_eq!(
        after_cancellation(Vec::new(), 0, CancellationDisposition::StableNoEgress).outcome,
        DispatchOutcome::Failed,
        "pre-egress cancellation remains a stable failure"
    );
}

#[test]
fn cancellation_physically_interrupts_an_in_flight_stream_exactly_once() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("listener address");
    let (request_read_tx, request_read_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("transport connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("request bytes");
        assert_eq!(&request, b"PING");
        request_read_tx.send(()).expect("request-read signal");
        release_rx.recv().expect("release server connection");
        drop(stream);
    });

    let cancellation = DispatchCancellation::new();
    let worker_cancellation = cancellation.clone();
    let worker = thread::spawn(move || {
        TcpTargetTransport::new().dispatch_cancellable(
            &action(target),
            &worker_cancellation,
            limits(),
        )
    });
    request_read_rx.recv().expect("target observed request");
    assert_eq!(
        cancellation.cancel(),
        Ok(CancellationDisposition::TargetOutcomeUnknown),
        "active TCP cancellation cannot acknowledge peer visibility"
    );
    assert_eq!(
        cancellation.cancel(),
        Ok(CancellationDisposition::TargetOutcomeUnknown),
        "repeated cancellation preserves the original unknown disposition"
    );
    let observation = worker.join().expect("transport worker");
    assert_eq!(observation.outcome, DispatchOutcome::UnknownOutcome);
    assert_eq!(observation.bytes_sent, 4);
    release_tx.send(()).expect("release server");
    server.join().expect("server worker");
}

#[test]
fn monotonic_deadline_interrupts_an_in_flight_stream_without_a_control_command() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("listener address");
    let (request_read_tx, request_read_rx) = mpsc::sync_channel(0);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("transport connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("request bytes");
        request_read_tx.send(()).expect("request-read signal");
        let mut trailing = Vec::new();
        stream
            .read_to_end(&mut trailing)
            .expect("deadline physically closes transport");
    });

    let started = Instant::now();
    let observation = TcpTargetTransport::new().dispatch_cancellable(
        &action(target),
        &DispatchCancellation::new(),
        DispatchLimits {
            deadline: started + Duration::from_millis(100),
            maximum_response_bytes: MAX_RESPONSE_BYTES,
        },
    );
    assert_eq!(request_read_rx.recv(), Ok(()));
    assert_eq!(observation.outcome, DispatchOutcome::UnknownOutcome);
    assert!(started.elapsed() < Duration::from_secs(1));
    server.join().expect("server worker");
}

#[test]
fn response_budget_is_enforced_while_reading_and_closes_the_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("transport connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("request bytes");
        stream.write_all(b"TOO-LARGE").expect("response bytes");
        let mut trailing = Vec::new();
        stream
            .read_to_end(&mut trailing)
            .expect("budget closure reaches target");
    });

    let observation = TcpTargetTransport::new().dispatch_cancellable(
        &action(target),
        &DispatchCancellation::new(),
        DispatchLimits {
            deadline: Instant::now() + Duration::from_secs(1),
            maximum_response_bytes: 4,
        },
    );
    assert_eq!(observation.outcome, DispatchOutcome::UnknownOutcome);
    assert_eq!(observation.response.len(), 4);
    server.join().expect("server worker");
}

#[test]
fn response_below_budget_completes_normally() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("transport connection");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("request bytes");
        stream.write_all(b"PONG").expect("response bytes");
    });

    let observation = TcpTargetTransport::new().dispatch_cancellable(
        &action(target),
        &DispatchCancellation::new(),
        DispatchLimits {
            deadline: Instant::now() + Duration::from_secs(1),
            maximum_response_bytes: 8,
        },
    );
    assert_eq!(observation.outcome, DispatchOutcome::Completed);
    assert_eq!(observation.response, b"PONG");
    server.join().expect("server worker");
}
