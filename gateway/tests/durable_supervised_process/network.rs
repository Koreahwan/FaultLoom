use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::fixtures::read_http_request;

pub(crate) const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
const NO_EGRESS_WINDOW: Duration = Duration::from_millis(150);

pub(crate) fn respond_once(listener: &TcpListener, body: &[u8]) -> JoinHandle<Vec<u8>> {
    let listener = listener.try_clone().expect("clone response listener");
    let body = body.to_vec();
    thread::spawn(move || {
        let mut stream = accept_bounded(&listener);
        let request = read_http_request(&mut stream);
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .expect("owned response headers");
        stream.write_all(&body).expect("owned response body");
        request
    })
}

pub(crate) fn observe_until_peer_close(
    listener: &TcpListener,
) -> (Receiver<Vec<u8>>, JoinHandle<()>) {
    let listener = listener.try_clone().expect("clone observation listener");
    let (observed_tx, observed_rx) = sync_channel(1);
    let worker = thread::spawn(move || {
        let mut stream = accept_bounded(&listener);
        let request = read_http_request(&mut stream);
        observed_tx
            .send(request)
            .expect("target observation signal");
        stream
            .set_read_timeout(Some(OBSERVATION_TIMEOUT))
            .expect("target close timeout");
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::UnexpectedEof
                ) => {}
            result => panic!("target did not observe bounded peer close: {result:?}"),
        }
    });
    (observed_rx, worker)
}

pub(crate) fn accept_bounded(listener: &TcpListener) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("nonblocking owned listener");
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("blocking owned stream");
                return stream;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("owned listener accept failed: {error}"),
        }
    }
}

pub(crate) fn assert_no_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("nonblocking target probe");
    let deadline = Instant::now() + NO_EGRESS_WINDOW;
    loop {
        match listener.accept() {
            Ok((_stream, peer)) => panic!("unexpected target connection from {peer}"),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("target probe failed: {error}"),
        }
    }
}
