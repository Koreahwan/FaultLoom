use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};

use faultloom_gateway::Digest;

use crate::bootstrap_fixture::TestBootstrap;
use crate::journal::AckCommitPause;
use crate::process::{ProcessHarness, now_millis};

static NEXT_RESTART: AtomicU64 = AtomicU64::new(0);

pub fn rotate_bootstrap_for_restart(
    bootstrap: &TestBootstrap,
    expected_journal_anchor: Digest,
) -> TestBootstrap {
    let sequence = NEXT_RESTART.fetch_add(1, Ordering::Relaxed);
    let now = now_millis();
    let rotated_key = |domain: &[u8]| {
        let mut material = Vec::with_capacity(domain.len() + 64);
        material.extend_from_slice(domain);
        material.extend_from_slice(&sequence.to_be_bytes());
        material.extend_from_slice(&now.to_be_bytes());
        material.extend_from_slice(bootstrap.secrets.gateway_boot_id.as_bytes());
        *Digest::of(&material).as_bytes()
    };

    let mut rotated = bootstrap.clone();
    rotated.secrets.channel_key_id = format!("channel-key:restart:{sequence}");
    rotated.secrets.channel_key = rotated_key(b"faultloom-test-restart-channel-key-v1\0");
    rotated.secrets.channel_boot_id = format!("channel-boot:restart:{sequence}");
    rotated
        .secrets
        .channel_nonce
        .copy_from_slice(&rotated_key(b"faultloom-test-restart-channel-nonce-v1\0")[..16]);
    rotated.secrets.channel_issued_at_millis = now.saturating_sub(1_000);
    rotated.secrets.channel_expires_at_millis = now + 120_000;
    rotated.secrets.epoch_channel_key_id = format!("epoch-key:restart:{sequence}");
    rotated.secrets.epoch_channel_key =
        rotated_key(b"faultloom-test-restart-epoch-channel-key-v1\0");
    rotated.secrets.gateway_boot_id = format!("gateway-boot:restart:{sequence}");
    rotated.secrets.gateway_challenge =
        rotated_key(b"faultloom-test-restart-gateway-challenge-v1\0");
    rotated.expected_journal_anchor = expected_journal_anchor;
    rotated.boot.issued_at_millis = now.saturating_sub(1_000);
    rotated.boot.expires_at_millis = now + 20_000;
    rotated.boot.sequence = bootstrap.boot.sequence.saturating_add(sequence + 1);
    rotated.boot.nonce.copy_from_slice(
        &rotated_key(b"faultloom-test-restart-boot-authorization-nonce-v1\0")[..16],
    );
    rotated
}

impl ProcessHarness {
    pub fn terminate_without_shutdown(mut self) {
        self.child
            .kill()
            .expect("kill supervised gateway before EOF");
        let status = self.wait_for_exit("forced supervisor termination");
        drop(self.input.take());
        self.close_journal_guards();
        self.join_journal();
        assert!(
            !status.success(),
            "killed supervised gateway reported success"
        );
    }

    pub fn terminate_during_paused_journal_ack(mut self, acknowledgement: AckCommitPause) {
        self.child
            .kill()
            .expect("kill supervised gateway while journal ACK is paused");
        let status = self.wait_for_exit("forced supervisor termination during journal ACK");
        drop(self.input.take());
        self.close_journal_guards();
        acknowledgement.release();
        self.join_journal_after_forced_ack_disconnect();
        assert!(
            !status.success(),
            "killed supervised gateway reported success"
        );
    }

    fn join_journal_after_forced_ack_disconnect(&mut self) {
        let error = self
            .journal_worker
            .take()
            .expect("fake journal worker")
            .join()
            .expect("join fake journal")
            .expect_err("paused journal ACK reply unexpectedly survived child termination");
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert_eq!(
            error.raw_os_error(),
            Some(32),
            "forced journal ACK disconnect was not an OS EPIPE: {error}"
        );
    }
}
