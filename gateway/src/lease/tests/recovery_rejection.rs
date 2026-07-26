    #[test]
    fn recovery_rejects_v6_format_rollback() {
        let source = authority_for_boot(
            budget(),
            "gateway:boot:rollback-source",
            b"rollback source challenge",
        );
        let checkpoint = source.checkpoint().expect("current checkpoint");
        let mut rollback = checkpoint.as_bytes().to_vec();
        rollback[4] = 6;

        assert_eq!(
            LeaseRecoveryCheckpoint::from_bytes(rollback),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );
    }

    #[test]
    fn recovery_rejects_tamper_wrong_anchor_same_boot_and_wrong_key() {
        let source = authority_for_boot(budget(), "gateway:boot:source", b"source challenge");
        let checkpoint = source.checkpoint().expect("checkpoint");

        let same_boot = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:source".to_owned(),
            Digest::of(b"different challenge"),
        )
        .expect("same boot authority");
        assert_eq!(
            same_boot.restore_checkpoint(&checkpoint, checkpoint.checkpoint_id()),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );

        let wrong_anchor = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:wrong-anchor".to_owned(),
            Digest::of(b"wrong anchor challenge"),
        )
        .expect("wrong anchor authority");
        assert_eq!(
            wrong_anchor.restore_checkpoint(&checkpoint, Digest::of(b"older checkpoint")),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );

        let mut tampered = checkpoint.as_bytes().to_vec();
        tampered[20] ^= 1;
        let tampered =
            LeaseRecoveryCheckpoint::from_bytes(tampered).expect("outer shape remains valid");
        let target = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            lease_key(),
            "gateway:boot:tamper-target".to_owned(),
            Digest::of(b"tamper target challenge"),
        )
        .expect("tamper target");
        assert_eq!(
            target.restore_checkpoint(&tampered, tampered.checkpoint_id()),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );

        let wrong_key = LeaseAuthority::new(
            "lease-key:test".to_owned(),
            std::array::from_fn(|index| u8::try_from(index + 65).expect("small wrong-key byte")),
            "gateway:boot:wrong-key".to_owned(),
            Digest::of(b"wrong key challenge"),
        )
        .expect("wrong key authority");
        assert_eq!(
            wrong_key.restore_checkpoint(&checkpoint, checkpoint.checkpoint_id()),
            Err(DenialCode::RecoveryCheckpointInvalid)
        );
    }
