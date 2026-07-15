use crate::Digest;
use crate::ipc::DenialCode;
use crate::supervisor_wire::Encoder;

use super::AuthorizedStartup;

impl AuthorizedStartup {
    pub(super) fn durability_binding(&self) -> Result<Digest, DenialCode> {
        let mut encoder = Encoder::new(b"FLDB", 4, 1);
        encoder.string(&self.stable.authority_key_id)?;
        encoder.digest(self.stable.grant_payload_digest);
        encoder.string(&self.stable.grant_id)?;
        encoder.u64(self.stable.grant_version);
        encoder.digest(self.stable.selection_digest);
        for (kind, key_id, key) in [
            (
                1,
                self.secrets.lease_key_id.as_str(),
                self.secrets.lease_key,
            ),
            (
                2,
                self.secrets.compiler_key_id.as_str(),
                self.secrets.compiler_key,
            ),
            (
                3,
                self.secrets.journal_key_id.as_str(),
                self.secrets.journal_key,
            ),
            (
                4,
                self.secrets.reconciliation_key_id.as_str(),
                self.secrets.reconciliation_verification_key,
            ),
        ] {
            encoder.byte(kind);
            encoder.string(key_id)?;
            encoder.key(key);
        }
        encoder.finish().map(|encoded| Digest::of(&encoded))
    }
}
