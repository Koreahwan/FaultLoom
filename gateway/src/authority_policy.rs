use std::net::{IpAddr, SocketAddr};

use crate::Digest;
use crate::ipc::valid_identifier;

use super::AuthorityError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestedSelectionParts {
    pub(crate) target_id: String,
    pub(crate) hostname: String,
    pub(crate) socket: SocketAddr,
    pub(crate) protocol: String,
    pub(crate) pack_id: String,
    pub(crate) action_family: String,
    pub(crate) identity_id: String,
    pub(crate) tenant_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestedSelection {
    target_id: String,
    hostname: String,
    socket: SocketAddr,
    protocol: String,
    pack_id: String,
    action_family: String,
    identity_id: String,
    tenant_id: Option<String>,
}

impl RequestedSelection {
    pub(crate) fn from_untrusted_parts(
        parts: RequestedSelectionParts,
    ) -> Result<Self, AuthorityError> {
        if !valid_identifier(&parts.target_id)
            || !valid_hostname(&parts.hostname)
            || parts.socket.port() == 0
            || !valid_protocol(&parts.protocol)
            || !valid_identifier(&parts.pack_id)
            || !valid_identifier(&parts.action_family)
            || !valid_identifier(&parts.identity_id)
            || parts
                .tenant_id
                .as_deref()
                .is_some_and(|tenant| !valid_identifier(tenant))
        {
            return Err(AuthorityError::InvalidSelection);
        }
        Ok(Self {
            target_id: parts.target_id,
            hostname: parts.hostname,
            socket: parts.socket,
            protocol: parts.protocol,
            pack_id: parts.pack_id,
            action_family: parts.action_family,
            identity_id: parts.identity_id,
            tenant_id: parts.tenant_id,
        })
    }

    pub(crate) fn target_id(&self) -> &str {
        &self.target_id
    }

    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }

    pub(crate) const fn socket(&self) -> SocketAddr {
        self.socket
    }

    pub(crate) fn protocol(&self) -> &str {
        &self.protocol
    }

    pub(crate) fn pack_id(&self) -> &str {
        &self.pack_id
    }

    pub(crate) fn action_family(&self) -> &str {
        &self.action_family
    }

    pub(crate) fn identity_id(&self) -> &str {
        &self.identity_id
    }

    pub(crate) fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub(crate) fn binding_digest(&self) -> Digest {
        let mut bytes = Vec::with_capacity(384);
        bytes.extend_from_slice(b"faultloom-requested-selection-v1\0");
        push_string(&mut bytes, &self.target_id);
        push_string(&mut bytes, &self.hostname);
        match self.socket.ip() {
            IpAddr::V4(address) => {
                bytes.push(4);
                bytes.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                bytes.push(6);
                bytes.extend_from_slice(&address.octets());
            }
        }
        bytes.extend_from_slice(&self.socket.port().to_be_bytes());
        push_string(&mut bytes, &self.protocol);
        push_string(&mut bytes, &self.pack_id);
        push_string(&mut bytes, &self.action_family);
        push_string(&mut bytes, &self.identity_id);
        match &self.tenant_id {
            Some(tenant) => {
                bytes.push(1);
                push_string(&mut bytes, tenant);
            }
            None => bytes.push(0),
        }
        Digest::of(&bytes)
    }
}

fn valid_hostname(value: &str) -> bool {
    if let Ok(address) = value.parse::<IpAddr>() {
        return value == address.to_string().to_ascii_lowercase();
    }
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_protocol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value == value.to_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}
