use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::error::ScopePolicyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, ScopePolicyError> {
        let (address, prefix) = canonical_network(address, prefix)?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(ScopePolicyError::InvalidNetwork);
        }
        Ok(Self {
            address: mask_ip(address, prefix),
            prefix,
        })
    }

    pub(crate) fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, canonical_ip(candidate)) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                mask_v4(candidate, self.prefix) == network
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                mask_v6(candidate, self.prefix) == network
            }
            _ => false,
        }
    }
}

fn canonical_network(address: IpAddr, prefix: u8) -> Result<(IpAddr, u8), ScopePolicyError> {
    match address {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) if prefix >= 96 => Ok((IpAddr::V4(mapped), prefix - 96)),
            Some(_) => Err(ScopePolicyError::InvalidNetwork),
            None => Ok((IpAddr::V6(address), prefix)),
        },
        IpAddr::V4(address) => Ok((IpAddr::V4(address), prefix)),
    }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

fn mask_ip(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(mask_v4(address, prefix)),
        IpAddr::V6(address) => IpAddr::V6(mask_v6(address, prefix)),
    }
}

fn mask_v4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn mask_v6(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

pub(super) fn is_special_address(address: IpAddr) -> bool {
    match canonical_ip(address) {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            value >> 24 == 0
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || value >> 22 == u32::from(Ipv4Addr::new(100, 64, 0, 0)) >> 22
                || value >> 8 == u32::from(Ipv4Addr::new(192, 0, 0, 0)) >> 8
                || value >> 8 == u32::from(Ipv4Addr::new(192, 0, 2, 0)) >> 8
                || value >> 17 == u32::from(Ipv4Addr::new(198, 18, 0, 0)) >> 17
                || value >= u32::from(Ipv4Addr::new(240, 0, 0, 0))
                || value >> 8 == u32::from(Ipv4Addr::new(198, 51, 100, 0)) >> 8
                || value >> 8 == u32::from(Ipv4Addr::new(203, 0, 113, 0)) >> 8
        }
        IpAddr::V6(address) => {
            let value = u128::from(address);
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || value >> 32 == 0
                || value >> 64 == u128::from(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0)) >> 64
                || value >> 121 == u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)) >> 121
                || value >> 118 == u128::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)) >> 118
                || value >> 118 == u128::from(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0)) >> 118
                || value >> 80 == u128::from(Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0)) >> 80
                || value >> 96 == u128::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)) >> 96
        }
    }
}
