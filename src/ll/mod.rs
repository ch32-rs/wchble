//! Link-layer state machines (legacy adv, connection, ACL, LL control).

pub mod acl;
pub mod adv;
pub mod central;
pub mod conn;
pub mod ctrl;
pub mod dle;
pub mod enc;
pub mod scan;

/// High-level LL role for the scaffold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Role {
    Advertiser,
    Scanner,
    Peripheral,
    Central,
}

/// Link-layer engine shell used by the soft HCI controller.
#[derive(Debug, Default)]
pub struct LinkLayer {
    pub role: Option<Role>,
    pub adv: adv::AdvState,
    pub conn: conn::ConnState,
}

impl LinkLayer {
    pub fn new() -> Self {
        Self::default()
    }
}
