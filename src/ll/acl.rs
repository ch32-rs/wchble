//! ACL data path stubs between HCI and air PDUs.

/// Direction of an ACL fragment relative to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AclDir {
    ToHost,
    FromHost,
}

/// Minimal ACL fragment descriptor (no ownership of bytes yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AclFragment {
    pub handle: u16,
    pub dir: AclDir,
    pub len: u16,
}
