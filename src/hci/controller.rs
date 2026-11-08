//! Soft HCI controller facade for Trouble Host.
//!
//! [`SoftController`] is `bt_hci`'s [`ExternalController`] over [`HciTransport`].
//! That single type already implements `Controller` plus every
//! `ControllerCmdSync` / `ControllerCmdAsync` bound Trouble demands — commands
//! are serialized onto the in-process channels; [`crate::hci::runner::SoftRunner`]
//! must reply with Command Complete / Status.

use bt_hci::controller::ExternalController;

use super::transport::HciTransport;

/// Number of concurrent command slots in the ExternalController state machine.
const CMD_SLOTS: usize = 4;

/// Soft HCI controller type consumed by `trouble_host::new`.
pub type SoftController = ExternalController<HciTransport, CMD_SLOTS>;

/// Build the Host-facing controller. Spawn / poll a [`super::runner::SoftRunner`]
/// alongside it or command `exec` will wait forever for Command Complete.
pub fn new() -> SoftController {
    ExternalController::new(HciTransport::new())
}

/// Compile-time proof that Phase A typechecks against `bt-hci`'s Controller trait.
#[cfg(test)]
mod bounds {
    use super::SoftController;
    use bt_hci::controller::Controller;

    fn assert_controller<T: Controller>() {}

    #[test]
    fn soft_controller_implements_bt_hci_controller() {
        assert_controller::<SoftController>();
    }
}
