//! One table slot that holds either role (X3.5 CP).
//!
//! `LinkTable` is a single-type table, so the CP fixture stores this enum and
//! forwards the timing contract to whichever engine the slot currently holds.

use crate::crypto::engine::AesEngine;
use crate::ll::conn::ConnError;
use crate::ll::sched::{Expiry, LinkWindow, ScheduledLink};
use crate::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use crate::rf::LinkRadio;
use crate::time::InstantUs;

use super::central::CentralLink;
use super::{step as peripheral_step, Control, LinkHost, Session, SessionLink};

/// A slot that can be a Peripheral or a Central link.
// The two engines differ in size by design; a slot holds exactly one of them.
#[allow(clippy::large_enum_variant)]
pub enum CpLink<E: AesEngine> {
    Peripheral(SessionLink<E>),
    Central(CentralLink),
}

impl<E: AesEngine> CpLink<E> {
    pub fn peripheral(session: Session<E>) -> Self {
        Self::Peripheral(SessionLink::new(session))
    }

    pub fn central(link: CentralLink) -> Self {
        Self::Central(link)
    }

    pub fn as_central(&self) -> Option<&CentralLink> {
        match self {
            Self::Central(link) => Some(link),
            Self::Peripheral(_) => None,
        }
    }

    pub fn as_central_mut(&mut self) -> Option<&mut CentralLink> {
        match self {
            Self::Central(link) => Some(link),
            Self::Peripheral(_) => None,
        }
    }

    pub fn as_session(&self) -> Option<&Session<E>> {
        match self {
            Self::Peripheral(link) => Some(&link.session),
            Self::Central(_) => None,
        }
    }

    /// Drive the held engine once; the table owns event advancement.
    #[allow(clippy::too_many_arguments)]
    pub fn step<H: LinkHost<Aes = E>, R: LinkRadio, C: InstantUs>(
        &mut self,
        host: &mut H,
        radio: &mut R,
        clock: &C,
        rx: &mut DmaBuf<RX_DMA_MIN>,
        tx: &mut DmaBuf<MAX_PDU>,
        finish: u32,
    ) -> Control {
        match self {
            Self::Peripheral(link) => {
                peripheral_step(&mut link.session, host, radio, clock, rx, tx, finish)
            }
            Self::Central(link) => super::central::step(link, host, radio, clock, rx, tx, finish),
        }
    }

    /// True once if the last [`step`] ran a connection event body.
    pub fn take_event_served(&mut self) -> bool {
        match self {
            Self::Peripheral(link) => link.session.take_event_served(),
            Self::Central(link) => link.take_event_served(),
        }
    }
}

impl<E: AesEngine> ScheduledLink for CpLink<E> {
    fn window(&self) -> LinkWindow {
        match self {
            Self::Peripheral(link) => link.window(),
            Self::Central(link) => link.window(),
        }
    }

    fn advance_one(&mut self) -> Result<(), ConnError> {
        match self {
            Self::Peripheral(link) => link.advance_one(),
            Self::Central(link) => link.advance_one(),
        }
    }

    fn expiry(&self, now: u32) -> Option<Expiry> {
        match self {
            Self::Peripheral(link) => link.expiry(now),
            Self::Central(link) => link.expiry(now),
        }
    }
}
