//! Fixed-capacity link scheduling policy for the two-link pilot.
//!
//! This module is radio-free: links expose their next event window and advance
//! their own channel/instant state. The table only decides what may run, hands
//! out one dispatch ticket at a time, and keeps an unconfirmed RF stop globally
//! blocking. Real `Session`/RF wiring stays outside this module.
//!
//! The table is the only advance owner. A driver must report whether an event
//! was consumed instead of advancing the connection itself; the existing
//! `connection_event` tail advance is a wiring item for a later stage.

use core::array::from_fn;

use super::conn::{time_reached, ConnError};

/// The X3 pilot supports at most two active links.
pub const MAX_LINKS: usize = 2;
/// Time reserved before a Peripheral RX window or a Central first TX.
pub const ARM_LEAD_US: u32 = 100;
/// Tail kept free after an event before the next interval.
pub const EVENT_TAIL_US: u32 = 600;

/// Link identity assigned by the table. `generation == 0` is never issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkId {
    slot: u8,
    generation: u32,
}

impl LinkId {
    pub fn slot(self) -> u8 {
        self.slot
    }
    pub fn generation(self) -> u32 {
        self.generation
    }
}

/// Background work identity; it never consumes a link slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkId {
    generation: u32,
}

impl WorkId {
    pub fn generation(self) -> u32 {
        self.generation
    }
}

/// Why a link is closing. The scheduler never invents a protocol reason for
/// terminations: the adapter supplies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseCause {
    EstablishmentTimeout,
    SupervisionTimeout,
    Termination,
    AdvanceError,
    InvalidWindow,
}

impl CloseCause {
    pub fn default_reason(self) -> u8 {
        match self {
            Self::EstablishmentTimeout | Self::AdvanceError | Self::InvalidWindow => 0x3e,
            Self::SupervisionTimeout => 0x08,
            Self::Termination => 0x13,
        }
    }
}

/// The next event of one link, as seen by the policy layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkWindow {
    /// Earliest resource occupancy (RX arm lead or Central TX lead).
    pub prepare_us: u32,
    /// Last legal start; at or after this point no new event may begin.
    pub latest_start_us: u32,
    /// Worst-case release bound of one complete modeled event.
    pub reservation_end_us: u32,
    /// Conservative occupancy needed for one legal service.
    pub min_service_us: u32,
    /// Link hard deadline (establishment, supervision or termination).
    pub deadline_us: u32,
    pub deadline_cause: CloseCause,
    pub deadline_reason: u8,
    pub channel: u8,
    /// Lower value wins when two links prepare at the same time.
    pub priority: u8,
    /// Connection event counter at the time the window was read.
    pub event: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    Order,
    Range,
    ServiceBudget,
}

impl LinkWindow {
    /// Validate ordering and half-range distances against the fresh `now`.
    pub fn validate(&self, now: u32) -> Result<(), WindowError> {
        if !half_ok(now, self.prepare_us)
            || !half_ok(now, self.latest_start_us)
            || !half_ok(now, self.reservation_end_us)
            || !half_ok(now, self.deadline_us)
        {
            return Err(WindowError::Range);
        }
        let prepare_to_latest =
            span(self.prepare_us, self.latest_start_us).ok_or(WindowError::Order)?;
        let latest_to_end =
            span(self.latest_start_us, self.reservation_end_us).ok_or(WindowError::Order)?;
        let prepare_to_end =
            span(self.prepare_us, self.reservation_end_us).ok_or(WindowError::Order)?;
        let _ = (prepare_to_latest, latest_to_end);
        if self.min_service_us > prepare_to_end {
            return Err(WindowError::ServiceBudget);
        }
        Ok(())
    }
}

/// A hard deadline that has already been observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expiry {
    pub at_us: u32,
    pub cause: CloseCause,
    pub reason: u8,
}

/// One link's timing source. The table is the only caller of `advance_one`.
pub trait ScheduledLink {
    fn window(&self) -> LinkWindow;
    /// Consume exactly one candidate event without RF. Must apply CSA/map and
    /// update instants, even when no packet is served. Only the table calls
    /// this: once for a skip and once after a reported `consumed_event`.
    fn advance_one(&mut self) -> Result<(), ConnError>;
    /// Must return `Some` no later than `window().deadline_us`, with the cause
    /// that applies. A deadline without a matching expiry keeps the link active.
    fn expiry(&self, now: u32) -> Option<Expiry>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundKind {
    Advertising,
    Scanning,
}

/// A background fragment. It is admitted only when the whole fragment and its
/// exit cost fit before the next connection preparation point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackgroundWindow {
    pub kind: BackgroundKind,
    pub start_us: u32,
    pub end_us: u32,
    pub exit_us: u32,
    pub priority: u8,
}

impl BackgroundWindow {
    fn validate(&self, now: u32) -> Result<(), WindowError> {
        if !half_ok(now, self.start_us) || !half_ok(now, self.end_us) {
            return Err(WindowError::Range);
        }
        let release = self.end_us.wrapping_add(self.exit_us);
        if self.exit_us > i32::MAX as u32
            || span(self.start_us, self.end_us).is_none()
            || span(self.end_us, release).is_none()
            || span(self.start_us, release).is_none()
        {
            return Err(WindowError::Order);
        }
        Ok(())
    }
}

/// A one-shot permission to run one link event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    id: LinkId,
    run: u32,
    event: u16,
    latest_start_us: u32,
    hard_end_us: u32,
}

impl Ticket {
    pub fn id(self) -> LinkId {
        self.id
    }
    pub fn run(self) -> u32 {
        self.run
    }
    pub fn event(self) -> u16 {
        self.event
    }
    pub fn latest_start_us(self) -> u32 {
        self.latest_start_us
    }
    pub fn hard_end_us(self) -> u32 {
        self.hard_end_us
    }
}

/// A one-shot permission to run one background fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkTicket {
    id: WorkId,
    run: u32,
    start_us: u32,
    end_us: u32,
    hard_end_us: u32,
}

impl WorkTicket {
    pub fn id(self) -> WorkId {
        self.id
    }
    pub fn run(self) -> u32 {
        self.run
    }
    pub fn start_us(self) -> u32 {
        self.start_us
    }
    pub fn end_us(self) -> u32 {
        self.end_us
    }
    pub fn hard_end_us(self) -> u32 {
        self.hard_end_us
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// The link's own window had already started.
    Late,
    /// A previously committed link event overlapped this window.
    Conflict,
    /// The complete reservation did not fit before the link deadline.
    ReservationBudget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Run {
        ticket: Ticket,
        window: LinkWindow,
    },
    RunBackground {
        ticket: WorkTicket,
        window: BackgroundWindow,
    },
    Skipped {
        id: LinkId,
        reason: SkipReason,
    },
    BackgroundMissed {
        id: WorkId,
    },
    Close {
        id: LinkId,
        cause: CloseCause,
        reason: u8,
    },
    Busy {
        until_us: u32,
    },
    Faulted,
    Idle {
        until_us: u32,
    },
    Budget,
    Invalid {
        id: LinkId,
        error: WindowError,
    },
    /// The dispatch counter is exhausted; existing links can still close.
    Exhausted,
}

/// What the driver reports after a dispatched event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventOutcome {
    /// The event ran. `idle_at_us` is the confirmed RF idle point.
    /// `consumed_event` asks the table to advance exactly one event; the
    /// driver must not advance the connection itself. `false` means no event
    /// occurred, so the same window may be retried while `latest_start` is
    /// still in the future (revalidated by `begin`).
    Done {
        consumed_event: bool,
        idle_at_us: u32,
    },
    /// The authorized event was lost with RF confirmed idle. The table
    /// advances exactly one event; outstanding LL data is left to the link
    /// layer.
    Missed { idle_at_us: u32 },
    /// RF/DMA idle was not confirmed. All further dispatch is blocked.
    StopUnconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompleteResult {
    Released {
        consumed_event: bool,
    },
    Overrun {
        consumed_event: bool,
        actual_end_us: u32,
    },
    /// RF/DMA idle was not confirmed; the table stays globally faulted.
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError {
    Full,
    GenerationExhausted,
    BackgroundBusy,
    Range,
    Order,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveError {
    NotFound,
    InFlight,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginError {
    StaleTicket,
    AlreadyBegun,
    NotReady,
    Expired,
    Removed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompleteError {
    StaleTicket,
    NotInFlight,
    /// Unconfirmed RF idle: the retained dispatch cannot be cancelled.
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetError {
    Busy,
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverError {
    NotFaulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Active,
    Closing {
        cause: CloseCause,
        reason: u8,
        reported: bool,
    },
}

/// The physical owner of the most recent confirmed RF release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Link(LinkId),
    Background,
    Recovery,
}

#[derive(Clone, Copy)]
struct Candidate {
    id: LinkId,
    window: LinkWindow,
}

#[derive(Clone, Copy)]
struct BackgroundWork {
    id: WorkId,
    window: BackgroundWindow,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Work {
    Link(Ticket),
    Background(WorkTicket),
}

impl Work {
    fn hard_end_us(self) -> u32 {
        match self {
            Self::Link(t) => t.hard_end_us,
            Self::Background(t) => t.hard_end_us,
        }
    }
}

#[derive(Clone, Copy)]
enum Dispatch {
    Reserved(Work),
    InFlight(Work),
}

impl Dispatch {
    fn work(self) -> Work {
        match self {
            Self::Reserved(w) | Self::InFlight(w) => w,
        }
    }
    fn hard_end_us(self) -> u32 {
        self.work().hard_end_us()
    }
    fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved(_))
    }
}

struct Slot<L> {
    id: LinkId,
    link: L,
    state: SlotState,
}

pub struct LinkTable<L: ScheduledLink, const N: usize> {
    slots: [Option<Slot<L>>; N],
    background: Option<BackgroundWork>,
    dispatch: Option<Dispatch>,
    next_generation: u32,
    next_work_generation: u32,
    next_run: u32,
    last_served: Option<u8>,
    last_owner: Option<Owner>,
    last_release_us: Option<u32>,
    guard_us: u32,
    faulted: bool,
    overruns: u32,
}

impl<L: ScheduledLink, const N: usize> LinkTable<L, N> {
    pub fn new(guard_us: u32) -> Self {
        assert!(N >= 1 && N <= MAX_LINKS, "link table capacity is 1..=2");
        assert!(
            guard_us <= i32::MAX as u32,
            "guard must stay inside the half range"
        );
        Self {
            slots: from_fn(|_| None),
            background: None,
            dispatch: None,
            next_generation: 1,
            next_work_generation: 1,
            next_run: 1,
            last_served: None,
            last_owner: None,
            last_release_us: None,
            guard_us,
            faulted: false,
            overruns: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn overruns(&self) -> u32 {
        self.overruns
    }

    pub fn is_faulted(&self) -> bool {
        self.faulted
    }

    pub fn link(&self, id: LinkId) -> Option<&L> {
        self.slots
            .iter()
            .flatten()
            .find(|s| s.id == id)
            .map(|s| &s.link)
    }

    /// Mutable access for control state. Window changes made here are
    /// revalidated by `begin`; callers must not use this to advance a reserved
    /// link behind the table's back.
    pub fn link_mut(&mut self, id: LinkId) -> Option<&mut L> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|s| s.id == id)
            .map(|s| &mut s.link)
    }

    pub fn insert(&mut self, link: L) -> Result<LinkId, InsertError> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(InsertError::Full)?;
        let generation = self.alloc_generation()?;
        let id = LinkId {
            slot: slot as u8,
            generation,
        };
        self.slots[slot] = Some(Slot {
            id,
            link,
            state: SlotState::Active,
        });
        Ok(id)
    }

    pub fn remove(&mut self, id: LinkId) -> Result<L, RemoveError> {
        let Some(idx) = self.slot_index(id) else {
            return Err(RemoveError::NotFound);
        };
        if self.dispatch_refers_to_link(id) {
            return Err(RemoveError::InFlight);
        }
        Ok(self.slots[idx].take().unwrap().link)
    }

    pub fn insert_background(
        &mut self,
        window: BackgroundWindow,
        now: u32,
    ) -> Result<WorkId, InsertError> {
        if self.background.is_some() {
            return Err(InsertError::BackgroundBusy);
        }
        window.validate(now).map_err(|error| match error {
            WindowError::Range => InsertError::Range,
            WindowError::Order | WindowError::ServiceBudget => InsertError::Order,
        })?;
        let generation = self.alloc_work_generation()?;
        let id = WorkId { generation };
        self.background = Some(BackgroundWork { id, window });
        Ok(id)
    }

    pub fn remove_background(&mut self, id: WorkId) -> Result<BackgroundWindow, RemoveError> {
        if self.dispatch_refers_to_work(id) {
            return Err(RemoveError::InFlight);
        }
        let Some(work) = self.background else {
            return Err(RemoveError::NotFound);
        };
        if work.id != id {
            return Err(RemoveError::NotFound);
        }
        self.background = None;
        Ok(work.window)
    }

    /// Decide the next action. One call advances at most one skipped event.
    pub fn select(&mut self, now: u32, finish: u32) -> Decision {
        if self.faulted {
            return Decision::Faulted;
        }
        if let Some(dispatch) = self.dispatch {
            return Decision::Busy {
                until_us: dispatch.hard_end_us(),
            };
        }
        if time_reached(now, finish) {
            return Decision::Budget;
        }

        // A link whose advance failed after its event must still be reported once.
        for slot in self.slots.iter_mut().flatten() {
            if let SlotState::Closing {
                cause,
                reason,
                reported: false,
            } = slot.state
            {
                slot.state = SlotState::Closing {
                    cause,
                    reason,
                    reported: true,
                };
                return Decision::Close {
                    id: slot.id,
                    cause,
                    reason,
                };
            }
        }

        // Deadlines are checked before any candidate, once per slot.
        let mut earliest_expiry: Option<(LinkId, Expiry)> = None;
        for slot in self.slots.iter().flatten() {
            if matches!(slot.state, SlotState::Closing { .. }) {
                continue;
            }
            if let Some(expiry) = slot.link.expiry(now) {
                if earliest_expiry
                    .map(|(_, best)| strictly_before(expiry.at_us, best.at_us))
                    .unwrap_or(true)
                {
                    earliest_expiry = Some((slot.id, expiry));
                }
            }
        }
        if let Some((id, expiry)) = earliest_expiry {
            if let Some(slot) = self.slot_mut(id) {
                slot.state = SlotState::Closing {
                    cause: expiry.cause,
                    reason: expiry.reason,
                    reported: true,
                };
            }
            return Decision::Close {
                id,
                cause: expiry.cause,
                reason: expiry.reason,
            };
        }

        // Read and validate fresh windows.
        let mut best: Option<Candidate> = None;
        let mut earliest_deadline: Option<u32> = None;
        let mut invalid: Option<(LinkId, WindowError)> = None;
        for slot in self.slots.iter() {
            let Some(slot) = slot else { continue };
            if matches!(slot.state, SlotState::Closing { .. }) {
                continue;
            }
            let window = slot.link.window();
            if let Err(error) = window.validate(now) {
                invalid = Some((slot.id, error));
                break;
            }
            earliest_deadline = Some(match earliest_deadline {
                Some(d) if strictly_before(d, window.deadline_us) => d,
                _ => window.deadline_us,
            });
            let candidate = Candidate {
                id: slot.id,
                window,
            };
            if best
                .map(|current| candidate_is_better(&candidate, &current, self.last_served))
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
        if let Some((id, error)) = invalid {
            if let Some(slot) = self.slot_mut(id) {
                slot.state = SlotState::Closing {
                    cause: CloseCause::InvalidWindow,
                    reason: CloseCause::InvalidWindow.default_reason(),
                    reported: true,
                };
            }
            return Decision::Invalid { id, error };
        }

        if let Some(candidate) = best {
            // A different link cannot arm before the previous release + guard.
            let gate = self.switch_gate(candidate.id);
            let earliest = match gate {
                Some(gate) if strictly_before(candidate.window.prepare_us, gate) => gate,
                _ => candidate.window.prepare_us,
            };
            if time_reached(now, candidate.window.latest_start_us) {
                let reason = self.skip_reason(candidate.id, candidate.window.prepare_us);
                return self.skip(candidate.id, reason);
            }
            if strictly_before(now, earliest) {
                // Not ready yet. Background may still fit in the gap.
                if let Some(decision) =
                    self.try_background(now, finish, Some(earliest), earliest_deadline)
                {
                    return decision;
                }
                let until = earlier(earliest, finish);
                let until = match earliest_deadline {
                    Some(deadline) if strictly_before(deadline, until) => deadline,
                    _ => until,
                };
                return Decision::Idle { until_us: until };
            }
            if let Some(gate) = gate {
                if time_reached(gate, candidate.window.latest_start_us) {
                    return self.skip(candidate.id, SkipReason::Conflict);
                }
            }
            // The ticket authorizes only up to the promised release; the
            // deadline and global finish can only shorten it.
            let hard_end = earlier(
                earlier(
                    candidate.window.reservation_end_us,
                    candidate.window.deadline_us,
                ),
                finish,
            );
            if !service_fits(now, candidate.window.min_service_us, hard_end) {
                return self.skip(candidate.id, SkipReason::ReservationBudget);
            }
            if self.next_run == 0 {
                return Decision::Exhausted;
            }
            let ticket = Ticket {
                id: candidate.id,
                run: self.next_run,
                event: candidate.window.event,
                latest_start_us: candidate.window.latest_start_us,
                hard_end_us: hard_end,
            };
            self.next_run = self.next_run.wrapping_add(1);
            self.dispatch = Some(Dispatch::Reserved(Work::Link(ticket)));
            return Decision::Run {
                ticket,
                window: candidate.window,
            };
        }

        // No active links: background work, if any.
        if let Some(decision) = self.try_background(now, finish, None, earliest_deadline) {
            return decision;
        }
        let mut until = finish;
        if let Some(deadline) = earliest_deadline {
            if strictly_before(deadline, until) {
                until = deadline;
            }
        }
        Decision::Idle { until_us: until }
    }

    /// Recheck a reserved link ticket against fresh time and link state.
    pub fn begin(&mut self, ticket: Ticket, now: u32) -> Result<(), BeginError> {
        let Some(dispatch) = self.dispatch else {
            return Err(BeginError::StaleTicket);
        };
        if !dispatch.is_reserved() {
            return Err(BeginError::AlreadyBegun);
        }
        let Work::Link(current) = dispatch.work() else {
            return Err(BeginError::StaleTicket);
        };
        if current != ticket {
            return Err(BeginError::StaleTicket);
        }
        let Some(slot) = self.slot_mut(ticket.id) else {
            self.dispatch = None;
            return Err(BeginError::Removed);
        };
        if matches!(slot.state, SlotState::Closing { .. }) {
            self.dispatch = None;
            return Err(BeginError::Removed);
        }
        // Revalidate the current window: event equality is not a version. If
        // the new bounds are tighter than the ticket, reject it rather than
        // let the driver keep a wider grant.
        let window = slot.link.window();
        let authorized_end = earlier(
            earlier(window.reservation_end_us, window.deadline_us),
            ticket.hard_end_us,
        );
        let expired = strictly_before(authorized_end, ticket.hard_end_us)
            || window.validate(now).is_err()
            || slot.link.expiry(now).is_some()
            || time_reached(now, window.latest_start_us)
            || time_reached(now, window.deadline_us)
            || time_reached(now, ticket.latest_start_us)
            || time_reached(now, ticket.hard_end_us)
            || window.event != ticket.event
            || !service_fits(now, window.min_service_us, authorized_end);
        if expired {
            self.dispatch = None;
            return Err(BeginError::Expired);
        }
        if strictly_before(now, window.prepare_us) {
            return Err(BeginError::NotReady);
        }
        self.dispatch = Some(Dispatch::InFlight(Work::Link(ticket)));
        self.last_served = Some(ticket.id.slot());
        Ok(())
    }

    /// Recheck a reserved background ticket before starting it.
    pub fn begin_background(&mut self, ticket: WorkTicket, now: u32) -> Result<(), BeginError> {
        let Some(dispatch) = self.dispatch else {
            return Err(BeginError::StaleTicket);
        };
        if !dispatch.is_reserved() {
            return Err(BeginError::AlreadyBegun);
        }
        let Work::Background(current) = dispatch.work() else {
            return Err(BeginError::StaleTicket);
        };
        if current != ticket {
            return Err(BeginError::StaleTicket);
        }
        let Some(work) = self.background else {
            self.dispatch = None;
            return Err(BeginError::Removed);
        };
        if work.id != ticket.id {
            self.dispatch = None;
            return Err(BeginError::Removed);
        }
        let start = match self.background_gate() {
            Some(gate) if strictly_before(work.window.start_us, gate) => gate,
            _ => work.window.start_us,
        };
        if strictly_before(now, start) {
            return Err(BeginError::NotReady);
        }
        let link_prepare = self.earliest_active_prepare();
        let gap_ok = match link_prepare {
            Some(prepare) => background_fits(work.window, now, prepare, self.guard_us),
            None => true,
        };
        if !gap_ok
            || time_reached(start, work.window.end_us)
            || time_reached(now, ticket.hard_end_us)
            || time_reached(now, work.window.end_us)
        {
            self.dispatch = None;
            return Err(BeginError::Expired);
        }
        self.dispatch = Some(Dispatch::InFlight(Work::Background(ticket)));
        Ok(())
    }

    pub fn complete(
        &mut self,
        ticket: Ticket,
        outcome: EventOutcome,
    ) -> Result<CompleteResult, CompleteError> {
        if self.faulted {
            return Err(CompleteError::NotInFlight);
        }
        let Some(dispatch) = self.dispatch else {
            return Err(CompleteError::StaleTicket);
        };
        let Dispatch::InFlight(Work::Link(current)) = dispatch else {
            return Err(CompleteError::NotInFlight);
        };
        if current != ticket {
            return Err(CompleteError::StaleTicket);
        }
        self.finish_dispatch(Some(ticket.id), ticket.hard_end_us, outcome)
    }

    pub fn complete_background(
        &mut self,
        ticket: WorkTicket,
        outcome: EventOutcome,
    ) -> Result<CompleteResult, CompleteError> {
        if self.faulted {
            return Err(CompleteError::NotInFlight);
        }
        let Some(dispatch) = self.dispatch else {
            return Err(CompleteError::StaleTicket);
        };
        let Dispatch::InFlight(Work::Background(current)) = dispatch else {
            return Err(CompleteError::NotInFlight);
        };
        if current != ticket {
            return Err(CompleteError::StaleTicket);
        }
        self.finish_dispatch(None, ticket.hard_end_us, outcome)
    }

    /// Cancel a reserved ticket before it starts. In-flight work must complete.
    pub fn cancel(&mut self, ticket: Ticket) -> Result<(), CompleteError> {
        self.cancel_dispatch(Work::Link(ticket))
    }

    pub fn cancel_background(&mut self, ticket: WorkTicket) -> Result<(), CompleteError> {
        self.cancel_dispatch(Work::Background(ticket))
    }

    /// Leave the global fault after the caller has confirmed RF/DMA idle at
    /// `idle_at_us`. The recovery release participates in the switch guard.
    pub fn recover_quiescent(&mut self, idle_at_us: u32) -> Result<(), RecoverError> {
        if !self.faulted {
            return Err(RecoverError::NotFaulted);
        }
        self.dispatch = None;
        self.faulted = false;
        self.last_owner = Some(Owner::Recovery);
        self.last_release_us = Some(idle_at_us);
        Ok(())
    }

    /// Clear all links; refused while a dispatch or fault is outstanding.
    /// The last confirmed RF release is kept so a switch guard still applies.
    pub fn reset(&mut self) -> Result<(), ResetError> {
        if self.faulted {
            return Err(ResetError::Faulted);
        }
        if self.dispatch.is_some() {
            return Err(ResetError::Busy);
        }
        self.slots = from_fn(|_| None);
        self.background = None;
        self.last_served = None;
        Ok(())
    }

    fn finish_dispatch(
        &mut self,
        link: Option<LinkId>,
        hard_end_us: u32,
        outcome: EventOutcome,
    ) -> Result<CompleteResult, CompleteError> {
        if link.is_none() {
            // A background fragment is consumed even when it faults; a failed
            // fragment must be submitted again after recovery.
            self.background = None;
        }
        match outcome {
            EventOutcome::StopUnconfirmed => {
                self.faulted = true;
                Ok(CompleteResult::Faulted)
            }
            EventOutcome::Done {
                consumed_event,
                idle_at_us,
            } => {
                self.release(link, hard_end_us, idle_at_us)?;
                if consumed_event {
                    if let Some(id) = link {
                        // The table is the only advance owner: consume exactly one.
                        self.advance_after_event(id);
                    }
                }
                Ok(if strictly_before(hard_end_us, idle_at_us) {
                    CompleteResult::Overrun {
                        consumed_event,
                        actual_end_us: idle_at_us,
                    }
                } else {
                    CompleteResult::Released { consumed_event }
                })
            }
            EventOutcome::Missed { idle_at_us } => {
                self.release(link, hard_end_us, idle_at_us)?;
                if let Some(id) = link {
                    // A missed event is retired: advance exactly one event.
                    self.advance_after_event(id);
                }
                Ok(if strictly_before(hard_end_us, idle_at_us) {
                    CompleteResult::Overrun {
                        consumed_event: false,
                        actual_end_us: idle_at_us,
                    }
                } else {
                    CompleteResult::Released {
                        consumed_event: false,
                    }
                })
            }
        }
    }

    fn release(
        &mut self,
        link: Option<LinkId>,
        hard_end_us: u32,
        idle_at_us: u32,
    ) -> Result<(), CompleteError> {
        if strictly_before(hard_end_us, idle_at_us) {
            self.overruns = self.overruns.saturating_add(1);
        }
        self.dispatch = None;
        self.last_owner = Some(match link {
            Some(id) => Owner::Link(id),
            None => Owner::Background,
        });
        self.last_release_us = Some(idle_at_us);
        Ok(())
    }

    fn advance_after_event(&mut self, id: LinkId) {
        let Some(slot) = self.slot_mut(id) else {
            return;
        };
        let before = slot.link.window();
        let failed = slot.link.advance_one().is_err();
        let after = slot.link.window();
        if failed || (after.event == before.event && after.prepare_us == before.prepare_us) {
            slot.state = SlotState::Closing {
                cause: CloseCause::AdvanceError,
                reason: CloseCause::AdvanceError.default_reason(),
                reported: false,
            };
        }
    }

    fn cancel_dispatch(&mut self, expected: Work) -> Result<(), CompleteError> {
        if self.faulted {
            return Err(CompleteError::Faulted);
        }
        let Some(dispatch) = self.dispatch else {
            return Err(CompleteError::StaleTicket);
        };
        if !dispatch.is_reserved() {
            return Err(CompleteError::NotInFlight);
        }
        if dispatch.work() != expected {
            return Err(CompleteError::StaleTicket);
        }
        self.dispatch = None;
        Ok(())
    }

    fn skip(&mut self, id: LinkId, reason: SkipReason) -> Decision {
        let Some(slot) = self.slot_mut(id) else {
            let cause = CloseCause::AdvanceError;
            return Decision::Close {
                id,
                cause,
                reason: cause.default_reason(),
            };
        };
        let before = slot.link.window();
        if slot.link.advance_one().is_err() {
            let cause = CloseCause::AdvanceError;
            slot.state = SlotState::Closing {
                cause,
                reason: cause.default_reason(),
                reported: true,
            };
            return Decision::Close {
                id,
                cause,
                reason: cause.default_reason(),
            };
        }
        let after = slot.link.window();
        if after.event == before.event && after.prepare_us == before.prepare_us {
            let cause = CloseCause::AdvanceError;
            slot.state = SlotState::Closing {
                cause,
                reason: cause.default_reason(),
                reported: true,
            };
            return Decision::Close {
                id,
                cause,
                reason: cause.default_reason(),
            };
        }
        Decision::Skipped { id, reason }
    }

    /// Earliest start after a previous owner. Re-arming the same link does not
    /// pay the switch cost again; every other owner (or link) does.
    fn switch_gate(&self, id: LinkId) -> Option<u32> {
        let release = self.last_release_us?;
        if self.last_owner == Some(Owner::Link(id)) {
            return None;
        }
        Some(release.wrapping_add(self.guard_us))
    }

    /// Background work always follows a confirmed release, including one from
    /// another background fragment or a recovery.
    fn background_gate(&self) -> Option<u32> {
        self.last_release_us
            .map(|release| release.wrapping_add(self.guard_us))
    }

    fn skip_reason(&self, id: LinkId, prepare_us: u32) -> SkipReason {
        match self.switch_gate(id) {
            Some(gate) if time_reached(gate, prepare_us) => SkipReason::Conflict,
            _ => SkipReason::Late,
        }
    }

    fn try_background(
        &mut self,
        now: u32,
        finish: u32,
        link_prepare: Option<u32>,
        deadline: Option<u32>,
    ) -> Option<Decision> {
        let work = self.background?;
        let window = work.window;
        if time_reached(now, window.end_us) {
            self.background = None;
            return Some(Decision::BackgroundMissed { id: work.id });
        }
        let start = match self.background_gate() {
            Some(gate) if strictly_before(window.start_us, gate) => gate,
            _ => window.start_us,
        };
        if time_reached(start, window.end_us) {
            self.background = None;
            return Some(Decision::BackgroundMissed { id: work.id });
        }
        if strictly_before(now, start) {
            let mut until = start;
            if let Some(prepare) = link_prepare {
                if strictly_before(prepare, until) {
                    until = prepare;
                }
            }
            if strictly_before(finish, until) {
                until = finish;
            }
            if let Some(deadline) = deadline {
                if strictly_before(deadline, until) {
                    until = deadline;
                }
            }
            return Some(Decision::Idle { until_us: until });
        }
        let gap_ok = match link_prepare {
            Some(prepare) => background_fits(window, now, prepare, self.guard_us),
            None => true,
        };
        if !gap_ok {
            return None;
        }
        let hard_end = window.end_us.wrapping_add(window.exit_us);
        if !service_fits(now, 0, hard_end) || !time_reached(finish, hard_end) {
            return None;
        }
        if self.next_run == 0 {
            return Some(Decision::Exhausted);
        }
        let ticket = WorkTicket {
            id: work.id,
            run: self.next_run,
            start_us: start,
            end_us: window.end_us,
            hard_end_us: hard_end,
        };
        self.next_run = self.next_run.wrapping_add(1);
        self.dispatch = Some(Dispatch::Reserved(Work::Background(ticket)));
        Some(Decision::RunBackground { ticket, window })
    }

    fn earliest_active_prepare(&self) -> Option<u32> {
        self.slots
            .iter()
            .flatten()
            .filter(|s| matches!(s.state, SlotState::Active))
            .map(|s| s.link.window().prepare_us)
            .reduce(earlier)
    }

    fn slot_index(&self, id: LinkId) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.id == id))
    }

    fn slot_mut(&mut self, id: LinkId) -> Option<&mut Slot<L>> {
        self.slots.iter_mut().flatten().find(|s| s.id == id)
    }

    fn dispatch_refers_to_link(&self, id: LinkId) -> bool {
        matches!(self.dispatch.map(Dispatch::work), Some(Work::Link(t)) if t.id == id)
    }

    fn dispatch_refers_to_work(&self, id: WorkId) -> bool {
        matches!(self.dispatch.map(Dispatch::work), Some(Work::Background(t)) if t.id == id)
    }

    fn alloc_generation(&mut self) -> Result<u32, InsertError> {
        if self.next_generation == 0 {
            return Err(InsertError::GenerationExhausted);
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        Ok(generation)
    }

    fn alloc_work_generation(&mut self) -> Result<u32, InsertError> {
        if self.next_work_generation == 0 {
            return Err(InsertError::GenerationExhausted);
        }
        let generation = self.next_work_generation;
        self.next_work_generation = self.next_work_generation.wrapping_add(1);
        Ok(generation)
    }
}

fn background_fits(window: BackgroundWindow, now: u32, link_prepare: u32, guard_us: u32) -> bool {
    if time_reached(now, window.end_us) {
        return false;
    }
    let release = window.end_us.wrapping_add(window.exit_us);
    // Validate the combined spans rather than trusting a signed subtraction.
    if span(window.start_us, release).is_none() {
        return false;
    }
    let Some(gap) = span(release, link_prepare) else {
        return false;
    };
    gap >= guard_us
}

/// `min_service_us` must still fit between a fresh `now` and `end_us`.
fn service_fits(now: u32, min_service_us: u32, end_us: u32) -> bool {
    if time_reached(now, end_us) {
        return false;
    }
    span(now, end_us).is_some_and(|available| available >= min_service_us)
}

fn candidate_is_better(a: &Candidate, b: &Candidate, last_served: Option<u8>) -> bool {
    if a.window.prepare_us != b.window.prepare_us {
        return strictly_before(a.window.prepare_us, b.window.prepare_us);
    }
    if a.window.priority != b.window.priority {
        return a.window.priority < b.window.priority;
    }
    match last_served {
        Some(slot) if a.id.slot() == slot => false,
        Some(slot) if b.id.slot() == slot => true,
        _ => a.id.slot() < b.id.slot(),
    }
}

fn earlier(a: u32, b: u32) -> u32 {
    if strictly_before(b, a) {
        b
    } else {
        a
    }
}

fn strictly_before(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}

fn half_ok(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) != i32::MIN
}

fn span(start: u32, end: u32) -> Option<u32> {
    let distance = end.wrapping_sub(start);
    (distance <= i32::MAX as u32).then_some(distance)
}

#[cfg(test)]
mod tests;
