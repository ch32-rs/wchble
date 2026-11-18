use super::*;
use crate::ll::central::CentralConnection;
use crate::ll::conn::{time_reached, ConnError, ConnectParams, PeripheralConnection};

const GUARD: u32 = 10;

fn window(prepare: u32, latest: u32, end: u32, deadline: u32) -> LinkWindow {
    LinkWindow {
        prepare_us: prepare,
        latest_start_us: latest,
        reservation_end_us: end,
        min_service_us: 0,
        deadline_us: deadline,
        deadline_cause: CloseCause::SupervisionTimeout,
        deadline_reason: 0x08,
        channel: 0,
        priority: 0,
        event: 0,
    }
}

#[derive(Debug)]
struct FakeLink {
    window: LinkWindow,
    step_us: u32,
    advances: u32,
    expiry: Option<Expiry>,
    fail_advance: bool,
    stuck: bool,
}

impl FakeLink {
    fn new(prepare: u32, latest: u32, end: u32, deadline: u32) -> Self {
        Self {
            window: window(prepare, latest, end, deadline),
            step_us: 1_000,
            advances: 0,
            expiry: None,
            fail_advance: false,
            stuck: false,
        }
    }

    fn priority(mut self, priority: u8) -> Self {
        self.window.priority = priority;
        self
    }

    fn min_service(mut self, min_service_us: u32) -> Self {
        self.window.min_service_us = min_service_us;
        self
    }

    fn step(mut self, step_us: u32) -> Self {
        self.step_us = step_us;
        self
    }

    fn expiry(mut self, cause: CloseCause, at_us: u32) -> Self {
        self.expiry = Some(Expiry {
            at_us,
            cause,
            reason: cause.default_reason(),
        });
        self
    }

    fn advance_fails(mut self) -> Self {
        self.fail_advance = true;
        self
    }

    fn stuck(mut self) -> Self {
        self.stuck = true;
        self
    }
}

impl ScheduledLink for FakeLink {
    fn window(&self) -> LinkWindow {
        self.window
    }

    fn advance_one(&mut self) -> Result<(), ConnError> {
        if self.fail_advance {
            return Err(ConnError::Parameters);
        }
        if self.stuck {
            return Ok(());
        }
        self.advances += 1;
        self.window.prepare_us = self.window.prepare_us.wrapping_add(self.step_us);
        self.window.latest_start_us = self.window.latest_start_us.wrapping_add(self.step_us);
        self.window.reservation_end_us = self.window.reservation_end_us.wrapping_add(self.step_us);
        self.window.deadline_us = self.window.deadline_us.wrapping_add(self.step_us);
        self.window.event = self.window.event.wrapping_add(1);
        Ok(())
    }

    fn expiry(&self, now: u32) -> Option<Expiry> {
        self.expiry.filter(|expiry| time_reached(now, expiry.at_us))
    }
}

fn table() -> LinkTable<FakeLink, 2> {
    LinkTable::new(GUARD)
}

fn insert(table: &mut LinkTable<FakeLink, 2>, link: FakeLink) -> LinkId {
    table.insert(link).unwrap()
}

fn run(table: &mut LinkTable<FakeLink, 2>, now: u32, finish: u32) -> Ticket {
    match table.select(now, finish) {
        Decision::Run { ticket, .. } => ticket,
        other => panic!("expected Run, got {other:?}"),
    }
}

fn begin_done(table: &mut LinkTable<FakeLink, 2>, ticket: Ticket, begin: u32, idle: u32) {
    table.begin(ticket, begin).unwrap();
    table
        .complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: idle,
            },
        )
        .unwrap();
}

#[test]
fn empty_table_idles_to_finish() {
    let mut table = table();
    assert_eq!(table.select(0, 10_000), Decision::Idle { until_us: 10_000 });
}

#[test]
fn insert_two_links_and_reject_a_third() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let second = insert(&mut table, FakeLink::new(4_000, 5_000, 6_000, 50_000));
    assert_eq!(first.slot(), 0);
    assert_eq!(second.slot(), 1);
    assert_ne!(first.generation(), second.generation());
    assert_eq!(table.len(), 2);
    assert_eq!(
        table.insert(FakeLink::new(1, 2, 3, 4)),
        Err(InsertError::Full)
    );
}

#[test]
fn select_waits_for_prepare_then_issues_one_ticket() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    assert_eq!(table.select(0, 100_000), Decision::Idle { until_us: 1_000 });
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.id(), id);
    assert_eq!(
        table.select(1_000, 100_000),
        Decision::Busy {
            until_us: ticket.hard_end_us()
        }
    );
    begin_done(&mut table, ticket, 1_000, 1_500);
    assert_eq!(
        table.select(1_500, 100_000),
        Decision::Idle { until_us: 2_000 }
    );
}

#[test]
fn begin_and_duplicate_completion_are_one_shot() {
    let mut table = table();
    insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500
            }
        ),
        Err(CompleteError::NotInFlight)
    );
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(table.begin(ticket, 1_000), Err(BeginError::AlreadyBegun));
    table
        .complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500,
            },
        )
        .unwrap();
    assert_eq!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500
            }
        ),
        Err(CompleteError::StaleTicket)
    );
}

#[test]
fn begin_before_prepare_is_not_ready_and_at_latest_start_expires() {
    let mut table = table();
    insert(&mut table, FakeLink::new(1_000, 1_100, 2_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(table.begin(ticket, 999), Err(BeginError::NotReady));
    assert_eq!(table.begin(ticket, 1_100), Err(BeginError::Expired));
    assert_eq!(
        table.select(1_100, 100_000),
        Decision::Skipped {
            id: ticket.id(),
            reason: SkipReason::Late,
        }
    );
}

#[test]
fn establishment_and_supervision_expiry_close_once() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 500).expiry(CloseCause::EstablishmentTimeout, 500),
    );
    assert_eq!(
        table.select(500, 100_000),
        Decision::Close {
            id,
            cause: CloseCause::EstablishmentTimeout,
            reason: 0x3e
        }
    );
    assert_eq!(
        table.select(500, 100_000),
        Decision::Idle { until_us: 100_000 }
    );

    let mut table = LinkTable::<FakeLink, 2>::new(GUARD);
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 900).expiry(CloseCause::SupervisionTimeout, 900),
    );
    assert_eq!(
        table.select(900, 100_000),
        Decision::Close {
            id,
            cause: CloseCause::SupervisionTimeout,
            reason: 0x08
        }
    );
}

#[test]
fn a_late_link_advances_exactly_one_event_per_poll() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 1_100, 2_000, 50_000).step(2_000),
    );
    assert_eq!(
        table.select(2_000, 100_000),
        Decision::Skipped {
            id,
            reason: SkipReason::Late
        }
    );
    assert_eq!(table.link(id).unwrap().advances, 1);
    assert_eq!(
        table.select(2_000, 100_000),
        Decision::Idle { until_us: 3_000 }
    );
    assert_eq!(table.link(id).unwrap().advances, 1);
}

#[test]
fn two_late_links_take_two_polls() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(1_000, 1_100, 2_000, 50_000));
    let second = insert(&mut table, FakeLink::new(1_100, 1_200, 2_000, 50_000));
    assert!(matches!(
        table.select(3_000, 100_000),
        Decision::Skipped { id, .. } if id == first
    ));
    assert_eq!(table.link(first).unwrap().advances, 1);
    assert_eq!(table.link(second).unwrap().advances, 0);
    assert!(matches!(
        table.select(3_000, 100_000),
        Decision::Skipped { id, .. } if id == second
    ));
    assert_eq!(table.link(second).unwrap().advances, 1);
}

#[test]
fn a_skipped_after_another_run_is_reported_as_conflict() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(1_000, 2_000, 2_500, 50_000));
    let second = insert(&mut table, FakeLink::new(1_200, 1_200, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.id(), first);
    begin_done(&mut table, ticket, 1_000, 2_500);
    assert_eq!(
        table.select(2_500, 100_000),
        Decision::Skipped {
            id: second,
            reason: SkipReason::Conflict
        }
    );
}

#[test]
fn a_reservation_that_does_not_fit_is_skipped() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 2_100, 50_000).min_service(1_000),
    );
    assert_eq!(
        table.select(1_900, 100_000),
        Decision::Skipped {
            id,
            reason: SkipReason::ReservationBudget
        }
    );
    assert_eq!(table.link(id).unwrap().advances, 1);
}

#[test]
fn an_overrun_is_recorded_and_releases_the_ticket() {
    let mut table = table();
    insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.hard_end_us(), 3_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 4_000
            }
        ),
        Ok(CompleteResult::Overrun {
            consumed_event: true,
            actual_end_us: 4_000
        })
    );
    assert_eq!(table.overruns(), 1);
}

#[test]
fn unconfirmed_stop_faults_all_dispatch_until_recovery() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    insert(&mut table, FakeLink::new(4_000, 5_000, 6_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(
        table.complete(ticket, EventOutcome::StopUnconfirmed),
        Ok(CompleteResult::Faulted)
    );
    assert!(table.is_faulted());
    assert_eq!(table.select(1_500, 100_000), Decision::Faulted);
    assert_eq!(table.cancel(ticket), Err(CompleteError::Faulted));
    assert_eq!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500
            }
        ),
        Err(CompleteError::NotInFlight)
    );
    assert_eq!(table.reset(), Err(ResetError::Faulted));
    assert_eq!(table.recover_quiescent(1_500), Ok(()));
    assert!(!table.is_faulted());
    assert_eq!(table.reset(), Ok(()));
    assert_eq!(table.len(), 0);
    assert_eq!(first.generation(), 1);
}

#[test]
fn recovery_requires_a_fault() {
    let mut table = table();
    assert_eq!(
        table.recover_quiescent(1_500),
        Err(RecoverError::NotFaulted)
    );
}

#[test]
fn in_flight_link_cannot_be_removed_or_reset() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(table.remove(id).unwrap_err(), RemoveError::InFlight);
    assert_eq!(table.reset(), Err(ResetError::Busy));
    table
        .complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500,
            },
        )
        .unwrap();
    assert!(table.remove(id).is_ok());
}

#[test]
fn cancel_releases_a_reserved_ticket_without_consuming_an_event() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.cancel(ticket).unwrap();
    assert_eq!(table.link(id).unwrap().advances, 0);
    let Decision::Run {
        ticket: again,
        window: issued,
    } = table.select(1_000, 100_000)
    else {
        panic!("expected a fresh run after cancel");
    };
    assert_eq!(again.id(), id);
    assert_eq!(issued, window(1_000, 2_000, 3_000, 50_000));
}

#[test]
fn same_prepare_priority_wins_then_equal_priority_rotates() {
    let mut table = table();
    let low = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 50_000).priority(1),
    );
    let high = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 50_000).priority(0),
    );
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.id(), high);
    begin_done(&mut table, ticket, 1_000, 1_500);
    assert_eq!(run(&mut table, 1_510, 100_000).id(), low);
    assert_eq!(low.slot(), 0);

    let mut table = LinkTable::<FakeLink, 2>::new(GUARD);
    let first = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let second = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.id(), first);
    table.begin(ticket, 1_000).unwrap();
    table
        .complete(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 1_500,
            },
        )
        .unwrap();
    assert_eq!(run(&mut table, 1_510, 100_000).id(), second);
}

#[test]
fn ordering_is_wrap_safe_near_u32_max() {
    let now = u32::MAX - 100;
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(10, 100, 1_000, 20_000));
    let second = insert(&mut table, FakeLink::new(20, 100, 1_000, 20_000));
    assert_eq!(table.select(now, 5_000), Decision::Idle { until_us: 10 });
    let ticket = run(&mut table, 10, 5_000);
    assert_eq!(ticket.id(), first);
    assert_eq!(second.slot(), 1);
}

#[test]
fn an_invalid_window_closes_only_that_link() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(2_000, 1_000, 3_000, 50_000));
    assert_eq!(
        table.select(0, 100_000),
        Decision::Invalid {
            id,
            error: WindowError::Order
        }
    );
    assert_eq!(
        table.select(0, 100_000),
        Decision::Idle { until_us: 100_000 }
    );
}

#[test]
fn an_advance_error_closes_the_link() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 1_100, 2_000, 50_000).advance_fails(),
    );
    assert_eq!(
        table.select(2_000, 100_000),
        Decision::Close {
            id,
            cause: CloseCause::AdvanceError,
            reason: 0x3e
        }
    );
}

#[test]
fn an_advance_without_progress_closes_the_link() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 1_100, 2_000, 50_000).stuck(),
    );
    assert_eq!(
        table.select(2_000, 100_000),
        Decision::Close {
            id,
            cause: CloseCause::AdvanceError,
            reason: 0x3e
        }
    );
}

#[test]
fn an_advance_error_after_a_served_event_is_reported_once() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 50_000).advance_fails(),
    );
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500
            }
        ),
        Ok(CompleteResult::Released {
            consumed_event: true
        })
    );
    assert_eq!(
        table.select(1_500, 100_000),
        Decision::Close {
            id,
            cause: CloseCause::AdvanceError,
            reason: 0x3e
        }
    );
    assert_eq!(
        table.select(1_500, 100_000),
        Decision::Idle { until_us: 100_000 }
    );
}

fn background(start: u32, end: u32, exit: u32) -> BackgroundWindow {
    BackgroundWindow {
        kind: BackgroundKind::Advertising,
        start_us: start,
        end_us: end,
        exit_us: exit,
        priority: 0,
    }
}

#[test]
fn background_runs_only_before_the_next_link_prepare() {
    let mut table = table();
    insert(&mut table, FakeLink::new(5_000, 6_000, 7_000, 50_000));
    let id = table
        .insert_background(background(1_000, 2_000, 100), 0)
        .unwrap();
    let Decision::RunBackground { ticket, .. } = table.select(1_000, 100_000) else {
        panic!("expected background run");
    };
    assert_eq!(ticket.id(), id);
    table.begin_background(ticket, 1_000).unwrap();
    table
        .complete_background(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 2_100,
            },
        )
        .unwrap();
    assert_eq!(
        table.select(2_100, 100_000),
        Decision::Idle { until_us: 5_000 }
    );
}

#[test]
fn background_that_overlaps_a_link_is_deferred() {
    let mut table = table();
    insert(&mut table, FakeLink::new(2_000, 3_000, 4_000, 50_000));
    table
        .insert_background(background(1_000, 2_500, 100), 0)
        .unwrap();
    assert_eq!(
        table.select(1_000, 100_000),
        Decision::Idle { until_us: 2_000 }
    );
}

#[test]
fn a_missed_background_fragment_is_reported_and_removed() {
    let mut table = table();
    let id = table
        .insert_background(background(1_000, 2_000, 100), 0)
        .unwrap();
    assert_eq!(
        table.select(2_500, 100_000),
        Decision::BackgroundMissed { id }
    );
    assert_eq!(
        table.select(2_500, 100_000),
        Decision::Idle { until_us: 100_000 }
    );
}

#[test]
fn background_begin_rechecks_the_gap_against_a_new_link() {
    let mut table = table();
    table
        .insert_background(background(1_000, 2_000, 100), 0)
        .unwrap();
    let Decision::RunBackground { ticket, .. } = table.select(1_000, 100_000) else {
        panic!("expected background run");
    };
    insert(&mut table, FakeLink::new(1_500, 2_000, 3_000, 50_000));
    assert_eq!(
        table.begin_background(ticket, 1_000),
        Err(BeginError::Expired)
    );
}

#[test]
fn background_does_not_advance_link_events() {
    let mut table = table();
    let link = insert(&mut table, FakeLink::new(5_000, 6_000, 7_000, 50_000));
    table
        .insert_background(background(1_000, 2_000, 100), 0)
        .unwrap();
    let Decision::RunBackground { ticket, .. } = table.select(1_000, 100_000) else {
        panic!("expected background run");
    };
    table.begin_background(ticket, 1_000).unwrap();
    table
        .complete_background(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 2_100,
            },
        )
        .unwrap();
    assert_eq!(table.link(link).unwrap().advances, 0);
}

fn params(chsel: bool) -> ConnectParams {
    ConnectParams {
        peer_addr: [1, 2, 3, 4, 5, 6],
        peer_random: true,
        chsel,
        access_addr: 0x1234_5678,
        crc_init: 0x0055_5555,
        win_size: 2,
        win_offset: 1,
        interval: 24,
        latency: 0,
        timeout: 200,
        channel_map: [0xff, 0xff, 0xff, 0xff, 0x1f],
        hop: 5,
        sca: 0,
    }
}

struct PeripheralAdapter {
    conn: PeripheralConnection,
}

impl ScheduledLink for PeripheralAdapter {
    fn window(&self) -> LinkWindow {
        let interval = u32::from(self.conn.params.interval) * 1250;
        let rx_start = self.conn.rx_start_us();
        let (cause, reason) = if self.conn.established() {
            (CloseCause::SupervisionTimeout, 0x08)
        } else {
            (CloseCause::EstablishmentTimeout, 0x3e)
        };
        LinkWindow {
            prepare_us: rx_start.wrapping_sub(ARM_LEAD_US),
            latest_start_us: rx_start,
            reservation_end_us: self
                .conn
                .event_start_us()
                .wrapping_add(interval)
                .wrapping_sub(EVENT_TAIL_US),
            min_service_us: self.conn.rx_complete_allowance_us(),
            deadline_us: self.conn.supervision_deadline_us(),
            deadline_cause: cause,
            deadline_reason: reason,
            channel: self.conn.channel(),
            priority: 0,
            event: self.conn.event_counter(),
        }
    }

    fn advance_one(&mut self) -> Result<(), ConnError> {
        self.conn.next_event()
    }

    fn expiry(&self, now: u32) -> Option<Expiry> {
        if self.conn.supervision_expired(now) {
            let (cause, reason) = if self.conn.established() {
                (CloseCause::SupervisionTimeout, 0x08)
            } else {
                (CloseCause::EstablishmentTimeout, 0x3e)
            };
            Some(Expiry {
                at_us: self.conn.supervision_deadline_us(),
                cause,
                reason,
            })
        } else {
            None
        }
    }
}

struct CentralAdapter {
    conn: CentralConnection,
}

impl ScheduledLink for CentralAdapter {
    fn window(&self) -> LinkWindow {
        let interval = u32::from(self.conn.params.interval) * 1250;
        let lead = self.conn.event_start_us().wrapping_sub(ARM_LEAD_US);
        let (cause, reason) = if self.conn.established() {
            (CloseCause::SupervisionTimeout, 0x08)
        } else {
            (CloseCause::EstablishmentTimeout, 0x3e)
        };
        LinkWindow {
            prepare_us: lead,
            latest_start_us: self.conn.event_start_us(),
            reservation_end_us: self
                .conn
                .event_start_us()
                .wrapping_add(interval)
                .wrapping_sub(EVENT_TAIL_US),
            min_service_us: self.conn.rx_complete_allowance_us(),
            deadline_us: self.conn.supervision_deadline_us(),
            deadline_cause: cause,
            deadline_reason: reason,
            channel: self.conn.channel(),
            priority: 0,
            event: self.conn.event_counter(),
        }
    }

    fn advance_one(&mut self) -> Result<(), ConnError> {
        self.conn.next_event()
    }

    fn expiry(&self, now: u32) -> Option<Expiry> {
        if self.conn.supervision_expired(now) {
            let (cause, reason) = if self.conn.established() {
                (CloseCause::SupervisionTimeout, 0x08)
            } else {
                (CloseCause::EstablishmentTimeout, 0x3e)
            };
            Some(Expiry {
                at_us: self.conn.supervision_deadline_us(),
                cause,
                reason,
            })
        } else {
            None
        }
    }
}

#[test]
fn peripheral_adapter_matches_the_connection_window() {
    let conn = PeripheralConnection::new(params(false), 10_000, false);
    let adapter = PeripheralAdapter { conn: conn.clone() };
    let window = adapter.window();
    assert_eq!(window.prepare_us, conn.rx_start_us() - ARM_LEAD_US);
    assert_eq!(window.latest_start_us, conn.rx_start_us());
    assert_eq!(
        window.reservation_end_us,
        conn.event_start_us() + u32::from(conn.params.interval) * 1250 - EVENT_TAIL_US
    );
    assert_eq!(window.deadline_us, conn.supervision_deadline_us());
    assert_eq!(window.channel, conn.channel());
    assert_eq!(window.event, conn.event_counter());
    assert_eq!(window.validate(0), Ok(()));
}

#[test]
fn central_adapter_matches_the_connection_window() {
    let conn = CentralConnection::new(params(false), 10_000);
    let adapter = CentralAdapter { conn: conn.clone() };
    let window = adapter.window();
    assert_eq!(window.prepare_us, conn.event_start_us() - ARM_LEAD_US);
    assert_eq!(window.latest_start_us, conn.event_start_us());
    assert_eq!(
        window.reservation_end_us,
        conn.event_start_us() + u32::from(conn.params.interval) * 1250 - EVENT_TAIL_US
    );
    assert_eq!(window.deadline_us, conn.supervision_deadline_us());
    assert_eq!(window.channel, conn.channel());
    assert_eq!(window.event, conn.event_counter());
    assert_eq!(window.validate(0), Ok(()));
}

#[test]
fn peripheral_skip_matches_next_event_reference() {
    let mut adapter = PeripheralAdapter {
        conn: PeripheralConnection::new(params(false), 10_000, false),
    };
    let mut reference = adapter.conn.clone();
    for _ in 0..8 {
        adapter.advance_one().unwrap();
        reference.next_event().unwrap();
        assert_eq!(adapter.conn.event_counter(), reference.event_counter());
        assert_eq!(adapter.conn.channel(), reference.channel());
        assert_eq!(
            adapter.window(),
            PeripheralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
    assert!(!adapter.conn.established());
}

#[test]
fn peripheral_skip_crosses_a_channel_map_instant() {
    let mut adapter = PeripheralAdapter {
        conn: PeripheralConnection::new(params(true), 10_000, true),
    };
    let mut reference = adapter.conn.clone();
    adapter
        .conn
        .schedule_channel_map([0x03, 0, 0, 0, 0], 3)
        .unwrap();
    reference
        .schedule_channel_map([0x03, 0, 0, 0, 0], 3)
        .unwrap();
    for _ in 0..6 {
        adapter.advance_one().unwrap();
        reference.next_event().unwrap();
        assert_eq!(adapter.conn.event_counter(), reference.event_counter());
        assert_eq!(adapter.conn.channel(), reference.channel());
        assert_eq!(
            adapter.window(),
            PeripheralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
}

#[test]
fn peripheral_skip_crosses_an_update_instant() {
    let mut adapter = PeripheralAdapter {
        conn: PeripheralConnection::new(params(false), 10_000, false),
    };
    let mut reference = adapter.conn.clone();
    let update = crate::ll::conn::ConnectionUpdate {
        win_size: 3,
        win_offset: 2,
        interval: 32,
        latency: 0,
        timeout: 300,
        instant: 3,
    };
    adapter.conn.schedule_update(update).unwrap();
    reference.schedule_update(update).unwrap();
    for _ in 0..6 {
        adapter.advance_one().unwrap();
        reference.next_event().unwrap();
        assert_eq!(adapter.conn.event_counter(), reference.event_counter());
        assert_eq!(adapter.conn.channel(), reference.channel());
        assert_eq!(
            adapter.window(),
            PeripheralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
}

#[test]
fn central_skip_matches_next_event_reference() {
    let mut adapter = CentralAdapter {
        conn: CentralConnection::new(params(true), 10_000),
    };
    let mut reference = adapter.conn.clone();
    for _ in 0..8 {
        adapter.advance_one().unwrap();
        reference.next_event().unwrap();
        assert_eq!(adapter.conn.event_counter(), reference.event_counter());
        assert_eq!(adapter.conn.channel(), reference.channel());
        assert_eq!(
            adapter.window(),
            CentralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
}

#[test]
fn csa2_skip_trajectory_is_wrap_safe() {
    let mut adapter = PeripheralAdapter {
        conn: PeripheralConnection::new(params(true), u32::MAX - 5_000, true),
    };
    let mut reference = adapter.conn.clone();
    for _ in 0..16 {
        adapter.advance_one().unwrap();
        reference.next_event().unwrap();
        assert_eq!(adapter.conn.event_counter(), reference.event_counter());
        assert_eq!(adapter.conn.channel(), reference.channel());
        assert_eq!(
            adapter.window(),
            PeripheralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
}

#[test]
fn switched_links_wait_for_release_plus_guard() {
    let mut table = table();
    let first = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 2_500, 50_000).step(5_000),
    );
    let second = insert(&mut table, FakeLink::new(2_490, 2_600, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.id(), first);
    begin_done(&mut table, ticket, 1_000, 2_500);
    assert_eq!(
        table.select(2_500, 100_000),
        Decision::Idle { until_us: 2_510 }
    );
    assert_eq!(run(&mut table, 2_510, 100_000).id(), second);
}

#[test]
fn a_committed_reservation_skips_an_overlapping_window() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(100, 200, 200, 50_000));
    let second = insert(&mut table, FakeLink::new(150, 180, 180, 50_000));
    assert_eq!(table.select(0, 100_000), Decision::Idle { until_us: 100 });
    let ticket = run(&mut table, 100, 100_000);
    assert_eq!(ticket.id(), first);
    begin_done(&mut table, ticket, 100, 200);
    assert_eq!(
        table.select(200, 100_000),
        Decision::Skipped {
            id: second,
            reason: SkipReason::Conflict
        }
    );
    assert_eq!(table.link(second).unwrap().advances, 1);
}

#[test]
fn a_link_can_still_run_before_the_other_reservation_is_committed() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(100, 200, 200, 50_000));
    let second = insert(&mut table, FakeLink::new(150, 180, 180, 50_000));
    let ticket = run(&mut table, 100, 100_000);
    table.cancel(ticket).unwrap();
    // A's cancelled window is recomputed, so B is not permanently skipped.
    table.link_mut(first).unwrap().advance_one().unwrap();
    assert_eq!(run(&mut table, 150, 100_000).id(), second);
}

#[test]
fn stale_ticket_is_rejected_after_the_window_moved() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.link_mut(id).unwrap().advance_one().unwrap();
    assert_eq!(table.begin(ticket, 1_000), Err(BeginError::Expired));
    assert_eq!(
        table.select(1_000, 100_000),
        Decision::Idle { until_us: 2_000 }
    );
}

#[test]
fn removing_a_link_reuses_its_slot_without_touching_the_other() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let second = insert(&mut table, FakeLink::new(5_000, 6_000, 7_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    table
        .complete(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 1_500,
            },
        )
        .unwrap();
    table.remove(first).unwrap();
    let third = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    assert_eq!(third.slot(), first.slot());
    assert_ne!(third.generation(), first.generation());
    assert!(table.link(first).is_none());
    assert!(table.link(second).is_some());
    assert_eq!(table.begin(ticket, 1_500), Err(BeginError::StaleTicket));
}

#[test]
fn only_the_high_slot_can_remain_active() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(9_000, 9_500, 9_900, 50_000));
    let second = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    assert_eq!(second.slot(), 1);
    table.remove(first).unwrap();
    assert_eq!(table.len(), 1);
    let ticket = run(&mut table, 1_000, 100_000);
    assert_eq!(ticket.id(), second);
}

#[test]
fn generation_exhaustion_is_rejected() {
    let mut table = table();
    table.next_generation = u32::MAX;
    let last = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    assert_eq!(last.generation(), u32::MAX);
    assert_eq!(
        table.insert(FakeLink::new(1_000, 2_000, 3_000, 50_000)),
        Err(InsertError::GenerationExhausted)
    );
    table.next_work_generation = 0;
    assert_eq!(
        table.insert_background(background(1_000, 2_000, 100), 0),
        Err(InsertError::GenerationExhausted)
    );
}

#[test]
fn n1_table_serves_one_link_and_rejects_a_second() {
    let mut table = LinkTable::<FakeLink, 1>::new(GUARD);
    let id = table
        .insert(FakeLink::new(1_000, 2_000, 3_000, 50_000))
        .unwrap();
    assert_eq!(
        table.insert(FakeLink::new(4_000, 5_000, 6_000, 50_000)),
        Err(InsertError::Full)
    );
    let Decision::Run { ticket, .. } = table.select(1_000, 100_000) else {
        panic!("expected run");
    };
    assert_eq!(ticket.id(), id);
}

enum RoleLink {
    Peripheral(PeripheralAdapter),
    Central(CentralAdapter),
}

impl ScheduledLink for RoleLink {
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

#[test]
fn central_and_peripheral_windows_are_ordered_by_prepare_point() {
    let peripheral = PeripheralAdapter {
        conn: PeripheralConnection::new(params(false), 10_000, false),
    };
    let central = CentralAdapter {
        conn: CentralConnection::new(params(false), 10_000),
    };
    let peripheral_window = peripheral.window();
    let central_window = central.window();
    assert!(peripheral_window.prepare_us < central_window.prepare_us);
    assert_eq!(
        peripheral_window.validate(peripheral_window.prepare_us),
        Ok(())
    );
    assert_eq!(
        central_window.validate(peripheral_window.prepare_us),
        Ok(())
    );

    let now = peripheral_window.prepare_us - 500;
    let mut table = LinkTable::<RoleLink, 2>::new(GUARD);
    let central_id = table.insert(RoleLink::Central(central)).unwrap();
    let peripheral_id = table.insert(RoleLink::Peripheral(peripheral)).unwrap();
    assert_eq!(
        table.select(now, 100_000),
        Decision::Idle {
            until_us: peripheral_window.prepare_us
        }
    );
    let Decision::Run { ticket, .. } = table.select(peripheral_window.prepare_us, 100_000) else {
        panic!("expected run");
    };
    assert_eq!(ticket.id(), peripheral_id);
    assert_ne!(ticket.id(), central_id);
}

#[test]
fn widening_moves_the_rx_prepare_point_per_event() {
    let mut conn = PeripheralConnection::new(params(false), 10_000, false);
    let before = PeripheralAdapter { conn: conn.clone() }.window();
    assert!(conn.on_rx_anchor(before.latest_start_us + 500, 1));
    let anchored = PeripheralAdapter { conn: conn.clone() }.window();
    conn.next_event().unwrap();
    let after = PeripheralAdapter { conn: conn.clone() }.window();
    // 500 ppm local + 500 ppm peer over one interval, plus the 16 us jitter.
    let widening = 30_000 * 1_000 / 1_000_000;
    assert_eq!(
        after.latest_start_us.wrapping_sub(anchored.latest_start_us),
        u32::from(conn.params.interval) * 1250 - widening
    );
    assert_eq!(after.validate(after.prepare_us), Ok(()));
    conn.set_rx_max_payload(251);
    let dle = PeripheralAdapter { conn: conn.clone() }.window();
    assert!(dle.min_service_us > after.min_service_us);
    assert_eq!(dle.validate(dle.prepare_us), Ok(()));
}

#[test]
fn begin_rejects_a_window_that_shrank_under_the_same_event() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    {
        let link = table.link_mut(id).unwrap();
        link.window.latest_start_us = 1_200;
        link.window.deadline_us = 1_500;
    }
    assert_eq!(table.begin(ticket, 1_600), Err(BeginError::Expired));
    assert_eq!(
        table.select(1_600, 100_000),
        Decision::Skipped {
            id,
            reason: SkipReason::Late
        }
    );
}

#[test]
fn begin_rejects_a_service_budget_that_no_longer_fits() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.link_mut(id).unwrap().window.min_service_us = 1_500;
    assert_eq!(table.begin(ticket, 1_600), Err(BeginError::Expired));
}

#[test]
fn begin_rejects_an_expiry_that_arrived_while_reserved() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.link_mut(id).unwrap().expiry = Some(Expiry {
        at_us: 1_400,
        cause: CloseCause::SupervisionTimeout,
        reason: 0x08,
    });
    assert_eq!(table.begin(ticket, 1_500), Err(BeginError::Expired));
}

#[test]
fn next_run_exhaustion_stops_dispatch_but_not_closing() {
    let mut table = table();
    let expiring = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 50_000).expiry(CloseCause::SupervisionTimeout, 900),
    );
    insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    table.next_run = 0;
    assert_eq!(
        table.select(900, 100_000),
        Decision::Close {
            id: expiring,
            cause: CloseCause::SupervisionTimeout,
            reason: 0x08
        }
    );
    assert_eq!(table.select(1_000, 100_000), Decision::Exhausted);
}

#[test]
fn missed_settles_one_event_and_moves_to_the_next() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(
        table.complete(ticket, EventOutcome::Missed { idle_at_us: 1_500 }),
        Ok(CompleteResult::Released {
            consumed_event: false
        })
    );
    assert_eq!(table.link(id).unwrap().advances, 1);
    assert_eq!(
        table.select(1_500, 100_000),
        Decision::Idle { until_us: 2_000 }
    );
}

#[test]
fn done_without_a_consumed_event_can_retry_the_same_window() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 1_500
            }
        ),
        Ok(CompleteResult::Released {
            consumed_event: false
        })
    );
    assert_eq!(table.link(id).unwrap().advances, 0);
    let retry = run(&mut table, 1_500, 100_000);
    assert_eq!(retry.id(), id);
    assert_eq!(retry.event(), 0);
}

#[test]
fn background_waits_for_the_link_release_guard() {
    let mut table = table();
    insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 50_000).step(5_000),
    );
    table
        .insert_background(background(1_500, 2_000, 100), 0)
        .unwrap();
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    table
        .complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: 1_500,
            },
        )
        .unwrap();
    assert_eq!(
        table.select(1_500, 100_000),
        Decision::Idle { until_us: 1_510 }
    );
    let Decision::RunBackground { ticket, .. } = table.select(1_510, 100_000) else {
        panic!("expected background run");
    };
    assert_eq!(table.begin_background(ticket, 1_510), Ok(()));
}

#[test]
fn background_release_gates_the_next_link() {
    let mut table = table();
    table
        .insert_background(background(1_000, 2_000, 100), 0)
        .unwrap();
    let Decision::RunBackground { ticket, .. } = table.select(1_000, 100_000) else {
        panic!("expected background run");
    };
    table.begin_background(ticket, 1_000).unwrap();
    table
        .complete_background(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 2_000,
            },
        )
        .unwrap();
    let id = insert(&mut table, FakeLink::new(2_005, 2_100, 3_000, 50_000));
    assert_eq!(
        table.select(2_005, 100_000),
        Decision::Idle { until_us: 2_010 }
    );
    assert_eq!(run(&mut table, 2_010, 100_000).id(), id);
}

#[test]
fn recovery_release_gates_the_first_dispatch() {
    let mut table = table();
    let first = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    assert_eq!(
        table.complete(ticket, EventOutcome::StopUnconfirmed),
        Ok(CompleteResult::Faulted)
    );
    table.recover_quiescent(3_000).unwrap();
    table.remove(first).unwrap();
    let second = insert(&mut table, FakeLink::new(3_005, 4_000, 5_000, 50_000));
    assert_eq!(
        table.select(3_005, 100_000),
        Decision::Idle { until_us: 3_010 }
    );
    assert_eq!(run(&mut table, 3_010, 100_000).id(), second);
}

#[test]
fn simultaneous_expiries_close_one_per_poll() {
    let mut table = table();
    let first = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 500).expiry(CloseCause::SupervisionTimeout, 500),
    );
    let second = insert(
        &mut table,
        FakeLink::new(1_100, 2_000, 3_000, 500).expiry(CloseCause::SupervisionTimeout, 500),
    );
    assert!(matches!(
        table.select(500, 100_000),
        Decision::Close { id, .. } if id == first
    ));
    assert!(matches!(
        table.select(500, 100_000),
        Decision::Close { id, .. } if id == second
    ));
    assert_eq!(
        table.select(500, 100_000),
        Decision::Idle { until_us: 100_000 }
    );
}

#[test]
fn a_persistently_late_link_closes_at_its_deadline() {
    let mut table = table();
    let late = insert(
        &mut table,
        FakeLink::new(1_000, 1_100, 2_000, 50_000)
            .step(1_000)
            .expiry(CloseCause::SupervisionTimeout, 5_000),
    );
    let mut now = 2_000;
    loop {
        match table.select(now, 100_000) {
            Decision::Skipped { id, .. } => {
                assert_eq!(id, late);
                now += 1_000;
            }
            Decision::Close { id, cause, .. } => {
                assert_eq!(id, late);
                assert_eq!(cause, CloseCause::SupervisionTimeout);
                break;
            }
            other => panic!("unexpected decision {other:?}"),
        }
        assert!(now < 10_000, "the late link never closed");
    }
    assert_eq!(now, 5_000);
}

fn interval_params(interval: u16) -> ConnectParams {
    let mut params = params(false);
    params.interval = interval;
    params
}

#[test]
fn n1_central_adapter_can_run_and_complete() {
    let mut table = LinkTable::<RoleLink, 1>::new(GUARD);
    let id = table
        .insert(RoleLink::Central(CentralAdapter {
            conn: CentralConnection::new(params(false), 10_000),
        }))
        .unwrap();
    let window = table.link(id).unwrap().window();
    assert!(window.prepare_us < window.latest_start_us);
    assert_eq!(
        table.select(window.prepare_us - 500, 100_000),
        Decision::Idle {
            until_us: window.prepare_us
        }
    );
    let Decision::Run { ticket, .. } = table.select(window.prepare_us, 100_000) else {
        panic!("expected run");
    };
    table.begin(ticket, window.prepare_us).unwrap();
    assert!(matches!(
        table.complete(
            ticket,
            EventOutcome::Done {
                consumed_event: true,
                idle_at_us: window.latest_start_us + 1_000,
            }
        ),
        Ok(CompleteResult::Released { .. })
    ));
}

#[test]
fn peripheral_and_central_both_serve_in_sequence() {
    let peripheral = RoleLink::Peripheral(PeripheralAdapter {
        conn: PeripheralConnection::new(interval_params(48), 10_000, false),
    });
    let central = RoleLink::Central(CentralAdapter {
        conn: CentralConnection::new(interval_params(96), 79_000),
    });
    let mut table = LinkTable::<RoleLink, 2>::new(GUARD);
    let p = table.insert(peripheral).unwrap();
    let c = table.insert(central).unwrap();
    let mut served = [0u8; 2];
    let mut now = 10_000;
    for _ in 0..100 {
        match table.select(now, 1_000_000) {
            Decision::Run { ticket, .. } => {
                let window = table.link(ticket.id()).unwrap().window();
                let start = window.prepare_us;
                table.begin(ticket, start).unwrap();
                let id = ticket.id();
                table
                    .complete(
                        ticket,
                        EventOutcome::Done {
                            consumed_event: true,
                            idle_at_us: start + 1_000,
                        },
                    )
                    .unwrap();
                if id == p {
                    served[0] += 1;
                } else if id == c {
                    served[1] += 1;
                }
                now = start + 1_000;
            }
            Decision::Idle { until_us } => now = until_us,
            other => panic!("unexpected decision {other:?}"),
        }
        if served[0] >= 2 && served[1] >= 1 {
            break;
        }
    }
    assert!(served[0] >= 2, "peripheral not served twice");
    assert!(served[1] >= 1, "central never served");
}

#[test]
fn table_skip_matches_the_reference_across_a_map_instant() {
    let conn = PeripheralConnection::new(params(true), 10_000, true);
    let mut table = LinkTable::<PeripheralAdapter, 1>::new(GUARD);
    let id = table.insert(PeripheralAdapter { conn }).unwrap();
    table
        .link_mut(id)
        .unwrap()
        .conn
        .schedule_channel_map([0x03, 0, 0, 0, 0], 2)
        .unwrap();
    let mut reference = PeripheralConnection::new(params(true), 10_000, true);
    reference
        .schedule_channel_map([0x03, 0, 0, 0, 0], 2)
        .unwrap();
    for _ in 0..4 {
        let window = table.link(id).unwrap().window();
        let decision = table.select(window.latest_start_us, 1_000_000);
        match decision {
            Decision::Skipped {
                id: skipped,
                reason: SkipReason::Late,
            } if skipped == id => {}
            other => panic!("window={window:?} decision={other:?}"),
        }
        reference.next_event().unwrap();
        let actual = table.link(id).unwrap().window();
        let expected = PeripheralAdapter {
            conn: reference.clone(),
        }
        .window();
        assert_eq!(actual, expected);
    }
}

#[test]
fn table_skip_matches_the_reference_across_an_update_instant() {
    let conn = PeripheralConnection::new(params(false), 10_000, false);
    let mut table = LinkTable::<PeripheralAdapter, 1>::new(GUARD);
    let id = table.insert(PeripheralAdapter { conn }).unwrap();
    let update = crate::ll::conn::ConnectionUpdate {
        win_size: 3,
        win_offset: 2,
        interval: 32,
        latency: 0,
        timeout: 300,
        instant: 2,
    };
    table
        .link_mut(id)
        .unwrap()
        .conn
        .schedule_update(update)
        .unwrap();
    let mut reference = PeripheralConnection::new(params(false), 10_000, false);
    reference.schedule_update(update).unwrap();
    for _ in 0..4 {
        let window = table.link(id).unwrap().window();
        assert!(matches!(
            table.select(window.latest_start_us, 1_000_000),
            Decision::Skipped { .. }
        ));
        reference.next_event().unwrap();
        let actual = table.link(id).unwrap().window();
        let expected = PeripheralAdapter {
            conn: reference.clone(),
        }
        .window();
        assert_eq!(actual, expected);
    }
}

#[test]
fn an_oversized_guard_cannot_admit_an_overlapping_background() {
    let mut table = LinkTable::<FakeLink, 1>::new(i32::MAX as u32);
    table
        .insert(FakeLink::new(5_000, 6_000, 7_000, 50_000))
        .unwrap();
    table
        .insert_background(background(1_000, 6_000, 0), 0)
        .unwrap();
    // The background covers the link preparation point; an insane guard must
    // not wrap the gap comparison into "fits".
    assert_eq!(
        table.select(1_000, 100_000),
        Decision::Idle { until_us: 5_000 }
    );
}

#[test]
fn table_skip_is_wrap_safe_near_u32_max() {
    let conn = PeripheralConnection::new(params(true), u32::MAX - 40_000, true);
    let mut reference = conn.clone();
    let mut table = LinkTable::<PeripheralAdapter, 1>::new(GUARD);
    let id = table.insert(PeripheralAdapter { conn }).unwrap();
    for _ in 0..4 {
        let window = table.link(id).unwrap().window();
        let now = window.latest_start_us;
        match table.select(now, 1_000_000) {
            Decision::Skipped { id: skipped, .. } if skipped == id => {}
            other => panic!("window={window:?} decision={other:?}"),
        }
        reference.next_event().unwrap();
        assert_eq!(
            table.link(id).unwrap().window(),
            PeripheralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
}

#[test]
fn table_skip_crosses_the_event_counter_wrap() {
    let mut conn = PeripheralConnection::new(params(false), 10_000, false);
    for i in 0..65_535 {
        conn.next_event().unwrap();
        if i % 50 == 0 {
            assert!(conn.on_rx_anchor(conn.event_start_us() + 500, 1));
        }
    }
    assert_eq!(conn.event_counter(), 65_535);
    let mut reference = conn.clone();
    let mut table = LinkTable::<PeripheralAdapter, 1>::new(GUARD);
    let id = table.insert(PeripheralAdapter { conn }).unwrap();
    for _ in 0..2 {
        let window = table.link(id).unwrap().window();
        let finish = window.latest_start_us.wrapping_add(1_000_000);
        assert!(matches!(
            table.select(window.latest_start_us, finish),
            Decision::Skipped { .. }
        ));
        reference.next_event().unwrap();
        assert_eq!(
            table.link(id).unwrap().window(),
            PeripheralAdapter {
                conn: reference.clone()
            }
            .window()
        );
    }
    assert!(reference.event_counter() <= 1);
}

#[test]
fn pending_update_does_not_outlive_the_old_deadline() {
    let conn = PeripheralConnection::new(params(false), 10_000, false);
    let deadline = conn.supervision_deadline_us();
    let update = crate::ll::conn::ConnectionUpdate {
        win_size: 3,
        win_offset: 2,
        interval: 32,
        latency: 0,
        timeout: 300,
        instant: 3,
    };
    let mut table = LinkTable::<PeripheralAdapter, 1>::new(GUARD);
    let id = table.insert(PeripheralAdapter { conn }).unwrap();
    table
        .link_mut(id)
        .unwrap()
        .conn
        .schedule_update(update)
        .unwrap();
    assert_eq!(
        table.select(deadline, 1_000_000),
        Decision::Close {
            id,
            cause: CloseCause::EstablishmentTimeout,
            reason: 0x3e
        }
    );
}

#[test]
fn begin_rejects_a_narrower_deadline_before_it_arrives() {
    let mut table = table();
    let id = insert(
        &mut table,
        FakeLink::new(1_000, 2_000, 3_000, 50_000).min_service(500),
    );
    let ticket = run(&mut table, 1_000, 100_000);
    table.link_mut(id).unwrap().window.deadline_us = 1_500;
    assert_eq!(table.begin(ticket, 1_100), Err(BeginError::Expired));
}

#[test]
fn begin_rejects_a_narrower_reservation_before_it_arrives() {
    let mut table = table();
    let id = insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.link_mut(id).unwrap().window.reservation_end_us = 2_500;
    assert_eq!(table.begin(ticket, 1_100), Err(BeginError::Expired));
}

#[test]
fn reset_keeps_the_recovery_gate() {
    let mut table = table();
    insert(&mut table, FakeLink::new(1_000, 2_000, 3_000, 50_000));
    let ticket = run(&mut table, 1_000, 100_000);
    table.begin(ticket, 1_000).unwrap();
    table
        .complete(ticket, EventOutcome::StopUnconfirmed)
        .unwrap();
    table.recover_quiescent(3_000).unwrap();
    table.reset().unwrap();
    let id = insert(&mut table, FakeLink::new(3_005, 4_000, 5_000, 50_000));
    assert_eq!(
        table.select(3_005, 100_000),
        Decision::Idle { until_us: 3_010 }
    );
    assert_eq!(run(&mut table, 3_010, 100_000).id(), id);
}

#[test]
fn reset_keeps_the_background_gate() {
    let mut table = table();
    table
        .insert_background(background(1_000, 2_000, 100), 0)
        .unwrap();
    let Decision::RunBackground { ticket, .. } = table.select(1_000, 100_000) else {
        panic!("expected background run");
    };
    table.begin_background(ticket, 1_000).unwrap();
    table
        .complete_background(
            ticket,
            EventOutcome::Done {
                consumed_event: false,
                idle_at_us: 2_000,
            },
        )
        .unwrap();
    table.reset().unwrap();
    let id = insert(&mut table, FakeLink::new(2_005, 3_000, 4_000, 50_000));
    assert_eq!(
        table.select(2_005, 100_000),
        Decision::Idle { until_us: 2_010 }
    );
    assert_eq!(run(&mut table, 2_010, 100_000).id(), id);
}

#[test]
fn background_span_beyond_half_range_is_rejected() {
    let mut table = table();
    assert_eq!(
        table.insert_background(
            BackgroundWindow {
                kind: BackgroundKind::Advertising,
                start_us: 0,
                end_us: 0x7fff_fff0,
                exit_us: 0x20,
                priority: 0,
            },
            0
        ),
        Err(InsertError::Order)
    );
}

#[test]
fn a_conflict_starved_link_closes_once_while_the_other_serves() {
    let mut table = table();
    let served = insert(
        &mut table,
        FakeLink::new(1_000, 1_050, 1_100, 100_000).step(1_000),
    );
    let starved = insert(
        &mut table,
        FakeLink::new(1_050, 1_055, 3_000, 50_000)
            .step(1_000)
            .expiry(CloseCause::SupervisionTimeout, 4_500),
    );
    let mut now = 1_000;
    let mut served_count = 0;
    let mut closes = 0;
    for _ in 0..40 {
        match table.select(now, 100_000) {
            Decision::Run { ticket, .. } => {
                assert_eq!(ticket.id(), served);
                table.begin(ticket, now).unwrap();
                table
                    .complete(
                        ticket,
                        EventOutcome::Done {
                            consumed_event: true,
                            idle_at_us: now + 50,
                        },
                    )
                    .unwrap();
                served_count += 1;
                now += 50;
            }
            Decision::Skipped { id, .. } => {
                assert_eq!(id, starved);
                assert!(table.link(starved).unwrap().advances <= 4);
            }
            Decision::Close { id, cause, .. } => {
                assert_eq!(id, starved);
                assert_eq!(cause, CloseCause::SupervisionTimeout);
                closes += 1;
            }
            Decision::Idle { until_us } => {
                assert_ne!(until_us, now);
                now = until_us;
            }
            other => panic!("unexpected decision {other:?}"),
        }
        if closes == 1 && served_count >= 5 {
            break;
        }
    }
    assert_eq!(closes, 1);
    assert!(served_count >= 5);
    assert_eq!(
        table.select(5_050, 100_000),
        Decision::Idle { until_us: 6_000 }
    );
    let Decision::Run { ticket, .. } = table.select(6_000, 100_000) else {
        panic!("the serving link stopped");
    };
    assert_eq!(ticket.id(), served);
}
