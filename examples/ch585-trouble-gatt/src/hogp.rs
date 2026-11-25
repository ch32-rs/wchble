//! Phase 1 D1: HID-over-GATT central client (discovery, report map,
//! notifications) with its acceptance counters in `HOGP_STATS`.

use embassy_time::{with_timeout, Duration, Instant};
use trouble_host::prelude::*;
use wchble::hogp::report_map::{Report, ReportKind, ReportMap, MAX_FIELDS};

const HID_SERVICE: u16 = 0x1812;
const HID_INFORMATION: u16 = 0x2A4A;
const REPORT_MAP: u16 = 0x2A4B;
const REPORT: u16 = 0x2A4D;
const PROTOCOL_MODE: u16 = 0x2A4E;
const REPORT_REFERENCE: u16 = 0x2908;
/// HIDP report type for an Input report (Report Reference descriptor).
const REF_INPUT: u8 = 0x01;

// Generic Desktop / Button usages decoded for the motion gate.
const PAGE_GENERIC: u16 = 0x01;
const PAGE_BUTTON: u16 = 0x09;
const USAGE_X: u16 = 0x30;
const USAGE_Y: u16 = 0x31;

const HOGP_WORDS: usize = 18;
pub const HOGP_MAGIC: u32 = 0x4847_5001;

pub const STAT_MAGIC: usize = 0;
pub const STAT_VERSION: usize = 1;
/// Input reports decoded from notifications.
pub const STAT_REPORTS: usize = 2;
/// Reports whose X or Y is nonzero.
pub const STAT_MOTION: usize = 3;
/// Reports with at least one button bit set.
pub const STAT_BUTTONS: usize = 4;
/// Input Report characteristics subscribed.
pub const STAT_SUBSCRIPTIONS: usize = 5;
pub const STAT_MAP_LEN: usize = 6;
pub const STAT_MAP_HASH: usize = 7;
/// Input report IDs declared by the Report Map.
pub const STAT_MAP_REPORTS: usize = 8;
/// Input Report Reference descriptors found and subscribed.
pub const STAT_REFERENCES: usize = 9;
pub const STAT_REQ_MIN: usize = 10;
pub const STAT_REQ_MAX: usize = 11;
/// Interval the link actually adopted, in 1.25 ms units.
pub const STAT_INTERVAL: usize = 12;
pub const STAT_PROTOCOL: usize = 13;
/// HID Information bCountryCode.
pub const STAT_HID_FLAGS: usize = 14;
pub const STAT_ERRORS: usize = 15;
pub const STAT_LAST_ERROR: usize = 16;

#[no_mangle]
static mut HOGP_STATS: [u32; HOGP_WORDS] = [0; HOGP_WORDS];

pub fn hogp_put(index: usize, value: u32) {
    // SAFETY: single-threaded example; only the Host poll writes these slots.
    unsafe {
        core::ptr::addr_of_mut!(HOGP_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

pub fn hogp_get(index: usize) -> u32 {
    unsafe {
        core::ptr::addr_of!(HOGP_STATS)
            .cast::<u32>()
            .add(index)
            .read_volatile()
    }
}

fn hogp_inc(index: usize) {
    hogp_put(index, hogp_get(index).wrapping_add(1));
}

fn fail(stage: u32) -> () {
    hogp_inc(STAT_ERRORS);
    hogp_put(STAT_LAST_ERROR, stage);
}

pub fn init() {
    hogp_put(STAT_MAGIC, HOGP_MAGIC);
    hogp_put(STAT_VERSION, 1);
}

/// Record the peripheral's L2CAP interval request (1.25 ms units).
pub fn note_interval_request(min: Duration, max: Duration) {
    hogp_put(STAT_REQ_MIN, (min.as_micros() / 1_250) as u32);
    hogp_put(STAT_REQ_MAX, (max.as_micros() / 1_250) as u32);
}

/// Record the interval the controller actually applied.
pub fn note_interval_applied(interval: Duration) {
    hogp_put(STAT_INTERVAL, (interval.as_micros() / 1_250) as u32);
}

/// Run discovery and collect input reports for `budget`.
pub async fn cycle<C, P>(client: &GattClient<'_, C, P, 4>, budget: Duration) -> Result<(), ()>
where
    C: Controller,
    P: PacketPool,
{
    let services = client
        .services_by_uuid(&Uuid::new_short(HID_SERVICE))
        .await
        .map_err(|_| fail(0x30))?;
    let service = services.first().ok_or_else(|| fail(0x31))?.clone();

    let characteristics = client
        .characteristics::<20>(&service)
        .await
        .map_err(|_| fail(0x32))?;

    if let Some(info) = find(&characteristics, HID_INFORMATION) {
        let mut value = [0u8; 4];
        if let Ok(4) = client.read_characteristic(info, &mut value).await {
            // Flags byte: bit0 remote wake, bit1 normally connectable.
            hogp_put(STAT_HID_FLAGS, u32::from(value[3]));
        }
    }

    let map_characteristic = find(&characteristics, REPORT_MAP).ok_or_else(|| fail(0x33))?;
    let mut map_bytes = [0u8; 512];
    let map_len = client
        .read_characteristic(map_characteristic, &mut map_bytes)
        .await
        .map_err(|_| fail(0x34))?;
    hogp_put(STAT_MAP_LEN, map_len as u32);
    hogp_put(STAT_MAP_HASH, fnv1a(&map_bytes[..map_len]));
    let map = ReportMap::parse(&map_bytes[..map_len]).ok_or_else(|| fail(0x35))?;
    hogp_put(STAT_MAP_REPORTS, map.input_ids().count() as u32);

    // The fixture reports in report protocol; switch back if it boots in
    // boot protocol. A refused write is fine: decoding still follows the map.
    if let Some(mode) = find(&characteristics, PROTOCOL_MODE) {
        let mut value = [0u8; 1];
        if let Ok(1) = client.read_characteristic(mode, &mut value).await {
            hogp_put(STAT_PROTOCOL, u32::from(value[0]));
            if value[0] == 0 && client.write_characteristic(mode, &[0x01]).await.is_ok() {
                hogp_put(STAT_PROTOCOL, 1);
            }
        }
    }

    let mut listener = client.listen_all().map_err(|_| fail(0x36))?;
    for characteristic in characteristics.iter() {
        if characteristic.uuid != Uuid::new_short(REPORT) {
            continue;
        }
        let Ok(reference) = client
            .descriptor_by_uuid::<_, [u8]>(characteristic, &Uuid::new_short(REPORT_REFERENCE))
            .await
        else {
            continue;
        };
        let mut value = [0u8; 2];
        if !matches!(client.read_descriptor(&reference, &mut value).await, Ok(2)) {
            continue;
        }
        // `value[1]` is the report type: only Input reports carry motion.
        if value[1] != REF_INPUT {
            continue;
        }
        let Some(cccd) = characteristic.cccd_handle else {
            continue;
        };
        hogp_inc(STAT_REFERENCES);
        // One `listen_all` subscriber covers every handle; `subscribe` would
        // take a second subscriber and hit MAX_SUBSCRIBERS=1.
        if client.write_handle(cccd, &[0x01, 0x00]).await.is_ok() {
            hogp_inc(STAT_SUBSCRIPTIONS);
        }
    }
    if hogp_get(STAT_SUBSCRIPTIONS) == 0 {
        fail(0x37);
        return Err(());
    }

    let deadline = Instant::now() + budget;
    let mut values = [0i32; MAX_FIELDS];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining == Duration::from_micros(0) || hogp_get(STAT_REPORTS) >= 100 {
            break;
        }
        let Ok(notification) = with_timeout(remaining, listener.next()).await else {
            break;
        };
        decode_report(&map, notification.as_ref(), &mut values);
    }
    Ok(())
}

fn find<'a, T: AsGatt + ?Sized>(
    list: &'a [Characteristic<T>],
    uuid: u16,
) -> Option<&'a Characteristic<T>> {
    list.iter().find(|c| c.uuid == Uuid::new_short(uuid))
}

fn decode_report(map: &ReportMap, data: &[u8], values: &mut [i32; MAX_FIELDS]) {
    let Some((id, payload)) = split_report_id(map, data) else {
        return;
    };
    let Some(report) = map.report(ReportKind::Input, id) else {
        return;
    };
    values.fill(0);
    report.decode(payload, values);
    hogp_inc(STAT_REPORTS);
    if let Some(index) = field_index(report, PAGE_GENERIC, USAGE_X) {
        if values[index] != 0 || field_value(report, values, PAGE_GENERIC, USAGE_Y) != 0 {
            hogp_inc(STAT_MOTION);
        }
    }
    if report
        .fields()
        .iter()
        .enumerate()
        .any(|(i, f)| f.usage_page == PAGE_BUTTON && values.get(i).is_some_and(|v| *v != 0))
    {
        hogp_inc(STAT_BUTTONS);
    }
}

/// Report protocol prefixes every value with its report ID; single-report
/// devices without a Report ID item send the payload alone.
fn split_report_id<'a>(map: &ReportMap, data: &'a [u8]) -> Option<(u8, &'a [u8])> {
    if let Some((&first, rest)) = data.split_first() {
        if map.report(ReportKind::Input, first).is_some() {
            return Some((first, rest));
        }
    }
    map.report(ReportKind::Input, 0).map(|_| (0, data))
}

fn field_index(report: &Report, page: u16, usage: u16) -> Option<usize> {
    report
        .fields()
        .iter()
        .position(|f| f.usage_page == page && f.usage == usage)
}

fn field_value(report: &Report, values: &[i32], page: u16, usage: u16) -> i32 {
    field_index(report, page, usage).map_or(0, |i| values[i])
}

/// FNV-1a: the runner recomputes it over the fixture's expected map.
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
