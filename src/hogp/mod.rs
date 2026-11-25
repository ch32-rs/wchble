//! Host-side HID-over-GATT helpers (chip independent).
//!
//! Only the report descriptor subset needed to decode input reports lives
//! here: usage page/usage, report size/count, logical range, and the
//! Input/Output/Feature bit offsets.

pub mod report_map;
