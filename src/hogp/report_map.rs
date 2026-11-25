//! Minimal HID report descriptor parser: flat fields at exact bit offsets,
//! so decoding is a lookup with no allocation.

/// Input, Output or Feature report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReportKind {
    Input,
    Output,
    Feature,
}

/// One report field (a single usage element, never a whole array).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Field {
    pub usage_page: u16,
    pub usage: u16,
    /// Bit offset inside the report payload (after the report ID byte).
    pub bit_offset: u16,
    pub bit_size: u8,
    pub signed: bool,
}

/// One report, keyed by kind and report ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub kind: ReportKind,
    pub id: u8,
    /// Payload length in bits.
    pub bit_len: u16,
    fields: [Field; MAX_FIELDS],
    len: usize,
}

impl Report {
    pub fn fields(&self) -> &[Field] {
        &self.fields[..self.len]
    }

    /// Decode every field into `out` at its field index, returning the number
    /// of values written.
    ///
    /// `data` is the report payload without the report ID byte. A field that
    /// would read past the payload is left untouched so callers can tell a
    /// short report from a zero value.
    pub fn decode(&self, data: &[u8], out: &mut [i32]) -> usize {
        let mut written = 0;
        for (index, field) in self.fields().iter().enumerate() {
            if index == out.len() {
                break;
            }
            let Some(raw) = read_bits(data, field.bit_offset, field.bit_size) else {
                continue;
            };
            out[index] = if field.signed {
                sign_extend(raw, field.bit_size)
            } else {
                raw as i32
            };
            written += 1;
        }
        written
    }

    /// First field matching `usage_page`/`usage`.
    pub fn find(&self, usage_page: u16, usage: u16) -> Option<&Field> {
        self.fields()
            .iter()
            .find(|f| f.usage_page == usage_page && f.usage == usage)
    }
}

/// Up to this many fields per report; extra elements are dropped.
pub const MAX_FIELDS: usize = 32;
/// Up to this many distinct reports (kind + ID pairs).
pub const MAX_REPORTS: usize = 12;

/// Parsed report descriptors.
#[derive(Clone, Copy, Debug)]
pub struct ReportMap {
    reports: [Option<Report>; MAX_REPORTS],
    len: usize,
}

impl ReportMap {
    /// Parse a HID report descriptor. Returns `None` for malformed items or
    /// when more than [`MAX_REPORTS`] reports are present.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let mut map = Self {
            reports: [None; MAX_REPORTS],
            len: 0,
        };
        let mut globals = Globals::default();
        let mut locals = Locals::default();
        let mut i = 0;
        while i < bytes.len() {
            let prefix = bytes[i];
            if prefix == 0xFE {
                // Long item: size follows, then a reserved byte and tag.
                let size = *bytes.get(i + 1)? as usize;
                i = i.checked_add(3 + size)?;
                if i > bytes.len() {
                    return None;
                }
                continue;
            }
            let size = match prefix & 0x03 {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            let kind = (prefix >> 2) & 0x03;
            let tag = prefix >> 4;
            let data = bytes.get(i + 1..i + 1 + size)?;
            let value = data
                .iter()
                .rev()
                .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
            match kind {
                0 => {
                    if matches!(tag, 0x8 | 0x9 | 0xB) {
                        let kind = match tag {
                            0x8 => ReportKind::Input,
                            0x9 => ReportKind::Output,
                            _ => ReportKind::Feature,
                        };
                        // Bit 0 of a main item's flags marks constant
                        // (padding) data, which advances the cursor only.
                        let constant = value & 1 != 0;
                        map.add_item(kind, &globals, &locals, constant)?;
                    }
                    locals.clear();
                }
                1 => globals.apply(tag, value, size),
                2 => locals.apply(tag, value, size),
                _ => {}
            }
            i += 1 + size;
        }
        Some(map)
    }

    fn add_item(
        &mut self,
        kind: ReportKind,
        g: &Globals,
        l: &Locals,
        constant: bool,
    ) -> Option<()> {
        if g.report_size == 0 || g.report_count == 0 || g.report_size > 32 {
            return Some(());
        }
        let index = self.index(kind, g.report_id)?;
        let report = self.reports[index].get_or_insert_with(|| Report {
            kind,
            id: g.report_id,
            bit_len: 0,
            fields: [Field {
                usage_page: 0,
                usage: 0,
                bit_offset: 0,
                bit_size: 0,
                signed: false,
            }; MAX_FIELDS],
            len: 0,
        });
        let start = report.bit_len;
        let total_bits = u32::from(g.report_size) * u32::from(g.report_count);
        if start as u32 + total_bits > u32::from(u16::MAX) {
            return None;
        }
        if !constant {
            for element in 0..u32::from(g.report_count) {
                if report.len == MAX_FIELDS {
                    break;
                }
                let (usage_page, usage) = l.usage_for(g.usage_page, element);
                let offset = u32::from(start) + element * u32::from(g.report_size);
                report.fields[report.len] = Field {
                    usage_page,
                    usage,
                    bit_offset: offset as u16,
                    bit_size: g.report_size as u8,
                    signed: g.logical_min < 0,
                };
                report.len += 1;
            }
        }
        report.bit_len = (start as u32 + total_bits) as u16;
        Some(())
    }

    fn index(&mut self, kind: ReportKind, id: u8) -> Option<usize> {
        for (i, slot) in self.reports[..self.len].iter().enumerate() {
            if let Some(report) = slot {
                if report.kind == kind && report.id == id {
                    return Some(i);
                }
            }
        }
        if self.len == MAX_REPORTS {
            return None;
        }
        self.len += 1;
        Some(self.len - 1)
    }

    pub fn report(&self, kind: ReportKind, id: u8) -> Option<&Report> {
        self.reports[..self.len]
            .iter()
            .flatten()
            .find(|r| r.kind == kind && r.id == id)
    }

    /// Every Input report ID in descriptor order.
    pub fn input_ids(&self) -> impl Iterator<Item = u8> + '_ {
        self.reports[..self.len]
            .iter()
            .flatten()
            .filter(|r| r.kind == ReportKind::Input)
            .map(|r| r.id)
    }
}

#[derive(Default)]
struct Globals {
    usage_page: u16,
    report_size: u32,
    report_count: u32,
    report_id: u8,
    logical_min: i32,
}

impl Globals {
    fn apply(&mut self, tag: u8, value: u32, size: usize) {
        match tag {
            0x0 => self.usage_page = value as u16,
            // Logical Minimum is signed with the item's own width.
            0x1 => self.logical_min = sign_extend(value, (size * 8) as u8),
            0x7 => self.report_size = value,
            0x8 => self.report_id = value as u8,
            0x9 => self.report_count = value,
            _ => {}
        }
    }
}

/// Local items: individual usages plus a usage min/max range.
struct Locals {
    usages: [(u16, u16); 8],
    len: usize,
    min: Option<(u16, u16)>,
}

impl Default for Locals {
    fn default() -> Self {
        Self {
            usages: [(0, 0); 8],
            len: 0,
            min: None,
        }
    }
}

impl Locals {
    fn clear(&mut self) {
        self.len = 0;
        self.min = None;
    }

    fn apply(&mut self, tag: u8, value: u32, size: usize) {
        // A two-byte usage carries its page in the high byte.
        let entry = if size == 2 {
            ((value >> 8) as u16, (value & 0xFF) as u16)
        } else {
            (0, value as u16)
        };
        match tag {
            0x0 => {
                if self.len < self.usages.len() {
                    self.usages[self.len] = entry;
                    self.len += 1;
                }
            }
            0x1 => self.min = Some(entry),
            _ => {}
        }
    }
}

impl Locals {
    fn usage_for(&self, global_page: u16, element: u32) -> (u16, u16) {
        let (page, usage) = if (element as usize) < self.len {
            self.usages[element as usize]
        } else if let Some((min_page, min)) = self.min {
            (min_page, min.wrapping_add(element as u16))
        } else if self.len > 0 {
            self.usages[self.len - 1]
        } else {
            (0, 0)
        };
        // A one-byte usage takes the current global page.
        (if page == 0 { global_page } else { page }, usage)
    }
}

fn read_bits(data: &[u8], offset: u16, size: u8) -> Option<u32> {
    if size == 0 || size > 32 {
        return None;
    }
    let offset = u32::from(offset);
    let size = u32::from(size);
    if offset + size > data.len() as u32 * 8 {
        return None;
    }
    let mut value = 0u32;
    for bit in 0..size {
        let position = offset + bit;
        let byte = data[(position / 8) as usize];
        if byte & (1 << (position % 8)) != 0 {
            value |= 1 << bit;
        }
    }
    Some(value)
}

fn sign_extend(value: u32, bits: u8) -> i32 {
    if bits == 0 || bits >= 32 {
        return value as i32;
    }
    let shift = 32 - u32::from(bits);
    ((value << shift) as i32) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard boot-style mouse: 5 buttons, 16-bit-free 8-bit X/Y/wheel.
    const MOUSE: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, // Usage Page, Usage (Mouse), Collection
        0x85, 0x01, // Report ID (1)
        0x09, 0x01, 0xA1, 0x00, // Usage (Pointer), Collection
        0x05, 0x09, 0x19, 0x01, 0x29, 0x05, // Buttons 1..5
        0x15, 0x00, 0x25, 0x01, 0x95, 0x05, 0x75, 0x01, 0x81, 0x02, // 5 x 1-bit inputs
        0x95, 0x01, 0x75, 0x03, 0x81, 0x01, // 3-bit padding
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, // Generic Desktop X, Y
        0x15, 0x81, 0x25, 0x7F, // Logical -127..127
        0x75, 0x08, 0x95, 0x02, 0x81, 0x06, // 2 x 8-bit relative
        0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06, // Wheel
        0xC0, 0xC0,
    ];

    const KEYBOARD: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, // Usage Page, Usage (Keyboard), Collection
        0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, // Modifiers 0xE0..0xE7
        0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, // 8 x 1-bit
        0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // reserved byte
        0x05, 0x07, 0x19, 0x00, 0x29, 0x65, // Key array 0..0x65
        0x15, 0x00, 0x25, 0x65, 0x75, 0x08, 0x95, 0x06, 0x81, 0x00, // 6 x 8-bit array
        0xC0,
    ];

    #[test]
    fn mouse_map_offsets_and_decode() {
        let map = ReportMap::parse(MOUSE).expect("parse");
        let mut ids = [0u8; 4];
        let mut count = 0;
        for id in map.input_ids() {
            ids[count] = id;
            count += 1;
        }
        assert_eq!(&ids[..count], &[1]);
        let report = map.report(ReportKind::Input, 1).expect("report");
        assert_eq!(report.bit_len, 32);
        assert_eq!(report.fields().len(), 8);
        for (i, field) in report.fields()[..5].iter().enumerate() {
            assert_eq!((field.usage_page, field.usage), (0x09, i as u16 + 1));
            assert_eq!((field.bit_offset, field.bit_size), (i as u16, 1));
        }
        let x = report.find(0x01, 0x30).expect("X");
        assert_eq!((x.bit_offset, x.bit_size, x.signed), (8, 8, true));
        let y = report.find(0x01, 0x31).expect("Y");
        assert_eq!(y.bit_offset, 16);
        let wheel = report.find(0x01, 0x38).expect("wheel");
        assert_eq!(wheel.bit_offset, 24);

        let mut values = [0i32; 8];
        let n = report.decode(&[0x02, 0xF6, 0x05, 0xFE], &mut values);
        assert_eq!(n, 8);
        assert_eq!(&values[..5], &[0, 1, 0, 0, 0]);
        assert_eq!(&values[5..], &[-10, 5, -2]);
    }

    #[test]
    fn keyboard_map_decodes_modifiers_and_keys() {
        let map = ReportMap::parse(KEYBOARD).expect("parse");
        let report = map.report(ReportKind::Input, 0).expect("report");
        assert_eq!(report.bit_len, 64);
        let left_alt = report.find(0x07, 0xE2).expect("left alt");
        assert_eq!(left_alt.bit_offset, 2);
        let mut values = [0i32; 16];
        let n = report.decode(&[0x04, 0x00, 0x04, 0, 0, 0, 0, 0], &mut values);
        assert_eq!(n, 14);
        assert_eq!(values[2], 1);
        assert_eq!(values[8], 4);
    }

    #[test]
    fn constant_items_advance_the_cursor_without_fields() {
        let map = ReportMap::parse(MOUSE).expect("parse");
        let report = map.report(ReportKind::Input, 1).expect("report");
        // The 3-bit padding between buttons and X is not a field.
        assert_eq!(report.fields().len(), 8);
    }

    /// The android-gatt HID fixture's exact report map (66 bytes).
    const FIXTURE_MOUSE: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x01, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19,
        0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01,
        0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x01, 0x80, 0x26, 0xFF,
        0x7F, 0x75, 0x10, 0x95, 0x02, 0x81, 0x06, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08,
        0x95, 0x01, 0x81, 0x06, 0xC0, 0xC0,
    ];

    #[test]
    fn fixture_mouse_map_decodes_16_bit_motion() {
        let map = ReportMap::parse(FIXTURE_MOUSE).expect("parse");
        let report = map.report(ReportKind::Input, 1).expect("report");
        assert_eq!(report.bit_len, 48);
        let x = report.find(0x01, 0x30).expect("X");
        assert_eq!((x.bit_offset, x.bit_size, x.signed), (8, 16, true));
        let y = report.find(0x01, 0x31).expect("Y");
        assert_eq!(y.bit_offset, 24);
        let wheel = report.find(0x01, 0x38).expect("wheel");
        assert_eq!((wheel.bit_offset, wheel.bit_size), (40, 8));

        // Fixture frame: id 1, button 1, dx=3, dy=-2, wheel=0.
        let mut values = [0i32; 8];
        let n = report.decode(&[0x01, 0x03, 0x00, 0xFE, 0xFF, 0x00], &mut values);
        assert_eq!(n, 6);
        assert_eq!(&values[..3], &[1, 0, 0]);
        assert_eq!(&values[3..6], &[3, -2, 0]);
    }

    #[test]
    fn malformed_descriptor_is_rejected() {
        assert!(ReportMap::parse(&[0x05]).is_none());
        assert!(ReportMap::parse(&[0xFE, 0x02, 0x00]).is_none());
    }
}
