//! X2a: non-connectable extended advertising beacon, cooperatively polled
//! outside RF deadlines.

use core::future::pending;

use embassy_time::Duration;
use trouble_host::prelude::*;

use crate::host::{
    HostStats, PHASE_ADVERTISING, PHASE_FATAL, PHASE_STARTING, STAT_ADVERTISE_ATTEMPTS, STAT_PHASE,
};

/// X2a acceptance marker: 128 bytes as one manufacturer-specific AD structure
/// (`127, 0xFF, 'W', 'C'`) — an incrementing sequence closed by the CRC-32 of
/// the first 124 bytes. The full payload is byte-compared on the scanner side.
pub const EXT_ADV_DATA_LEN: usize = 128;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = u32::from(crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn marker() -> [u8; EXT_ADV_DATA_LEN] {
    let mut data = [0u8; EXT_ADV_DATA_LEN];
    // One AD structure exactly fills the payload: length 127 covers the type
    // octet plus the 126 bytes after it.
    data[0] = (EXT_ADV_DATA_LEN - 1) as u8;
    data[1] = 0xff;
    data[2] = b'W';
    data[3] = b'C';
    for (i, slot) in data.iter_mut().enumerate().take(124).skip(4) {
        *slot = (i * 7 + 5) as u8;
    }
    let crc = crc32(&data[..124]);
    data[124..128].copy_from_slice(&crc.to_le_bytes());
    data
}

/// The 2M round mirrors the 1M image: only the AUX PHY differs.
#[cfg(feature = "x2-ext-adv-2m")]
const SECONDARY_PHY: PhyKind = PhyKind::Le2M;
#[cfg(not(feature = "x2-ext-adv-2m"))]
const SECONDARY_PHY: PhyKind = PhyKind::Le1M;

/// One-shot beacon bring-up: params + data + enable, then park forever. The
/// advertiser must stay alive or its drop guard disables the set.
pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats, address: [u8; 6]) {
    stats.phase(PHASE_STARTING);
    // No connections are ever accepted; one slot only keeps `peripheral()`
    // from requiring a zero-sized connection table.
    let mut resources: HostResources<DefaultPacketPool, 1, 0, 1, 0> = HostResources::new();
    let builder =
        trouble_host::new(controller, &mut resources).set_random_address(Address::random(address));
    let stack = builder.build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    stats.phase(PHASE_ADVERTISING);
    stats.inc(STAT_ADVERTISE_ATTEMPTS);
    let beacon_task = async {
        let data = marker();
        let params = AdvertisementParameters {
            primary_phy: PhyKind::Le1M,
            secondary_phy: SECONDARY_PHY,
            // A min==max range runs at max in this controller.
            interval_min: Duration::from_millis(160),
            interval_max: Duration::from_millis(160),
            ..AdvertisementParameters::default()
        };
        let sets = [AdvertisementSet {
            params,
            data: Advertisement::ExtNonconnectableNonscannableUndirected {
                adv_data: &data,
                anonymous: false,
            },
            address: None,
        }];
        let mut handles = AdvertisementSet::handles(&sets);
        if let Err(_) = peripheral.advertise_ext(&sets, &mut handles).await {
            stats.set(STAT_PHASE, PHASE_FATAL);
        }
        // The advertiser must stay alive or its drop guard disables the set.
        pending::<()>().await
    };
    // The Host's HCI round trips only advance while `runner.run()` is polled.
    let _ = embassy_futures::join::join(runner.run(), beacon_task).await;
}
