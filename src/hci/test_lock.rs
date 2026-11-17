//! One lock for every test that touches the global HCI channels or link table.

extern crate std;

use std::sync::{Mutex, MutexGuard};

pub(crate) fn lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}
