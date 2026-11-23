//! One probe session for CH585 preflight shutdown and verified download.
//!
//! Standalone `probe-rs read` resumes the core after each access, so separate
//! register reads cannot establish that RF stays stopped. This helper halts
//! once, performs the documented engine shutdown, requires two zero CMD
//! acknowledgements, and only then downloads and starts the requested image.
//! Images may be ELF or Intel HEX (the vendor EVT packages ship `.hex`), so
//! differential runs against the vendor stack take the same stop-first path.

use std::path::Path;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant};

use probe_rs::flashing::{
    download_file_with_options, DownloadOptions, ElfLoader, ElfOptions, FlashProgress, Flasher,
    HexLoader,
};
use probe_rs::probe::list::Lister;
use probe_rs::probe::{DebugProbeSelector, WireProtocol};
use probe_rs::{MemoryInterface, Permissions};

const CMD: u64 = 0x4000_c200;
const MODE: u64 = 0x4000_c250;
const BB: u64 = 0x4000_c100;
const RF: u64 = 0x4000_d008;

fn read(core: &mut probe_rs::Core<'_>, address: u64) -> Result<u32, probe_rs::Error> {
    core.inner_mut().read_word_32(address)
}

fn write(core: &mut probe_rs::Core<'_>, address: u64, value: u32) -> Result<(), probe_rs::Error> {
    core.inner_mut().write_word_32(address, value)
}

/// Stop the known CH585 engine. Returns `Err` unless both acknowledgements are
/// zero; the caller must not download in that case.
fn shut_down(core: &mut probe_rs::Core<'_>) -> Result<(), String> {
    let cmd = read(core, CMD).map_err(|e| e.to_string())?;
    let mode = read(core, MODE).map_err(|e| e.to_string())?;
    let bb = read(core, BB).map_err(|e| e.to_string())?;
    let rf = read(core, RF).map_err(|e| e.to_string())?;
    println!("preflight stop: cmd={cmd:08x} mode={mode:08x} bb={bb:08x} rf={rf:08x}");

    // Same engine-stop policy as the radio backend, with separate MODE writes.
    write(core, MODE, mode & !0x10).map_err(|e| e.to_string())?;
    write(core, MODE, mode & !0x710).map_err(|e| e.to_string())?;
    write(core, CMD, cmd | 8).map_err(|e| e.to_string())?;
    write(core, BB, (bb & !0x300) | 0x100).map_err(|e| e.to_string())?;
    write(core, RF, rf & 0xffcd_ffff).map_err(|e| e.to_string())?;
    write(core, MODE, 0x0003_0000).map_err(|e| e.to_string())?;

    for index in 0..2 {
        let value = read(core, CMD).map_err(|e| e.to_string())?;
        println!("preflight idle acknowledgement {index}: {value:08x}");
        if value & 3 != 0 {
            return Err(format!(
                "RF did not acknowledge stop; refusing flash ({value:08x})"
            ));
        }
        sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// What the single probe session does after the RF shutdown check.
enum Action {
    /// Download an image and start it.
    Download(String),
    /// Reset and start the image already in flash. This is a debug reset, not
    /// a power cycle: RAM is cleared, DataFlash is retained either way.
    Reset,
    /// Read DataFlash through the target's `pc_read` algorithm. Direct bus
    /// reads return the sentinel `0xF3F9BDA9`, so this must use the flasher.
    Dump {
        path: String,
        address: u64,
        length: usize,
    },
    /// Read-modify-write CodeFlash (header/body corruption for OTA rounds).
    /// DataFlash is rejected: its contents are only reachable through the
    /// device's own code paths.
    WriteRaw { path: String, address: u64 },
}

/// Pick the flash algorithm that owns `address`.
fn algorithm_for(
    target: &probe_rs::Target,
    address: u64,
) -> Option<&probe_rs::config::RawFlashAlgorithm> {
    target.flash_algorithms.iter().find(|algorithm| {
        let range = &algorithm.flash_properties.address_range;
        address >= range.start && address < range.end
    })
}

fn run() -> Result<(), (u8, String)> {
    let mut args = std::env::args().skip(1);
    let mut selector = None;
    let mut target = None;
    let mut protocol = None;
    let mut image = None;
    let mut verify = false;
    let mut reset = false;
    let mut dump = None;
    let mut write_raw = None;
    let mut raw_address = 0u64;
    let mut no_run = false;
    let mut dataflash_address = 0x0007_7E00u64;
    let mut dataflash_length = 0x200usize;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--probe" => selector = args.next(),
            "--chip" => target = args.next(),
            "--protocol" => protocol = args.next(),
            "--verify" => verify = true,
            "--no-run" => no_run = true,
            "--reset" => reset = true,
            "--write-raw" => write_raw = args.next(),
            "--raw-addr" => {
                let raw = args.next().ok_or((2, "missing --raw-addr".into()))?;
                raw_address =
                    u64::from_str_radix(raw.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .map_err(|e| (2, format!("invalid --raw-addr: {e}")))?;
            }
            "--dump-dataflash" => dump = args.next(),
            "--dataflash-addr" => {
                let raw = args.next().ok_or((2, "missing --dataflash-addr".into()))?;
                dataflash_address =
                    u64::from_str_radix(raw.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .map_err(|e| (2, format!("invalid --dataflash-addr: {e}")))?;
            }
            "--dataflash-len" => {
                let raw = args.next().ok_or((2, "missing --dataflash-len".into()))?;
                dataflash_length = raw
                    .parse()
                    .map_err(|e| (2, format!("invalid --dataflash-len: {e}")))?;
            }
            other => image = Some(other.to_owned()),
        }
    }
    let selector = selector.ok_or((2, "missing --probe".into()))?;
    let target = target.ok_or((2, "missing --chip".into()))?;
    let action = match (reset, dump, image, write_raw) {
        (true, None, None, None) => Action::Reset,
        (false, Some(path), None, None) => Action::Dump {
            path,
            address: dataflash_address,
            length: dataflash_length,
        },
        (false, None, Some(image), None) => Action::Download(image),
        (false, None, None, Some(path)) => {
            if raw_address >= 0x0007_0000 {
                return Err((2, "--write-raw is CodeFlash only (addr < 0x70000)".into()));
            }
            Action::WriteRaw {
                path,
                address: raw_address,
            }
        }
        _ => {
            return Err((
                2,
                "use exactly one of an image, --reset, --dump-dataflash or --write-raw".into(),
            ))
        }
    };

    let selector: DebugProbeSelector = selector
        .parse()
        .map_err(|e| (2, format!("invalid probe: {e}")))?;
    let mut probe = Lister::new()
        .open(selector)
        .map_err(|e| (2, format!("open probe: {e}")))?;
    let protocol = match protocol.as_deref() {
        None | Some("jtag") => WireProtocol::Jtag,
        Some("swd") => WireProtocol::Swd,
        Some(other) => return Err((2, format!("unsupported protocol {other}"))),
    };
    probe
        .select_protocol(protocol)
        .map_err(|e| (2, format!("select protocol: {e}")))?;
    let mut session = probe
        .attach(target.as_str(), Permissions::default())
        .map_err(|e| (2, format!("attach target: {e}")))?;

    {
        let mut core = session.core(0).map_err(|e| (2, format!("core0: {e}")))?;
        let info = core
            .halt(Duration::from_secs(2))
            .map_err(|e| (3, format!("halt: {e}")))?;
        println!("preflight halted at pc={:#x}", info.pc);
        shut_down(&mut core).map_err(|e| (3, e))?;
    }

    if let Action::Dump {
        path,
        address,
        length,
    } = &action
    {
        let target = session.target().clone();
        // Select by address range: the algorithm names differ across the
        // CH57X/CH58X/CH59X target families.
        let raw = algorithm_for(&target, *address)
            .ok_or((4, format!("no flash algorithm covers {address:#x}")))?
            .clone();
        let mut flasher =
            Flasher::new(&target, 0, &raw).map_err(|e| (4, format!("flasher: {e:?}")))?;
        let mut progress = FlashProgress::empty();
        let mut data = vec![0u8; *length];
        flasher
            .run_verify(&mut session, &mut progress, |active, _| {
                active.read_flash(*address, &mut data)
            })
            .map_err(|e| (4, format!("read DataFlash: {e:?}")))?;
        std::fs::write(path, &data).map_err(|e| (4, format!("write {path}: {e}")))?;
        let non_empty = data
            .iter()
            .position(|&byte| byte != 0xFF)
            .map_or("empty".to_owned(), |offset| {
                format!("first used byte +{offset:#x}")
            });
        println!("preflight: dumped {length} bytes at {address:#x} to {path} ({non_empty})");
        return Ok(());
    }

    if let Action::WriteRaw { path, address } = &action {
        let bytes = std::fs::read(path).map_err(|e| (2, format!("read {path}: {e}")))?;
        if bytes.is_empty() {
            return Err((2, format!("{path} is empty")));
        }
        if address + bytes.len() as u64 > 0x0007_0000 {
            return Err((2, "--write-raw must stay in CodeFlash (< 0x70000)".into()));
        }
        let target = session.target().clone();
        let raw = algorithm_for(&target, *address)
            .ok_or((4, format!("no flash algorithm covers {address:#x}")))?
            .clone();
        // Sector, not page: probe-rs erases a whole sector per staged range.
        let sector_size = raw
            .flash_properties
            .sector_info(*address)
            .map_or(raw.flash_properties.page_size as u64, |sector| sector.size);
        let first = *address / sector_size * sector_size;
        let end = address + bytes.len() as u64;
        let mut patched = Vec::new();
        {
            // CodeFlash is memory-mapped for reads, so a plain bus read is
            // enough to preserve the bytes outside the patched span.
            let mut core = session.core(0).map_err(|e| (4, format!("core0: {e}")))?;
            let mut sector = first;
            while sector < end {
                let mut buffer = vec![0u8; sector_size as usize];
                core.read(sector, &mut buffer)
                    .map_err(|e| (4, format!("read {sector:#x}: {e}")))?;
                let copy_start = sector.max(*address);
                let copy_end = (sector + sector_size).min(end);
                let source = (copy_start - *address) as usize;
                let target_offset = (copy_start - sector) as usize;
                let count = (copy_end - copy_start) as usize;
                buffer[target_offset..target_offset + count]
                    .copy_from_slice(&bytes[source..source + count]);
                patched.push((sector, buffer));
                sector += sector_size;
            }
        }
        let mut loader = session.target().flash_loader();
        for (sector, buffer) in &patched {
            loader
                .add_data(*sector, buffer)
                .map_err(|e| (4, format!("stage {sector:#x}: {e}")))?;
        }
        let mut options = DownloadOptions::default();
        options.do_chip_erase = false;
        options.verify = verify;
        loader
            .commit(&mut session, options)
            .map_err(|e| (4, format!("write raw: {e:?}")))?;
        println!(
            "preflight: wrote {} bytes at {address:#x} ({} sector(s))",
            bytes.len(),
            patched.len()
        );
        if !no_run {
            let mut core = session.core(0).map_err(|e| (5, format!("core0: {e}")))?;
            core.reset_and_halt(Duration::from_secs(2))
                .map_err(|e| (5, format!("reset: {e}")))?;
            core.run().map_err(|e| (5, format!("start: {e}")))?;
        }
        return Ok(());
    }

    if matches!(action, Action::Reset) {
        let mut core = session.core(0).map_err(|e| (5, format!("core0: {e}")))?;
        core.reset_and_halt(Duration::from_secs(2))
            .map_err(|e| (5, format!("reset: {e}")))?;
        if !no_run {
            core.run().map_err(|e| (5, format!("start: {e}")))?;
        }
        println!(
            "preflight: reset the image in flash (no download, {})",
            if no_run { "halted" } else { "started" }
        );
        return Ok(());
    }

    let Action::Download(image) = action else {
        unreachable!("dump and reset returned above");
    };
    let mut options = DownloadOptions::default();
    options.verify = verify;
    // A chip erase would wipe the other OTA slot; erase only the sectors
    // this image touches.
    options.do_chip_erase = false;
    let download_started = Instant::now();
    let is_hex = Path::new(&image)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("hex"));
    if is_hex {
        download_file_with_options(&mut session, &image, HexLoader, options)
            .map_err(|e| (4, format!("download: {e:?}")))?;
    } else {
        download_file_with_options(
            &mut session,
            &image,
            ElfLoader(ElfOptions::default()),
            options,
        )
        .map_err(|e| (4, format!("download: {e:?}")))?;
    }
    let download_ms = download_started.elapsed().as_millis();

    if !no_run {
        let mut core = session.core(0).map_err(|e| (4, format!("core0: {e}")))?;
        core.reset_and_halt(Duration::from_secs(2))
            .map_err(|e| (5, format!("reset: {e}")))?;
        core.run().map_err(|e| (5, format!("start: {e}")))?;
    }
    println!(
        "preflight: downloaded {image} and {} (download {download_ms} ms)",
        if no_run { "left halted" } else { "started it" }
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("ch585-preflight: {message}");
            ExitCode::from(code)
        }
    }
}
