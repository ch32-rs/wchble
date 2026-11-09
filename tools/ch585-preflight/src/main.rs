//! One probe session for CH585 preflight shutdown and verified download.
//!
//! Standalone `probe-rs read` resumes the core after each access, so separate
//! register reads cannot establish that RF stays stopped. This helper halts
//! once, performs the documented engine shutdown, requires two zero CMD
//! acknowledgements, and only then downloads and starts the requested ELF.

use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant};

use probe_rs::flashing::{download_file_with_options, DownloadOptions, ElfLoader, ElfOptions};
use probe_rs::probe::list::Lister;
use probe_rs::probe::{DebugProbeSelector, WireProtocol};
use probe_rs::Permissions;

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
            return Err(format!("RF did not acknowledge stop; refusing flash ({value:08x})"));
        }
        sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn run() -> Result<(), (u8, String)> {
    let mut args = std::env::args().skip(1);
    let mut selector = None;
    let mut target = None;
    let mut protocol = None;
    let mut elf = None;
    let mut verify = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--probe" => selector = args.next(),
            "--chip" => target = args.next(),
            "--protocol" => protocol = args.next(),
            "--verify" => verify = true,
            other => elf = Some(other.to_owned()),
        }
    }
    let selector = selector.ok_or((2, "missing --probe".into()))?;
    let target = target.ok_or((2, "missing --chip".into()))?;
    let elf = elf.ok_or((2, "missing ELF path".into()))?;

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

    let mut options = DownloadOptions::default();
    options.verify = verify;
    let download_started = Instant::now();
    download_file_with_options(&mut session, &elf, ElfLoader(ElfOptions::default()), options)
        .map_err(|e| (4, format!("download: {e:?}")))?;
    let download_ms = download_started.elapsed().as_millis();

    {
        let mut core = session.core(0).map_err(|e| (4, format!("core0: {e}")))?;
        core.reset_and_halt(Duration::from_secs(2))
            .map_err(|e| (5, format!("reset: {e}")))?;
        core.run().map_err(|e| (5, format!("start: {e}")))?;
    }
    println!("preflight: downloaded and started {elf} (download {download_ms} ms)");
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
