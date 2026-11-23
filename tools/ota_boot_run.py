#!/usr/bin/env python3
"""Run the X6b boot-manager rounds on the CH585 from a prebuilt manifest."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import ota_image

DEFAULT_PROBE = "1a86:8010:F93D8F067E10"
DEFAULT_PREFLIGHT = Path(__file__).with_name("ch585-preflight") / \
    "target" / "release" / "ch585-preflight"
SCAN_TOOL = Path(__file__).resolve().parent.parent / "examples" / \
    "ch585-rf-smoke" / "tools" / "scan_ch585.swift"

SLOT_BASES = {"a": ota_image.SLOT_A_BASE, "b": ota_image.SLOT_B_BASE}
METADATA_BASE = 0x70000  # DataFlash region base (not an image-header constant)
METADATA_DUMP_LEN = 0x200  # both metadata pages
BOOT_MAGIC = 0x544F4F42  # "BOOT", matches `stats::BOOT_MAGIC`
BOOT_VERSION = 1
ELAPSED_WORD = 11  # `ELAPSED_US` in `stats.rs`

STAT_NAMES = {
    2: "slot_a_state", 3: "slot_b_state", 4: "seq_a", 5: "seq_b",
    6: "selected", 7: "attempts", 8: "action", 9: "meta_load",
    10: "meta_save", 11: "elapsed_us", 12: "rollback",
}
ACTION_NAMES = {0: "boot", 1: "no_valid_slot", 2: "all_failed",
                3: "metadata_write_failed"}
# Matches `slots::SlotState` in `examples/ch585-boot-manager`.
SLOT_STATE_NAMES = {0: "valid", 1: "read", 2: "bad_magic", 3: "bad_format",
                    4: "bad_length", 5: "bad_sequence", 6: "bad_header_crc",
                    7: "bad_image_crc"}


class RunError(RuntimeError):
    pass


# ---------------------------------------------------------------- manifest

def load_manifest(path):
    data = json.loads(Path(path).read_text())
    base = Path(path).resolve().parent
    entries = {"boot": data["boot"], **data["images"]}
    for name, entry in entries.items():
        file_path = base / entry["file"]
        if not file_path.exists():
            raise RunError(f"manifest entry {name}: missing {file_path}")
        digest = sha256(file_path)
        if entry.get("sha256") and entry["sha256"] != digest:
            raise RunError(
                f"manifest entry {name}: sha256 {digest} != {entry['sha256']}")
        entry["path"] = file_path
        entry["sha256"] = digest
    for name, entry in data["images"].items():
        if entry["slot"] not in SLOT_BASES:
            raise RunError(f"manifest entry {name}: bad slot {entry['slot']}")
        if entry.get("sequence", 0) <= 0:
            raise RunError(f"manifest entry {name}: sequence must be >= 1")
    return {"boot": entries["boot"], "images": data["images"], "path": path}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def assert_monotonic(downloads, failed):
    """Refuse a sequence that cannot win or would revive a failed slot."""
    by_slot = {}
    for name, entry in downloads:
        slot = entry["slot"]
        sequence = entry["sequence"]
        by_slot.setdefault(slot, []).append((name, sequence))
        if sequence <= failed.get(slot, 0):
            raise RunError(
                f"{name}: sequence {sequence} <= failed_seq[{slot}] "
                f"{failed.get(slot)}")
    for slot, items in by_slot.items():
        for (first, a), (second, b) in zip(items, items[1:]):
            if b <= a:
                raise RunError(f"{slot}: {second} seq {b} not above {first} {a}")


# ---------------------------------------------------------------- metadata

def _newer(a, b):
    """Wrap-safe `a` is newer than `b` (same rule as `select`)."""
    return a != b and (a - b) & 0xFFFF_FFFF < 0x8000_0000


def decode_pages(blob):
    """Return the newest valid metadata record in a 512 B two-page dump."""
    best = None
    for index, offset in enumerate((0, 0x100)):
        page = blob[offset:offset + 0x100]
        if len(page) < 0x100:
            continue
        try:
            record = ota_image.decode_metadata(page)
        except ota_image.ElfError:
            continue
        record["page"] = index
        if best is None or _newer(record["store_seq"], best["store_seq"]):
            best = record
    return best


def blank_file(path, length=0x1000):
    Path(path).write_bytes(b"\xff" * length)
    return path


# ---------------------------------------------------------------- probe

def parse_word_output(output, count):
    """Parse `probe-rs read` hex-table output (`ADDR: w0 w1 ...`)."""
    values = []
    for line in output.splitlines():
        if ":" in line:
            line = line.split(":", 1)[1]
        values.extend(line.split())
    return [int(token, 16) for token in values][:count]


class Probe:
    def __init__(self, selector, chip="CH585", protocol="jtag",
                 preflight=DEFAULT_PREFLIGHT):
        self.selector = selector
        self.chip = chip
        self.protocol = protocol
        self.preflight = str(preflight)

    def _run(self, argv, timeout=120):
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=timeout)
        if result.returncode != 0:
            raise RunError(f"{' '.join(argv)} failed ({result.returncode}): "
                           f"{result.stderr.strip()}")
        return result.stdout

    def preflight_cmd(self, *args):
        return [self.preflight, "--probe", self.selector, "--chip", self.chip,
                "--protocol", self.protocol, *map(str, args)]

    def download(self, path, no_run=True):
        args = ["--no-run"] if no_run else []
        return self._run(self.preflight_cmd(*args, path))

    def reset(self, no_run=False):
        args = ["--reset"]
        if no_run:
            args.append("--no-run")
        return self._run(self.preflight_cmd(*args))

    def write_raw(self, path, address, no_run=True):
        args = ["--write-raw", path, "--raw-addr", hex(address)]
        if no_run:
            args.append("--no-run")
        return self._run(self.preflight_cmd(*args))

    def dump_metadata(self, path):
        return self._run(self.preflight_cmd(
            "--dump-dataflash", path,
            "--dataflash-addr", hex(METADATA_BASE),
            "--dataflash-len", str(METADATA_DUMP_LEN)))

    def read_words(self, address, count):
        argv = ["probe-rs", "read", "--probe", self.selector,
                "--chip", self.chip, "--protocol", self.protocol,
                "b32", hex(address), str(count)]
        output = self._run(argv)
        return parse_word_output(output, count)

    def scan(self, name, seconds=6):
        result = subprocess.run(
            ["swift", str(SCAN_TOOL), name, str(seconds)],
            capture_output=True, text=True, timeout=seconds + 30)
        # The scanner exits 1 for "ran, saw nothing" and 2 for a failure.
        if result.returncode not in (0, 1):
            raise RunError(f"scan failed ({result.returncode}): "
                           f"{result.stderr.strip()}")
        return {"name": name, "seen": result.returncode == 0,
                "output": result.stdout.strip()}


# ---------------------------------------------------------------- rounds

@dataclass
class Step:
    kind: str
    args: tuple = ()


def Dl(name):
    return Step("download", (name,))


def Blank(address):
    return Step("blank", (address,))


def Reset():
    return Step("reset")


def Scan(name, seconds=6):
    return Step("scan", (name, seconds))


def Wait(seconds):
    return Step("wait", (seconds,))


def Stats():
    return Step("stats")


def Dump():
    return Step("dump")


def CorruptHeader(address):
    return Step("corrupt_header", (address,))


def Poke(address, data):
    return Step("poke", (address, data))


@dataclass
class Round:
    steps: list
    gates: list
    note: str = ""


def scan_gate(index, name, seen=True):
    return ("scan", index, name, seen)


def stat_gate(key, expected):
    return ("stat", key, expected)


def meta_gate(key, expected):
    return ("meta", key, expected)


# R6 (both metadata copies corrupt) stays offline; the old streaming-CRC
# rounds R0/R9 were dropped with the boot-time read-back approach.
ROUNDS = {
    "R1": Round([
        Dl("boot"), Blank(SLOT_BASES["b"]), Dl("wipe"), Reset(), Wait(4.0),
        Dl("a2"), Reset(), Scan("wch585-ota-a"), Stats(), Dump(),
    ], [
        stat_gate("action", 0), stat_gate("selected", 0),
        stat_gate("meta_save", 1), meta_gate("active_slot", 0),
        meta_gate("good_seq", 2), scan_gate(0, "wch585-ota-a"),
    ], note="first boot of A interrupts a candidate attempt"),
    "R2": Round([
        Dl("b3"), Reset(), Scan("wch585-ota-b"), Stats(), Dump(),
    ], [
        stat_gate("action", 0), stat_gate("selected", 1),
        stat_gate("attempts", 1), meta_gate("active_slot", 1),
        meta_gate("good_seq", 3), scan_gate(0, "wch585-ota-b"),
    ], note="higher sequence in B wins"),
    "R3": Round([
        CorruptHeader(SLOT_BASES["b"]), Reset(),
        Scan("wch585-ota-a"), Stats(), Dump(),
    ], [
        stat_gate("action", 0), stat_gate("selected", 0),
        meta_gate("active_slot", 0), meta_gate("good_seq", 2),
        scan_gate(0, "wch585-ota-a"),
    ], note="bad B header rolls back to A; A was not touched"),
    "R4": Round([
        Dl("b3-nogood"), Reset(), Scan("wch585-ota-b", 5),
        Reset(), Scan("wch585-ota-b", 5),
        Reset(), Scan("wch585-ota-a"), Stats(), Dump(),
    ], [
        stat_gate("action", 0), stat_gate("selected", 0),
        stat_gate("rollback", 1), meta_gate("failed_seq_b", 3),
        meta_gate("active_slot", 0), scan_gate(0, "wch585-ota-b"),
        scan_gate(1, "wch585-ota-b"), scan_gate(2, "wch585-ota-a"),
    ], note="never-good candidate exhausts two attempts, then rolls back"),
    "R5": Round([
        Dl("b4"), Poke(SLOT_BASES["b"] + 0x10, b"\x05"), Reset(),
        Scan("wch585-ota-a"), Stats(), Dump(),
    ], [
        stat_gate("action", 0), stat_gate("selected", 0),
        stat_gate("slot_b_state", 6), meta_gate("active_slot", 0),
        meta_gate("good_seq", 2), scan_gate(0, "wch585-ota-a"),
    ], note="header CRC rejects a damaged sequence; the body is untouched"),
    "R7": Round([
        Dl("b5-fault"), Reset(), Stats(), Dump(),
        Reset(), Stats(), Dump(),
        Reset(), Scan("wch585-ota-a"), Stats(), Dump(),
    ], [
        stat_gate("action", 0), stat_gate("selected", 0),
        stat_gate("rollback", 1), meta_gate("failed_seq_b", 5),
        scan_gate(0, "wch585-ota-a"),
    ], note="truncated good-mark stays unseen; the attempt count survives"),
    "R8": Round([
        Blank(SLOT_BASES["a"]), Blank(SLOT_BASES["b"]), Reset(),
        Scan("wch585-ota-a", 4), Stats(),
    ], [
        stat_gate("action", 1), stat_gate("selected", 0xFF),
        scan_gate(0, "wch585-ota-a", seen=False),
    ], note="both slots invalid: park, watchdog fed, no advertisement"),
}


# ---------------------------------------------------------------- gates

def gate_failures(round_spec, evidence):
    stats = evidence.get("stats", {})
    meta = evidence.get("metadata") or {}
    scans = evidence.get("scans", [])
    failures = []
    for gate in round_spec.gates:
        kind, *rest = gate
        if kind == "stat":
            key, expected = rest
            actual = stats.get(key)
            if actual != expected:
                failures.append(f"stat {key}: {actual!r} != {expected!r}")
        elif kind == "meta":
            key, expected = rest
            actual = meta.get(key)
            if actual != expected:
                failures.append(f"metadata {key}: {actual!r} != {expected!r}")
        elif kind == "scan":
            index, name, seen = rest
            actual = scans[index]
            if actual["seen"] != seen:
                failures.append(
                    f"scan {index} {name}: seen={actual['seen']} != {seen}")
    return failures


# ---------------------------------------------------------------- execution

def run_round(round_id, manifest, work_dir, probe):
    round_spec = ROUNDS[round_id]
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    evidence = {"round": round_id, "started": time.time(), "steps": [],
                "scans": [], "downloads": [], "stats": {}, "metadata": None,
                "sha256": {}}

    def resolve(name):
        entry = manifest["boot"] if name == "boot" else manifest["images"][name]
        return entry

    baseline = None
    planned = []
    for step in round_spec.steps:
        if step.kind == "download":
            planned.append((step.args[0], resolve(step.args[0])))
    # A wipe round erases the metadata the archive describes, so earlier
    # failed sequences do not constrain it.
    wipes = any(entry.get("variant") == "wipe" for _, entry in planned)
    failed = {}
    archive = work_dir / "state.json"
    if archive.exists() and not wipes:
        failed = json.loads(archive.read_text()).get("failed", {})
    image_downloads = [item for item in planned if item[1].get("slot")]
    assert_monotonic(image_downloads, failed)

    for step in round_spec.steps:
        entry = {"step": step.kind, "args": list(step.args)}
        output = None
        if step.kind == "download":
            name = step.args[0]
            image = resolve(name)
            output = probe.download(image["path"], no_run=True)
            evidence["downloads"].append(name)
            evidence["sha256"][name] = image["sha256"]
        elif step.kind == "blank":
            address = step.args[0]
            path = work_dir / f"blank-{address:x}.bin"
            blank_file(path)
            output = probe.write_raw(path, address)
        elif step.kind == "corrupt_header":
            address, = step.args
            path = work_dir / f"bad-header-{address:x}.bin"
            path.write_bytes(b"XXXX")
            output = probe.write_raw(path, address)
        elif step.kind == "poke":
            address, data = step.args
            path = work_dir / f"poke-{address:x}.bin"
            path.write_bytes(bytes(data))
            output = probe.write_raw(path, address)
        elif step.kind == "reset":
            # The old BOOT_STATS survives Reset; remember it so the stats step
            # can wait for the new boot instead of reading stale words.
            baseline = read_stats_words(manifest, probe)
            output = probe.reset()
        elif step.kind == "scan":
            name, seconds = step.args
            result = probe.scan(name, seconds)
            evidence["scans"].append(result)
            output = result["output"]
        elif step.kind == "wait":
            time.sleep(step.args[0])
            output = f"slept {step.args[0]}s"
        elif step.kind == "stats":
            # The manager writes BOOT_STATS ~1 s after reset, and the array
            # survives Reset, so wait until it differs from the baseline.
            words = wait_for_stats(manifest, probe, baseline)
            evidence["stats"] = stats_from_words(words)
            output = evidence["stats"]
        elif step.kind == "dump":
            page = work_dir / "metadata.bin"
            output = probe.dump_metadata(page)
            evidence["metadata"] = decode_pages(page.read_bytes())
        else:
            raise RunError(f"unknown step {step.kind}")
        entry["output"] = output
        evidence["steps"].append(entry)

    evidence["failures"] = gate_failures(round_spec, evidence)
    evidence["ok"] = not evidence["failures"]
    evidence["finished"] = time.time()
    result_path = work_dir / f"{round_id}.json"
    result_path.write_text(json.dumps(evidence, indent=2, default=str) + "\n")
    if evidence["metadata"]:
        archive.write_text(json.dumps({"failed": {
            slot: evidence["metadata"].get(f"failed_seq_{slot}", 0)
            for slot in ("a", "b")
        }}, indent=2) + "\n")
    return evidence


def stats_address(manifest):
    elf = ota_image.parse_elf(manifest["boot"]["path"])
    symbol = elf["symbols"].get("BOOT_STATS")
    if symbol is None:
        raise RunError("boot ELF has no BOOT_STATS symbol")
    return symbol[0]


def read_stats_words(manifest, probe):
    return probe.read_words(stats_address(manifest), 32)


def stats_from_words(words):
    stats = {STAT_NAMES[index]: words[index]
             for index in STAT_NAMES if index < len(words)}
    stats["magic"] = words[0]
    stats["version"] = words[1]
    stats["action_name"] = ACTION_NAMES.get(stats.get("action"), "?")
    stats["slot_a_name"] = SLOT_STATE_NAMES.get(stats.get("slot_a_state"), "?")
    stats["slot_b_name"] = SLOT_STATE_NAMES.get(stats.get("slot_b_state"), "?")
    return stats


def wait_for_stats(manifest, probe, baseline, timeout=12.0):
    """Poll until a fresh complete record appears (magic is written last)."""
    address = stats_address(manifest)
    deadline = time.monotonic() + timeout
    while True:
        words = probe.read_words(address, 32)
        if (words[0] == BOOT_MAGIC
                and words[1] == BOOT_VERSION
                and words[ELAPSED_WORD] != 0
                and words != baseline):
            return words
        if time.monotonic() >= deadline:
            raise RunError("BOOT_STATS did not refresh after reset")
        time.sleep(0.2)


def read_stats(manifest, probe):
    return stats_from_words(read_stats_words(manifest, probe))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    round_parser = sub.add_parser("round")
    round_parser.add_argument("round", choices=sorted(ROUNDS))
    round_parser.add_argument("--manifest", required=True)
    round_parser.add_argument("--work-dir", required=True)
    round_parser.add_argument("--probe", default=DEFAULT_PROBE)
    round_parser.add_argument("--chip", default="CH585")
    round_parser.add_argument("--protocol", default="jtag")
    round_parser.add_argument("--preflight", default=str(DEFAULT_PREFLIGHT))

    stats_parser = sub.add_parser("stats")
    stats_parser.add_argument("--manifest", required=True)
    stats_parser.add_argument("--probe", default=DEFAULT_PROBE)
    stats_parser.add_argument("--chip", default="CH585")
    stats_parser.add_argument("--protocol", default="jtag")

    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        probe = Probe(args.probe, args.chip, args.protocol,
                      getattr(args, "preflight", DEFAULT_PREFLIGHT))
        if args.command == "stats":
            print(json.dumps(read_stats(manifest, probe), indent=2))
            return 0
        evidence = run_round(args.round, manifest, args.work_dir, probe)
        print(json.dumps({"round": evidence["round"], "ok": evidence["ok"],
                          "failures": evidence["failures"],
                          "stats": evidence["stats"],
                          "metadata": evidence["metadata"]}, indent=2))
        return 0 if evidence["ok"] else 1
    except (RunError, ota_image.ElfError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
