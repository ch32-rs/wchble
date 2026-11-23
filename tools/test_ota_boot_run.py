#!/usr/bin/env python3
"""Offline tests for ota_boot_run.py; no probe, no Swift scan."""
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

_spec = importlib.util.spec_from_file_location("ota_boot_run", HERE / "ota_boot_run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)
ota = run.ota_image
ota_image_test = __import__("test_ota_image")


def page(**overrides):
    values = dict(active="a", candidate="b", attempts=1, flags=0,
                  candidate_seq=3, good_seq=2, failed_a=0, failed_b=0,
                  store_seq=1)
    values.update(overrides)
    return ota.encode_metadata(type("Args", (), values)())


def write_manifest(directory, images, boot_sha=None):
    directory = Path(directory)
    boot = directory / "boot.elf"
    boot.write_bytes(b"elf")
    data = {"boot": {"file": "boot.elf", "sha256": boot_sha or run.sha256(boot)},
            "images": {}}
    for name, (kind, sequence) in images.items():
        path = directory / f"{name}.bin"
        path.write_bytes(bytes([sequence % 256]) * 0x1000)
        data["images"][name] = {
            "file": path.name,
            "slot": "a" if kind == "a" else "b",
            "sequence": sequence,
            "sha256": run.sha256(path),
        }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(data))
    return manifest_path


class ManifestTest(unittest.TestCase):
    def test_records_sha_and_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(tmp, {"a2": ("a", 2)})
            manifest = run.load_manifest(path)
            self.assertEqual(manifest["images"]["a2"]["sequence"], 2)
            self.assertTrue(manifest["images"]["a2"]["path"].exists())
            self.assertEqual(len(manifest["images"]["a2"]["sha256"]), 64)

    def test_rejects_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(tmp, {"a2": ("a", 2)}, boot_sha="0" * 64)
            with self.assertRaises(run.RunError):
                run.load_manifest(path)

    def test_rejects_bad_slot_and_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(tmp, {"a2": ("a", 0)})
            with self.assertRaises(run.RunError):
                run.load_manifest(path)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(tmp, {"a2": ("a", 2)})
            data = json.loads(Path(path).read_text())
            data["images"]["a2"]["slot"] = "z"
            Path(path).write_text(json.dumps(data))
            with self.assertRaises(run.RunError):
                run.load_manifest(path)


class MonotonicTest(unittest.TestCase):
    def images(self, *pairs):
        return [(f"i{index}", {"slot": slot, "sequence": sequence, "name": name})
                for index, (name, slot, sequence) in enumerate(pairs)]

    def test_accepts_increasing(self):
        run.assert_monotonic(self.images(("wipe", "a", 1), ("a2", "a", 2),
                                         ("b3", "b", 3)), {})

    def test_rejects_equal_or_decreasing(self):
        with self.assertRaises(run.RunError):
            run.assert_monotonic(self.images(("a2", "a", 2), ("a3", "a", 2)), {})
        with self.assertRaises(run.RunError):
            run.assert_monotonic(self.images(("a4", "a", 4), ("a3", "a", 3)), {})

    def test_rejects_sequence_not_above_failed(self):
        with self.assertRaises(run.RunError):
            run.assert_monotonic(self.images(("b3", "b", 3)), {"b": 3})

    def test_uses_the_firmware_wrap_rule(self):
        # B was re-stamped across the 32-bit wrap.
        run.assert_monotonic(self.images(("old", "b", 0xFFFF_FFF0),
                                         ("new", "b", 5)), {})
        run.assert_monotonic(self.images(("b1", "b", 1)),
                             {"b": 0xFFFF_FFFE})


class MetadataTest(unittest.TestCase):
    def test_picks_newest_page(self):
        blob = page(store_seq=1) + page(store_seq=2, good_seq=7)
        record = run.decode_pages(blob)
        self.assertEqual(record["page"], 1)
        self.assertEqual(record["good_seq"], 7)

    def test_ignores_corrupt_page(self):
        bad = bytearray(page(store_seq=5))
        bad[30] ^= 0xFF
        blob = bytes(bad) + page(store_seq=2)
        self.assertEqual(run.decode_pages(blob)["store_seq"], 2)

    def test_ignores_tombstone_page(self):
        dead = bytearray(page(store_seq=5))
        struct.pack_into("<H", dead, 12, 0)
        struct.pack_into("<I", dead, 16, 0)
        struct.pack_into("<I", dead, 20, ota.crc32(dead[:20]))
        blob = bytes(dead) + page(store_seq=2)
        self.assertEqual(run.decode_pages(blob)["store_seq"], 2)

    def test_newer_handles_sequence_wrap(self):
        self.assertTrue(run._newer(5, 0xFFFF_FFF0))
        self.assertFalse(run._newer(0xFFFF_FFF0, 5))
        self.assertFalse(run._newer(3, 3))

    def test_none_when_both_invalid(self):
        self.assertIsNone(run.decode_pages(b"\xff" * 512))


class GateTest(unittest.TestCase):
    def evidence(self, stats=None, meta=None, scans=None):
        return {"stats": stats or {}, "metadata": meta,
                "scans": scans or []}

    def test_r4_passes_when_all_evidence_matches(self):
        round_spec = run.ROUNDS["R4"]
        evidence = self.evidence(
            stats={"action": 0, "selected": 0, "rollback": 1},
            meta={"failed_seq_b": 3, "active_slot": 0},
            scans=[{"seen": True}, {"seen": True}, {"seen": True}])
        self.assertEqual(run.gate_failures(round_spec, evidence), [])

    def test_r4_fails_on_missing_rollback(self):
        round_spec = run.ROUNDS["R4"]
        evidence = self.evidence(
            stats={"action": 0, "selected": 0, "rollback": 0},
            meta={"failed_seq_b": 3, "active_slot": 0},
            scans=[{"seen": True}, {"seen": True}, {"seen": True}])
        self.assertTrue(any("rollback" in item
                            for item in run.gate_failures(round_spec, evidence)))

    def test_r5_requires_a_bad_header_crc(self):
        round_spec = run.ROUNDS["R5"]
        evidence = self.evidence(
            stats={"action": 0, "selected": 0, "slot_b_state": 0},
            meta={"active_slot": 0, "good_seq": 2},
            scans=[{"seen": True}])
        self.assertTrue(any("slot_b_state" in item
                            for item in run.gate_failures(round_spec, evidence)))
        evidence["stats"]["slot_b_state"] = 6
        self.assertEqual(run.gate_failures(round_spec, evidence), [])

    def test_r8_requires_absence_of_advertisement(self):
        round_spec = run.ROUNDS["R8"]
        evidence = self.evidence(stats={"action": 1, "selected": 0xFF},
                                 scans=[{"seen": False}])
        self.assertEqual(run.gate_failures(round_spec, evidence), [])
        evidence["scans"][0]["seen"] = True
        self.assertTrue(run.gate_failures(round_spec, evidence))


class ScanTest(unittest.TestCase):
    def test_scanner_failure_is_not_a_negative_observation(self):
        probe = run.Probe("1a86:8010:test")
        failed = mock.Mock(returncode=2, stdout="", stderr="unavailable")
        with mock.patch.object(run.subprocess, "run", return_value=failed):
            with self.assertRaises(run.RunError):
                probe.scan("wch585-ota-a", 1)

    def test_zero_observations_is_seen_false(self):
        probe = run.Probe("1a86:8010:test")
        empty = mock.Mock(returncode=1, stdout="observations=0\n", stderr="")
        with mock.patch.object(run.subprocess, "run", return_value=empty):
            self.assertFalse(probe.scan("wch585-ota-a", 1)["seen"])


class ProbeCommandTest(unittest.TestCase):
    def test_write_raw_passes_no_run(self):
        probe = run.Probe("sel")
        seen = []
        probe._run = lambda argv, timeout=120: seen.append(argv) or ""
        probe.write_raw(Path("x.hex"), 0x4000)
        self.assertIn("--no-run", seen[0])
        probe.write_raw(Path("x.hex"), 0x4000, no_run=False)
        self.assertNotIn("--no-run", seen[1])


class StatsWaitTest(unittest.TestCase):
    def boot_elf(self, tmp):
        path = Path(tmp) / "stats.elf"
        path.write_bytes(ota_image_test.make_elf(
            0, [(0, b"\x00" * 64), (0x40, 0x20000000, b"\x00" * 4)],
            {"BOOT_STATS": 0x20000000}))
        return path

    def test_waits_for_words_to_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"boot": {"path": self.boot_elf(tmp)}}
            probe = FakeProbe()
            baseline = run.read_stats_words(manifest, probe)
            words = run.wait_for_stats(manifest, probe, baseline)
            self.assertEqual(words[11], 2)
            self.assertEqual(run.stats_from_words(words)["magic"],
                             run.BOOT_MAGIC)

    def test_rejects_a_half_written_record(self):
        class HalfWritten(FakeProbe):
            def read_words(self, address, count):
                self.calls.append(("read", address, count))
                words = list(self.words)
                words[11] = 0  # init zeroed the fields; magic not written yet
                return words

        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"boot": {"path": self.boot_elf(tmp)}}
            probe = HalfWritten()
            with self.assertRaises(run.RunError):
                run.wait_for_stats(manifest, probe, None, timeout=0.05)

    def test_times_out_when_stats_never_refresh(self):
        class Stale(FakeProbe):
            def read_words(self, address, count):
                self.calls.append(("read", address, count))
                return list(self.words)

        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"boot": {"path": self.boot_elf(tmp)}}
            probe = Stale()
            with self.assertRaises(run.RunError):
                run.wait_for_stats(manifest, probe, list(probe.words),
                                   timeout=0.01)


class SlotStateTest(unittest.TestCase):
    def test_names_match_the_firmware_enum(self):
        # examples/ch585-boot-manager/src/slots.rs `SlotState`
        self.assertEqual(run.SLOT_STATE_NAMES[0], "valid")
        self.assertEqual(run.SLOT_STATE_NAMES[2], "bad_magic")
        self.assertEqual(run.SLOT_STATE_NAMES[7], "bad_image_crc")


class WordOutputTest(unittest.TestCase):
    def test_parses_hex_table(self):
        text = "20000000: 544f4f42 00000001\n20000008: 00000000\n"
        self.assertEqual(run.parse_word_output(text, 3),
                         [0x544F4F42, 1, 0])

    def test_truncates_to_count(self):
        self.assertEqual(run.parse_word_output("a: 1 2 3 4", 2), [1, 2])


class FakeProbe:
    def __init__(self, words=None, metadata=None):
        self.calls = []
        self.words = list(words) if words else [0] * 32
        if self.words[0] == 0:
            self.words[0] = run.BOOT_MAGIC
        if self.words[1] == 0:
            self.words[1] = run.BOOT_VERSION
        self.metadata = metadata
        self.reads = 0

    def download(self, path, no_run=True):
        self.calls.append(("download", Path(path).name, no_run))
        return "ok"

    def reset(self):
        self.calls.append(("reset",))
        return "ok"

    def write_raw(self, path, address, no_run=True):
        self.calls.append(("write_raw", Path(path).name, address,
                           Path(path).read_bytes(), no_run))
        return "ok"

    def dump_metadata(self, path):
        Path(path).write_bytes(self.metadata or b"\xff" * 512)
        self.calls.append(("dump", Path(path).name))
        return "ok"

    def read_words(self, address, count):
        self.calls.append(("read", address, count))
        self.reads += 1
        words = list(self.words)
        words[11] = self.reads  # elapsed_us: a new boot differs
        return words

    def scan(self, name, seconds=6):
        self.calls.append(("scan", name, seconds))
        return {"name": name, "seen": True, "output": ""}


class RoundTest(unittest.TestCase):
    def test_r2_step_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = write_manifest(tmp, {"b3": ("b", 3)})
            manifest = run.load_manifest(manifest_path)
            # The boot ELF is needed for BOOT_STATS; give the fake the symbol.
            probe = FakeProbe(words=[0] * 32,
                              metadata=page(active="b", candidate="b",
                                            good_seq=3, candidate_seq=3))
            manifest["boot"]["path"] = self.boot_elf(tmp)
            evidence = run.run_round("R2", manifest, Path(tmp) / "work", probe)
            kinds = [call[0] for call in probe.calls]
            self.assertEqual(kinds,
                             ["download", "read", "reset", "scan", "read",
                              "dump"])
            self.assertTrue(probe.calls[0][2], "downloads must use --no-run")
            self.assertEqual(evidence["stats"]["selected"], 0)
            self.assertTrue((Path(tmp) / "work" / "R2.json").exists())

    def test_corrupt_header_writes_four_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = write_manifest(tmp, {"b3": ("b", 3)})
            manifest = run.load_manifest(manifest_path)
            manifest["boot"]["path"] = self.boot_elf(tmp)
            probe = FakeProbe()
            run.run_round("R3", manifest, Path(tmp) / "work", probe)
            raw = [call for call in probe.calls if call[0] == "write_raw"]
            self.assertEqual(raw[0][3], b"XXXX")
            self.assertEqual(raw[0][2], 0x3A000)
            self.assertTrue(raw[0][4], "injections must stay halted")

    def test_poke_writes_the_sequence_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = write_manifest(tmp, {"b4": ("b", 4)})
            manifest = run.load_manifest(manifest_path)
            manifest["boot"]["path"] = self.boot_elf(tmp)
            probe = FakeProbe()
            run.run_round("R5", manifest, Path(tmp) / "work", probe)
            raw = [call for call in probe.calls if call[0] == "write_raw"]
            self.assertEqual(raw[0][2], 0x3A000 + 0x10)
            self.assertEqual(raw[0][3], b"\x05")
            self.assertTrue(raw[0][4], "injections must stay halted")

    def boot_elf(self, tmp):
        path = Path(tmp) / "stats.elf"
        path.write_bytes(ota_image_test.make_elf(
            0, [(0, b"\x00" * 64), (0x40, 0x20000000, b"\x00" * 4)],
            {"BOOT_STATS": 0x20000000}))
        return path

    def test_read_stats_names_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = write_manifest(tmp, {"a2": ("a", 2)})
            manifest = run.load_manifest(manifest_path)
            manifest["boot"]["path"] = self.boot_elf(tmp)
            words = [0] * 32
            words[0] = run.ota_image.IMAGE_MAGIC
            words[6] = 1
            words[8] = 0
            probe = FakeProbe(words=words)
            stats = run.read_stats(manifest, probe)
            self.assertEqual(stats["selected"], 1)
            self.assertEqual(stats["action_name"], "boot")
            self.assertEqual(probe.calls[0][1], 0x20000000)


if __name__ == "__main__":
    unittest.main()
