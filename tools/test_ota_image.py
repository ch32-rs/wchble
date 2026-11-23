#!/usr/bin/env python3
"""Offline tests for ota_image.py; synthetic ELFs only, no probe access."""
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "ota_image", Path(__file__).with_name("ota_image.py"))
ota = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ota)

# Same vectors as `src/ota/tests.rs`; both sides must stay byte-identical.
HEADER_GOLDEN = bytes.fromhex(
    "43 48 35 58 01 00 01 00 40 00 00 00 f2 3a 0f 8e"
    "02 00 00 00 01 00 00 00 84 42 5b 4b 00 00 00 00")
META_GOLDEN = bytes.fromhex(
    "4f 54 41 4d 01 00 01 01 00 00 00 00 03 00 00 00"
    "02 00 00 00 00 00 00 00 00 00 00 00 0c fb cc 5f")


def golden_body():
    return bytes(range(32, 64))


def make_elf(entry, segments, symbols=None):
    """ELF32 LE with PT_LOAD segments and a small symtab.

    Segments are (paddr, blob) or (paddr, vaddr, blob) when VMA differs.
    """
    phnum = len(segments)
    phoff = 52
    offset = phoff + 32 * phnum
    placed = []
    for segment in segments:
        paddr, vaddr, blob = (segment[0], segment[0], segment[1]) \
            if len(segment) == 2 else segment
        placed.append((paddr, vaddr, blob, offset))
        offset += len(blob)

    syms = b"\x00" * 16
    strtab = b"\x00"
    for name, address in (symbols or {}).items():
        name_off = len(strtab)
        strtab += name.encode() + b"\x00"
        syms += struct.pack("<IIIBBH", name_off, address, 4, 0x11, 0, 1)
    symtab_off = offset
    offset += len(syms)
    strtab_off = offset
    offset += len(strtab)
    shoff = (offset + 3) & ~3

    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH", 2, ota.EM_RISCV, 1, entry, phoff, shoff, 0,
        52, 32, phnum, 40, 4, 0)
    out = bytearray(header)
    for paddr, vaddr, blob, seg_off in placed:
        out += struct.pack("<IIIIIIII", 1, seg_off, vaddr, paddr,
                           len(blob), len(blob), 5, 4)
    for _, _, blob, _ in placed:
        out += blob
    out += syms + strtab
    out += b"\x00" * (shoff - len(out))
    text_addr, _, text_blob, text_off = placed[0]
    names = [b"", b".text", b".symtab", b".strtab"]
    for name, kind, addr, off, size, link in (
            (names[0], 0, 0, 0, 0, 0),
            (names[1], 1, text_addr, text_off, len(text_blob), 0),
            (names[2], 2, 0, symtab_off, len(syms), 3),
            (names[3], 3, 0, strtab_off, len(strtab), 0)):
        out += struct.pack("<IIIIIIIIII", 0, kind, 0, addr, off, size,
                           link, 0, 1, 0)
    return bytes(out)


def jal_body(offset=0x100):
    """A 32 B body whose first instruction is `j entry+offset`."""
    imm = offset
    word = (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3FF) << 21) | \
        (((imm >> 11) & 1) << 20) | (((imm >> 12) & 0xFF) << 12) | 0x6F
    return struct.pack("<I", word) + b"\x00" * 28


def slot_elf(slot="a", body=None, entry_offset=None, symbols=None):
    base = ota.slot_base(slot)
    entry = base + ota.ENTRY_OFFSET
    if entry_offset is not None:
        entry = entry_offset
    return make_elf(entry, [(base + ota.ENTRY_OFFSET, body or golden_body())],
                    symbols)


class HeaderVectorTest(unittest.TestCase):
    def test_crc_vector_matches_ieee(self):
        self.assertEqual(ota.crc32(b"123456789"), 0xCBF43926)

    def test_stamp_matches_rust_golden(self):
        flat = bytearray(b"\xff" * 32) + bytearray(golden_body())
        info = ota.stamp(flat, 2, ota.FLAG_HOST_VERIFIED)
        self.assertEqual(bytes(flat[:32]), HEADER_GOLDEN)
        self.assertEqual(info["image_len"], 64)

    def test_stamp_is_idempotent(self):
        flat = bytearray(b"\xff" * 32) + bytearray(golden_body())
        ota.stamp(flat, 2)
        first = bytes(flat)
        ota.stamp(flat, 2)
        self.assertEqual(bytes(flat), first)

    def test_check_header_accepts_golden(self):
        info = ota.check_header(HEADER_GOLDEN + golden_body(), 2)
        self.assertEqual(info["sequence"], 2)
        self.assertEqual(info["image_crc32"], 0x8E0F3AF2)

    def test_check_header_rejects_damage(self):
        raw = bytearray(HEADER_GOLDEN + golden_body())
        cases = {}
        for name, mutate in {
            "magic": lambda b: b.__setitem__(0, b[0] ^ 0xFF),
            "format": lambda b: b.__setitem__(4, 2),
            "length": lambda b: b.__setitem__(8, 32),
            "header_crc": lambda b: b.__setitem__(25, b[25] ^ 1),
            "body": lambda b: b.__setitem__(40, b[40] ^ 1),
        }.items():
            broken = bytearray(raw)
            mutate(broken)
            cases[name] = broken
        for name, broken in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ota.ElfError):
                    ota.check_header(bytes(broken))

    def test_check_header_rejects_nonzero_reserved_tail(self):
        raw = bytearray(HEADER_GOLDEN + golden_body())
        raw[30] = 1
        with self.assertRaises(ota.ElfError):
            ota.check_header(bytes(raw))

    def test_check_header_rejects_sequence_zero(self):
        raw = bytearray(HEADER_GOLDEN + golden_body())
        struct.pack_into("<I", raw, 16, 0)
        struct.pack_into("<I", raw, 12, 0)
        struct.pack_into("<I", raw, 24, 0)
        struct.pack_into("<I", raw, 12, ota.crc32(raw[:64]))
        struct.pack_into("<I", raw, 24, ota.crc32(raw[:24]))
        with self.assertRaises(ota.ElfError):
            ota.check_header(bytes(raw))

    def test_check_header_sequence_gate(self):
        with self.assertRaises(ota.ElfError):
            ota.check_header(HEADER_GOLDEN + golden_body(), 3)


class MetadataVectorTest(unittest.TestCase):
    def encode(self, **overrides):
        values = dict(active="a", candidate="b", attempts=1, flags=0,
                      candidate_seq=3, good_seq=2, failed_a=0, failed_b=0,
                      store_seq=1)
        values.update(overrides)
        return ota.encode_metadata(type("Args", (), values)())

    def test_payload_matches_rust_golden(self):
        page = self.encode()
        self.assertEqual(
            bytes(page[ota.STORE_HEADER_LEN:ota.STORE_HEADER_LEN + 32]),
            META_GOLDEN)

    def test_decode_round_trip(self):
        info = ota.decode_metadata(self.encode())
        self.assertEqual(info["candidate_slot"], 1)
        self.assertEqual(info["attempts_done"], 1)
        self.assertEqual(info["active_slot"], 0)
        self.assertEqual(info["candidate_seq"], 3)
        self.assertEqual(info["good_seq"], 2)

    def test_decode_rejects_a_tombstone_page(self):
        dead = bytearray(self.encode())
        struct.pack_into("<H", dead, 12, 0)
        struct.pack_into("<I", dead, 16, 0)
        struct.pack_into("<I", dead, 20, ota.crc32(dead[:20]))
        with self.assertRaises(ota.ElfError):
            ota.decode_metadata(bytes(dead))

    def test_decode_rejects_corruption(self):
        for index in (0, 8, 20, 24, 30):
            page = bytearray(self.encode())
            page[index] ^= 0xFF
            with self.subTest(index=index):
                with self.assertRaises(ota.ElfError):
                    ota.decode_metadata(bytes(page))

    def test_hex_round_trip_both_bases(self):
        with tempfile.TemporaryDirectory() as tmp:
            for slot in ("a", "b"):
                data = bytes(range(64))
                path = Path(tmp) / f"{slot}.hex"
                ota.write_hex(path, data, ota.slot_base(slot))
                text = path.read_text()
                self.assertIn(":00000001FF", text)
                self.assertEqual(ota.read_hex(path), data)


class StampTest(unittest.TestCase):
    def test_stamp_elf_produces_verifiable_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = Path(tmp) / "slot.elf"
            elf_path.write_bytes(slot_elf("a"))
            out = Path(tmp) / "out"
            result = ota.main(["stamp", "--elf", str(elf_path), "--slot", "a",
                               "--sequence", "2", "--out-dir", str(out)])
            self.assertEqual(result, 0)
            image = (out / "slot-a.bin").read_bytes()
            info = ota.check_header(image, 2)
            self.assertEqual(info["image_len"], 64)
            self.assertEqual(image[32:], golden_body())
            self.assertEqual(ota.read_hex(out / "slot-a.hex"), image)

    def test_stamp_rejects_wrong_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = Path(tmp) / "slot.elf"
            elf_path.write_bytes(slot_elf("a", entry_offset=0x4000))
            result = ota.main(["stamp", "--elf", str(elf_path), "--slot", "a",
                               "--sequence", "2", "--out-dir", tmp])
            self.assertEqual(result, 1)

    def test_stamp_rejects_segment_outside_slot(self):
        body = bytes(ota.SLOT_LEN)
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = Path(tmp) / "slot.elf"
            elf_path.write_bytes(slot_elf("b", body=body))
            result = ota.main(["stamp", "--elf", str(elf_path), "--slot", "b",
                               "--sequence", "2", "--out-dir", tmp])
            self.assertEqual(result, 1)

    def test_stamp_rejects_sequence_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = Path(tmp) / "slot.elf"
            elf_path.write_bytes(slot_elf("a"))
            result = ota.main(["stamp", "--elf", str(elf_path), "--slot", "a",
                               "--sequence", "0", "--out-dir", tmp])
            self.assertEqual(result, 1)

    def test_stamp_checks_embedded_sequence_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = ota.slot_base("a")
            elf_path = Path(tmp) / "slot.elf"
            elf_path.write_bytes(slot_elf(
                "a", symbols={"OTA_IMAGE_SEQUENCE": base + 32}))
            # The body at 0x4020 holds bytes(range(32,64)); its first word
            # is 0x27262524, not the requested sequence.
            result = ota.main(["stamp", "--elf", str(elf_path), "--slot", "a",
                               "--sequence", "2", "--out-dir", tmp])
            self.assertEqual(result, 1)


class VerifyCommandTest(unittest.TestCase):
    def test_verify_rejects_a_mismatched_hex_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.hex"
            ota.write_hex(path, bytes(HEADER_GOLDEN + golden_body()),
                          ota.SLOT_A_BASE)
            self.assertEqual(
                ota.main(["verify", "--hex", str(path), "--slot", "a"]), 0)
            self.assertEqual(
                ota.main(["verify", "--hex", str(path), "--slot", "b"]), 1)


class VerifyElfTest(unittest.TestCase):
    def verify(self, role, elf_bytes):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.elf"
            path.write_bytes(elf_bytes)
            return ota.main(["verify-elf", "--role", role,
                             "--elf", str(path)])

    def test_slot_roles_accept_carrier_layout(self):
        self.assertEqual(self.verify("slot-a", slot_elf("a", body=jal_body())), 0)
        self.assertEqual(self.verify("slot-b", slot_elf("b", body=jal_body())), 0)

    def test_slot_rejects_misaligned_entry(self):
        self.assertEqual(self.verify("slot-a", slot_elf("a", entry_offset=0x4000)), 1)

    def test_slot_rejects_non_jal_entry(self):
        elf = slot_elf("b", body=b"\x13\x00\x00\x00" + b"\x00" * 28)
        self.assertEqual(self.verify("slot-b", elf), 1)

    def test_slot_rejects_jump_outside_slot(self):
        elf = slot_elf("a", body=jal_body(ota.SLOT_LEN))
        self.assertEqual(self.verify("slot-a", elf), 1)

    def test_boot_role_accepts_small_image(self):
        elf = make_elf(0, [(0, jal_body(0x80)),
                           (0x100, 0x20000000, b"\x00" * 4)])
        self.assertEqual(self.verify("boot", elf), 0)

    def test_boot_role_rejects_non_jal_vector(self):
        elf = make_elf(0, [(0, b"\x00" * 0x100),
                           (0x100, 0x20000000, b"\x00" * 4)])
        self.assertEqual(self.verify("boot", elf), 1)

    def test_boot_role_requires_highcode(self):
        self.assertEqual(self.verify("boot", make_elf(0, [(0, b"\x00" * 64)])), 1)

    def test_boot_role_rejects_entry(self):
        elf = make_elf(0x20, [(0, b"\x00" * 64),
                              (0x40, 0x20000000, b"\x00" * 4)])
        self.assertEqual(self.verify("boot", elf), 1)

    def test_boot_role_rejects_oversize(self):
        elf = make_elf(0, [(0, b"\x00" * 0x4000),
                           (0x4000, 0x20000000, b"\x00" * 4)])
        self.assertEqual(self.verify("boot", elf), 1)


if __name__ == "__main__":
    unittest.main()
