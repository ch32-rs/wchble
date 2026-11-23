#!/usr/bin/env python3
"""Stamp and verify CH585 OTA slot images (mirrors `wchble::ota`)."""

import argparse
import json
import struct
import sys
import zlib
from pathlib import Path

IMAGE_MAGIC = 0x58354843  # "CH5X"
HEADER_FORMAT = 1
IMAGE_FORMAT = 1
HEADER_LEN = 32
ENTRY_OFFSET = 0x20
SLOT_A_BASE = 0x4000
SLOT_B_BASE = 0x3A000
SLOT_LEN = 0x36000
FLAG_HOST_VERIFIED = 1 << 0
FLAG_DEBUG = 1 << 1

METADATA_MAGIC = 0x4D41544F  # "OTAM"
METADATA_VERSION = 1
METADATA_LEN = 32
STORE_MAGIC = 0x33444E42  # "BND3"
STORE_FORMAT = 3
PAGE_SIZE = 0x100
STORE_HEADER_LEN = 24

EM_RISCV = 243
PT_LOAD = 1
SHT_SYMTAB = 2


class ElfError(ValueError):
    pass


def slot_base(slot):
    return SLOT_A_BASE if slot == "a" else SLOT_B_BASE


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_elf(path):
    """Minimal ELF32 LE reader: header, program headers and the symbol table."""
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if data[4] != 1 or data[5] != 1:
        raise ElfError("expected ELF32 little-endian")
    (e_type, e_machine, _version, e_entry, e_phoff, e_shoff, _flags,
     _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    if e_machine != EM_RISCV:
        raise ElfError(f"expected RISC-V, got e_machine={e_machine}")
    if e_type != 2:
        raise ElfError("expected an executable ELF")

    segments = []
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
         _p_flags, _align) = struct.unpack_from("<IIIIIIII", data, offset)
        if p_type == PT_LOAD and p_filesz:
            if p_offset + p_filesz > len(data):
                raise ElfError("segment runs past the file")
            segments.append({
                "offset": p_offset,
                "vaddr": p_vaddr,
                "paddr": p_paddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            })

    sections = []
    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        fields = struct.unpack_from("<IIIIIIIIII", data, offset)
        sections.append({"name_off": fields[0], "type": fields[1],
                         "addr": fields[3], "offset": fields[4],
                         "size": fields[5], "link": fields[6],
                         "entsize": fields[9]})

    symbols = {}
    for section in sections:
        if section["type"] != SHT_SYMTAB or section["link"] >= len(sections):
            continue
        strtab = sections[section["link"]]
        strings = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        count = section["size"] // 16
        for i in range(count):
            offset = section["offset"] + i * 16
            st_name, st_value, st_size, _info, _other, _shndx = \
                struct.unpack_from("<IIIBBH", data, offset)
            end = strings.find(b"\x00", st_name)
            if end < 0:
                continue
            name = strings[st_name:end].decode()
            if name:
                symbols.setdefault(name, (st_value, st_size))

    return {
        "entry": e_entry,
        "segments": segments,
        "sections": sections,
        "symbols": symbols,
        "data": data,
    }


def flatten(elf, base, role):
    """Overlay PT_LOAD segments into a 0xFF-filled slot image."""
    entry = base + ENTRY_OFFSET
    if elf["entry"] != entry:
        raise ElfError(f"entry {elf['entry']:#x} != {entry:#x} for {role}")
    limit = base + SLOT_LEN
    end = 0
    for segment in elf["segments"]:
        start = segment["paddr"]
        stop = start + segment["filesz"]
        if start < entry or stop > limit:
            raise ElfError(
                f"segment {start:#x}..{stop:#x} outside [{entry:#x}, {limit:#x})")
        end = max(end, stop)
    image_len = end - base
    if image_len <= HEADER_LEN or image_len > SLOT_LEN:
        raise ElfError(f"image length {image_len:#x} out of slot bounds")
    flat = bytearray(b"\xff" * image_len)
    for segment in elf["segments"]:
        start = segment["paddr"] - base
        flat[start:start + segment["filesz"]] = \
            elf["data"][segment["offset"]:segment["offset"] + segment["filesz"]]
    return flat


def stamp(flat, sequence, flags=FLAG_HOST_VERIFIED):
    image_len = len(flat)
    # The whole header is host-owned; the 0xFF fill must not survive in the
    # reserved tail (the Rust `raw_zeroed` form is all zeros).
    flat[0:HEADER_LEN] = b"\x00" * HEADER_LEN
    struct.pack_into("<IHHIIII", flat, 0, IMAGE_MAGIC, HEADER_FORMAT,
                     IMAGE_FORMAT, image_len, 0, sequence, flags)
    image_crc = crc32(flat)
    struct.pack_into("<I", flat, 12, image_crc)
    header_crc = crc32(flat[:24])
    struct.pack_into("<I", flat, 24, header_crc)
    return {"image_len": image_len, "image_crc32": image_crc,
            "header_crc32": header_crc}


def check_header(raw, expect_sequence=None):
    if len(raw) < HEADER_LEN:
        raise ElfError("image shorter than the header")
    magic, header_format, image_format, image_len, image_crc, sequence, \
        flags = struct.unpack_from("<IHHIIII", raw, 0)
    header_crc = struct.unpack_from("<I", raw, 24)[0]
    if magic != IMAGE_MAGIC:
        raise ElfError(f"bad magic {magic:#x}")
    if header_format != HEADER_FORMAT or image_format != IMAGE_FORMAT:
        raise ElfError("bad header/image format")
    if not HEADER_LEN < image_len <= SLOT_LEN:
        raise ElfError(f"bad image length {image_len:#x}")
    if sequence == 0:
        raise ElfError("sequence 0 is invalid")
    if image_len > len(raw):
        raise ElfError("image truncated")
    if header_crc != crc32(raw[:24]):
        raise ElfError("header CRC mismatch")
    if raw[28:32] != b"\x00" * 4:
        raise ElfError("reserved header tail is not zero")
    body = bytearray(raw[:image_len])
    struct.pack_into("<I", body, 12, 0)
    struct.pack_into("<I", body, 24, 0)
    if image_crc != crc32(body):
        raise ElfError("image CRC mismatch")
    if expect_sequence is not None and sequence != expect_sequence:
        raise ElfError(f"sequence {sequence} != expected {expect_sequence}")
    return {"image_len": image_len, "sequence": sequence, "flags": flags,
            "image_crc32": image_crc, "header_crc32": header_crc}


def write_hex(path, data, base):
    lines = []
    upper = None
    offset = 0
    while offset < len(data):
        take = min(16, len(data) - offset)
        address = base + offset
        if upper != address >> 16:
            upper = address >> 16
            lines.append(hex_record(0, 0x04,
                                    struct.pack(">H", upper & 0xFFFF)))
        lines.append(hex_record(address & 0xFFFF, 0x00,
                                data[offset:offset + take]))
        offset += take
    lines.append(":00000001FF")
    Path(path).write_text("\n".join(lines) + "\n")


def hex_record(address, kind, payload):
    body = bytes([len(payload)]) + struct.pack(">H", address) + \
        bytes([kind]) + bytes(payload)
    checksum = (-sum(body)) & 0xFF
    return ":" + body.hex().upper() + f"{checksum:02X}"


def read_hex(path):
    """Return the HEX payload, rebased to its lowest address."""
    return read_hex_based(path)[0]


def read_hex_based(path):
    """Return `(payload, lowest address)` from an Intel HEX file."""
    data = bytearray()
    base = 0
    lowest = None
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line.startswith(":"):
            continue
        raw = bytes.fromhex(line[1:])
        count, address, kind = raw[0], struct.unpack(">H", raw[1:3])[0], raw[3]
        payload = raw[4:4 + count]
        if kind == 0x04:
            base = struct.unpack(">H", payload)[0] << 16
        elif kind == 0x00:
            start = base + address
            lowest = start if lowest is None else min(lowest, start)
            if len(data) < start + count:
                data.extend(b"\xff" * (start + count - len(data)))
            data[start:start + count] = payload
        elif kind == 0x01:
            break
    if lowest is None:
        return b"", 0
    return bytes(data[lowest:]), lowest


def encode_metadata(args):
    candidate = {"a": 0, "b": 1, "none": 0xFF}[args.candidate]
    active = {"a": 0, "b": 1, "none": 0xFF}[args.active]
    payload = bytearray(METADATA_LEN)
    struct.pack_into("<IHBBBB", payload, 0, METADATA_MAGIC, METADATA_VERSION,
                     candidate, args.attempts, args.flags, active)
    struct.pack_into("<I", payload, 12, args.candidate_seq)
    struct.pack_into("<I", payload, 16, args.good_seq)
    struct.pack_into("<I", payload, 20, args.failed_a)
    struct.pack_into("<I", payload, 24, args.failed_b)
    struct.pack_into("<I", payload, 28, crc32(payload[:28]))

    page = bytearray(b"\xff" * PAGE_SIZE)
    struct.pack_into("<IHHIHHI", page, 0, STORE_MAGIC, STORE_FORMAT, 0,
                     args.store_seq, METADATA_LEN, 0, crc32(payload))
    struct.pack_into("<I", page, 20, crc32(page[:20]))
    page[STORE_HEADER_LEN:STORE_HEADER_LEN + METADATA_LEN] = payload
    return page


def decode_metadata(page):
    if len(page) < STORE_HEADER_LEN:
        raise ElfError("store header truncated")
    magic, version, _flags, store_seq, payload_len, _pad, payload_crc = \
        struct.unpack_from("<IHHIHHI", page, 0)
    header_crc = struct.unpack_from("<I", page, 20)[0]
    if magic != STORE_MAGIC or version != STORE_FORMAT:
        raise ElfError("not a BND3 record")
    if header_crc != crc32(page[:20]):
        raise ElfError("store header CRC mismatch")
    if payload_len != METADATA_LEN:
        raise ElfError(f"payload length {payload_len} != {METADATA_LEN}")
    payload = page[STORE_HEADER_LEN:STORE_HEADER_LEN + payload_len]
    if len(payload) != payload_len:
        raise ElfError("store payload truncated")
    if crc32(payload) != payload_crc:
        raise ElfError("store payload CRC mismatch")
    (meta_magic, meta_version, candidate, attempts, flags, active) = \
        struct.unpack_from("<IHBBBB", payload, 0)
    if meta_magic != METADATA_MAGIC or meta_version != METADATA_VERSION:
        raise ElfError("not an OTAM payload")
    if struct.unpack_from("<I", payload, 28)[0] != crc32(payload[:28]):
        raise ElfError("metadata CRC mismatch")
    return {
        "store_seq": store_seq,
        "candidate_slot": candidate,
        "attempts_done": attempts,
        "flags": flags,
        "active_slot": active,
        "candidate_seq": struct.unpack_from("<I", payload, 12)[0],
        "good_seq": struct.unpack_from("<I", payload, 16)[0],
        "failed_seq_a": struct.unpack_from("<I", payload, 20)[0],
        "failed_seq_b": struct.unpack_from("<I", payload, 24)[0],
    }


def verify_elf(args):
    elf = parse_elf(args.elf)
    if args.role == "boot":
        # `.highcode` keeps its LMA in flash; only code-flash segments count
        # against the 16 KiB window.
        flash_end = max((s["paddr"] + s["filesz"] for s in elf["segments"]
                         if s["paddr"] < 0x2000_0000), default=0)
        if elf["entry"] != 0:
            raise ElfError(f"boot entry {elf['entry']:#x} != 0")
        first = None
        for segment in elf["segments"]:
            if segment["paddr"] == 0:
                first = struct.unpack_from("<I", elf["data"],
                                           segment["offset"])[0]
        if first is None or first & 0x7F != 0x6F:
            raise ElfError("boot vector is not a JAL (`j handle_reset`)")
        if flash_end > 0x3C00:
            raise ElfError(f"boot image reaches {flash_end:#x}, gate is 0x3C00")
        # `.highcode` is VMA in RAM (0x2000_0000), LMA in flash.
        highcode = [s for s in elf["segments"]
                    if s["vaddr"] >= 0x2000_0000 and s["paddr"] < 0x2000_0000]
        if not highcode:
            raise ElfError("boot manager has no .highcode (RAM VMA, flash LMA)")
        return {"role": args.role, "flash_end": flash_end,
                "highcode": bool(highcode)}

    base = SLOT_A_BASE if args.role == "slot-a" else SLOT_B_BASE
    flat = flatten(elf, base, args.role)
    entry = base + ENTRY_OFFSET
    word = struct.unpack_from("<I", flat, ENTRY_OFFSET)[0]
    if word & 0x7F != 0x6F:
        raise ElfError("entry is not a JAL (`j handle_reset`)")
    imm = ((word >> 31) << 20) | (((word >> 12) & 0xFF) << 12) | \
          (((word >> 20) & 1) << 11) | (((word >> 21) & 0x3FF) << 1)
    if imm & (1 << 20):
        imm -= 1 << 21
    target = entry + imm
    if not entry < target < base + SLOT_LEN:
        raise ElfError(f"entry jumps outside the slot ({target:#x})")
    return {"role": args.role, "entry": entry, "jump_target": target,
            "image_len": len(flat)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    stamp_parser = sub.add_parser("stamp")
    stamp_parser.add_argument("--elf", required=True)
    stamp_parser.add_argument("--slot", choices=("a", "b"), required=True)
    stamp_parser.add_argument("--sequence", type=int, required=True)
    stamp_parser.add_argument("--flags", type=lambda v: int(v, 0),
                              default=FLAG_HOST_VERIFIED)
    stamp_parser.add_argument("--out-dir", required=True)
    stamp_parser.add_argument("--bin", default=None)
    stamp_parser.add_argument("--hex", default=None)

    verify_parser = sub.add_parser("verify")
    inputs = verify_parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--bin", dest="image")
    inputs.add_argument("--hex", dest="hex_image")
    verify_parser.add_argument("--slot", choices=("a", "b"), required=True)
    verify_parser.add_argument("--expect-sequence", type=int, default=None)

    elf_parser = sub.add_parser("verify-elf")
    elf_parser.add_argument("--role", choices=("boot", "slot-a", "slot-b"),
                            required=True)
    elf_parser.add_argument("--elf", required=True)

    meta_parser = sub.add_parser("metadata")
    meta_parser.add_argument("--active", choices=("a", "b", "none"),
                             default="none")
    meta_parser.add_argument("--candidate", choices=("a", "b", "none"),
                             default="none")
    meta_parser.add_argument("--attempts", type=int, default=0)
    meta_parser.add_argument("--flags", type=int, default=0)
    meta_parser.add_argument("--candidate-seq", type=int, default=0)
    meta_parser.add_argument("--good-seq", type=int, default=0)
    meta_parser.add_argument("--failed-a", type=int, default=0)
    meta_parser.add_argument("--failed-b", type=int, default=0)
    meta_parser.add_argument("--store-seq", type=int, default=1)
    meta_parser.add_argument("--out", required=True)

    decode_parser = sub.add_parser("metadata-decode")
    decode_parser.add_argument("--page", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "stamp":
            if args.sequence <= 0:
                raise ElfError("sequence must be >= 1 (0 is invalid)")
            base = slot_base(args.slot)
            elf = parse_elf(args.elf)
            flat = flatten(elf, base, f"slot-{args.slot}")
            info = stamp(flat, args.sequence, args.flags)
            if "OTA_IMAGE_SEQUENCE" in elf["symbols"]:
                address = elf["symbols"]["OTA_IMAGE_SEQUENCE"][0]
                index = address - base
                if not 0 <= index <= len(flat) - 4:
                    raise ElfError("OTA_IMAGE_SEQUENCE is outside the image")
                built = struct.unpack_from("<I", flat, index)[0]
                if built != args.sequence:
                    raise ElfError(
                        f"built sequence {built} != --sequence {args.sequence}")
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            bin_name = args.bin or f"slot-{args.slot}.bin"
            hex_name = args.hex or f"slot-{args.slot}.hex"
            (out_dir / bin_name).write_bytes(flat)
            write_hex(out_dir / hex_name, flat, base)
            info.update({"slot": args.slot, "slot_base": base,
                         "hex_base": base})
            print(json.dumps(info, sort_keys=True))
        elif args.command == "verify":
            if args.image:
                raw = Path(args.image).read_bytes()
            else:
                raw, base = read_hex_based(args.hex_image)
                expected = slot_base(args.slot)
                if base != expected:
                    raise ElfError(
                        f"HEX base {base:#x} != slot {args.slot} "
                        f"({expected:#x})")
            print(json.dumps(check_header(raw, args.expect_sequence),
                             sort_keys=True))
        elif args.command == "verify-elf":
            print(json.dumps(verify_elf(args), sort_keys=True))
        elif args.command == "metadata":
            Path(args.out).write_bytes(encode_metadata(args))
            print(json.dumps({"out": args.out}, sort_keys=True))
        elif args.command == "metadata-decode":
            page = Path(args.page).read_bytes()
            print(json.dumps(decode_metadata(page), sort_keys=True))
    except (ElfError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
