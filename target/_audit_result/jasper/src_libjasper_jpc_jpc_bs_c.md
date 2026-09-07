I have now read all 446 lines of `jpc_bs.c` and examined the header, macro definitions (JAS_ONES, getbit_macro, putbit_macro), and caller files. Here is the full per-group analysis:

**Group 1 (lines 1–163): allocation / open / close**
- `jpc_bitstream_alloc()`: `jas_malloc(sizeof(jpc_bitstream_t))` — fixed-size struct allocation, return value NULL-checked. Clean.
- `jpc_bitstream_sopen()`: delegates to alloc, fills struct fields with constants. Clean.
- `jpc_bitstream_close()`: calls align, conditionally closes stream, frees. Clean.

**Group 2 (lines 165–236): getbits / putbits**
- `jpc_bitstream_getbits()`: validates `n ∈ [0,31]`, loop runs at most 31 iterations over single-bit reads. No arrays, no malloc. Clean.
- `jpc_bitstream_putbits()`: same n validation. `assert(!(v & ~JAS_ONES(n)))` — only an assertion, not memory corruption; `JAS_ONES(n) = (1<<n)-1`. Loop body shifts v left (bounded). Clean.

**Group 3 (lines 238–269): fillbuf**
- `buf_` is `uint_fast16_t`; `(buf_ << 8) & 0xffff` stays within 16 bits.
- `cnt_` set only to 6 or 7 on lines 266; thus `(1 << (cnt_+1)) - 1` is `(1<<7)-1` or `(1<<8)-1` — both safe on 32-bit int. Clean.
- Right-shift `buf_ >> cnt_` where cnt_ ∈ {6,7}: safe. Clean.

**Group 4 (lines 271–344): needalign / pending / align**
- Pure integer checks on struct fields. No allocations. Clean.

**Group 5 (lines 347–445): inalign / outalign**
- `inalign`: n derived from `bitstream->cnt_` (bounded 0..7) or fixed constant 7 — both within `getbits()` valid range. Clean.
- `outalign`: `n = bitstream->cnt_` checked to be in (0,8); shift `filldata >> (7-n)` where n ∈ [1,7], so shift is 0..6. `putbits(n, v)` passes the n<32 check. Clean.

No malloc with file-controlled sizes, no array indexing with external values, no pointer arithmetic beyond struct fields, no memcpy with untrusted lengths found anywhere in the 446-line file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
