After thorough analysis of all code paths in `cbs_vp8.c`, the syntax template, the header structures, and the CBS infrastructure:

**Key findings from the analysis:**

1. **All allocations are fixed-size**: `ff_cbs_alloc_unit_content` allocates exactly `sizeof(VP8RawFrame)` — a compile-time constant with no untrusted-input dependency.

2. **All loop bounds use compile-time constants**: Array loops iterate over fixed dimensions (4, 8, 3, 11, 2, 19, etc.) that match the fixed-size arrays in `VP8RawFrameHeader`. No untrusted `nb_entries` drives any allocation.

3. **Pointer arithmetic is guarded**: `frame->data = unit->data + pos` (line 351) is protected by `av_assert0(pos <= unit->data_size)` at line 345.

4. **Bitfield widths are small**: The bool decoder asserts `width <= 8`; the LE reader accepts `width <= 24` with explicit range validation. `first_partition_length_in_bytes` (19 bits, max 524287) is stored in a `uint32_t` field and never used as a malloc size.

5. **Bool decoder arithmetic is safe**: The normalization loop `while (range < 128)` is bounded by at most 7 iterations; the `split` computation cannot produce underflow given range is always ≥ 128 post-normalization.

6. **Type mismatch in `read_signed`** (passing `int32_t*` where `uint32_t*` is expected, line 164): technically a strict-aliasing violation but not a memory-safety vulnerability — same size on all platforms, only 1-8 bits written.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
