# VULN 001 – OOB Stack Array Access in decode_current_mul via 32-bit FFV1 remap

## Vulnerability Summary

**File**: `libavcodec/ffv1dec.c`
**Functions**: `decode_remap()` (lines 300–377) / `decode_current_mul()` (lines 289–298)

When decoding a 32-bit float FFV1 stream with `remap` enabled, `decode_remap` iterates
through all 2^32 possible float bit-patterns to build a lookup table (`fltmap32`).
After writing the last entry at `i = end = 0xFFFFFFFF`, the code increments `i` to
`0x100000000` and then calls:

```c
current_mul = decode_current_mul(&sc->c, state[0][2], mul, mul_count, i);
```

with `i = 0x100000000` (past the valid range). Inside `decode_current_mul`:

```c
int ndx = (i * mul_count) >> 32;
av_assert2(ndx <= 4096U);
if (mul[ndx] < 0)
    mul[ndx] = ff_ffv1_get_symbol(rc, state, 0) & 0x3FFFFFFF;
return mul[ndx];
```

## Actual OOB Calculation

The vulnerability report states `ndx = 268435456` for `mul_count = 4096`. The correct
calculation is:

```
ndx = (0x100000000LL * 4096LL) >> 32
    = (4294967296 * 4096) >> 32
    = 17592186044416 >> 32
    = 4096
```

`ndx = 4096`, not 268435456. Since `mul[]` is declared as `int mul[4096+1]` (4097 elements,
indices 0..4096), accessing `mul[4096]` is **within bounds** — it was explicitly initialized
to `1` at line 338 (`mul[mul_count] = 1`).

For ndx = 268435456 to occur, `mul_count` would need to be `268435456`, but the decoder
explicitly rejects `mul_count > 4096U` at line 332–333.

## Trigger Conditions Attempted

| Condition | Status |
|-----------|--------|
| `bits_per_raw_sample = 32`, `flt = 1` | Achieved via `gbrpf32le` pixel format |
| FFV1 v4 with `combined_version >= 0x40004` | Requires `-strict experimental` |
| `sc->remap = 2` | Set via `-remap_mode 2` |
| `mul_count = 4096` (range coder output) | Attempted via mutation of slice bytes |
| i traverses to `0xFFFFFFFF` | Requires 2^32 unique float values in the image |

## PoC Approach

1. **Step 1** (`vuln_001_gen.py`): Use the FFmpeg binary at
   `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` as a subprocess to
   encode a 256×256 all-zero `gbrpf32le` frame into an FFV1 MKV file with
   `-remap_mode 2 -remap_optimizer 5 -strict experimental`.

2. **Step 2**: Parse the MKV (EBML) container to locate the SimpleBlock payload
   containing the FFV1 slice.

3. **Step 3**: Mutate the range-coder bytes inside the slice payload. Filling them
   with `0xFF` drives the range coder toward large symbol values, which can yield a
   high `mul_count` and large multiplier values, increasing the chance of `i` advancing
   rapidly toward `0xFFFFFFFF`.

4. **Step 4**: Decode the mutated file through the build ffmpeg with ASAN enabled
   and check for memory errors.

## Assessment

Based on code analysis, the exact OOB access described in the report (accessing
`mul[268435456]`) is **mathematically impossible** under the current code constraints:
`mul_count ≤ 4096` is enforced, and with `i = 0x100000000` the computed `ndx` equals
exactly `mul_count ≤ 4096`, which is always within the `mul[4097]` array. The
`av_assert2(ndx <= 4096U)` assertion would catch any future regression.

The PoC is provided for completeness. Expected result: `AVERROR_INVALIDDATA` (graceful
error) or `SIGABRT` from `av_assert2` failure, rather than SIGSEGV from a true OOB.

If future versions change the `mul` array size or the `mul_count` bound, the OOB
could become triggerable. The root cause (calling `decode_current_mul` with
`i = end + 1 = 0x100000000` past the valid domain) is a real logic bug even if it is
currently bounded.
