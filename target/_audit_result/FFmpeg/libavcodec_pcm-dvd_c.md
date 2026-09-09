I've confirmed the `_u` (unchecked) variants in bytestream.h skip bounds checking (line 68-70: they directly call the raw `bytestream_get_` function). Now I'll verify the decode reads exactly `block_size` bytes per block for every path, and audit all three `memcpy` call sites for buffer bounds.

**Byte-counting audit for `pcm_dvd_decode_samples`:**

| channels | bits | block_size formula | block_size | groups_per_block | bytes read per block |
|---|---|---|---|---|---|
| 1 | 20 | 4×20/8 | 10 | (special: 2-iter loop) | 2×(2+2+1) = 10 ✓ |
| 2,4 | 20 | 4×20/8 | 10 | 1 | 1×(8+2) = 10 ✓ |
| 8 | 20 | 8×20/8 | 20 | 2 | 2×10 = 20 ✓ |
| 3,5,6,7 | 20 | 4×ch×20/8 | 10×ch | ch | ch×10 ✓ |
| 1 | 24 | 4×24/8 | 12 | (special) | 2×(2+2+1+1) = 12 ✓ |
| 2,4 | 24 | 4×24/8 | 12 | 1 | 1×(8+4) = 12 ✓ |
| 8 | 24 | 8×24/8 | 24 | 2 | 2×12 = 24 ✓ |
| 3,5,6,7 | 24 | 4×ch×24/8 | 12×ch | ch | ch×12 ✓ |

All cases read exactly `block_size` bytes per block — matching the `bytestream2_init` size. The unchecked reads never exceed the initialized buffer.

**`extra_samples[96]` buffer audit:**

Maximum `block_size` = 4×7×24/8 = **84** bytes (7 channels, 24-bit). All three `memcpy` sites write at most `block_size` bytes total into `extra_samples`:
- Line 265: writes `missing_samples = block_size − extra_sample_count`, starting at offset `extra_sample_count` → total write = `block_size` ≤ 84 < 96 ✓
- Line 274: in else branch, `buf_size < missing_samples`, so `extra_sample_count + buf_size < block_size` ≤ 84 < 96 ✓  
- Line 289: `buf_size` = remainder after complete-block subtraction, < `block_size` ≤ 84 < 96 ✓

**`blocks` / `nb_samples` arithmetic:**

- `block_size` ≥ 2 always (16-bit mono minimum), no division-by-zero at line 253.
- `samples_per_block` ≥ 1 always; output buffer = `blocks × samples_per_block × channels × bytes/sample` exactly matches decode output in all paths.
- Block_size transitions between packets: guarded by reset of `extra_sample_count` at both line 76 (`pcm_dvd_parse_header`) and line 247 (`pcm_dvd_decode_frame`), preventing stale counts with a new geometry.

After exhaustive analysis of all allocation sites, pointer arithmetic, array accesses, bytestream reads, and `memcpy` destinations:

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
