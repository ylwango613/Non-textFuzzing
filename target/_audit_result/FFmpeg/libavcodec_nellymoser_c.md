**Full analysis summary:**

**nellymoser.c (shared)**:
- `ff_nelly_get_sample_bits`: `sbuf[128]` accessed only [0,124); `bits[]` clipped via `av_clip(…, 0, NELLY_BIT_CAP=6)`. The while-loop at line 216 is bounded because entering the branch requires `bitsum > NELLY_DETAIL_BITS=198`, and `bitsum` is provably equal to the sum of all `bits[]` elements (same arithmetic formula), so the loop terminates before `i == NELLY_FILL_LEN=124`.

**nellymoserdec.c (decoder)**:
- `init_get_bits` initialized with exactly `NELLY_BLOCK_LEN*8=512` bits; all `get_bits` calls read bounded amounts from a guaranteed-full 64-byte block.
- `ff_nelly_init_table[get_bits(&s->gb, 6)]`: 6-bit read → indices [0,63], table size 64 ✓
- `ff_nelly_delta_table[get_bits(&s->gb, 5)]`: 5-bit read → indices [0,31], table size 32 ✓
- `ff_nelly_dequantization_table[(1<<bits[j])-1+v]`: bits[j]∈[0,6], v∈[0,(1<<bits[j])-1], max index = 63+63=126, table size 127 ✓
- `decode_tag`: `blocks > INT_MAX / NELLY_SAMPLES` guard prevents multiplication overflow for `nb_samples` ✓

**nellymoserenc.c (encoder, trellis path)**:
- `get_exponent_dynamic`: `idx_max = FFMIN(OPT_SIZE, …)` can equal `OPT_SIZE=35768`; guard `if (idx > idx_max)` is strict-greater, so `idx == OPT_SIZE` bypasses it → `opt[band][OPT_SIZE]` OOB write. However, this is **encoder-only** (not triggered by crafted media files for decoding) and requires explicit non-default `avctx->trellis != 0`.

No external crafted-media-file-triggerable memory safety bug found in the decoder or shared codec paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
