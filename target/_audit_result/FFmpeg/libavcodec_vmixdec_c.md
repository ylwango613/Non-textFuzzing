After reading the complete file (316 lines) and tracing all relevant context — `av_fast_mallocz`/`fast_malloc` internals, `init_get_bits8`, `get_ue_golomb_long`, `idct_put` signature, and the `AV_INPUT_BUFFER_PADDING_SIZE` packet padding guarantee — I conducted the following checks:

**Bounds checks in `decode_frame` (lines 250–284):**
Both DC and AC slice loops validate: `offset + 4 > avpkt->size`, `slice_size > avpkt->size`, and `avpkt->size - slice_size - 4LL < offset`. The mixed-signedness arithmetic produces correct `long long` comparison (no unsigned wrap enabling bypass).

**`av_fast_mallocz` size calculation (line 246):**
`s->nb_slices * sizeof(*s->slices)` — `nb_slices` is `int`, promoted to `size_t`. On 64-bit, no overflow. On 32-bit, extreme heights would first cause signed UB in `(height+15)/16`, but `fast_malloc` internally caps at `max_alloc_size` and returns NULL on excess, caught by the `if (!s->slices)` check.

**Array accesses in `decode_dcac` (lines 145–146):**
`i = scan[n]` with `n ∈ [0,63]` — `scan` is 64 elements. `ff_permute_scantable` guarantees values are a permutation of [0,63], so `block[i]` and `factors[i]` are both in-bounds.

**Frame buffer write bounds:**
`by = n * 16`, `n ∈ [0, nb_slices-1]`, `nb_slices = (height+15)/16`. Frame is allocated with `coded_height = FFALIGN(height,16)`. Last row written: `(nb_slices-1)*16 + 15 = coded_height - 1`. No OOB.

**Bitstream reads:**
`init_get_bits8` initializes with the slice's known size. `get_ue_golomb_long` uses `show_bits_long(gb, 32)` which reads up to 32 bits; the AVPacket padding guarantee (`AV_INPUT_BUFFER_PADDING_SIZE`) covers this. Explicit `get_bits_left` checks guard all reads.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
