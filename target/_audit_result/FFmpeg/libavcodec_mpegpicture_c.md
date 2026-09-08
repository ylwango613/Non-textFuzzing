After reading the complete `mpegpicture.c` (259 lines) and tracing all related headers, pool allocation sizing, and check functions, here is the full analysis:

**`ff_mpv_framesize_alloc` (lines 138–179):**
- `linesizeabs = FFABS(linesize)`: if `linesize = INT_MIN`, FFABS returns INT_MIN (signed overflow UB), but the check `linesizeabs < 24` catches this case and returns early.
- `alloc_size = FFALIGN(linesizeabs + 64, 32)`: if `linesizeabs` is near INT_MAX, `linesizeabs + 64` overflows. However, the result passed as `unsigned` to `av_image_check_size2` then appears as a value > INT32_MAX, which is explicitly rejected by the `w > INT32_MAX` guard. No exploitable path.
- After `av_image_check_size2` passes, `alloc_size` is bounded to < 657,870 (derived from the `stride*(h+128ULL) < INT_MAX` constraint). Consequently `alloc_size * 280` < 184 M and `alloc_size * 128` < 84 M — both within `int` range, so no overflow in the `FF_ALLOCZ_TYPED_ARRAY` arguments.

**`alloc_picture_tables` (lines 206–235):**
- Pool sizes: `qscale_table` pool = `(mb_height + 2) * mb_stride + 1` bytes; offset applied = `2 * mb_stride + 1`, leaving `mb_height * mb_stride` accessible — correct.
- `motion_val_base[i] + 4`: pool = `(b8_array_size + 4)` int16_t[2] pairs; after +4 offset, `b8_array_size` pairs remain — correct.
- `mb_type_base + 2 * mb_stride + 1`: same arithmetic in uint32_t units, correct.

**`ff_mpv_replace_picture` (lines 121–126):**
- `av_refstruct_replace(&dst->ptr, src->ptr)` properly decrements old `dst->ptr` refcount and increments `src->ptr` refcount before `memcpy` overwrites all fields. The memcpy then writes `src->ptr` (same value already in `dst->ptr`), so refcounts remain correct. No UAF or double-free.

**All other functions** (`mpv_pic_reset`, `mpv_pic_init`, `mpv_pic_free`, `ff_mpv_workpic_from_pic`, `ff_mpv_unref_picture`, `ff_mpv_pic_check_linesize`) perform only refstruct unref/alloc, frame alloc/free, and bounds comparisons — no unsafe memory patterns.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
