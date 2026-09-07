# VULN 002 – mem_read Heap Over-Read via Negative cnt Widened to SIZE_MAX

## Vulnerability Summary

| Field | Value |
|-------|-------|
| ID | VULN 002 |
| CWE | CWE-122 (Heap-Based Buffer Overflow — Over-read) |
| File | `src/libjasper/base/jas_stream.c` |
| Function | `mem_read()` |
| Lines | 1171–1184 |

## Root Cause

In `mem_read()`:

```c
static int mem_read(jas_stream_obj_t *obj, char *buf, int cnt)
{
    ssize_t n;
    assert(cnt >= 0);
    jas_stream_memobj_t *m = (jas_stream_memobj_t *)obj;
    n = m->len_ - m->pos_;    // (1) negative when pos_ > len_
    cnt = JAS_MIN(n, cnt);    // (2) cnt becomes negative
    memcpy(buf, &m->buf_[m->pos_], cnt);  // (3) SIZE_MAX memcpy → crash
    m->pos_ += cnt;
    return cnt;
}
```

When `m->pos_ > m->len_`:
1. `n = m->len_ - m->pos_` is negative (both are `int_fast32_t`)
2. `cnt = JAS_MIN(n, cnt)` sets cnt to the negative value
3. `memcpy(buf, ..., cnt)` receives negative cnt; implicit cast to `size_t`
   widens it to SIZE_MAX, causing a heap over-read → SIGSEGV or ASAN abort

This is a **follow-on** to VULN 001 (`mem_seek` dead unsigned check): VULN 001
allows `m->pos_` to be set past `m->len_` without error, and VULN 002 fires
when a read is subsequently attempted on that stream.

## Trigger Chain

```
imginfo -f crafted.jp2
  → jas_image_decode()
  → jp2_decode()
  → jpc_decode()         [creates image with memory-backed component streams]
  → jas_image_create()
  → jas_image_cmpt_create()
  → jas_stream_memopen2(0, size)  [m->len_=0, m->bufsize_=size]
  → jas_stream_seek(stream, size-1, SEEK_SET)  [m->pos_=size-1 > m->len_=0]
    → VULN 001: mem_seek silently sets pos > len (dead unsigned check)
  → jas_stream_putc()    [writes, updates m->len_=size]
  → jas_stream_seek(0, SEEK_SET)  [resets m->pos_=0]
  [JPC decoder writes tile data to streams]
  → jp2_decode() processes PCLR+CMAP boxes
  → jas_image_depalettize()
  → jas_image_readcmptsample()
  → jas_stream_seek(stream, offset, SEEK_SET)
  → jas_stream_getc()
  → jas_stream_fillbuf()
  → mem_read()           [if pos_ > len_: negative cnt → SIZE_MAX memcpy → CRASH]
```

## PoC Strategy

Three variants are attempted:

**Variant 1**: 1×1 grayscale image with PCLR (4 entries) + CMAP (palette mapping)
using a known-valid 1×1 codestream. Forces the `jas_image_depalettize` path
which calls `jas_image_readcmptsample` on the component stream.

**Variant 2**: 100×100 grayscale image with PCLR+CMAP and a short tile data
section. The JPC decoder processes a truncated codestream, possibly leaving
the component stream in an intermediate state.

**Variant 3**: 4096×4096 grayscale image with PCLR+CMAP. Larger stream
(16 MB) increases the probability of the seek landing in an invalid region.
Within the 256 MB in-memory threshold (16 MB << 256 MB) so uses memory stream.

## Expected Behavior (Unpatched Build)

- ASAN: `heap-buffer-overflow` in `mem_read()` at `jas_stream.c:1181`
- Or: SIGSEGV due to memcpy with SIZE_MAX

## Note on Build Configuration

- Build type: Release (NDEBUG → assertions disabled, including `assert(cnt >= 0)`)
- Compiler flags: `-fsanitize=address,undefined -O3`
- With NDEBUG, the `assert(cnt >= 0)` in `mem_read` is compiled away,
  allowing the `memcpy` with negative cnt to proceed to the crash.

## Files

| File | Purpose |
|------|---------|
| `vuln_002_gen.py` | Generates `vuln_002.jp2` (3 variants) |
| `vuln_002_run.sh` | Runs imginfo with ASAN and collects output |
| `vuln_002_result.txt` | stdout/stderr + ASAN log output |
| `asan.log.*` | Raw ASAN/UBSAN report files |
| `vuln_002_notes.md` | This file |
| `vuln_002_status.txt` | Final verdict (VERIFIED_CRASH / UNVERIFIED / ERROR) |
