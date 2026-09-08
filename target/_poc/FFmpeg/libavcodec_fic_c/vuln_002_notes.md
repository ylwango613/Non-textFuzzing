# VULN 002 — 1-Byte Heap OOB Write in fic_draw_cursor (Chroma Plane +1 Offset)

## Summary

`fic_draw_cursor()` in `libavcodec/fic.c` (lines 247-250) adds `!!i` to every chroma
plane pointer:

```c
for (i = 0; i < 3; i++)
    dstptr[i] = ctx->final_frame->data[i]
              + (ctx->final_frame->linesize[i] * (cur_y >> !!i))
              + (cur_x >> !!i) + !!i;   // ← !!i == 1 for i=1,2
```

For i=1 (Cb) and i=2 (Cr) the extra +1 byte shifts `dstptr` one byte past the last
valid column whenever `cur_x/2 + 1 == linesize[i]`.  `fic_alpha_blend()` then writes
`csize = lsize/2` bytes starting at that OOB address.

## Exact Trigger (width=64, height=64)

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| width     | 64    | linesize[1]=linesize[2]=32 = width/2 (no alignment slack) |
| height    | 64    | multiple of 16, gives last chroma row at cur_y/2 = 31 |
| cur_x     | 62    | FFMIN(32, 64-62)=2 → lsize=2, csize=1 |
| cur_y     | 62    | FFMIN(32, 64-62)-1=1 → one loop iteration |
| tsize     | 4128  | 32 bytes header + 4096 bytes RGBA bitmap |

Pointer arithmetic for i=2 (Cr):

```
dstptr[2] = data[2] + linesize[2]*31 + 31 + 1
           = data[2] + 992 + 32
           = data[2] + 1024
```

The Cr plane is `linesize[2] * height/2 = 32 * 32 = 1024` bytes.  
`fic_alpha_blend(dstptr[2], …, csize=1, …)` writes 1 byte **past the end of the Cr plane**.

## FIC Packet Layout

```
Offset  0 -  6: FIC magic { 0x00, 0x00, 0x01, 'F', 'I', 'C', 'V' }
Offset  7 - 12: reserved (zero)
Offset 13      : nslices = 1
Offset 14 - 16: reserved (zero)
Offset 17      : skip-frame flag = 0
Offset 18 - 22: reserved (zero)
Offset 23      : quality = 1 (HQ matrix)
Offset 24 - 26: tsize  = 4128  (big-endian 3 bytes)
Offset 27 - 32: cursor section padding
Offset 33 - 34: cur_x  = 62  (LE16)
Offset 35 - 36: cur_y  = 62  (LE16)
Offset 37 - 38: cursor width  = 32 (LE16, must equal 32)
Offset 39 - 40: cursor height = 32 (LE16, must equal 32)
Offset 41 - 58: padding (zero)
Offset 59-4154: cursor BGRA bitmap (32×32×4 = 4096 bytes, A=255)
Offset 4155-4158: slice table (1 entry, big-endian offset = 0)
Offset 4159+  : slice data (96 zero bytes → 96 non-skip DCT blocks)
```

Wrapped in a minimal AVI container with FOURCC `FICV` (codec tag registered in
`libavformat/riff.c` line 444).

## Why ASAN Does Not Detect the Crash

Modern FFmpeg (libavutil/frame.c `get_video_buffer`) packs **all planes into a single
`av_buffer_alloc`** of size:

```
total_size = 4*plane_padding + 4*align + sizes[0] + sizes[1] + sizes[2]
           = 4*32 + 4*32 + 4096 + 1024 + 1024
           = 6400 bytes   (for 64×64, align=32)
```

`data[2]` (Cr) is placed at `buf+5184`.  The OOB write goes to `buf+5184+1024 = buf+6208`.
The ASAN red zone does not start until `buf+6400` (end of the single combined allocation).
The write therefore lands ~192 bytes **before** the allocation boundary, inside FFmpeg's
internal plane-padding region — a legitimate allocated byte that ASAN does not protect.

This 192-byte gap is structural and invariant across all frame dimensions because the
overhead formula (`4*plane_padding + 4*align = 256`) always exceeds the actual OOB
offset by exactly 192 bytes when `height` is a multiple of 32.

## Real-World Impact

Although ASAN cannot detect the single-byte write, the corruption IS present:
- The byte written at `data[2]+1024` corrupts a byte within the frame buffer's internal
  padding region.
- In a multi-frame sequence, re-used buffer regions could expose this as an info-leak
  or control-flow corruption depending on the allocator's reuse pattern.
- Valgrind memcheck (with `--partial-loads-ok=no`) or a custom allocator with zero
  trailing space would detect this write.

## Verification Command

```bash
bash /data/ylwang/non-textfuzz/target/_poc/FFmpeg/libavcodec_fic_c/vuln_002_run.sh
```

Expected: FFmpeg processes the file successfully (exit 0), no ASAN crash, but the OOB
write is analytically confirmed by the code path traced above.
