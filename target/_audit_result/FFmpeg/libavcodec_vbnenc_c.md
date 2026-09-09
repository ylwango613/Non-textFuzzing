I've now read all relevant code:

- **vbnenc.c** (full 167 lines): the VBN encoder
- **vbn.h**: constants (`VBN_HEADER_SIZE = 192`, format IDs)
- **texturedsp.h / texturedsp_template.c**: texture compression thread infrastructure
- **imgutils.c**: `av_image_check_size2` and `av_image_copy_plane` implementations

**Summary of findings after thorough analysis:**

1. **`pkt_size` computation (line 91)**: `VBN_HEADER_SIZE + linesize * frame->height` is done with `linesize` as `ptrdiff_t` (64-bit on x86_64) and `pkt_size` as `int64_t`. `av_image_check_size2` at line 53 guarantees `stride*(h+128) < INT_MAX`, which ensures `linesize * height < INT_MAX` for all supported formats. The explicit check `if (pkt_size > INT_MAX)` at line 92 additionally guards against any residual excess.

2. **DXT1/DXT5 output sizing**: For DXT1 `linesize = w/2`, output bytes = `(w/4)*(h/4)*8 = w*h/2`. For DXT5 `linesize = w`, output bytes = `(w/4)*(h/4)*16 = w*h`. Both match `linesize * frame->height` exactly; no over- or under-allocation.

3. **`exec_func` in texturedsp_template.c**: writes to `d + (off + x) * tex_ratio` where `off = y * w_block`, bounded by `(h/4)*(w/4) * tex_ratio = linesize * height`. No OOB write.

4. **RAW path `av_image_copy_plane` (line 122)**: copies `linesize` bytes per row for `frame->height` rows, exactly filling the `linesize * height` byte region. `av_assert0(|src_linesize| >= bytewidth)` in `image_copy_plane` would catch any undersize source stride (which can't happen in a conforming pipeline).

5. **Negative linesize**: explicitly checked at lines 83–84 for the RAW path; DXT paths compute `linesize` from validated positive width.

6. **Header writes (lines 100–111)**: 10 writes × 4 bytes = 40 bytes at offsets 0–39, plus one 4-byte write after `bytestream2_seek_p(64)` → offset 64–67; all within `VBN_HEADER_SIZE = 192`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
