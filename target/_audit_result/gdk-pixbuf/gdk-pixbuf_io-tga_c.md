The analysis is complete. The critical issue is confirmed:

- `ctx->cmap->cols` is allocated for exactly `cmap_n_colors` entries (line 689)
- In `parse_data_for_row_pseudocolor` (lines 367-371) and `parse_rle_data_pseudocolor` (lines 466, 480-486), `*s` — a raw byte from the image pixel data (range 0–255) — is used **without any bounds check** against `ctx->cmap->size` to index into `ctx->cmap->cols`
- An attacker can set `cmap_n_colors = 1` while having pixel values up to 255, causing reads up to `255 * sizeof(TGAColor) = 1020 bytes` past the end of the allocated array

## VULN: Heap OOB read via unchecked colormap index in pseudocolor TGA decoding
- **漏洞类别**: memory-safety
- **函数**: `parse_data_for_row_pseudocolor()`, `parse_rle_data_pseudocolor()`
- **行号**: 360-373, 449-502 (critical indexing at lines 367-371, 466, 480-486)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted TGA image file (pseudocolor type 1 or RLE pseudocolor type 9)
- **外部触发路径**: `gdk_pixbuf__tga_load_increment()` → `parse_data_for_row()` → `parse_data_for_row_pseudocolor()` / `parse_rle_data_pseudocolor()`
- **描述**: `ctx->cmap->cols` is allocated at line 689 with exactly `cmap_n_colors` entries (`sizeof(TGAColor) * LE16(ctx->hdr->cmap_n_colors)`). In both the non-RLE path (`parse_data_for_row_pseudocolor`, lines 367–371) and the RLE path (`parse_rle_data_pseudocolor`, lines 466 and 480–486), each source pixel byte `*s` (attacker-controlled, range 0–255) is used directly as an array index into `ctx->cmap->cols[*s]` with **no bounds check** against `ctx->cmap->size`. An attacker who sets `cmap_n_colors = 1` in the TGA header causes the colormap to be allocated as a single 4-byte `TGAColor` entry, while pixel bytes of value 255 cause reads at `ctx->cmap->cols[255]` — i.e., 1020 bytes past the end of the heap allocation. The out-of-bounds heap bytes are then copied verbatim into the output `GdkPixbuf` pixel buffer, potentially leaking adjacent heap contents to the caller.
- **触发条件**: 构造 TGA 文件，设置 `type = 1`（PSEUDOCOLOR）或 `type = 9`（RLE_PSEUDOCOLOR），`bpp = 8`，`cmap_bpp = 24` 或 32，`cmap_n_colors` 设为很小的值（如 1），然后在像素数据中放置大于等于 `cmap_n_colors` 的字节（如 0xFF）。解码时即触发越界读。
- **安全影响**: 堆越界读取导致相邻堆内存内容（可能包含指针、密钥、其他敏感数据）被写入输出 pixbuf 像素数据，最坏情况下可被攻击者获取（信息泄露），同时若越界地址落入不可读页则导致进程崩溃（DoS）。在 GTK 缩略图生成或网页图片渲染场景下，泄露的堆数据可能随 pixbuf 返回给上层应用，造成进程内存内容泄露（ASLR 信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
