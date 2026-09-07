Now I have the complete picture. Let me analyze the key vulnerabilities found across all three read passes:

**Pass 1 (lines 0–100):** `pixdata_get_length()` RLE walk — `rle_buffer` advances without input bounds; used only internally for sizing.

**Pass 2 (lines 100–500):** Critical: `gdk_pixdata_deserialize()` length check (line 235) can be trivially bypassed (set `pixdata->length = GDK_PIXDATA_HEADER_LENGTH`). Then `gdk_pixbuf_from_pixdata()` RLE loop (lines 459–495) reads `rle_buffer` with zero input-side bounds. Also: `gdk_pixdata_from_pixbuf()` integer overflow `pad + n_bytes` when both equal `0x80000000`.

**Pass 3 (lines 499–914):** Confirmed that check_overrun only guards the output buffer (`image_buffer` vs `image_limit`), never the input `rle_buffer`. `gdk_pixbuf_new_from_inline()` is the public entry point.

---

## VULN: Heap Out-of-Bounds Read in gdk_pixbuf_from_pixdata() RLE Decoder — No Input Bounds on rle_buffer
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()` / `gdk_pixdata_deserialize()`
- **行号**: 235 (deserialize length bypass), 459–495 (unbounded rle_buffer reads)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted serialized GdkPixdata blob (inline pixbuf data)
- **外部触发路径**: attacker-crafted data → `gdk_pixbuf_new_from_inline(data_length, crafted_data, TRUE, NULL)` → `gdk_pixdata_deserialize()` (line 235 check bypassed) → `gdk_pixbuf_from_pixdata()` → RLE decode loop (lines 459–495) reads `rle_buffer` past end of input
- **描述**: `gdk_pixdata_deserialize()` 在第 235 行检查像素数据长度：`if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)`。当攻击者将序列化流中的 `length` 字段设置为 `GDK_PIXDATA_HEADER_LENGTH`（即 24），则右侧表达式为 0，条件变为 `stream_length < 0`（guint 恒为假），检查被完全绕过，`pixdata->pixel_data` 指向输入缓冲区末尾甚至之外。随后 `gdk_pixbuf_from_pixdata()` 的 RLE 解码循环中，`rle_buffer`（指向 `pixdata->pixel_data`）被无限制地推进：`*(rle_buffer++)` 读取 chunk header，`memcpy(image_buffer, rle_buffer, length)` 及 `rle_buffer += length` 均无上界约束。`check_overrun` 标志仅防止输出缓冲区（`image_buffer`/`image_limit`）越界，对输入端 `rle_buffer` 没有任何限制。循环持续直到 `image_buffer >= image_limit`（输出耗尽），整个过程中 `rle_buffer` 可无限制地向高地址读取堆内存。
- **触发条件**: 构造序列化 GdkPixdata 流：`magic=0x47646b50`，`length=24`（= GDK_PIXDATA_HEADER_LENGTH），`pixdata_type` 设置为 RGBA+RLE 编码，`rowstride` 和 `height` 取大值（如各 1000），实际流总长度仅 24 字节（无像素数据）。`data_length` 可设为 24 或 -1，均可触发。
- **安全影响**: 堆越界读取（heap over-read）：（1）信息泄露——读取堆上相邻内存（可能包含指针、密钥等敏感数据），（2）进程崩溃（DoS）——当 rle_buffer 越过已映射页边界触发 SIGSEGV，（3）在特定分配布局下，结合信息泄露可辅助绕过 ASLR 进而实现远程代码执行。

## VULN: Integer Overflow in gdk_pixdata_from_pixbuf() pad+n_bytes Heap Allocation → Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixdata_from_pixbuf()`
- **行号**: 349, 371–372, 375–377
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted GdkPixbuf with attacker-influenced rowstride (e.g., loaded from malicious image file with large width)
- **外部触发路径**: malicious image file → gdk_pixbuf_new_from_file() → image loader creates pixbuf with large rowstride → application calls `gdk_pixdata_from_pixbuf(pixdata, pixbuf, TRUE)` → integer overflow in `pad + n_bytes` → undersized heap allocation → `rl_encode_rgbx()` writes full image data past buffer end
- **描述**: 第 349 行 `n_bytes = rowstride * height`（均为 `guint` = 32-bit unsigned），乘法可能溢出。以 `rowstride = 0x80000000`，`height = 1` 为例：`n_bytes = 0x80000000`，`n_bytes % bpp == 0` 跳过修正分支。第 371 行 `pad = rowstride = 0x80000000`；第 372 行 `data = g_new(guint8, pad + n_bytes) = g_new(guint8, 0x80000000 + 0x80000000)`，`guint` 32位加法溢出为 0（在 32-bit 系统）或极端情况下极小值。`g_new` 分配一个极小/零字节的堆块。随后第 375–377 行 `rl_encode_rgbx(img_buffer, buf->pixels, buf->pixels + n_bytes, bpp)` 尝试向该极小堆块写入 `n_bytes`（约 2GB）字节，导致堆溢出。
- **触发条件**: 提供宽度约 `0x80000000 / bpp`（对于 RGBA 约 536870912 像素宽）的图像使 pixbuf->rowstride 达到 0x80000000，然后通过 `gdk_pixdata_from_pixbuf` 进行 RLE 编码。实际上也可通过拼接两个大图或利用 io-bmp.c 等解析器接受过大 biWidth 间接触发。
- **安全影响**: 堆缓冲区溢出，写入攻击者控制的像素数据，最坏情况下可导致任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
