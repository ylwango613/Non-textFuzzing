Now I have enough data. Let me document my findings based on the complete code analysis.

**Analysis Summary:**

**Group 1 — io-bmp.c**: BMP LineWidth calculations for large widths produce signed overflow (UB) but are protected downstream by `gdk_pixbuf_new()`'s `rowstride/channels != width` check and `grow_buffer()`'s zero-size guard.

**Group 2 — io-ico.c**: `DecodeHeader()` computes palette byte range in `HeaderBuf` from `biClrUsed * 4` (field from file). When `biClrUsed` is non-zero but small (e.g. 1), the `I==0 → use default 256` fallback does NOT trigger. `HeaderBuf` is undersized. `OneLine8()` and `OneLine4()` then read `HeaderBuf[4 * pixel_index + 40/41/42 + DIBoffset]` with `pixel_index` from pixel data bytes (0–255 for 8bpp, 0–15 for 4bpp) — no bounds check against actual palette size. Confirmed heap OOB read.

**Group 3 — gdk-pixdata.c**: `gdk_pixdata_deserialize()` line 235 check is `stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH` instead of the correct `stream_length < pixdata->length`. This allows `pixdata->length` to exceed `stream_length` by up to 23 bytes, causing subsequent RLE/raw decoding in `gdk_pixbuf_from_pixdata()` to read up to 23 bytes past the end of the supplied stream buffer.

**Group 4 — io-gif.c**: LZW stack is bounded by `CHECK_LZW_SP()` macro; table access is guarded by `(1 << MAX_LZW_BITS)` checks. No confirmed OOB.

**Group 5 — io-ani.c**: chunk_size is always word-padded before use; `g_try_malloc(chunk_size+1)` overflow path (chunk_size=UINT32_MAX) is defused by padding wrapping to 0. ANI pos vs NumFrames is bounded by pre-creation check. No confirmed OOB.

## VULN: ICO heap OOB read in OneLine8/OneLine4 via undersized palette (biClrUsed)
- **漏洞类别**: memory-safety
- **函数**: `OneLine8()`, `OneLine4()`, `DecodeHeader()`
- **行号**: DecodeHeader: 378–387; OneLine8: 665–689; OneLine4: 690–728
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted ICO/CUR image file
- **外部触发路径**: `gdk_pixbuf__ico_image_load_increment()` → `DecodeHeader()` (undersizes HeaderBuf) → `OneLine8()` / `OneLine4()` (reads OOB from HeaderBuf with unchecked pixel color index)
- **描述**: `DecodeHeader()` reads `biClrUsed` from the DIB header (`BIH[32..35]`) and computes `I = biClrUsed * 4`. When `I != 0`, the `if ((I==0)&&(State->Type==8)) I = 256*4` default does NOT fire, so `HeaderBuf` (which holds both the DIB header and the color palette) is sized to contain only `biClrUsed` palette entries. However, `OneLine8()` indexes into the palette as `HeaderBuf[4 * LineBuf[X] + 40 + DIBoffset]` where `LineBuf[X]` is a raw pixel byte (0–255 for 8bpp) with no upper bound check against `biClrUsed`. When an attacker sets `biClrUsed = 1`, `HeaderBuf` is allocated with only 4 palette bytes, but any non-zero pixel value causes reads up to 1022 bytes past the palette start — well beyond the allocation. The same flaw exists in `OneLine4()` for 4bpp icons with `biClrUsed < 16`.
- **触发条件**: 构造一个 8bpp ICO 文件，将 BITMAPINFOHEADER 中的 biClrUsed 字段设为 1（或任何 < 256 的非零值），像素数据中包含非零颜色索引（如 0x01–0xFF 均可触发），文件通过任何使用 gdk-pixbuf ICO 加载器的应用加载。
- **安全影响**: 最坏情况下读取 HeaderBuf 末尾以后的堆内存（最多 `4*(255-biClrUsed)*3 ≈ 3kb`），可泄露相邻堆块中的敏感指针/数据；若越界区域跨页则触发 crash（DoS）；在特定堆布局下有辅助 ASLR 绕过的信息泄露价值。

## VULN: gdk-pixdata incorrect bounds check in gdk_pixdata_deserialize() leads to heap OOB read
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixdata_deserialize()`, `gdk_pixbuf_from_pixdata()`
- **行号**: gdk-pixdata.c:235 (wrong check); gdk-pixdata.c:459–494 (OOB read during RLE decode)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.2 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted inline pixbuf data stream (via gdk_pixbuf_new_from_inline() or io-pixdata loader)
- **外部触发路径**: `gdk_pixbuf_new_from_inline()` → `gdk_pixdata_deserialize()` (passes wrong check) → `gdk_pixbuf_from_pixdata()` → RLE/RAW decode loop reads past end of `stream` buffer
- **描述**: `gdk_pixdata_deserialize()` 第 235 行的越界检查写错为 `if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)` ，正确写法应为 `if (stream_length < pixdata->length)`。错误检查使攻击者可以将序列化流中的 `length` 字段设置为最多比 `stream_length` 大 23 的值（`GDK_PIXDATA_HEADER_LENGTH - 1 = 23`），通过边界检查后将 `pixdata->pixel_data` 设置为指向流缓冲区末尾附近的指针；随后 `gdk_pixbuf_from_pixdata()` 中的 RLE 解码循环（或 RAW `memcpy`）按 `pixdata->rowstride * pixdata->height` 字节读取像素数据，从而读取 stream 缓冲区结束后最多 23 字节的堆内存。
- **触发条件**: 提供一段 GdkPixdata 序列化数据，其 `length` 字段比实际流长度大 1–23 字节，`rowstride * height` 大于实际可用像素字节数；通过任何调用 `gdk_pixbuf_new_from_inline()` 处理外部数据的应用触发。
- **安全影响**: 从堆中读取最多 23 字节的越界内存，可导致信息泄露或潜在崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
