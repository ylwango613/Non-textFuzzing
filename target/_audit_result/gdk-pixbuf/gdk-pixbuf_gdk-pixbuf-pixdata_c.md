Now I have a complete picture. Let me analyze the critical functions in depth before writing the final report.

**Batch 1 findings (gdk_pixdata_deserialize, lines 198–240):**
- Line 235: `if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)` — length check compares against claimed size, not actual decoded size; when `pixdata->length = GDK_PIXDATA_HEADER_LENGTH = 24`, the subtraction is 0, and `stream_length < 0u` is always FALSE → check always passes even with 0 pixel bytes.

**Batch 2 findings (gdk_pixbuf_from_pixdata, lines 452–503):**

Critical finding A: In the constant-run RLE branch (lines 463–484), after `length = length - 128`, when the control byte is **0x80** → `length = 0`. Then:
- `check_overrun = image_buffer + 0*bpp > image_limit` → FALSE
- Enters `do { memcpy(image_buffer, rle_buffer, 3); image_buffer += 3; } while (--length);`
- First iteration always executes (do-while), then `--length` wraps UINT to UINT_MAX → loops 4 billion times → **heap buffer overflow**.
- Contrast: `pixdata_get_length()` at lines 68–71 has `if (!chunk_length) return 0;` — this safety check is **missing** in `gdk_pixbuf_from_pixdata`.

Critical finding B: `rle_buffer` has **no upper-bound check** against `pixdata->pixel_data + pixel_data_length` anywhere in the loop (lines 459–494). When RLE input bytes are exhausted before the output buffer is full, subsequent `*(rle_buffer++)` and `memcpy(image_buffer, rle_buffer, ...)` read from heap beyond the allocated buffer → **OOB read**.

## VULN: Heap Buffer Overflow via RLE Control Byte 0x80 in gdk_pixbuf_from_pixdata
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf_from_pixdata() in gdk-pixdata.c
- **行号**: 463-483
- **CWE**: CWE-787 (Out-of-bounds Write via integer underflow in do-while counter)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted inline pixdata stream (serialized GdkPixdata byte sequence)
- **外部触发路径**: attacker-crafted pixdata byte stream → gdk_pixbuf_new_from_inline() → gdk_pixdata_deserialize() → gdk_pixbuf_from_pixdata() → RLE decode loop (lines 463-483)
- **描述**: 在 gdk_pixbuf_from_pixdata() 的 RLE 解码循环中，读取到常量游程控制字节 0x80（二进制 10000000）时，执行 `length = length - 128 = 128 - 128 = 0`（guint 类型）。随后的 `check_overrun = image_buffer + 0 * bpp > image_limit` 为 FALSE，length 保持为 0，不被截断。紧接的 `do { memcpy(image_buffer, rle_buffer, 3); image_buffer += 3; } while (--length)` 是 do-while 循环，至少执行一次后 `--length` 对 guint 0 下溢为 UINT_MAX（4294967295），循环继续执行约 42 亿次，每次向 image_buffer 写入 3 或 4 字节，迅速溢出仅分配 rowstride*height 字节的堆缓冲区，破坏堆元数据和相邻对象。对照：同文件中 pixdata_get_length() 的第 68–71 行包含 `if (!chunk_length) return 0;` 保护，但 gdk_pixbuf_from_pixdata() 中完全缺失该检查。
- **触发条件**: 攻击者构造一个 GdkPixdata 序列化字节流（24 字节头部 + pixel_data 起始字节为 0x80），传递给 gdk_pixbuf_new_from_inline() 或直接调用 gdk_pixbuf_from_pixdata()。攻击者将 pixdata_type 设置为 GDK_PIXDATA_ENCODING_RLE，width/height/rowstride 设置为合法小值以保证 copy_pixels=TRUE 分配成功，pixel_data 第一字节为 0x80。
- **安全影响**: 堆缓冲区越界写入（Heap Buffer Overflow），进程因写入超出分配区域而崩溃（DoS），结合堆风水布局可实现任意代码执行（RCE）。

## VULN: Out-of-Bounds Read in RLE Decoder due to Missing rle_buffer Bounds Check
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf_from_pixdata() in gdk-pixdata.c
- **行号**: 459-494
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted inline pixdata stream (serialized GdkPixdata byte sequence)
- **外部触发路径**: attacker-crafted pixdata stream → gdk_pixbuf_new_from_inline() → gdk_pixdata_deserialize() → gdk_pixbuf_from_pixdata() → RLE decode loop lines 459-494
- **描述**: 在 gdk_pixbuf_from_pixdata() 的 RLE 解码循环中，`rle_buffer` 指针从 pixdata->pixel_data 起始、无任何上界校验地持续递增。外层 while 循环条件仅检查输出缓冲区 `image_buffer < image_limit`，而不检查 `rle_buffer` 是否超过 pixel_data 末尾。当攻击者提供的 RLE 编码数据字节数少于解码完整输出所需字节数时（例如：pixdata->rowstride * pixdata->height = 300 字节输出，但 pixel_data 仅有 4 字节的 RLE 数据），解码循环在耗尽合法 RLE 输入后仍继续执行，`*(rle_buffer++)` 和 `memcpy(image_buffer, rle_buffer, bpp)` 读取 pixel_data 缓冲区末尾之后的堆内存，造成越界读取。gdk_pixdata_deserialize() 第 235 行的边界检查 `stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH` 仅验证流中存在不少于声称的字节数，不能阻止 RLE 解码过程中的 rle_buffer 越界。
- **触发条件**: 攻击者构造 pixdata 流，设置 pixdata->length（pixel_data 声明字节数）为较小值（如 4 字节），但 pixdata->rowstride * pixdata->height（期望输出字节数）较大（如 300 字节）；pixel_data 中的 RLE 内容在产生少量输出后耗尽（例如单条字面游程），之后 rle_buffer 无界递增，读取 pixel_data 缓冲区末尾之外的堆内存。
- **安全影响**: 越界读取堆内存（Out-of-Bounds Read），可泄露堆中敏感数据（信息泄露），也可能因读取不可访问内存页造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
