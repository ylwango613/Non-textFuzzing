I now have all the evidence needed. Let me produce the final audit report.

## VULN: Heap Buffer Overflow via RLE Repeat-Run Zero-Length in gdk_pixbuf_from_pixdata
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()`
- **行号**: 463-483 (gdk-pixdata.c)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Critical
- **攻击向量**: crafted `.gdkp` image file (GdkPixdata format)
- **外部触发路径**: 恶意 `.gdkp` 文件 → `io-pixdata.c:pixdata_image_stop_load()` → `try_load()` → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` → 堆溢出
- **描述**: `gdk_pixbuf_from_pixdata()` 解码 RLE 压缩像素数据时，变量 `length`（类型为 `guint`，即 unsigned int）由 `*(rle_buffer++) = 0x80`（= 128）得到 `length = 128 - 128 = 0`。overrun 检查 `image_buffer + 0 * bpp > image_limit` 为 FALSE（无过界），不做截断。随后进入 do-while 循环：第一次迭代写入 `bpp`（3 或 4）字节，执行 `--length`：`(guint)0 - 1 = UINT_MAX = 4294967295`（无符号下溢），循环继续 ~42 亿次，每次向 `image_buffer` 写入 `bpp` 字节，总写入量约 12–17 GB，远超分配的 `height * rowstride` 字节缓冲区边界，覆盖相邻堆数据。
- **触发条件**: 构造一个以 `GdkP`（0x47646b50）开头的 GdkPixdata 文件，`pixdata_type` 编码字段设为 `GDK_PIXDATA_ENCODING_RLE`，像素数据中包含值为 `0x80` 的字节（repeat-run，run count = 0）。
- **安全影响**: 任意堆内存损坏；攻击者可通过精心构造的 `.gdkp` 文件覆盖相邻堆对象实现 RCE，或直接触发进程崩溃（DoS）。

## VULN: Heap OOB Read via Unbounded rle_buffer in gdk_pixbuf_from_pixdata
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()`
- **行号**: 454-494 (gdk-pixdata.c)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted `.gdkp` image file (GdkPixdata format)
- **外部触发路径**: 恶意 `.gdkp` 文件 → `io-pixdata.c:try_load()` → `gdk_pixdata_deserialize()` (将 `pixdata->pixel_data` 设为流内指针) → `gdk_pixbuf_from_pixdata()` RLE 解码循环 → OOB 读
- **描述**: RLE 解码循环中的 `rle_buffer` 指针（`const guint8 *rle_buffer = pixdata->pixel_data`）仅受 `image_buffer < image_limit`（输出缓冲区上界）约束，从未与输入 `pixdata->pixel_data` 的结束地址对比。攻击者可设置 `pixdata->length = GDK_PIXDATA_HEADER_LENGTH + N`（提供 N 字节 RLE 输入），但图像声称需要 M >> N 字节解码空间：当 N 字节 RLE 数据消耗完毕而 `image_buffer < image_limit` 仍成立时，后续 `*(rle_buffer++)` 及 `rle_buffer += length` 将读超出 `pixdata->pixel_data` 缓冲区边界，访问相邻堆内存，可造成信息泄露或进程崩溃。
- **触发条件**: 构造 `.gdkp` 文件，声明大尺寸图像（如 width=100, height=100, rowstride=400），但 `pixdata->length` 仅包含极少字节 RLE 像素数据（如 3 字节），`gdk_pixdata_deserialize` 通过验证后 `gdk_pixbuf_from_pixdata` 读取超界。
- **安全影响**: 堆内存越界读；可泄露相邻堆内存（含指针、密钥等敏感数据）；读取未映射内存时崩溃（DoS）。

## VULN: Integer Overflow in gdk_pixbuf_new_from_bytes Size Validation Bypasses Buffer Check
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_new_from_bytes()`
- **行号**: 113 (gdk-pixbuf-data.c)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: 应用调用此公共 API 时传入来自图像文件的 width/height
- **外部触发路径**: 图像加载 → 解析 width/height → `gdk_pixbuf_new_from_bytes(data, …, width, height, …)` → 整数溢出绕过尺寸检查 → 创建虚假大尺寸 pixbuf
- **描述**: `gdk_pixbuf_new_from_bytes()` 中尺寸校验代码（第 113 行）为：`g_return_val_if_fail (g_bytes_get_size (data) >= width * height * (has_alpha ? 4 : 3), NULL);` 右侧 `width * height * (has_alpha ? 4 : 3)` 使用有符号 `int` 算术（三个 `int` 操作数），可溢出。例如 `width = 32768, height = 32768, has_alpha = TRUE`：`32768 × 32768 × 4 = 4294967296`，在 32 位 signed int 下溢出为 `0`。此时比较变为 `g_bytes_get_size(data) >= 0`，对任意非负长度的 GBytes 均成立，允许调用者传入远小于实际像素数据的 GBytes（如仅 1 字节），后续所有像素访问均为越界读取。
- **触发条件**: 调用方将来自图像文件的超大 width/height（使乘积溢出 int）传入 `gdk_pixbuf_new_from_bytes`，同时 GBytes 数据大小不足。
- **安全影响**: 使用返回的 pixbuf 读写像素时触发堆越界读；若写路径被触发（如 `gdk_pixbuf_get_pixels` 后修改），可升级为堆溢出写。

## VULN: Infinite Loop DoS via RLE Literal-Run Zero-Length in gdk_pixbuf_from_pixdata
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()`
- **行号**: 485-494 (gdk-pixdata.c)
- **CWE**: CWE-835 (Loop with Unreachable Exit Condition / Infinite Loop)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted `.gdkp` image file (GdkPixdata format)
- **外部触发路径**: 恶意 `.gdkp` 文件 → `io-pixdata.c:pixdata_image_stop_load()` → `try_load()` → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` → 无限循环
- **描述**: 在 RLE 解码 else 分支（literal run）中，当 RLE 字节为 `0x00`（literal run，length = 0）：`length *= bpp = 0`，`check_overrun = image_buffer + 0 > image_limit` 为 FALSE，`memcpy(image_buffer, rle_buffer, 0)` 不复制任何字节，`image_buffer += 0` 和 `rle_buffer += 0` 均无进展。随后外层 `while (image_buffer < image_limit)` 条件依然为真，循环再次进入相同分支读取同一字节 `0x00`，无限重复，进程 CPU 100% 永远不退出。注意：`gdk_pixdata_serialize`/`pixdata_get_length` 中对零长度有检查（返回 `0` 视为 corrupt），而 `gdk_pixbuf_from_pixdata` 解码路径完全缺失此验证。
- **触发条件**: 构造 `.gdkp` 文件，将 RLE 编码像素数据的第一个字节设为 `0x00`（literal run，count = 0）。
- **安全影响**: 进程无限占用 CPU 资源，调用线程永久挂起，导致 gdk-pixbuf 加载图像的应用（GNOME 桌面、GTK 应用、thumbnailers 等）完全拒绝服务。

<!-- AUDIT_PROMPT_VERSION: 1 -->
