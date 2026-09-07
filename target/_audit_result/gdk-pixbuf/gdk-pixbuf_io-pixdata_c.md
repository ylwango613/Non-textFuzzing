I've completed a thorough analysis. Here is my final auditing report.

## VULN: Heap Out-of-Bounds Read in RAW pixel copy — rowstride×height not validated against declared pixel data length
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()`
- **行号**: gdk-pixdata.c:505-506 (root: deserialization at 234-237)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted .gdkp image file (GdkPixdata format)
- **外部触发路径**: `pixdata_image_load_increment()` → `pixdata_image_stop_load()` → `try_load()` → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` → `memcpy(data, pixdata->pixel_data, pixdata->rowstride * pixdata->height)` [gdk-pixdata.c:506]
- **描述**: `gdk_pixdata_deserialize()` 在 gdk-pixdata.c:235 校验 `stream_length >= pixdata->length - GDK_PIXDATA_HEADER_LENGTH`，即实际收到的流至少达到文件头中 `pixdata->length` 字段所声明的像素数据大小。但该校验与后续实际使用的像素数据量（`pixdata->rowstride * pixdata->height`）完全解耦。攻击者可将 `pixdata->length` 设为一个很小的值（如 `GDK_PIXDATA_HEADER_LENGTH + 100 = 124`）并在流中仅提供 100 字节像素数据，同时将 `pixdata->rowstride = 100000`、`pixdata->height = 100` 设为大值（均满足 `rowstride >= width` 验证）。反序列化校验通过后，`gdk_pixbuf_from_pixdata` 在 RAW 编码路径以 `g_try_malloc_n(height, rowstride)` 分配 10MB 缓冲区（该函数内部溢出安全），然后执行 `memcpy(data, pixdata->pixel_data, 100000 * 100 = 10,000,000)` 从仅有 100 字节的 `pixdata->pixel_data` 出发读取 10MB，导致堆上越界读取约 9,999,900 字节。
- **触发条件**: 攻击者构造一个 .gdkp 文件，设置 `pixdata->length = 24 + N`（N 较小），并使 `rowstride * height >> N`。文件总大小仅需 `24 + N` 字节即可通过反序列化校验，但后续 memcpy 会读取远超实际数据的字节数。
- **安全影响**: 堆内存信息泄露（可能暴露 ASLR 地址、密钥或其他敏感数据）；若读取越过堆段边界则触发 SIGSEGV，导致进程崩溃（DoS）；在某些配置下可被进一步利用升级为 RCE。

## VULN: Heap Out-of-Bounds Read in RLE decode — rle_buffer advances without input-side bounds check
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()`
- **行号**: gdk-pixdata.c:452-503
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted .gdkp image file with RLE encoding flag
- **外部触发路径**: `pixdata_image_load_increment()` → `pixdata_image_stop_load()` → `try_load()` → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` → RLE decode loop at gdk-pixdata.c:459-503
- **描述**: RLE 解码循环（gdk-pixdata.c:459）以 `image_buffer < image_limit` 为终止条件，其中 `image_limit = data + pixdata->rowstride * pixdata->height`（输出缓冲区上限）。循环内 `rle_buffer` 逐字节推进（gdk-pixdata.c:461 `guint length = *(rle_buffer++)`）并通过 `memcpy(image_buffer, rle_buffer, ...)` 读取像素字节（gdk-pixdata.c:472、480、491），但全程没有任何检查 `rle_buffer` 是否仍在 `pixdata->pixel_data` 合法范围内。代码仅对输出缓冲的写入做了溢出保护（`check_overrun`），却对输入 RLE 数据流完全不设边界。攻击者设置 RLE 编码标志，声明 `pixdata->length = 24 + N`（N 字节 RLE 数据），同时设置 `rowstride * height` 远大于 N，则解码循环在输入 N 字节耗尽后继续推进 `rle_buffer`，从堆上 GString 内部缓冲区之外的内存读取数据，直到输出缓冲区被填满。
- **触发条件**: 攻击者发送 RLE 编码的 .gdkp 文件，其中实际 RLE 像素数据字节数（`pixdata->length - 24`）小于解码输出所需的 `rowstride * height` 字节数。`pixdata->length` 小、`rowstride` 与 `height` 大，文件总大小可极小。
- **安全影响**: 堆内存信息泄露（从 GString 分配区之后的任意堆内容被读入新分配的 pixbuf 缓冲区，进而可能通过图像像素数据通道暴露给调用者）；访问到未映射内存时导致进程崩溃（DoS）；特定堆布局下读入敏感指针/内容可被进一步利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
