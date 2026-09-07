I have now fully traced both vulnerability chains. Here is the final audit report:

## VULN: GdkPixdata RAW decoder heap OOB read – rowstride*height not bounded by stream length
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixdata_deserialize()` / `gdk_pixbuf_from_pixdata()`
- **行号**: gdk-pixdata.c:235 (bounds check) + gdk-pixdata.c:506 (memcpy)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted GdkPixdata image file (.gdkp, MIME: image/x-gdkpixdata)
- **外部触发路径**: `gdk_pixbuf_new_from_file()` [gdk-pixbuf-io.c:1058] → `_gdk_pixbuf_generic_image_load()` [gdk-pixbuf-io.c:1021] → `generic_load_incrementally()` [gdk-pixbuf-io.c:982] → `pixdata_image_load_increment()` [io-pixdata.c:116] → `try_load()` [io-pixdata.c:70] → `gdk_pixdata_deserialize()` [gdk-pixdata.c:199] → `gdk_pixbuf_from_pixdata()` [gdk-pixdata.c:414]
- **描述**: `gdk_pixdata_deserialize()` 在 line 235 对像素数据边界的校验存在缺陷：`if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)` 仅将总流长度与头部声明的像素数据字节数对比，但 `gdk_pixbuf_from_pixdata()` 在 RAW 编码路径（line 506）实际使用 `memcpy(data, pixdata->pixel_data, pixdata->rowstride * pixdata->height)` 复制 `rowstride * height` 字节，而代码对 `rowstride * height` 是否超出实际可用字节数（`stream_length - GDK_PIXDATA_HEADER_LENGTH`）从无校验。攻击者可将 `pixdata->length` 设为 24（最小合法值，令 line 235 的检查 `stream_length < 0` 恒为 FALSE），同时将 `rowstride * height` 设为任意大值，使 memcpy 的源指针 `pixdata->pixel_data` 大幅越界读取堆内存。
- **触发条件**: 构造一个 24 字节（或略大）的 `.gdkp` 文件，头部 magic=`GdkP`，`length=24`，`pixdata_type=RGB+RAW`，`rowstride=10000`，`width=10`，`height=100`。`gdk_pixdata_deserialize` 的边界检查(`25 < 24-24=0` → FALSE)通过，随后 `memcpy` 从仅 0 有效字节的 `pixel_data` 读取 1,000,000 字节。
- **安全影响**: 堆越界读，可泄露堆上任意内存内容（密钥、凭据、ASLR 地址等），或因访问未映射页引发 SIGSEGV 导致进程崩溃（DoS）。

## VULN: GdkPixdata RLE decoder heap OOB read – rle_buffer 无输入边界检查
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf_from_pixdata()`
- **行号**: gdk-pixdata.c:459–493 (RLE decode loop)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted GdkPixdata image file with RLE encoding (.gdkp)
- **外部触发路径**: `gdk_pixbuf_new_from_file()` [gdk-pixbuf-io.c:1058] → `generic_load_incrementally()` [gdk-pixbuf-io.c:982] → `pixdata_image_load_increment()` [io-pixdata.c:116] → `try_load()` [io-pixdata.c:70] → `gdk_pixdata_deserialize()` [gdk-pixdata.c:199] → `gdk_pixbuf_from_pixdata()` [gdk-pixdata.c:414, RLE branch]
- **描述**: RLE 解码循环（line 459）只对输出指针 `image_buffer` 做上界检查（`while (image_buffer < image_limit)`），但对输入指针 `rle_buffer` 完全没有边界校验。`rle_buffer` 初始化为 `pixdata->pixel_data`，其可用字节数为 `stream_length - GDK_PIXDATA_HEADER_LENGTH`，但循环在 `image_buffer` 填满输出缓冲区（`rowstride * height` 字节）前会持续读取 `*(rle_buffer++)`（line 461）以及 `memcpy(image_buffer, rle_buffer, length)`（line 491）。若 RLE 输入字节数极少但 `rowstride * height` 很大，`rle_buffer` 将持续越界读取像素数据缓冲区之后的堆内存。
- **触发条件**: 构造 `.gdkp` 文件：RLE 编码，像素数据区仅 2 字节（如 `0x01 0xFF 0xFF 0xFF`），但 `rowstride=100, height=100`（期望输出 10000 字节）。`gdk_pixdata_deserialize` 的 line 235 检查通过后，RLE 循环在写满 10000 字节输出之前，`rle_buffer` 持续读取超出 2 字节像素数据的堆内存。
- **安全影响**: 堆越界读，可泄露进程堆上的任意内存内容，或在 `rle_buffer` 跨越映射边界时导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
