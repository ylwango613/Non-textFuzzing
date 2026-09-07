I have thoroughly analyzed the target file and all related functions. Let me compile my final findings.

## VULN: Heap Buffer Overflow via Zero-Length Constant Run in GdkPixdata RLE Decoder
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf_from_pixdata()
- **行号**: 462-483 (gdk-pixdata.c)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted GdkPixdata image file (.gdkp)
- **外部触发路径**: gdk-pixbuf-csource input.gdkp → gdk_pixbuf_new_from_file() → io-pixdata.c: pixdata_image_stop_load() → gdk_pixdata_deserialize() → gdk_pixbuf_from_pixdata() → RLE decode do-while loop
- **描述**: 在 gdk_pixbuf_from_pixdata() 的 RLE 解码器中，当处理 encoding==RLE 的 pixdata 时，若读到常量游程长度字节 0x80（length = 0x80 - 128 = 0），check_overrun 被计算为 `image_buffer + 0*bpp > image_limit` = FALSE，导致 length 不被截断。随后进入 `do { memcpy(image_buffer, rle_buffer, bpp); image_buffer += bpp; } while (--length)` 循环：初始 length=0，第一次迭代后 `--length = UINT_MAX`（无符号下溢），循环继续执行约 2^32 次，持续向 image_buffer 写入直到触碰未映射页面。攻击者控制 rle_buffer 指向的内容（紧跟 0x80 之后的 4 字节），因此同时控制写入的数据内容。
- **触发条件**: 构造一个 GdkPixdata 二进制流：魔数 'GdkP'，pixdata_type = RGBA|RLE|SAMPLE_WIDTH_8，width/height/rowstride 合法，pixel_data 中包含字节 0x80（一个长度字段减 128 后为 0 的常量游程条目）。
- **安全影响**: 32 位系统上堆指针回绕，可覆盖任意堆内存（函数指针、堆元数据），潜在 RCE；64 位系统上快速越界写入触发崩溃（DoS）。

## VULN: Out-of-Bounds Heap Read via Missing rle_buffer Bounds Check in GdkPixdata Decoder
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf_from_pixdata()
- **行号**: 452-503 (gdk-pixdata.c)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted GdkPixdata image file (.gdkp)
- **外部触发路径**: gdk-pixbuf-csource input.gdkp → gdk_pixbuf_new_from_file() → io-pixdata loader → gdk_pixdata_deserialize() → gdk_pixbuf_from_pixdata() → RLE decode while loop reads rle_buffer OOB
- **描述**: gdk_pixbuf_from_pixdata() 的 RLE 解码器以 `while (image_buffer < image_limit)` 作为循环终止条件，仅检查输出缓冲区是否填满，从不检查 rle_buffer 是否超出 pixel_data 边界（无 `rle_buffer < pixel_data + pixel_data_size` 校验）。若构造的 RLE 数据在 image_limit 被达到之前耗尽，rle_buffer 会读取 pixel_data 后的堆内存。配合 gdk_pixdata_deserialize() 中的错误长度检查（见下一条漏洞），可更容易触发。
- **触发条件**: 构造 .gdkp 文件：pixdata_type=RLE|RGBA，height×rowstride 声明大量输出字节，但实际 pixel_data 内的 RLE 编码仅能解码出少量输出字节，致使 rle_buffer 在 image_buffer 到达 image_limit 前越出 pixel_data 末端。
- **安全影响**: 读取堆上相邻内存（信息泄露）；若读到未映射页则崩溃（DoS）。

## VULN: Off-by-Header-Length Integer Check in gdk_pixdata_deserialize Enables Truncated-Stream Attacks
- **漏洞类别**: memory-safety
- **函数**: gdk_pixdata_deserialize()
- **行号**: 235 (gdk-pixdata.c)
- **CWE**: CWE-131 (Incorrect Calculation of Buffer Size)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted GdkPixdata image file (.gdkp)
- **外部触发路径**: gdk-pixbuf-csource input.gdkp → gdk_pixbuf_new_from_file() → io-pixdata loader → gdk_pixdata_deserialize() (length check bypassed) → gdk_pixbuf_from_pixdata() (OOB read)
- **描述**: gdk_pixdata_deserialize() 第 235 行的长度校验为 `if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)` ，实际应为 `if (stream_length < pixdata->length)`。当前检查比正确逻辑宽松了整整 GDK_PIXDATA_HEADER_LENGTH（24 字节）：攻击者可提供总长度在区间 `[pixdata->length - 24, pixdata->length - 1]` 内的流，使 pixel_data 实际字节数比头部声明的少最多 24 字节，此校验仍通过。随后 gdk_pixbuf_from_pixdata() 使用 pixdata->height×pixdata->rowstride（头部中的大值）决定需要解码的输出量，而 rle_buffer 仅有截断的 pixel_data 可读，与上条 OOB read 漏洞组合可放大越界读取范围。
- **触发条件**: 构造 .gdkp 流，其中 pixdata->length 声明值 = stream_length + K（1 ≤ K ≤ 24），使截断检查恰好绕过，同时 height×rowstride 足够大，令 RLE 解码器在 pixel_data 耗尽前无法填满输出缓冲区。
- **安全影响**: 绕过长度保护，配合 OOB read 漏洞实现堆信息泄露或崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
