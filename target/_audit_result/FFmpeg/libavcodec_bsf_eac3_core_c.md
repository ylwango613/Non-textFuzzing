文件仅 94 行，已完整读取并分析 `ff_ac3_parse_header` 实现及相关结构体。

**逐行分析结果：**

1. **`init_get_bits8` 返回值已检查**（第 42-44、58-60 行），GetBitContext 内部有边界保护。
2. **`FFMIN(hdr.frame_size, pkt->size)`**（第 54 行）防止将 `pkt->size` 设置为超出实际数据的值。
3. **`pkt->size > hdr.frame_size` 条件**（第 55 行）在使用 `hdr.frame_size` 做指针偏移前已验证安全性，避免了 `pkt->data + hdr.frame_size` 越界读。
4. **`hdr.frame_size` 来源验证**：E-AC3 路径（`bitstream_id > 10`）在 `ac3_parser.c:362` 校验 `frame_size >= AC3_HEADER_SIZE (7)`，不存在 0 值；常规 AC3 路径使用查找表，同样非 0。
5. **无直接内存分配**：文件内不存在 `av_malloc`/`memcpy`，无堆溢出/欠分配机会。
6. **`pkt->data += hdr.frame_size; pkt->size -= hdr.frame_size;`**（第 70-71 行）：在 `pkt->size > hdr.frame_size` 已验证的前提下，减法不下溢，指针偏移合法。AVPacket 内部 `buf` 引用计数正确跟踪原始分配边界，`av_packet_unref` 时不会 UAF。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
