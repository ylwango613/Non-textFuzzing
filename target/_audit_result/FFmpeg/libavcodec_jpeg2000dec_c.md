The analysis is complete. I have thoroughly reviewed all 2965 lines of `jpeg2000dec.c` in 5 batches, verified the bytestream2 unchecked-read semantics in `bytestream.h`, and traced the call chain through `jpeg2000_read_main_headers`.

**Finding summary:**

The only confirmed, externally-triggerable memory-safety bug is in `get_cap()` (lines 455–464): the bounds check guarantees only 6 bytes before reading a 4-byte Pcap word, leaving just 2 bytes of buffer headroom, but the subsequent loop calls `bytestream2_get_be16u` (confirmed unchecked — it calls `bytestream_get_be16(&g->buffer)` directly with no `buffer_end` guard) once for every bit set in Pcap. A crafted CAP marker with `len = 8` (smallest value that passes the `< 6` check) and two or more bits set in Pcap makes the second Ccap read go 2 bytes past the guaranteed data; with all 32 bits set it reads 62 bytes past. If the marker sits at the end of the packet buffer this becomes a real heap over-read.

All other patterns I investigated — `get_ppm`/`get_ppt` integer overflow in `packed_headers_size`, `tag_tree_decode` stack depth, `dequantization_*` index math, `write_frame` coordinate arithmetic — were either bounded by prior validated constraints or would produce allocation failures (ENOMEM) rather than memory corruption.

---

## VULN: OOB Heap Read in get_cap() via Untrusted Pcap Bitmask
- **漏洞类别**: memory-safety
- **函数**: get_cap()
- **行号**: 455-464
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted JP2/J2K media file
- **外部触发路径**: ffmpeg -i <crafted.jp2> -f null - → avcodec_decode_video2() → jpeg2000_decode_frame() → jpeg2000_read_main_headers() → get_cap()
- **描述**: `get_cap()` 在进入时仅检查剩余字节数 ≥ 6（line 455），随后以无边界检查的 `bytestream2_get_be32u` 读取 4 字节 Pcap，留下最少 2 字节可用数据。紧接着的 for 循环（lines 462-464）对 Pcap 中每个置位的 bit 调用一次 `bytestream2_get_be16u`——该函数内部直接执行 `AV_RB16(g->buffer); g->buffer += 2`，无任何边界检查。当 `len = 8`（满足外层 `len - 2 ≥ 6` 及内层 `< 6` 两道检查的最小值）且 Pcap 中有 2 个或更多 bit 置位时，第二次 Ccap 读取将超出 marker 边界 2 字节；若 Pcap 全为 1（32 bits），则超出达 62 字节。若 CAP marker 位于 packet buffer 末尾，上述读取将越过 `avpkt->data + avpkt->size`，造成堆越界读取。
- **触发条件**: 攻击者构造一个 JP2 / J2K 文件，使其包含 CAP marker，将 marker 长度字段 `len` 设为 8（或其他较小值），同时将 `Pcap` 字段中超过 `(len-6)/2` 个 bit 置位（如将所有 32 bit 均置为 1）。将该 CAP marker 放置在 packet 数据的最末尾，使得超出读取直接越出 avpkt 分配的堆缓冲区。
- **安全影响**: 最坏情况下可泄露堆内存中的相邻数据（如指针、密钥等敏感信息），也可能因读取未映射内存页而导致进程崩溃（DoS）。在沙盒化环境较弱的场景下，信息泄露可辅助进一步的漏洞利用链构建。

<!-- AUDIT_PROMPT_VERSION: 1 -->
