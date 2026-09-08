Now I have the complete picture. Let me analyze the key findings:

**Bug 1 (confirmed):** In `ff_h274_hash_freep()` (lines 916–927), `c = *ctx` saves the struct pointer, then `av_freep(ctx)` frees that struct and nulls `*ctx`. On big-endian, `av_freep(&c->buf)` then reads and writes `c->buf` inside the already-freed struct — a UAF read + UAF write.

**Bug 2 (ruled out):** `num_intensity_intervals` — the h2645_sei.c parser uses `get_bits(gb, 8) + 1` (range 1–256) and VVC uses `uint8_t + 1` (same range), so the loop bound in `generate()` never exceeds 256. No OOB.

**Bug 3 (ruled out):** `x_offset`/`y_offset` into `film_grain_db.db[13][13][64][64]` — max values are 56 which is within [0..63]. No OOB.

**Bug 4 (ruled out):** `h`/`v` indices — hard-clamped by `av_clip(..., 2, 14) - 2` to [0, 12], matching the `[13][13]` array bounds.

The sole confirmed memory-safety vulnerability is the BIGENDIAN UAF in the cleanup path.

## VULN: Use-After-Free in ff_h274_hash_freep() on Big-Endian Builds
- **漏洞类别**: memory-safety
- **函数**: ff_h274_hash_freep()
- **行号**: 916-927
- **CWE**: CWE-416 (Use After Free)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (VVC/H264/HEVC with picture hash SEI)
- **外部触发路径**: ffmpeg -i <crafted.vvc> -f null - → avcodec_close() → ff_h274_hash_freep() → UAF on freed H274HashContext.buf
- **描述**: 在 `ff_h274_hash_freep()` 中，局部指针 `c` 先保存 `*ctx` 的值（指向 `H274HashContext` 堆块）。随后 `av_freep(ctx)` 释放该堆块并将 `*ctx` 清零。而在 `#if HAVE_BIGENDIAN` 分支中，后续的 `av_freep(&c->buf)` 继续通过已释放堆块中的 `c->buf` 字段进行读写：`av_freep` 实现会先 `memcpy` 读出 `c->buf` 的值（UAF 读），再将该地址处写 NULL（UAF 写），最后以读出的值作为参数调用 `av_free()`（潜在任意 free）。若在两次 `av_freep` 之间另一线程或操作重新分配了该内存，攻击者可通过堆占位令 `c->buf` 字段指向任意地址，从而导致任意堆指针被释放，进而实现堆元数据破坏乃至 RCE。
- **触发条件**: 攻击者需构造包含 picture hash SEI（类型为 MD5 或 CRC，且帧像素格式为 16-bit，使 `ps != 0`）的 VVC/HEVC/H264 码流，在大端序平台（HAVE_BIGENDIAN，如 MIPS、PowerPC、s390x）上解码后触发解码器关闭路径（调用 `avcodec_close()` 或 `avformat_close_input()`），即可触发此 UAF。
- **安全影响**: 最坏情况下，攻击者通过堆占位控制释放的指针，可导致堆破坏，进而实现远程代码执行（RCE）；在大端序嵌入式环境（如网络设备固件中内嵌 FFmpeg）中实际可利用性更高。

<!-- AUDIT_PROMPT_VERSION: 1 -->
