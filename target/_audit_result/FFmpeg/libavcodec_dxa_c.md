Now I have all the information needed for a complete analysis. Let me synthesize the full findings:

**Probe dimension cap**: `dxa_probe` at line 52 caps `w ≤ 2048 && h ≤ 2048` for auto-detection, meaning the largest product via auto-detection is 2048×2048×2 = 8,388,608 — no overflow in `decode_init`.

**Integer overflow path**: With explicit `-f dxa` (bypassing probe), `avio_rb16` can set `w,h` up to 65535. For example, `w=65532, h=32772` gives `w*h*2 = 4,295,229,408` which wraps to `262,112` as `int32` — `decomp_buf` is allocated as ~256 KB while actual frame dimensions demand ~2 GB.

**decode_13 bounds check**: The within-block pointer overreads (msk, data, mv advancing up to 16 bytes past `src_end` within one block) are precisely absorbed by `DECOMP_BUF_PADDING = 16`, which is zeroed via `memset(c->decomp_buf + dsize, 0, DECOMP_BUF_PADDING)`. Not a true heap OOB.

**decode_frame compr=4**: For this compression type the code skips `uncompress()` and uses `srcptr = c->decomp_buf` directly. With an underallocated `decomp_buf` (256 KB) and `avctx->width * avctx->height` ~2 billion, the rendering loop `memcpy(outptr, srcptr, avctx->width)` reads massively past the heap allocation — a multi-GB heap OOB read into `frame->data[0]`.

## VULN: Integer Overflow in decode_init Causes Heap OOB Read via Underallocated decomp_buf
- **漏洞类别**: memory-safety
- **函数**: decode_init() / decode_frame()
- **行号**: 340-341 (overflow), 235-279 (OOB read)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted DXA media file opened with explicit format forcing (`ffmpeg -f dxa -i`)
- **外部触发路径**: `ffmpeg -f dxa -i malicious.dxa -f null -` → `avformat_open_input()` → `dxa_read_header()` (sets `st->codecpar->width/height` from `avio_rb16` up to 65535) → `avcodec_open2()` → `decode_init()` (line 340: `c->dsize = avctx->width * avctx->height * 2` — signed int32 overflow → wraps to small positive, e.g. 262,112 for w=65532,h=32772) → `av_malloc(262112 + 16)` = 256 KB buffer → `decode_frame()` with `compr=4` → `srcptr = c->decomp_buf` (256 KB) → rendering loop `memcpy(outptr, srcptr, avctx->width)` × `avctx->height` rows → ~2 GB OOB read past heap allocation
- **描述**: `decode_init()` 的第 340 行计算 `c->dsize = avctx->width * avctx->height * 2`，使用有符号 `int` 类型运算，当 `avctx->width` 和 `avctx->height` 同时较大（两者均需为 4 的倍数，可由 `avio_rb16` 写入，最大 65532）时发生 signed integer overflow，`c->dsize` 回绕为一个远小于实际帧大小的正整数。随后 `av_malloc(c->dsize + DECOMP_BUF_PADDING)` 仅分配数百 KB 的 `decomp_buf`。在 `decode_frame()` 中，当压缩类型 `compr=4`（跳过 `uncompress()`）时，`srcptr = c->decomp_buf`（数百 KB），渲染循环按行执行 `memcpy(outptr, srcptr, avctx->width)` 共 `avctx->height` 次，从而将数 GB 的堆内存（超出 `decomp_buf` 末尾的相邻堆块）复制进 `frame->data[0]`，形成大规模堆越界读。注：`dxa_probe()` 将自动探测时的 `w,h` 限制在 ≤ 2048，故本漏洞仅在使用 `-f dxa` 显式指定格式时可达。
- **触发条件**: 攻击者构造一个 DXA 文件，其文件头中 `width` 和 `height` 字段（均为 16 位大端整数，来自偏移 11 和 13）设置为满足 `width × height × 2` 产生 int32 溢出回绕到较小正值的特定维度组合（如 width=65532, height=32772），且帧数据中压缩类型字节设置为 `0x04`（compr=4，无压缩原始帧）。须通过 `ffmpeg -f dxa -i <file>` 或编程方式显式指定 DXA 格式打开。目标系统需有约 2 GB 空闲内存用于帧缓冲区分配。
- **安全影响**: 大规模堆越界读：`frame->data[0]` 将包含 `decomp_buf` 以外的堆内存内容（相邻堆块中的数据、指针、密钥材料等敏感信息）。若输出帧被写入文件、通过网络传输或以任何方式可被攻击者读取，则造成严重信息泄露（堆内存布局泄露，辅助 ASLR 绕过）。在某些内存布局下也可能导致进程崩溃（访问未映射内存）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
