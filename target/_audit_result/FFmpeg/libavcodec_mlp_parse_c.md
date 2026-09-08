The vulnerability is confirmed. In `mlp_parse.c:160`, `mh->num_substreams = get_bits(gb, 4)` produces a value 0–15 with no upper-bound check. In `mlp_parser.c:195`, this is stored in `mp->num_substreams` without any validation (unlike `mlpdec.c` which properly checks `> MAX_SUBSTREAMS`). The parity loop at lines 146–154 then reads `buf[p++]` for `1 + mp->num_substreams` iterations with no check of `p < buf_size`, causing a heap OOB read when a short non-sync frame follows a sync frame that set `num_substreams = 15`.

## VULN: mlp_parser Heap OOB Read via Unvalidated num_substreams in Parity Loop
- **漏洞类别**: memory-safety
- **函数**: mlp_parse() / ff_mlp_read_major_sync()
- **行号**: mlp_parse.c:160 (source), mlp_parser.c:146-154 (sink)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MLP/TrueHD media file
- **外部触发路径**: ffmpeg -i crafted.thd -f null - → avcodec_open2() → AVCodecParser invoked → mlp_parse() [mlp_parser.c] → sync frame path: ff_mlp_read_major_sync() [mlp_parse.c:160] reads num_substreams=get_bits(gb,4) (0–15, no upper bound) → mp->num_substreams = mh.num_substreams [mlp_parser.c:195, no MAX_SUBSTREAMS check] → next non-sync frame: parity loop [mlp_parser.c:146–154] reads buf[p++] for (1+mp->num_substreams) iterations without checking p < buf_size → heap OOB read
- **描述**: `ff_mlp_read_major_sync()` (mlp_parse.c:160) reads `num_substreams` from a 4-bit bitstream field, yielding values 0–15, and stores it in `MLPHeaderInfo.num_substreams` with no upper-bound validation. `mlp_parser.c` copies this directly into `mp->num_substreams` (line 195) without the `> MAX_SUBSTREAMS` guard that `mlpdec.c` applies (mlpdec.c:391). On the subsequent non-sync frame, the parity check loop (`for (i = -1; i < mp->num_substreams; i++)`) unconditionally reads 2–4 bytes per iteration from `buf[p++]` without ever comparing `p` against `buf_size`. With `num_substreams = 15`, the loop reads up to 4 + 15×4 = 64 bytes; a short frame (e.g., 4 bytes, controlled via the 12-bit length field × 2 in bytes 0–1 of each access unit) causes the read pointer `p` to advance far past the end of the heap-allocated frame buffer assembled by `ff_combine_frame`.
- **触发条件**: 攻击者需要构造一个 MLP/TrueHD 文件（.mlp 或 .thd）：(1) 第一帧为含 major sync header 的同步帧，其中 4-bit `num_substreams` 字段设为 15；(2) 第二帧为非同步帧，通过 12-bit 长度字段将帧长设为很小的值（如 4 字节），使 `buf_size` 远小于 parity 循环将要读取的 `4 + 15×(2~4)` 字节。
- **安全影响**: 堆越界读取，最坏情况下导致：(1) 进程崩溃（SIGSEGV），即可靠的 DoS；(2) 相邻堆内存信息泄露（如堆元数据、指针值），可作为进一步利用的信息探测手段；结合堆布局控制技术，在边界条件下可能辅助实现 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
