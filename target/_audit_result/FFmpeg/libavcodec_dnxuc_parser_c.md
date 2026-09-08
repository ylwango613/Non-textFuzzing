Now I have all the context needed for a complete analysis. Let me trace the key code paths carefully.

**File: `dnxuc_parser.c` (91 lines) — complete analysis**

Key logic (lines 52–72):
```c
if (ipc->remaining == 0) {
    uint64_t state = ipc->pc.state64;
    for (int i = 0; i < buf_size; i++) {
        state = (state << 8) | buf[i];
        if (ipc->pc.index + i >= 7 && (uint32_t)state == MKBETAG('p','a','c','k')) {
            uint32_t size = av_bswap32(state >> 32);
            if (size >= 8) {
                 next = i - 7;                          // ← can be negative
                 ipc->remaining = size + FFMIN(next, 0);
                 break;
            }
        }
    }
```

**Case: `i = 0` with `ipc->pc.index >= 7`** (the 'pack' marker found at the first byte of the current chunk, with ≥7 bytes accumulated from previous calls):
- `next = 0 − 7 = −7`
- `ipc->remaining = size + (−7)` → since `size ≥ 8`, wraps cleanly to `≥ 1` — OK for uint32_t
- `ff_combine_frame(&ipc->pc, −7, &buf, &buf_size)` is called at line 72

**Inside `ff_combine_frame` with `next = −7`, `pc->index >= 7`** (parser.c lines 256–277):
```c
*buf_size = pc->overread_index = pc->index + next;   // = pc->index − 7

if (pc->index) {                                      // true (accumulated bytes exist)
    new_buffer = av_fast_realloc(pc->buffer, ...,
                    next + pc->index + AV_INPUT_BUFFER_PADDING_SIZE);
    // allocates: −7 + pc->index + 64  bytes

    if (next > -AV_INPUT_BUFFER_PADDING_SIZE)         // −7 > −64: TRUE
        memcpy(&pc->buffer[pc->index], *buf,
               next + AV_INPUT_BUFFER_PADDING_SIZE);  // copies −7 + 64 = 57 bytes from *buf
```

`*buf` is the current input chunk. If this chunk contains only 1 byte (just the 'k' terminal byte of the tag), `memcpy` reads **57 bytes** from a buffer that has only **1 byte** allocated → **heap OOB read of 56 bytes**.

The destination (`pc->buffer`) is correctly sized at `pc->index + 57` bytes (no OOB write). However, the source `*buf` has only `orig_buf_size` bytes, and `orig_buf_size` can be as small as 1.

**Trigger construction:** Attacker crafts a DNxUncompressed bitstream split across precisely two parser calls: the first N ≥ 7 bytes contain arbitrary preamble (filling `pc->state64`) ending with bytes `[SIZE_BE][p][a][c]`, and the second call's first byte is `[k]`. The `i=0` match fires, `next = −7`, OOB read occurs.

## VULN: OOB Heap Read in ff_combine_frame via Negative next from dnxuc_parse
- **漏洞类别**: memory-safety
- **函数**: dnxuc_parse() → ff_combine_frame()
- **行号**: 59-72 (dnxuc_parser.c) / 272-274 (parser.c)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (DNxUncompressed / SMPTE RDD 50)
- **外部触发路径**: `ffmpeg -i crafted.dnxuc -f null -` → `av_parser_parse2()` → `dnxuc_parse()` (next = i−7 = −7 when 'pack' tag straddles buffer boundary) → `ff_combine_frame(&ipc->pc, −7, &buf, &buf_size)` → `memcpy(&pc->buffer[pc->index], *buf, −7 + AV_INPUT_BUFFER_PADDING_SIZE)` reads 57 bytes from a 1-byte source buffer
- **描述**: In `dnxuc_parse()`, when the 8-byte 'pack' header (4-byte big-endian size + literal bytes `p a c k`) straddles two consecutive parser-call boundaries such that the first 7 bytes were accumulated into `pc->state64` in prior calls and only the terminal `k` byte arrives in the current `buf[]`, the loop detects the tag at index `i = 0` and computes `next = i − 7 = −7`. This negative value is passed directly to `ff_combine_frame()`. Inside that function, the branch at line 272 of parser.c (`if (next > -AV_INPUT_BUFFER_PADDING_SIZE)`) evaluates to true (−7 > −64), so `memcpy(&pc->buffer[pc->index], *buf, next + AV_INPUT_BUFFER_PADDING_SIZE)` executes with a copy length of 57 bytes. The source pointer `*buf` points to the current input chunk, which has only `buf_size` (e.g., 1) bytes allocated. The `memcpy` therefore reads 56 bytes beyond the end of the heap-allocated input buffer, constituting a heap out-of-bounds read.
- **触发条件**: 构造一个 DNxUncompressed 媒体文件，使得 'pack' 标签（8字节：4字节大端 size + 字节序列 `p a c k`）跨越两次 `av_parser_parse2` 调用的边界：第一次调用传入前7字节（至少包含 `[SIZE_BE][p][a][c]`），第二次调用的第一个字节为 `k`（且 `size ≥ 8`）。第二次调用的 `buf_size` 设置为 1（仅1字节），触发 `next = −7` 后的 57 字节越界读。
- **安全影响**: 越界读取 input chunk 后最多 56 字节的堆内存（相邻堆块内容），在转码服务场景下（攻击者提供输入、获取输出）可导致堆内存信息泄露（如指针、密钥等敏感数据）；也可能因读入未映射内存页而触发 SIGSEGV，造成进程崩溃（DoS）。ASAN 将检测为 heap-buffer-overflow（读）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
