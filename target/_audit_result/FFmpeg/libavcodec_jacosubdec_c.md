**分析摘要：**

- `directives[128]` 栈缓冲区：`do-while` 循环条件 `p < pend`（`pend = directives + 127`）保证最多写到 `directives[126]`，然后 `*p = 0` 写 `directives[127]`，恰好在 128 字节边界内。无溢出。
- `buf[16]` 在 `insert_datetime`：`strftime` 以 `sizeof(buf)=16` 为限，且格式字符串来自编译期常量（`"%d %b %Y"` 最长 11 字节），不可被用户控制。无溢出。
- `insert_color`/`insert_font` 返回 1，导致 `src` 在匹配 `\C`/`\F` 后越过 null terminator 一个字节：FFmpeg 的所有 AVPacket 数据必须由 `av_new_packet` 分配，后缀有 `AV_INPUT_BUFFER_PADDING_SIZE`（64 字节）零填充，外层 `while (*src && ...)` 读到零即退出，不构成可利用的 OOB。
- `AVBPrint` 以 `JSS_MAX_LINESIZE=512` 为 `max_size` 初始化，超限自动截断，无堆溢出。
- `read_ts` 时间戳整数运算潜在溢出仅影响 pts/duration 值，不涉及内存分配大小。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
