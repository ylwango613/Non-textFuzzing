Confirmed. `GetMP3GainErrorStr` at line 225 correctly uses `buffer[buflen-1]` with the comment "don't assume buffer has extra byte at the end for null terminator" — while `GetDLLVersion` at line 260 uses `buffer[buflen]`, writing one byte past the end. This is a clear off-by-one OOB write.

## VULN: Off-by-one OOB write in GetDLLVersion
- **漏洞类别**: memory-safety
- **函数**: GetDLLVersion()
- **行号**: 253-263
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted application call to the DLL export with exact-size buffer
- **外部触发路径**: caller application → GetDLLVersion(buffer, buflen) → buffer[buflen] = '\0' (one byte past end of buffer)
- **描述**: 在 `GetDLLVersion`（第260行）中，代码执行 `buffer[buflen] = '\0'`，而调用者提供的缓冲区合法索引范围为 `buffer[0]` 到 `buffer[buflen-1]`。这导致在缓冲区末尾之后写入一个 null 字节（单字节堆/栈越界写）。同文件中功能相似的 `GetMP3GainErrorStr` 函数在第225行正确使用了 `buffer[buflen-1]`，并附有注释"don't assume buffer has extra byte at the end for null terminator"，说明这是一个遗漏的一致性修复，属于明确的实现错误。后续 `strncpy(buffer, MP3GAIN_VERSION, buflen-1)` 本身是正确的，但前面的越界写已经发生。
- **触发条件**: 调用方以精确大小分配缓冲区（例如 `char buf[N]; GetDLLVersion(buf, N);`），此时 `buf[N]` 越过堆块或栈帧边界；buflen >= 1 即可触发（函数只对 `buflen < 1` 做了提前返回）。
- **安全影响**: 单字节 null 覆写紧接着缓冲区之后的内存。若缓冲区在堆上，可覆写堆管理元数据（chunk header），导致后续 malloc/free 触发任意写，进而可能实现 RCE；若在栈上，可覆写相邻局部变量或函数指针，导致控制流劫持或 DoS（崩溃）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
