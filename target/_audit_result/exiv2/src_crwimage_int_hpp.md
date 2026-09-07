The confirmed finding is clear: the code's own comment at line 187 says the check is to prevent "infinite recursion" (cycles), but there is absolutely no depth counter — only a structural constraint that each sub-buffer be strictly smaller. This allows linear nesting of depth ≈ fileSize/12, which can easily overflow a typical 8MB stack.

## VULN: Stack Overflow via Unbounded Recursive CIFF Directory Parsing
- **漏洞类别**: memory-safety
- **函数**: CiffDirectory::readDirectory() / CiffDirectory::doRead()
- **行号**: 212-252 (crwimage_int.cpp)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted CRW image file
- **外部触发路径**: `exiv2 pr <file>` → `CrwImage::readMetadata()` (crwimage.cpp:55) → `CrwParser::decode()` (crwimage.cpp:73) → `CiffHeader::read()` (crwimage_int.cpp:141) → `CiffDirectory::readDirectory()` (crwimage_int.cpp:167) → `m->read()` for each directory-type entry (crwimage_int.cpp:248) → `CiffDirectory::doRead()` (crwimage_int.cpp:212) → `CiffDirectory::readDirectory()` (crwimage_int.cpp:220) → [RECURSIVE, no depth limit]
- **描述**: `CiffDirectory::readDirectory()` 解析目录表中的每个条目，当条目类型为 directory（tag & 0x3800 == 0x2800 or 0x3000）时，分配一个 `CiffDirectory` 对象并调用 `m->read(pData, size, o, byteOrder)` → `CiffDirectory::doRead()` → 再次调用 `readDirectory(pData + offset(), this->size(), byteOrder)`，形成相互递归。代码在第 186-198 行的注释明确指出这是为防止"循环 IFD 引用导致无限递归"而加入的结构性约束（子目录数据区不得与其 10 字节目录项重叠），但该约束仅防止循环（cycle），**不防止线性深度嵌套**。每一层递归至少使子目录缓冲区减少 12 字节（最小化：`offset_ >= start + 10 = 2 + 10 = 12`，子目录大小 = `size_ <= size - 12`），因此最大递归深度为 ≈ fileSize / 12。对于 500KB 的 CRW 文件，递归深度可达约 40,000 层（每帧约 200 字节栈，两帧/层：readDirectory + doRead），在 8MB 默认线程栈上触发栈溢出（segfault），在极端情况下可能覆盖栈上的返回地址，导致控制流劫持。
- **触发条件**: 攻击者构造一个 ≈500KB 的 CRW 文件：CIFF 头指向一个根目录区，根目录中只有一个 directory 类型的条目，该条目的数据区也只有一个 directory 条目，如此线性嵌套约 40,000 层。每层占约 12 字节，总文件约 480KB。`tag` 字段的高两位设为 `0x28xx` 或 `0x30xx`（directory 类型），`size_` 字段设为恰好比父缓冲区小 12，`offset_` 设为 `start + 10` 以通过边界检查。
- **安全影响**: 最坏情况下：栈溢出覆盖返回地址 → 任意代码执行（RCE）；最可能情况：进程崩溃（DoS）。任何处理用户提供 CRW 图像的服务（如在线相册、图像转换管道）均受影响，无需认证。

<!-- AUDIT_PROMPT_VERSION: 1 -->
