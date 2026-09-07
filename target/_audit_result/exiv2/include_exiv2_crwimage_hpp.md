Complete analysis done. I've confirmed the single exploitable memory safety vulnerability: an unbounded mutual recursion between `CiffDirectory::readDirectory` (line 226) and `CiffDirectory::doRead` (line 212) with no depth limit. The code's anti-circular-reference guard at line 195 (`enforce(offset_ >= start + 10)`) only prevents self-referential loops; it does NOT bound linear chain depth. Each recursive level consumes a sub-slice of the parent buffer (minimum 12 bytes smaller), so O(N/12) recursion depth is achievable. On an 8 MB default stack with ~200 bytes per frame pair (readDirectory + doRead), a ~512 KB crafted CRW file can exhaust the stack.

No heap corruption, OOB write, integer overflow leading to underallocation, UAF, or IPTC/XMP vulnerabilities were found in the CRW code path — bounds checks at lines 176, 192, 195–197, 228, 231, 238, 683–685, 800 adequately protect the read operations.

## VULN: Uncontrolled Recursion in CIFF Directory Parsing Causes Stack Exhaustion
- **漏洞类别**: memory-safety
- **函数**: CiffDirectory::readDirectory() / CiffDirectory::doRead()
- **行号**: 212-252 (crwimage_int.cpp)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted CRW image file
- **外部触发路径**: `exiv2 pr <file>` → `CrwImage::readMetadata()` → `CrwParser::decode()` → `CiffHeader::read()` → `CiffDirectory::readDirectory()` → loop: `m->read()` → `CiffDirectory::doRead()` → `CiffComponent::doRead()` [validates bounds, sets offset_/size_] → `CiffDirectory::readDirectory(pData+offset(), this->size(), byteOrder)` [mutual recursion, no depth limit]
- **描述**: `readDirectory` 与 `doRead` 之间存在无限制的相互递归。对每个类型为 `directory` 的 CIFF entry（tag & 0x3800 == 0x2800 或 0x3000），解析器调用 `CiffDirectory::doRead`，后者再调用 `readDirectory(pData + offset(), this->size(), byteOrder)` 形成互递归。代码注释（第 187 行）表明开发者曾意识到"无限递归"问题，但仅通过 `enforce(offset_ >= start + 10)` 防止了循环引用；对于向前递进的深层线性嵌套没有设置任何深度上限。每一递归层消耗父缓冲区中至少 12 字节（子目录数据必须从 `start + 10` 之后开始），因此递归深度可达 O(N/12)。对于约 512 KB 的精心构造文件，深度约 43,000 层，约 4 个栈帧/层、每帧约 100 字节，将耗尽典型 8 MB 系统栈，触发栈溢出（SIGSEGV）。
- **触发条件**: 构造一个合法的 CRW 文件头（`II` + `HEAPCCDR` 签名），其中根目录含一个 `CiffDirectory` 类型的 entry（tag 高位为 0x2000 或 0x3000），该子目录再嵌套另一个 `CiffDirectory`，以此类推，形成不循环但极深的链式嵌套结构。每层子目录仅需在父缓冲区偏移 ≥ entry_start + 10 处放置 6~16 字节合法内容即可通过所有 enforce 检查。约 512 KB 的文件即可制造足以溢出默认栈的深度。
- **安全影响**: 必然 DoS（进程因 SIGSEGV 崩溃）。当 exiv2 作为服务端图像处理库使用（如 Web 服务上传处理场景）时，一个恶意文件即可崩溃服务进程，导致持续拒绝服务。在极少数没有栈 canary 或保护措施不足的环境下，栈溢出可能进一步被利用为代码执行原语（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
