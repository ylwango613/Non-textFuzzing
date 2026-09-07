I've now read the full implementation and traced all calling paths. Let me compile the complete analysis:

**`futils.cpp` analysis summary:**

**`urldecode`** (lines 129–147): The `sizeStr` snapshot + in-place write pattern is safe because `idxOut ≤ idxIn` always holds. The `str[idxIn+1]`/`str[idxIn+2]` accesses when `idxIn = sizeStr-1` are safe because C++11 guarantees `str[str.size()]` returns `\0`, and short-circuit `&&` prevents the `str[sizeStr+1]` access.

**`base64encode`** (lines 150–176): The `dataLength + 2` can theoretically overflow to 0 → `output_length = 0`, but requires allocating `~SIZE_MAX` bytes which is practically impossible.

**`base64decode`** (lines 178–218): **Found genuine issue** — `decoding_table[256]` is declared on the stack (line 185) but only 64 entries (those corresponding to valid base64 characters) are initialized. For any non-base64 character `c` in the input, `decoding_table[c]` (lines 199–202) reads an **uninitialized stack slot**, constituting UB (CWE-457). The corrupted sextets are folded into `triple` and the resulting garbage bytes are written to the output buffer and then into the temp file. This is directly reachable from `XPathIo::writeDataToFile()` (basicio.cpp:964) via a crafted `data://` URI with invalid base64 characters.

No heap-overflow, UAF, or stack-overflow from recursive parsing was found in this utility file.

## VULN: base64decode Uninitialized Stack Memory Read via Invalid Base64 Characters
- **漏洞类别**: memory-safety
- **函数**: base64decode()
- **行号**: 185-202
- **CWE**: CWE-457 (Use of Uninitialized Variable)
- **CVSS v3.1**: 3.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Low
- **攻击向量**: crafted data:// URI passed as image path argument
- **外部触发路径**: `exiv2 pr 'data://text/plain;base64,AAAA!!!!'` → `ImageFactory::open()` → `XPathIo::XPathIo()` → `XPathIo::writeDataToFile()` (basicio.cpp:964) → `base64decode(data.c_str(), decodeData.get(), data.length())` → reads `decoding_table[buff[i]]` where `decoding_table[256]` is uninitialized for non-base64 byte values
- **描述**: 在 `futils.cpp:185` 处，`unsigned char decoding_table[256]` 是一个栈上局部数组，仅有 64 个条目被初始化（循环 `for (unsigned char i = 0; i < 64; i++) decoding_table[encoding_table[i]] = i`，仅初始化与合法 base64 字符对应的槽位）。当输入字符串包含不在 base64 字母表中的字节 `c`（如 `!`、`@`、`#`、空格等）时，`decoding_table[c]`（第 199–202 行）读取未初始化的栈内存，产生未定义行为（UB）。该未初始化值被作为 6-bit sextet 融入 `triple`，并最终写入 `out` 缓冲区（通过 `& 0xFF` 提取字节），使攻击者可将进程栈内存内容导入临时解码文件中。
- **触发条件**: 攻击者提供一个 `data://text/plain;base64,XXXX` 形式的路径作为 exiv2 的输入，其中 base64 数据段长度为 4 的倍数，且包含不在 `[A-Za-z0-9+/=]` 中的字符（如 `AAAA!!!!`）。`input_length % 4 == 0` 的验证可通过，但非合法 base64 字符绕过了 `decoding_table` 的初始化范围，触发未初始化读取。
- **安全影响**: 进程栈内存（可能包含函数返回地址、栈 canary、局部变量数据、指针等）被写入攻击者可预测的临时文件中。在将 exiv2 嵌入 Web 服务等场景下，若解码后的临时文件内容可被观察（如通过错误消息、元数据输出等），则可能泄露 ASLR 布局信息，辅助后续利用链的构建。

<!-- AUDIT_PROMPT_VERSION: 1 -->
