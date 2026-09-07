Now I have all the context needed. Let me do the final analysis.

**Group 1 — `AP4_ObjectDescriptor` constructor (lines 68-104):**

- Line 79: reads 2-byte `bits` → consumes 2 bytes from `start`
- Lines 85-88 (UrlFlag path): reads 1 byte `url_length` + `url_length` bytes → total consumed = `3 + url_length`
- Line 95-96: computes `payload_size - AP4_Size(offset-start)` — both are `AP4_UI32`; if attacker sets `payload_size = 2` with `url_length = 200`, the subtraction is `2 - 203 = 0xFFFFFF35` (unsigned wraparound → huge SubStream size)
- The SubStream with `m_Size ≈ 4 GB` wraps the raw file stream; `AP4_SubStream::ReadPartial` clamps only to `m_Size` (huge), not to the actual descriptor payload — the loop then reads arbitrary bytes from the file far beyond the descriptor boundary

**Group 2 — `AP4_InitialObjectDescriptor` constructor (lines 215-263):**

- Same code structure; non-URL path reads 5 extra profile-level bytes → consumed = 7 bytes minimum
- Same subtraction at lines 254-255 — underflows when `payload_size < 7` (or when UrlFlag + url_length causes similar overrun)

**Stack buffer check (lines 86-88 / 239-241):**

`char url[256]`; `url_length` is `unsigned char` (0–255); `url[url_length] = '\0'` writes at most to index 255, which is within the 256-element array. **No overflow here.**

---

## VULN: Integer Underflow in AP4_ObjectDescriptor substream size → Out-of-Bounds Read
- **漏洞类别**: memory-safety
- **函数**: AP4_ObjectDescriptor::AP4_ObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)
- **行号**: 74-103
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File() → AP4_AtomFactory → AP4_EsdsAtom::AP4_EsdsAtom() → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_ObjectDescriptor::AP4_ObjectDescriptor(stream, tag, header_size, payload_size) → unsigned subtraction wraps → AP4_SubStream(stream, offset, 0xFFFFFF...) → recursive CreateDescriptorFromStream loop reads OOB
- **描述**: 在 `AP4_ObjectDescriptor` 流构造函数（Ap4ObjectDescriptor.cpp:74-103）中，`start` 记录进入构造函数时的流位置，之后从流读取 2 字节 bits 字段，若 `m_UrlFlag == true` 则再读取 1 字节 `url_length` 加上 `url_length` 字节的 URL 数据，共消耗 `3 + url_length` 字节。随后第 95–96 行计算 `payload_size - AP4_Size(offset - start)`，两侧均为 `AP4_UI32`（无符号 32 位），当攻击者将描述符头部的 `payload_size` 设为小于实际消耗字节数的值时（例如 `payload_size=2`，`url_length=200`，则 `2 - 203 = 0xFFFFFF35`），发生无符号整数下溢，结果作为 `AP4_LargeSize` 传入 `AP4_SubStream` 构造函数，使得该 SubStream 的 `m_Size` 约为 4 GB。`AP4_SubStream::ReadPartial` 仅对 `m_Size` 做边界截断，不对实际描述符载荷做限制，因此其上运行的 `CreateDescriptorFromStream` 循环可从底层文件流读取远超合法描述符载荷边界的字节，并将攻击者精心布置的任意文件内容解析为嵌套描述符结构。
- **触发条件**: 构造一个 MP4 文件，在 `esds` atom 中嵌入 tag=0x01（ObjectDescriptor），将 MPEG-4 展开长度编码的 `payload_size` 设为 2（如仅 `\x01\x02`），同时将 bits 字段的 UrlFlag 位（bit 5）置 1，并将 `url_length` 字节设为 200，从而令实际消耗字节数 203 超过 `payload_size` 2，触发 `0xFFFFFF35` 的下溢值。
- **安全影响**: 攻击者可读取 esds atom 载荷之外的任意 MP4 文件数据，造成信息泄露（C:H）；OOB 字节被当作描述符解析，若后续子描述符的 `payload_size` 字段为极大值，`AP4_UnknownDescriptor` 将以该值调用 `m_Data.SetDataSize()` 并 `stream.Read()`，可导致进程崩溃或内存耗尽（A:H）；在适当条件下可进一步链式触发其他描述符解析函数中的内存破坏漏洞，最坏情况可能达到 RCE。

## VULN: Integer Underflow in AP4_InitialObjectDescriptor substream size → Out-of-Bounds Read
- **漏洞类别**: memory-safety
- **函数**: AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)
- **行号**: 226-263
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_EsdsAtom::AP4_EsdsAtom() → AP4_DescriptorFactory::CreateDescriptorFromStream() [tag=0x02/0x10] → AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor(stream, tag, header_size, payload_size) → unsigned subtraction wraps → AP4_SubStream 尺寸约 4 GB → recursive CreateDescriptorFromStream loop 越界读文件
- **描述**: `AP4_InitialObjectDescriptor` 流构造函数（Ap4ObjectDescriptor.cpp:226-263）与 `AP4_ObjectDescriptor` 同根同源：记录 `start`，读取 2 字节 bits；若 `m_UrlFlag == false`（非 URL 路径），还额外读取 5 字节轮廓级别指示字段，共消耗 7 字节；若 `m_UrlFlag == true`，消耗 `3 + url_length` 字节。第 254–255 行同样执行 `payload_size - AP4_Size(offset - start)` 的 `AP4_UI32` 无符号减法，当 `payload_size` 小于实际消耗字节数时（非 URL 路径只需 `payload_size < 7` 即可触发，例如 `payload_size=2`），下溢结果约为 `0xFFFFFFF9`，同样被传入 `AP4_SubStream` 成为其 `m_Size`，后续嵌套描述符循环越界读取底层文件流。
- **触发条件**: 在 `esds` atom 内嵌入 tag=0x02（IOD）或 0x10（MP4_IOD）的描述符，将展开编码的 `payload_size` 设为 6（小于非 URL 路径所需的 7 字节），同时 bits 字段令 `m_UrlFlag=false`、`m_IncludeInlineProfileLevelFlag` 任意，使构造函数消耗 7 字节而 `payload_size` 仅为 6，`6 - 7 = 0xFFFFFFFF` 下溢。
- **安全影响**: 与 AP4_ObjectDescriptor 变体相同：越界读文件数据（C:H）、将 OOB 字节作为描述符解析可导致崩溃（A:H）；若嵌套子描述符 payload_size 极大则 `AP4_UnknownDescriptor` 在巨型 heap 分配后对可能无效的指针执行 `stream.Read()`，最坏情况下可链式达到 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
