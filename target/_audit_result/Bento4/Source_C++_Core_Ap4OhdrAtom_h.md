Now I have all the context I need. Let me analyze the full picture:

**Group 1 — Constructor (lines 80–127 of .cpp)**

- Line 105: `new char[content_id_length]` — `AP4_UI16` max 65535; no overflow in allocation itself.
- Line 106: `stream.Read(buffer, content_id_length)` — reads exactly `content_id_length` bytes from stream; no heap overflow.
- Lines 111–114, 117–120: same pattern for the other two string fields.
- **Critical gap**: there is no check that `content_id_length + rights_issuer_url_length + textual_headers_length ≤ size − (FULL_ATOM_HEADER_SIZE + 16)` before reading. The only guard in `Create` is `size < AP4_FULL_ATOM_HEADER_SIZE` (12 bytes), which is far too loose — the fixed non-string fields alone require 16 more bytes (1+1+8+2+2+2).
- Lines 123–126: `bytes_used` check is post-hoc; strings are already consumed.

**Group 2 — `bytes_used` integer overflow check**

Max bytes_used = 12 + 16 + 3×65535 = 196633, well within `AP4_UI32`. No overflow.

**Group 3 — `InspectFields` null-terminator write (lines 162–186 of .cpp)**

`Reserve(1 + data_size)` then `SetData(data, data_size)`: since `SetData` doesn't shrink the buffer (only `m_DataSize` changes, `m_BufferSize` is unchanged), writing `[data_size] = '\0'` is within the reserved capacity. Safe.

**Conclusion on stream OOB read**: With atom `size` as small as 12 (the only guard), the constructor reads 1+1+8+2+2+2 = 16 bytes of fixed fields plus up to 3×65535 = 196605 bytes of string data from the stream, all without checking that those reads fall within `[stream_position, stream_position + size - FULL_ATOM_HEADER_SIZE)`. This is a textbook CWE-125 OOB read at the atom-boundary level: file fields drive byte counts that exceed the declared available region.

## VULN: OOB Read via Unchecked String Lengths in AP4_OhdrAtom Constructor
- **漏洞类别**: memory-safety
- **函数**: AP4_OhdrAtom::AP4_OhdrAtom() (private stream constructor)
- **行号**: 96-126
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_OhdrAtom::Create(size, stream, atom_factory) → AP4_OhdrAtom::AP4_OhdrAtom(size=12, version, flags, stream, atom_factory)
- **描述**: `Create()` 对 atom size 的唯一校验是 `size < AP4_FULL_ATOM_HEADER_SIZE`（即 size < 12），允许 size = 12 通过。私有构造函数随后从 stream 中读取 16 字节固定字段（1+1+8+2+2+2），再依次读取 `content_id_length`、`rights_issuer_url_length`、`textual_headers_length`（各为 `AP4_UI16`，最大 65535）个字节到堆缓冲区。在这些读取全部完成之后，才在第 123–126 行做 `bytes_used <= size` 的事后校验——此时 stream 已被消费。三个字符串的读取均未检查 `content_id_length + rights_issuer_url_length + textual_headers_length ≤ size − 28`，导致 stream 读取位置超出 ohdr atom 的声明边界最多 3×65535 ≈ 196 KB。
- **触发条件**: 构造一个 ohdr atom，令 atom size 字段 = 28（固定字段的最小合法值）或任意小值，同时将 content_id_length、rights_issuer_url_length、textual_headers_length 三个 UI16 字段均设为 0xFFFF（65535）。解析器会分配三块 65535 字节的堆缓冲区，并从 stream 各读取 65535 字节，实际消费的字节数远超 atom 的声明大小。
- **安全影响**: (1) OOB 流读取：跨 atom 边界读取约 196 KB 的相邻 atom 数据或文件尾部内容，导致后续所有 atom 的 stream 偏移损坏，引发解析状态混乱或崩溃（DoS）；(2) 信息泄露：若底层流基于内存缓冲区（如 `AP4_MemoryByteStream`），超出 atom 边界的读取会访问缓冲区内相邻数据，可能泄露敏感内存内容；(3) 可作为 exploit 原语配合其他漏洞使用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
