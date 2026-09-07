Now I have enough context. Let me do a final analysis pass before writing the report.

**Analysis of `Ap4Dec3Atom.cpp`:**

**Group 1 — `Create()` (lines 45-57):**
- `payload_size = size - AP4_ATOM_HEADER_SIZE`. The factory guard at line 215 of AtomFactory.cpp confirms `size >= 8`, so no underflow here.

**Group 2 — Constructor (lines 62-106):**
- `substream_count = 1 + (payload[1] & 7)` → 1–8, bounded. Safe.
- Line 80: guard `if (payload_size < 3)` ensures we proceed only with ≥ 3 bytes.
- Line 95: `payload[2]` → valid (payload_size ≥ 3).
- Line 96-98: **`if (m_SubStreams[i].num_dep_sub)` then `payload[3]`** is read — but the only guard was `payload_size >= 3`, NOT `>= 4`. When `payload_size == 3`, `payload[3]` is 1 byte past the allocated buffer → **heap over-read**.
- Line 99: `payload_size -= 4` when `payload_size == 3` → unsigned wrap to `0xFFFFFFFC`. In subsequent iterations `payload_size < 3` evaluates `0xFFFFFFFC < 3` → **false**, so the guard is bypassed and subsequent iterations read arbitrarily far past the buffer. With `substream_count = 8`, up to 8 iterations each reading 3-4 more bytes OOB.

**Trigger conditions:**
- `dec3` box with `size = 13` (payload_size = 5): after skipping 2 DataRate bytes, `payload_size = 3` exactly
- Byte `payload[2]` (offset 4 in box payload) has bits 4:1 non-zero → `num_dep_sub != 0`
- Byte `payload[1]` bits 2:0 = 7 → `substream_count = 8` → 7 additional OOB iterations

**Confirmed**: externally-triggerable heap over-read in AP4_Dec3Atom constructor.

## VULN: Heap Over-Read via Missing Bounds Check in AP4_Dec3Atom Constructor
- **漏洞类别**: memory-safety
- **函数**: AP4_Dec3Atom::AP4_Dec3Atom()
- **行号**: 96-104
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Dec3Atom::Create(size_32, stream) → new AP4_Dec3Atom(size, payload) → constructor loop accesses payload[3] with only payload_size >= 3 verified
- **描述**: 在 `AP4_Dec3Atom::AP4_Dec3Atom`（Ap4Dec3Atom.cpp 第 80 行）中，循环进入条件仅检查 `payload_size < 3`，但第 96–98 行在 `num_dep_sub != 0` 时访问 `payload[3]`，未验证 `payload_size >= 4`。当 box size 为 13（令 payload_size = 5，减去 DataRate 的 2 字节后恰好剩余 3 字节）且 `num_dep_sub` 非零时，`payload[3]` 越过堆缓冲区末尾 1 字节进行读取。更严重的是，随后 `payload_size -= 4`（unsigned 类型减 4 却只有 3）导致 `payload_size` 绕回至 `0xFFFFFFFC`，使后续迭代中的 `< 3` 保护完全失效，最多再触发 `substream_count - 1`（最大 7）次 OOB 读取，每次读 3–4 字节，总计可越界读取 30+ 字节堆数据。
- **触发条件**: 构造一个 dec3 box：4 字节 size 字段设为 0x0000000D（13），4 字节 type 为 `dec3`；payload[0] 任意；payload[1] 低 3 位设为 0x07（substream_count=8）；payload[2]（第 5 字节）的 bits[4:1] 设为非零（令 num_dep_sub ≠ 0）；payload[3] 是越界字节（攻击者无需控制其值，读取即触发）。该 dec3 box 需嵌套在 EC-3 或 enca 采样条目的 stsd box 中。
- **安全影响**: 堆越界读可泄露相邻堆块内容（堆指针、libc 地址等），可用于绕过 ASLR；在服务端 MP4 转码场景中可远程触发信息泄露；同时 payload_size 绕回后持续越界读可能访问不可读页导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
