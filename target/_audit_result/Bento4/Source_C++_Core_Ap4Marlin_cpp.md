I now have all the information needed. Let me compile the final security audit report.

**Analysis Summary:**

**Batch 1 (lines 1–600):**
- `AP4_MarlinIpmpParser::Parse` (lines 304–315): `sinf` and `schm` are not null-checked before use. `sinf->FindChild("schm")` returns NULL when the SINF atom has no "schm" child; the subsequent `AP4_DYNAMIC_CAST` produces NULL, and `schm->GetSchemeType()` on line 308 is a null-pointer dereference.

**Batch 2 (lines 600–1198):**
- `AP4_MkidAtom` constructor (line 1122): `entry_count * (16+4)` is `AP4_UI32 * int` evaluated as 32-bit unsigned → wraps for `entry_count ≥ 0x0CCCCCCE`, producing a tiny value. Guard `available < entry_count*20` is bypassed; `m_Entries.SetItemCount(entry_count)` triggers a massive (GB-scale) `::operator new` that throws uncaught `std::bad_alloc`. On 32-bit, if `count*sizeof(Entry)` itself wraps, an undersized buffer is allocated and the placement-new loop writes past it (heap buffer overflow).
- Line 1127: `4 + entry_size` overflows when `entry_size ≥ 0xFFFFFFFC` (wraps to ≤3), bypassing the `available < 4+entry_size` guard. Control then reaches line 1131: `content_id_size = entry_size - 16` becomes ≈ 4.3 GB; `new char[content_id_size]` → uncaught `std::bad_alloc` (64-bit) or undersized allocation (32-bit), after which `stream.Read(content_id, content_id_size)` writes far beyond the buffer.

**Confirmed by cross-reference:**
- `AP4_Size` = `AP4_UI32` (Ap4Types.h:51); `AP4_Cardinal` = `unsigned int` (Ap4Types.h:43).
- MKID atom IS registered in default factory (Ap4AtomFactory.cpp:707–711) — triggered when parent context is `AP4_ATOM_TYPE_MARL`, reachable via any crafted MP4 containing a `marl` box.
- The `schm` null-check is present at line 543 but absent at line 307–308 — asymmetric handling.

## VULN: AP4_MkidAtom integer overflow in entry_count bounds check → heap OOM / 32-bit heap overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_MkidAtom::AP4_MkidAtom()
- **行号**: 1119-1123
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File(stream) → AP4_DefaultAtomFactory::CreateAtomFromStream → case AP4_ATOM_TYPE_MKID → AP4_MkidAtom::Create → AP4_MkidAtom::AP4_MkidAtom(size, version, flags, stream)
- **描述**: 在 AP4_MkidAtom 构造函数中，`entry_count`（AP4_UI32）来自文件字段，第1122行执行 `if (available < entry_count*(16+4)) return;` 用作上界检查。由于 `entry_count * 20` 是无符号32位乘法，当 `entry_count ≥ 0x0CCCCCCE`（约2.1亿）时结果回绕为一个小数（例如 `0x0CCCCCCE * 20 = 4` mod 2^32），使得该检查形同虚设。随后 `m_Entries.SetItemCount(entry_count)` 调用 `EnsureCapacity(entry_count)` → `::operator new(entry_count * sizeof(Entry))`。在64位平台上，约6–8 GB 分配请求导致 `std::bad_alloc` 未被捕获而崩溃（DoS）；在32位平台上，若 `count * sizeof(Entry)` 再次溢出产生微小分配，随后 `SetItemCount` 内的 placement-new 循环越界写入堆（heap buffer overflow）。
- **触发条件**: 在 `marl` 父容器中构造一个 `mkid` box，令 box 数据中的 entry_count = 0x0CCCCCCD（或任何使 `entry_count * 20 mod 2^32 < available` 的值），同时 available 满足正常（box size 合理）条件。
- **安全影响**: 64位平台：未捕获 `std::bad_alloc` 导致进程崩溃（DoS）。32位平台：分配大小回绕为极小值后，heap buffer overflow 可能被利用实现 RCE。

## VULN: AP4_MkidAtom integer overflow in entry_size guard → heap OOM / 32-bit heap write overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_MkidAtom::AP4_MkidAtom()
- **行号**: 1125-1133
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File(stream) → AP4_DefaultAtomFactory::CreateAtomFromStream → case AP4_ATOM_TYPE_MKID → AP4_MkidAtom::Create → AP4_MkidAtom::AP4_MkidAtom(size, version, flags, stream)
- **描述**: 在同一构造函数的循环体内，第1126行从流中读取每条 entry 的 `entry_size`（AP4_UI32，完全受攻击者控制）。第1127行 `if (available < 4+entry_size) break;` 中，`4 + entry_size` 为无符号32位加法：当 `entry_size = 0xFFFFFFFC` 时，`4 + 0xFFFFFFFC = 0`（回绕），`available < 0` 恒为假，break 被跳过。随后第1128行 `if (entry_size < 16) continue;` 不会过滤（0xFFFFFFFC ≥ 16）；第1131行 `content_id_size = entry_size - 16 = 0xFFFFFFEC`（约4.3 GB）；第1132行 `new char[content_id_size]` 触发约4.3 GB 分配；第1133行 `stream.Read(content_id, content_id_size)` 以4.3 GB 大小写入该缓冲区。在64位上，分配请求抛出未捕获 `std::bad_alloc` 致崩溃；在32位上，如果 `content_id_size` 在 `new char[]` 内作为 `size_t`（32位）溢出为极小值，则分配极小缓冲后 `stream.Read` 写入 GB 级数据，造成严重堆溢出。
- **触发条件**: 构造合法大小的 `mkid` box，设 entry_count = 1，entry_size = 0xFFFFFFFF 或 0xFFFFFFFC（满足 entry_size ≥ 16 且 4+entry_size 溢出），content_id 字段填充任意字节。
- **安全影响**: 64位平台：进程崩溃（DoS）。32位平台：极小缓冲区后的 stream.Read 写越界，heap corruption，可能实现 RCE。

## VULN: NULL pointer dereference in AP4_MarlinIpmpParser::Parse on missing schm atom
- **漏洞类别**: memory-safety
- **函数**: AP4_MarlinIpmpParser::Parse()
- **行号**: 306-310
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: 使用 Marlin 解密流程的工具 → AP4_MarlinIpmpDecryptingProcessor::Initialize → AP4_MarlinIpmpParser::Parse → 内层 do-while 循环解析 IPMP descriptor 数据中的 SINF atom → 第307–308行
- **描述**: 第306行对 atom 做动态转型得到 `sinf`，第307行 `sinf->FindChild("schm")` 在 SINF 容器无 schm 子节点时返回 NULL，`AP4_DYNAMIC_CAST(AP4_SchmAtom, NULL)` 返回 NULL 赋给 `schm`；第308行 `schm->GetSchemeType()` 对 NULL 指针解引用，触发空指针访问。同文件第543行存在正确的 NULL 检查（`if (schm == NULL) return NULL;`），但第307–310行的同类调用缺少该保护，属于不一致的防御。
- **触发条件**: 构造一个具有 MGSV 品牌的 Marlin 格式 MP4 文件，其 IPMP 描述符数据中包含一个不含 `schm` 子节点的 `sinf` box（attacker 完全控制 IPMP descriptor 的字节内容）。
- **安全影响**: 进程崩溃（DoS）；在极少数情况下，NULL 解引用位于可映射地址的平台上可能被利用于更严重的内存破坏，但通常影响为拒绝服务。

<!-- AUDIT_PROMPT_VERSION: 1 -->
