**Analysis complete.** Here is the finding:

**Line 55**: `AP4_Size data_size = size - 8;`

`AP4_Size` is `typedef AP4_UI32`. `size` is an `AP4_UI32` parameter passed from the factory as `size_32`. When a tref-subtype atom (hint/cdsc/sync/mpod/dpnd/ipir/alis/chap) is crafted with the `size` field set to `0` in the MP4 file, the outer factory recalculates the 64-bit `size` to `stream_size - start` but passes the original `size_32 = 0` to the `AP4_TrefTypeAtom` constructor. Inside the constructor, `0 - 8` on an unsigned 32-bit type wraps to `0xFFFFFFF8`. The loop then runs ~1 billion iterations calling `stream.ReadUI32()` (return value ignored) and `m_TrackIds.Append()` (return value ignored), exhausting heap memory and causing OOM/crash.

---

## VULN: Integer Underflow in AP4_TrefTypeAtom Constructor → OOM DoS
- **漏洞类别**: memory-safety
- **函数**: AP4_TrefTypeAtom::AP4_TrefTypeAtom(AP4_Atom::Type, AP4_UI32, AP4_ByteStream&)
- **行号**: 55-63
- **CWE**: CWE-191 (Integer Underflow / Wrap-around)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac(main) → AP4_File::AP4_File → AP4_AtomFactory::CreateAtomFromStream(stream, bytes_available, atom) [Ap4AtomFactory.cpp:139] → CreateAtomFromStream(stream, type, size_32=0, size_64, atom) [Ap4AtomFactory.cpp:221] → AP4_TrefTypeAtom::Create(type, size_32=0, stream) [Ap4AtomFactory.cpp:739] → AP4_TrefTypeAtom::AP4_TrefTypeAtom(type, 0, stream) [Ap4TrefTypeAtom.cpp:50]
- **描述**: `size` 参数类型为 `AP4_UI32`（unsigned 32-bit），当其值为 0 时，第 55 行 `AP4_Size data_size = size - 8` 产生无符号整数下溢，`data_size` 变为 `0xFFFFFFF8`（约 4GB）。第 58 行 `while (data_size >= 4)` 循环条件成立，循环将执行约 10 亿次（`0xFFFFFFF8 / 4 ≈ 1.07×10⁹`），每次调用 `m_TrackIds.Append(track_id)` 不断向堆分配内存，最终导致进程 OOM 崩溃。循环内 `stream.ReadUI32` 和 `m_TrackIds.Append` 的返回值均未被检查，错误无法中断循环。
- **触发条件**: 构造一个 MP4 文件，其中 `tref` 容器 box 内含一个 `hint`/`cdsc`/`sync`/`mpod`/`dpnd`/`ipir`/`alis`/`chap` 类型的子 box，将该子 box 的 4 字节 size 字段设置为 `0x00000000`（表示"延伸至文件尾"）。Bento4 工厂将 `size_32=0` 传入 `AP4_TrefTypeAtom` 构造函数，触发下溢。
- **安全影响**: 进程因 OOM 崩溃（DoS）；在将 mp42aac/Bento4 嵌入服务端批量处理管线的场景下，单个恶意 MP4 文件即可使服务不可用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
