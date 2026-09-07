Based on my thorough analysis of `types.hpp`, `types.cpp`, `tiffvisitor_int.cpp`, `tiffcomposite_int.cpp`, `crwimage_int.cpp`, `crwimage.cpp`, `jpgimage.cpp`, `pngimage.cpp`, `webpimage.cpp`, `bmffimage.cpp`, `iptc.cpp`, `photoshop.cpp`, `value.cpp`, and related headers, I have confirmed one real memory safety vulnerability:

**Summary of analysis:**
- `DataBuf` methods (`read_uint8/16/32/64`, `write_*`, `c_data`, `cmpBytes`) all throw `std::out_of_range` — no OOB via DataBuf API
- TIFF IFD parser has integer overflow check (`count > SIZE_MAX / typeSize`), circular reference detection (`dirList_`), and data bounds checks — no TIFF IFD OOB
- IPTC parser bounds-checks `sizeData <= pEnd - pRead` before reading — safe
- Photoshop IRB parser has `dataSize > (sizePsData - position)` check — safe
- WEBP/ASF/QuickTime all have explicit recursion depth limits — safe
- CRW (CIFF) format: `CiffDirectory::readDirectory()` and `CiffDirectory::doRead()` call each other recursively **with no depth counter or recursion limit**

## VULN: CRW CIFF Directory Parsing Uncontrolled Recursion Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: CiffDirectory::readDirectory() / CiffDirectory::doRead()
- **行号**: 212-224 / 226-252 (crwimage_int.cpp)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted CRW image file
- **外部触发路径**: exiv2 pr <crafted.crw> -> CrwImage::readMetadata() -> CrwParser::decode() -> CiffHeader::read() -> CiffDirectory::readDirectory() -> [for each CiffDirectory child] m->read() -> CiffDirectory::doRead() -> CiffDirectory::readDirectory() [unbounded recursion]
- **描述**: `CiffDirectory::doRead()` (crwimage_int.cpp:212) calls `CiffComponent::doRead()` to parse the entry header, then calls `CiffDirectory::readDirectory()` (crwimage_int.cpp:220) on the sub-data region. Inside `readDirectory()`, each child entry of type directory creates a new `CiffDirectory` object and calls `m->read()` (line 248), which dispatches via vtable to `CiffDirectory::doRead()`, repeating the cycle. There is no depth counter, no maximum recursion limit, and no `visited` set. The only bound is that each child's data (`size_`) must be a proper sub-region of the parent (`size_ <= size - offset_`, enforced at lines 192-197 and 217-218), so depth is bounded only by `filesize / ~22 bytes`. For a 1 MB crafted file this yields ~45,000 recursive stack frames, exhausting the ~8 MB default thread stack.
- **触发条件**: 攻击者构造一个 CRW 文件，其 CIFF 目录结构深度嵌套：每一层目录包含恰好一个子目录（类型标志为 `directory`），子目录数据区是父目录数据区的严格子集（满足 `offset_ >= start+10` 且 `size_ <= size-offset_` 的检查），且最小化每层消耗的字节数（约 22 字节/层）。1 MB 的畸形文件即可产生约 45,000 层递归。
- **安全影响**: 栈溢出导致进程崩溃（SIGSEGV）。在极端情况下，若攻击者可控制栈上布局，有可能转化为 RCE。任何将 exiv2 用作库的应用程序（如 GNOME/KDE 文件管理器、digiKam、libgexiv2 绑定的程序）均会受到影响：通过向用户发送一张精心构造的 CRW 图像文件，可触发远程 DoS，无需任何认证。

<!-- AUDIT_PROMPT_VERSION: 1 -->
