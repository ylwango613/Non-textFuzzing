Based on my thorough analysis of `exif.hpp`, `exif.cpp`, `tiffvisitor_int.cpp`, `tiffcomposite_int.cpp`, `tiffimage_int.cpp`, `iptc.cpp`, `jpgimage.cpp`, `bmffimage.cpp`, `preview.cpp`, `value.cpp`, and `types.cpp`, I now have enough information for the final report.

## VULN: Unbounded Recursion via IFD Next-Pointer Chain Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: TiffDirectory::doAccept()
- **行号**: 664-667 (tiffcomposite_int.cpp)
- **CWE**: CWE-674 (Uncontrolled Recursion) / CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF image file
- **外部触发路径**: exiv2 pr <crafted.tif> → TiffImage::readMetadata() → TiffParser::decode() → TiffParserWorker::decode() → TiffParserWorker::parse() → rootDir->accept(TiffReader) → TiffDirectory::doAccept() → [recursive via pNext_->accept()] → stack overflow
- **描述**: `TiffDirectory::doAccept()`（tiffcomposite_int.cpp:664）在访问完当前 IFD 的所有子条目后，通过 `pNext_->accept(visitor)` 递归调用自身来处理下一个 IFD。`pNext_` 由 `TiffReader::visitDirectory()`（tiffvisitor_int.cpp:1117-1134）在读取 4 字节 "next IFD offset" 字段时设置，唯一的防护措施是 `circularReference()` 检查——它仅阻止对**同一字节地址**的重复访问，而不限制链的深度。`TiffDecoder::max_recursion_depth_` 参数仅传递给 XMP 解析器（`decodeXmp` 内部调用 `XmpParser::decode`），**从未用于约束 IFD 遍历深度**。攻击者可构造一个含 N 个不同偏移量（每个 IFD 仅含 count=0 和 next_offset 共 6 字节）的 IFD 链，导致 N 层 `TiffDirectory::doAccept` 递归调用，最终耗尽线程栈内存（默认 8 MB），写穿栈底，产生堆栈损坏。
- **触发条件**: 构造一个合法的 TIFF 文件（或嵌入 JPEG APP1 段的 TIFF 块），其中 IFD0 的 "next IFD" 字段指向另一个 IFD（地址不同于 IFD0），该 IFD 再次指向下一个，如此形成深链。每个空 IFD 仅需 6 字节（`uint16_t count=0` + `uint32_t next_offset`）。一个约 250 KB 的 TIFF 文件（~41,000 个空 IFD 链）即可在 8 MB 栈上触发溢出。对 TIFF 格式无文件大小限制，可构造更大文件。
- **安全影响**: 最坏情况下：（1）DoS——栈指针穿越保护页引发 SIGSEGV，程序崩溃；（2）在无栈金丝雀或旧版编译器环境下，有限的帧内容控制可能导致返回地址被覆盖从而实现远程代码执行（RCE）。任何使用 libexiv2 解析用户提供图像的应用均受影响。

<!-- AUDIT_PROMPT_VERSION: 1 -->
