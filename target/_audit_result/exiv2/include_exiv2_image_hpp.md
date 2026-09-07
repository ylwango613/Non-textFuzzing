Now I have enough context. Let me verify the recursion path one final time before writing the report:

**Group 1 findings (lines 326–527 of src/image.cpp):**
- `printIFDStructure` recurses at lines 462, 497, 502 with `depth + 1`, but never checks `depth` against `max_recursion_depth_` (which IS checked in `asfvideo.cpp:274`, `quicktimevideo.cpp:576`, `bmffimage.cpp:232`).
- `visits` global static set (line 324) only catches cycles (same file offset), not deep linear chains.
- CLI `-pR` is `#ifndef NDEBUG`-gated (exiv2.cpp:651–657), but the **library API** `image->printStructure(out, kpsRecursive)` has no NDEBUG guard in the library itself (`src/image.cpp`).
- Confirmed: no depth limit check anywhere in `printIFDStructure` or `printTiffStructure`.

**Group 2 findings (other paths):**
- `readMetadata()` TIFF path (`tiffvisitor_int.cpp:1066-1138`) correctly uses `circularReference()` + bounded entry count (n≤256) + `size_` bounds checks. No exploitable OOB.
- `appendIccProfile` uses `Safe::add` overflow protection + correctly sized `memcpy`. Safe.
- `byteSwap2/4/8` all call `DataBuf::read_uint8` which throws on OOB. Safe.
- JPEG segment parsing bounds all validated through `readSegmentSize` + `size >= 2` enforce. Safe.
- `count=0` string-type IFD entry causes unhandled `std::out_of_range` exception from `makeSlice(buf,0,0)` → process abort via DoS, but not heap/stack corruption.

## VULN: Unbounded Recursion Stack Overflow in printIFDStructure via Crafted SubIFD Chain
- **漏洞类别**: memory-safety
- **函数**: `Image::printIFDStructure()`
- **行号**: 326-527 (src/image.cpp)；声明于 include/exiv2/image.hpp:339
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF/JPEG image file
- **外部触发路径**: crafted_file → libexiv2 consumer calls `image->printStructure(out, kpsRecursive)` → `TiffImage::printStructure()` (tiffimage.cpp:278) → `Image::printTiffStructure()` (image.cpp:541) → `Image::printIFDStructure(depth=1)` (image.cpp:462) → recursive `printIFDStructure(depth+1)` for each SubIFD/ExifIFD/tiffIfd-typed entry (lines 459-463) → unbounded stack growth → stack overflow / SIGSEGV
- **描述**: `printIFDStructure`（image.cpp:326）在处理 `kpsRecursive` 选项时，对每个 tag==0x8769（ExifTag）、tag==0x014a（SubIFDs）或 type==tiffIfd 的 IFD 条目（line 458），以 `depth+1` 进行递归调用（line 462）。函数内部没有任何针对 `depth` 的上限检测，尽管 `Image` 类中存在 `max_recursion_depth_` 成员变量（image.hpp:511），其余同类递归函数（asfvideo.cpp:274，quicktimevideo.cpp:576，bmffimage.cpp:232）均有对应的 `enforce(depth <= max_recursion_depth_)` 检查，而此函数缺失该检查。循环检测机制（`visits` set，line 354）仅防止同一文件偏移量的再次访问，无法阻止具有唯一偏移量的深链式 IFD。CLI 的 `-pR` 入口虽通过 `#ifndef NDEBUG` 限制（app/exiv2.cpp:651），但库 API `image->printStructure(out, kpsRecursive)` 在发布版本中完全暴露，无任何编译期保护。攻击者可构造一个在 ExifIFD 下包含深链式 SubIFD（每个指向下一层）的 TIFF 文件：深度约 1万层（仅需约 180 KB 文件）即可耗尽典型 8 MB 线程栈导致 SIGSEGV。
- **触发条件**: 构造一个 TIFF 文件，其 IFD0 包含 ExifTag（0x8769）或 SubIFDs（0x014a），且该 ExifIFD/SubIFD 内部再递归嵌套同类标签，形成深度约 ≥10000 层的线性链。每层使用唯一文件偏移量以绕过 `visits` 集合的环检测；提供给任何内部调用 `image->printStructure(stream, kpsRecursive)` 的应用程序（如 GUI 查看器、元数据调试工具或通过 CI 使用 libexiv2 的图像管道）即可触发。
- **安全影响**: 任何嵌入 libexiv2 并以 `kpsRecursive` 选项调用 `printStructure` 的应用程序在处理攻击者提供的图像文件时将因栈溢出崩溃（Denial of Service）。在没有栈保护（stack canaries/ASLR）的环境下，深度栈溢出可能覆盖相邻内存区域，存在潜在的代码执行可能性（Remote/Local Code Execution），但在现代系统上最坏情况为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
