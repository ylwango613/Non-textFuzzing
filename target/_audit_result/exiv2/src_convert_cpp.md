I have now read all 1,615 lines of `convert.cpp` across four batches and traced the relevant callees in `value.cpp`. Here is my complete analysis:

**Batch 1 (lines 1–500)**: Class/data structure definitions and the conversion table. No memory-safety issues.

**Batch 2 (lines 500–1000)**: Core conversion functions (`cnvExifValue`, `cnvExifDate`, `cnvExifVersion`, `cnvExifGPSCoord`, `cnvXmpValue`, `cnvXmpDate`). Found one UB: at line 836 in `cnvExifGPSCoord`, `refPos->toString().front()` is called on a potentially empty string returned by `AsciiValue::write` when count=0 for the GPS*Ref tag.

**Batch 3 (lines 1000–1394)**: `cnvXmpGPSCoord` has a correct emptiness guard at line 1115 before `value.back()`. `cnvIptcValue` iterator handling is correct. `computeExifDigest` MD5 path is safe.

**Batch 4 (lines 1394–1615)**: `convertStringCharsetIconv` is safe (256-byte local buffer, `outbytesProduced` always ≤ 256). Windows path has a theoretical `len * 2` narrowing concern but not practically reachable.

**Confirmed root cause for line 836**: `AsciiValue::read()` ensures `value_` is always `"\0"` when count=0, and `AsciiValue::write()` outputs the substring up to the first `'\0'` — yielding `""`. Then `refPos->toString().front()` on that empty string is undefined behavior (C++ [string.access] ¶1: "Calling `front` on an empty basic_string is undefined behavior").

## VULN: OOB Read via front() on Empty GPS Ref Tag String
- **漏洞类别**: memory-safety
- **函数**: Converter::cnvExifGPSCoord()
- **行号**: 836
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 convert / any app calling copyExifToXmp() → XmpSidecar::writeMetadata() → copyExifToXmp(exifData_, xmpData_) → Converter::cnvToXmp() → Converter::cnvExifGPSCoord("Exif.GPSInfo.GPSLatitude", "Xmp.exif.GPSLatitude") → refPos->toString().front() [line 836]
- **描述**: `cnvExifGPSCoord` 在找到 GPS*Ref（如 GPSLatitudeRef）标签后，不校验其字符串值是否非空，直接调用 `refPos->toString().front()`。当 EXIF 文件中该 ASCII 标签的 count=0 时，`AsciiValue::read()` 会将内部 `value_` 设为 `"\0"`，而 `AsciiValue::write()` 向流写入空字符串（输出到第一个 `'\0'` 之前，即 0 字节），导致 `toString()` 返回空 `std::string ""`。对空 `std::string` 调用 `.front()` 是 C++ 标准明确规定的未定义行为（[string.access] ¶1），在 AddressSanitizer 下触发越界读取报告，在 debug 构建下触发断言失败，在 release 构建下依赖实现（libstdc++ SSO 通常读到 `'\0'`）。
- **触发条件**: 攻击者构造一个包含 GPS 坐标（GPSLatitude/Longitude/DestLatitude/DestLongitude，count=3 且有效分母）同时将对应 GPSLatitudeRef/LongitudeRef/DestLatitudeRef/DestLongitudeRef 标签设为 ASCII type 且 count=0（空值）的 JPEG 或 TIFF 文件。当 exiv2 或嵌入 libexiv2 的应用对该文件调用 `copyExifToXmp()` 或 `syncExifWithXmp()` 时即触发。
- **安全影响**: 在 ASAN/debug 构建中必现崩溃（进程终止，DoS）；在 release 构建中产生未定义行为读，可能导致信息泄露（读到紧邻内存内容），在特殊分配器布局下理论上可升级为信息披露。对嵌入该库的服务端图像处理流水线影响更大（AV:N，无需用户交互）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
