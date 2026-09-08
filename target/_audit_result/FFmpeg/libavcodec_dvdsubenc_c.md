Now I have enough context to make a definitive analysis. Let me confirm the key path:

- `av_image_check_size2` bounds via `stride*(h+128ULL) >= INT_MAX` — limits `w*h` to ≈267 million when called (line 303), preventing integer overflow there.
- But that call is **only** inside the `if (rects > 1)` block (line 286). For `rects == 1`, **no size check is performed**.
- Line 344: `vrect.w * vrect.h / 2 + 17 + 21` — signed `int × int` multiplication, can overflow when `w×h > INT_MAX`.
- Example: `w=46341, h=46342` → `w*h = 2,147,551,722` → signed wraps to `−2,147,415,574` → check becomes `4 + (−1,073,707,787) + 38 = −1,073,707,745 > outbuf_size` → **false → check passes incorrectly**.
- `dvd_encode_rle` then proceeds to write RLE-encoded output into `outbuf` far beyond its allocated size.

## VULN: Integer Overflow in Single-Rect Buffer Size Check Leads to Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: dvdsub_encode()
- **行号**: 344-353
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (subtitle stream with bitmap rectangle of crafted dimensions)
- **外部触发路径**: `ffmpeg -i malicious.mkv -c:s dvdsub out.vob` → `avcodec_encode_subtitle()` (encode.c:213) → `dvdsub_encode()` (dvdsubenc.c:253) → buffer size check at line 344 (integer overflow) → `dvd_encode_rle()` (dvdsubenc.c:349) writes past outbuf
- **描述**: 在 `dvdsub_encode()` 中，当输入字幕只包含单个矩形（`rects == 1`）时，代码直接使用 `vrect = *h->rects[0]`（第284行），跳过了 `av_image_check_size` 维度校验（该校验仅在 `rects > 1` 的分支即第303行执行）。第344行的输出缓冲区溢出保护检查为 `(q - outbuf) + vrect.w * vrect.h / 2 + 17 + 21 > outbuf_size`，其中 `vrect.w` 和 `vrect.h` 均为 `int`，当攻击者控制的字幕矩形尺寸满足 `w * h > INT_MAX`（如 `w=46341, h=46342`，乘积 2,147,551,722 溢出为负数 −2,147,415,574）时，保护检查表达式结果变为大负数，条件判断为 false，错误地放行。随后 `dvd_encode_rle()` 以实际的大尺寸（w、h）迭代位图，持续向 `outbuf` 末尾之外写入 RLE 编码数据，造成堆越界写入。
- **触发条件**: 攻击者构造含有位图字幕流的容器文件（如 MKV/MPEG-PS/VOB），其中单个字幕矩形的 `w` 和 `h` 值满足有符号乘积溢出（`w*h > INT_MAX`，例如 w≥46341 且 h≥46342）。字幕解码器（如 dvdsubdec、pgssub 等）需为该尺寸分配实际位图内存，并传递给 dvdsub 编码器。
- **安全影响**: 堆缓冲区越界写入，可覆盖相邻堆块元数据或函数指针。在最坏情况下可被利用为任意代码执行（RCE）；最低限度造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
