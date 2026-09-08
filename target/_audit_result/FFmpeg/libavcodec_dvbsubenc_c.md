Now I have the complete picture. Let me perform the final analysis before writing the report.

**Detailed analysis of `dvb_encode_rle8` (lines 214–274):**

The check at line 225:
```c
if (buf_size * 8 < w * 12 + 24)
    return AVERROR_BUFFER_TOO_SMALL;
```

The comment says *"3 bytes overhead"* = 24 bits. But the actual per-line overhead is:
- **1 byte** header: `*q++ = 0x12` (line 228)
- **3 bytes** footer: `*q++ = 0x00; *q++ = 0x00; *q++ = 0xf0` (lines 265–267)
- **Total: 4 bytes = 32 bits**

The check is off by 1 byte (24 bits instead of 32 bits). For the worst-case pixel pattern (alternating zero / nonzero pixels, which produces exactly 12 bits per pixel), with `w=2`:
- Check passes at `buf_size = 6` (since `6*8=48 >= 2*12+24=48`)
- Actual bytes written: 1 (header) + 2 (zero pixel: `0x00`,`0x01`) + 1 (nonzero pixel: `color`) + 3 (footer) = **7 bytes**
- This writes 1 byte (`0xf0`) past the end of the buffer → **1-byte heap buffer overflow**

For `dvb_encode_rle2` (check: `w*3+32`) and `dvb_encode_rle4` (check: `w*6+32`) I traced all overhead paths — those correctly use 32 bits for the overhead constant and match the actual 4-byte per-line overhead (header + conditional flush + footer).

Only `dvb_encode_rle8` has this discrepancy.

## VULN: dvb_encode_rle8 Off-by-One Heap Buffer Overflow (1 byte past output buffer)
- **漏洞类别**: memory-safety
- **函数**: dvb_encode_rle8()
- **行号**: 225-269
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file with subtitle stream
- **外部触发路径**: `ffmpeg -i <crafted_input> -c:s dvbsub output.ts` → `avcodec_encode_subtitle()` → `dvbsub_encode()` (dvbsubenc.c:276) → `dvb_encode_rle8()` (dvbsubenc.c:214) → 1-byte write past heap buffer at line 267
- **描述**: `dvb_encode_rle8()` 的缓冲区充裕性检查（第 225 行）使用常量 24 位（3 字节）作为每行固定开销，但实际开销为 32 位（4 字节）：1 字节行标头（`*q++ = 0x12`，第 228 行）加 3 字节行尾（`0x00 0x00 0xf0`，第 265–267 行）。当 `w=2`、像素图案为交替零/非零时（最坏情况为 12 bits/pixel），检查在 `buf_size=6` 时通过（`6*8=48 >= 2*12+24=48`），但实际写入 7 字节：1+2+1+3=7，导致第 267 行的 `*q++ = 0xf0` 将固定字节 `0xf0` 写入堆输出缓冲区末尾之后 1 字节处，造成堆缓冲区溢出。
- **触发条件**: 攻击者需构造包含 subtitle 流的输入文件（MKV/TS/MP4 等），使得 subtitle rect 的像素宽度为 2（或更小的偶数），像素数据为交替 0/非零图案，并以 `ffmpeg -i <file> -c:s dvbsub output.ts` 触发 dvbsub 字幕重编码路径。当 `dvbsub_encode` 传入的剩余 `buf_size` 恰好等于检查允许的最小值时，越界写入发生。
- **安全影响**: 向 `outbuf` 堆缓冲区末尾之后 1 字节写入固定值 `0xf0`，可能破坏相邻堆元数据或对象字段。结合堆布局控制，最坏情况下可导致远程代码执行（RCE）；若堆布局不可控，则导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
