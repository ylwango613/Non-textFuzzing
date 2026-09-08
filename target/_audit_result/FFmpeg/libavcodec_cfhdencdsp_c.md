分析完了。以下が最終報告です。

---

## VULN: filter() heap OOB read with len < 6 in CFHD encoder DSP
- **漏洞类别**: memory-safety
- **函数**: filter()
- **行号**: 31-46
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (source video fed to CFHD encoder)
- **外部触发路径**: `ffmpeg -i crafted_w16.yuv422p10 -c:v cfhd out.cfhd` → `cfhd_encode_frame()` (cfhdenc.c:534) → `dsp->horiz_filter(... width*2=4, ...)` → `horiz_filter()` (cfhdencdsp.c:54) → `filter(input, 1, low, 1, high, 1, len=4)` (cfhdencdsp.c:55)
- **描述**: `filter()` の先頭ブロック（line 32–34）は `len` の値に関係なく常に `input[4*in_stride]` および `input[5*in_stride]` を読み取る。さらに末尾ブロック（line 45–46）は `input[((len-2)-3)*in_stride]`（= `input[(len-5)*in_stride]`）および `input[((len-2)-4)*in_stride]`（= `input[(len-6)*in_stride]`）を読み取るため、`len < 6` のときに負インデックスによるヒープ領域外読み出しが発生する。エンコーダは `width & 15 == 0`（16 の倍数）のみを検証し、最小幅の下限は設けていない。`width=16`・YUV422P10（`chroma_h_shift=1`）の場合、最深 DWT レベルでのクロマプレーンは `band[0][0].width = (8/8)<<0 = 1` となり、`horiz_filter` が `width*2 = 2`（= `len=2`）で呼ばれる。ルマプレーンも `band[0][0].width = (16/8)<<0 = 2`、`len=4` で同様に OOB を引き起こす。`len=2` では先頭ブロックが割り当てサイズ外の `input[4]`, `input[5]` を読み取り、末尾ブロックは `input[-4]`（負インデックス）を読み取る。
- **触发条件**: 攻击者向 CFHD 转码管道提供一个宽度为 16（或 32，见下）像素、格式为 YUV422P10 的源视频文件（宽度是 16 的倍数，满足编码器唯一的宽度约束）。`ffmpeg -i crafted.mp4 -vf scale=16:32 -pix_fmt yuv422p10le -c:v cfhd output.cfhd` 可触发此路径。
- **安全影响**: 堆缓冲区越界读取（heap over-read），可读取堆相邻内存中的敏感数据（信息泄露），或在访问 glibc malloc 元数据/未映射页时引发 SIGSEGV（DoS）。在支持精确堆布局控制的攻击场景下，理论上可借助信息泄露绕过 ASLR，进一步辅助其他漏洞利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
