분석 완료. `validate_cc_data_pair`가 항상 `[+1]`과 `[+2]` 오프셋을 접근하고, `decode()` 루프 조건이 3바이트 잔여 여부를 미확인하는 점을 확인했습니다.

## VULN: Heap OOB Read in decode() When avpkt->size Is Not a Multiple of 3
- **漏洞类别**: memory-safety
- **函数**: decode()
- **行号**: 869-881
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (MPEG-TS, MP4) containing EIA-608 subtitle packet with non-multiple-of-3 byte size
- **外部触发路径**: `ffmpeg -i <crafted_file> -f null -` → `avformat_open_input()` → demuxer extracts subtitle AVPacket with `size % 3 != 0` → `avcodec_decode_subtitle2()` → `decode()` → `validate_cc_data_pair(bptr + i, &hi)` reads `bptr[i+1]` and `bptr[i+2]` beyond valid buffer → `bptr[i + 2]` read at line 881 further past end
- **描述**: `decode()` 的循环条件为 `i < len`（其中 `len = avpkt->size`），步长为 3，但未校验剩余字节是否 ≥ 3。当 `avpkt->size % 3 != 0`（如 size=2 或 size=4）时，最后一次迭代使 `i` 满足 `i < len` 却剩余不足 3 字节。`validate_cc_data_pair(bptr + i, &hi)` 无条件读取 `cc_data_pair[1]`（383行）和 `cc_data_pair[2]`（390、400行），而 `decode()` 第 881 行又直接读取 `bptr[i + 2]`，均超出缓冲区边界，形成堆越界读取。
- **触发条件**: 攻击者构造包含 EIA-608（AV_CODEC_ID_EIA_608）字幕数据的 MPEG-TS 或 MP4 文件，其中字幕 AVPacket 的字节长度不是 3 的倍数（例如 1、2、4、5 等），使解码器在最后一次循环迭代中读取分配缓冲区末端之后的内存。
- **安全影响**: 堆越界读取 1-2 字节；在无 AV_INPUT_BUFFER_PADDING_SIZE 保证的场景下（如自定义分流路径、subtitle 过滤器）可导致进程崩溃（DoS）或泄露堆内存内容（信息泄露，可辅助 ASLR 绕过）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
