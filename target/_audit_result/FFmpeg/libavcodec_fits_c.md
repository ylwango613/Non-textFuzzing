I have all the information needed from my full read of `fits.c`, `fits.h`, and both `fitsdec.c` files. Here is my complete analysis:

**Key facts confirmed:**

- `fits.h:50` — `int naxisn[999]` — valid indices are 0..998 (999 elements total).
- `fits.c:163-172` (`STATE_NAXIS`) — `naxis` is parsed with plain `sscanf(value, "%d", &header->naxis)` via the `CHECK_VALUE` macro; **no upper-bound check** exists before transitioning to `STATE_NAXIS_N`.
- `fits.c:181` (`STATE_NAXIS_N`) — writes `sscanf(value, "%d", &header->naxisn[header->naxis_index])` with `naxis_index` bounded only by the `naxis_index == naxis` equality check (line 188), never by `naxis_index < 999`. When `naxis >= 1000`, `naxis_index` reaches 999 and writes to `naxisn[999]` which is one past the last valid element.
- Both `libavformat/fitsdec.c:144` and `libavcodec/fitsdec.c:199` declare `FITSHeader header` as a local (stack) variable, so the OOB write targets stack memory.
- Post-hoc checks (`naxis != 2`, `naxis != 3`) occur **after** all header lines are parsed — the OOB writes are complete before any rejection.

## VULN: Stack OOB Write via Unchecked NAXIS Value in FITS Header Parser
- **漏洞类别**: memory-safety
- **函数**: avpriv_fits_header_parse_line() / STATE_NAXIS_N branch
- **行号**: 163-191 (fits.c); triggered via fits_read_packet() libavformat/fitsdec.c:144 and fits_decode_frame() libavcodec/fitsdec.c:199
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted FITS media file
- **外部触发路径**: `ffmpeg -i crafted.fits -f null -` → `avformat_open_input()` → `fits_read_packet()` (libavformat/fitsdec.c:153) → `is_image()` (libavformat/fitsdec.c:94) → `avpriv_fits_header_parse_line()` (fits.c:181); 同时 decode 路径: `fits_decode_frame()` (libavcodec/fitsdec.c:204) → `fits_read_header()` (libavcodec/fitsdec.c:118) → `avpriv_fits_header_parse_line()` (fits.c:181)
- **描述**: `fits.h` 中 `FITSHeader.naxisn` 声明为 `int naxisn[999]`（合法索引 0..998）。在 `avpriv_fits_header_parse_line()` 的 `STATE_NAXIS` 分支（fits.c:165），`naxis` 字段通过 `CHECK_VALUE` 宏直接用 `sscanf(value, "%d", &header->naxis)` 从文件中解析，**没有任何上界检查**（FITS 标准规定 NAXIS ≤ 999，但代码未强制执行）。随后在 `STATE_NAXIS_N` 分支（fits.c:181），写操作 `sscanf(value, "%d", &header->naxisn[header->naxis_index])` 仅当 `naxis_index == naxis` 时停止（fits.c:188），而对 `naxis_index < 999` 没有任何防护。当攻击者将 NAXIS 设置为 ≥ 1000 并提供相应数量的 `NAXISn` 关键字时，`naxis_index` 会到达 999 并写入 `naxisn[999]`（越界），继续提供更多关键字可继续覆盖后续栈内存（`pcount`、`gcount`、`groups`、`rgb` 等结构体字段，乃至返回地址）。写入的值由攻击者通过关键字 value 字段完全控制（受限于 `%d` 解析）。两条调用路径（demuxer 层 `libavformat/fitsdec.c:144` 和 decoder 层 `libavcodec/fitsdec.c:199`）均将 `FITSHeader` 分配在栈上，因此这是一个栈上越界写。
- **触发条件**: 攻击者构造一个畸形 FITS 文件，在主头（HDU0）中将 `NAXIS` 关键字设置为整数 ≥ 1000（如 1050），并随后提供 1050 个连续 `NAXIS1`、`NAXIS2`、…、`NAXIS1050` 关键字，每个关键字的值为攻击者期望写入的整数。FITS 头块大小为 2880 字节（36 行 × 80 字节），1050 个关键字约需 30 个块（~87 KB 头部），在实践中完全可行。
- **安全影响**: 最坏情况下，攻击者可将任意整数值写入栈上 `naxisn[999]` 以远的位置，覆盖相邻栈帧数据，包括可能的返回地址，导致**远程代码执行（RCE）**；在有栈保护（stack canary）的环境下至少可导致**崩溃（DoS）**。由于两条解析路径（demuxer 和 decoder）均受影响，任何将 FITS 文件传递给 FFmpeg 的场景均在攻击范围内。

<!-- AUDIT_PROMPT_VERSION: 1 -->
