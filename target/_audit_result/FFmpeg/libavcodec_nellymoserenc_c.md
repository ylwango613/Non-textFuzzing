Analysis complete. The key facts:

- `opt` and `path` are `float(*)[OPT_SIZE]` / `uint8_t(*)[OPT_SIZE]` allocated as `NELLY_BANDS * OPT_SIZE` elements — valid indices per row: `[0, OPT_SIZE-1]`.
- `idx_max = FFMIN(OPT_SIZE, cand[band-1] + q)` → can equal **OPT_SIZE = 35768** when audio produces large `cand` values.
- Break condition at line 268: `if (idx > idx_max) break;` uses strict `>`, so when `idx == idx_max == OPT_SIZE`, the break does NOT fire.
- With `i = 35431` and `ff_nelly_delta_table[18] = 337`: `idx = 35768 = OPT_SIZE` → `opt[band][35768]` and `path[band][35768]` are written — both one element past the end of each row.
- At `band = NELLY_BANDS-1 = 22`: this is one element past the entire `opt` / `path` heap allocation.
- Trigger requires `-trellis 1` (runtime option, compiled in by default) and crafted float audio samples (~10^6) embedded in a WAV/PCM_F32LE file.

## VULN: get_exponent_dynamic off-by-one heap OOB write via crafted float audio
- **漏洞类别**: memory-safety
- **函数**: get_exponent_dynamic()
- **行号**: 260-278
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (WAV/PCM_F32LE with extreme float sample values)
- **外部触发路径**: ffmpeg -i malicious.wav -c:a nellymoser -trellis 1 output.flv -> avcodec_send_frame() -> encode_frame() -> encode_block() -> get_exponent_dynamic() -> heap OOB write at opt[band][OPT_SIZE] / path[band][OPT_SIZE]
- **描述**: `opt` and `path` are heap-allocated 2-D arrays with `NELLY_BANDS * OPT_SIZE` (23 × 35768) elements each, where valid per-row indices are `[0, OPT_SIZE-1]`. Inside `get_exponent_dynamic`, `idx_max` is set to `FFMIN(OPT_SIZE, cand[band-1] + q)`, which equals `OPT_SIZE = 35768` when the MDCT-derived float candidate value is large enough. The loop break condition `if (idx > idx_max) break` uses strict `>` instead of `>=`, so when `idx == idx_max == 35768`, the break is skipped and the code writes to `opt[band][35768]` and `path[band][35768]`—both one element past the end of their respective rows. When `band == NELLY_BANDS - 1 == 22`, this lands one element past the entire heap allocation, corrupting adjacent heap memory.
- **触发条件**: 攻击者构造一个包含 PCM_F32LE 格式浮点采样的 WAV 文件，采样值约达 1×10^6 量级（合法的 IEEE 754 float 表示），使 MDCT 系数 `coeff_sum` 超过 5×10^12，进而令 `cand[band] >= OPT_SIZE - 1000 ≈ 34768`，使 `idx_max` 被钳制为 `OPT_SIZE`。用户以 `-trellis 1` 选项将该文件编码为 Nellymoser（trellis 为运行时选项，代码默认编译进二进制）。
- **安全影响**: 堆越界写入 1 个 `float`（4 字节）或 1 个 `uint8_t` 超出 heap chunk 末尾，破坏相邻堆元数据或其他分配对象，最坏情况下可被利用实现远程代码执行（RCE）；至少可导致可靠的进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
