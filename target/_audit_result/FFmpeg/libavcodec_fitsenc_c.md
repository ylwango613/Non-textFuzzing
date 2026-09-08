분석 완료. 핵심 취약점을 확인했습니다.

**분석 결과:**

`fitsenc.c:80`에서 `data_size` 계산이 모두 `int` 산술로 수행된 후 `uint64_t`에 대입됩니다. `(bitpix >> 3) * avctx->height * avctx->width * naxis3` 에서 모든 피연산자가 `int`이므로, 큰 width/height 값(예: 65537×65537)에서 signed integer overflow가 발생해 `data_size`가 실제보다 훨씬 작은 값(예: 131,073)으로 truncate됩니다. 이로 인해 `ff_get_encode_buffer`가 작은 패킷 버퍼를 할당하지만, 이후 루프(88-102행)는 `avctx->height/width`를 직접 사용해 수 GB의 실제 데이터를 쓰므로 힙 버퍼 오버플로우가 발생합니다.

예: width=65537, height=65537, GRAY8
- `1 * 65537 * 65537 = 4,295,098,369` → int32 overflow → `131,073`
- 할당 버퍼: `~132,480` bytes
- 실제 쓰기: `65537 × 65537 = 4.3 GB` → 거대한 힙 오버플로우

---

## VULN: FITS encoder integer overflow in data_size leads to heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: fits_encode_frame()
- **行号**: 80-102
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted FITS media file
- **外部触发路径**: `ffmpeg -i crafted.fits -c:v fits output.fits` → `avcodec_open2()` → `avcodec_send_frame()` → `fits_encode_frame()` → integer overflow at line 80 → `ff_get_encode_buffer()` underallocates → heap OOB write in pixel copy loop (lines 88-102)
- **描述**: 在 `fits_encode_frame()` 第 80 行，`data_size` 的计算表达式 `(bitpix >> 3) * avctx->height * avctx->width * naxis3` 中所有操作数均为 `int` 类型，整个乘法在 32 位有符号整数域完成后才赋值给 `uint64_t data_size`。当 `avctx->width` 和 `avctx->height` 较大时（如均为 65537，GRAY8 格式），`65537 * 65537 = 4,295,098,369` 发生 signed int32 溢出，截断为 `131,073`，导致 `padded_data_size` 约为 `132,480` 字节。随后 `ff_get_encode_buffer` 按此小值分配堆缓冲区，但第 88-102 行的像素拷贝循环直接使用 `avctx->height`、`avctx->width` 进行迭代，实际写入约 4.3 GB 数据，造成严重的堆溢出。
- **触发条件**: 攻击者构造一个包含超大图像尺寸（如 width=65537, height=65537）的 FITS 输入文件，通过转码流程（`ffmpeg -i evil.fits -c:v fits out.fits`）触发 FITS 编码器，使 `avctx->width * avctx->height` 乘积在 int32 范围内发生正向回绕（产生小正数），从而导致缓冲区欠分配与后续堆溢出。
- **安全影响**: 堆缓冲区溢出可覆盖相邻堆元数据和对象，在典型 Linux/glibc 堆布局下具备利用为任意代码执行（RCE）的潜力；最坏情况下可导致攻击者控制的代码在 FFmpeg 进程权限下运行。

<!-- AUDIT_PROMPT_VERSION: 1 -->
