## VULN: Heap Buffer Overflow via Integer Overflow in tilingPatternFill Overprint Mask Allocation

- **漏洞类别**: Heap Buffer Overflow（堆缓冲区溢出）
- **函数**: `SplashOutputDev::tilingPatternFill`
- **行号**: `SplashOutputDev.cc:2122–2124`
- **CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` → **7.5 High**
- **严重程度**: High
- **攻击向量**: 攻击者提供恶意 PDF 文件，由 pdftoppm 或 xpdf（CMYK 模式）处理时触发
- **外部触发路径**: 恶意 PDF → `Gfx::doTilingPatternFill` → `SplashOutputDev::tilingPatternFill` → 第 2122 行 `gmallocn` → 第 2124 行 `memset`
- **描述**:

  在 `#if SPLASH_CMYK` 分支（第 2117–2131 行）中，当 overprint preview 启用且色彩模式为 `splashModeCMYK8` 时，代码分配 overprint mask 位图：

  ```c
  overprintMaskBitmap =
      (Guint *)gmallocn(tileH, tileW * (int)sizeof(Guint));   // 行 2122-2123
  memset(overprintMaskBitmap, 0, tileH * tileW * sizeof(Guint));  // 行 2124
  ```

  `tileW * (int)sizeof(Guint)` 是 `int * int` 的 32-bit 有符号乘法，当 `tileW > INT_MAX / 4 = 536,870,912` 时发生有符号整数溢出（C++ UB，实际 wrap）。

  在 64-bit 构建中，`maxTileSize = 2,000,000,000`（见 `SplashBitmap.h`），允许 `tileW` 最大约 2 × 10⁹（当 `tileH = 1` 时）。以 `tileW = 1,073,741,825`（即 2³⁰ + 1）为例：

  - `tileW * 4 = 4,294,967,300`，wrap 为 32-bit 有符号值 `4`（即 `4,294,967,300 mod 2³² - 2³² = 4`）
  - `gmallocn(1, 4)` 通过所有检查（`nObjs=1 < INT_MAX/4`），仅分配 **4 字节**
  - `memset(ptr, 0, 1 × 1,073,741,825 × 4)` = `memset(ptr, 0, 4,294,967,300)` → 向 4 字节堆块写入 **~4 GB 数据**，造成大规模堆损坏

  先前的 `tileSize` 越界检查（第 1877–1881 行）：`tileSize = 1 × 1,073,741,825 = 1,073,741,825 < maxTileSize = 2,000,000,000`，`tileW = 1,073,741,825 ≤ INT_MAX / tileH = INT_MAX`——两项检查均通过，代码正常进入 overprint 分支。

- **触发条件**:
  1. 64-bit 构建，编译时定义 `SPLASH_CMYK=1`（pdftoppm CMYK 模式）
  2. `globalParams->getOverprintPreview()` 返回 `true`
  3. 当前色彩模式为 `splashModeCMYK8`
  4. PDF 包含 tiling pattern，其设备空间宽度使得 `tileW ≥ 2³⁰ + 1`（约 1.07 × 10⁹ 像素），`tileH = 1`（高度 1 像素），且 `tileW < maxTileSize = 2 × 10⁹`

- **安全影响**: 堆损坏（~4 GB 零字节写入），必然导致进程崩溃（DoS）；在可控堆布局下可能实现远程代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
