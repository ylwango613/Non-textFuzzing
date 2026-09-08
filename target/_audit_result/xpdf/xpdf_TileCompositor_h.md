Now I have all the context needed. Let me do a final synthesis of my findings.

**Group 1 — TileCompositor.h (lines 1-73)**: Pure header/declaration file. Contains class declaration, forward declarations, and private member variables only. No implementation code, no memory safety issues here.

**Group 2 — TileCompositor.cc blit() (lines 292-343)**: 
- No source-bounds check in `blit()` itself, but the caller (`getBitmap()`) clips `w`/`h` against window bounds.
- Mathematically verified: when `px >= 0`, `xSrc=0`, `w ≤ min(tw, winW-px) ≤ tw`. When `px < 0`, `xSrc=-px`, after right-edge clip `w = min(tw+px, winW)`, and `xSrc+w = -px + min(tw+px, winW) ≤ tw`. Reads stay within source tile bounds in both cases.
- `SplashOutputDev` is constructed with `bitmapTopDown=gTrue` (default from SplashOutputDev.h line 48). Both compositor bitmap (`topDown=gTrue`, line 66 in .cc) and tile bitmaps are top-down → `rowSize > 0`, pointer arithmetic correct.

**Group 3 — clearBitmap() (lines 228-286)**:
- Correctly handles negative rowSize with explicit branches.
- `memset(data, ..., rowSize * h)`: On 64-bit, `SplashBitmapRowSize = long long`, multiplication is `long long * int = long long`; no practical overflow. On 32-bit, overflow to negative produces a huge `size_t` argument, but reaching such sizes requires memory infeasible on 32-bit.

**Group 4 — Data race in TileCache**:
- `startPageCbk` sets `ct->bitmap = out->getBitmap()` with `freeBitmap=false`. 
- In the canceled path, `delete out` frees `original_bitmap`; main thread may then call `blit()` on it → UAF.
- However, cancellation requires user scroll/zoom: NOT purely PDF-triggered.

**Group 5 — fill() and applySelection() (lines 347-445)**:
- Both functions have their own internal clipping logic (clip xDest/yDest against winW/winH). No OOB.

**Group 6 — TileMap.cc `updatePageParams()`**: `pageW = (int)((rotPageBoxW * dpi / 72.0) + 0.5)` — checked with `< 1` guard. PDF max page size (14400 pts) × extreme zoom won't overflow `int`. Tile dimensions flow cleanly to `blit()`.

**Conclusion**: TileCompositor.h is a GUI-only component (xpdf viewer, not pdftotext). The blit clipping is mathematically correct. The one race condition (potential UAF on tile cancellation) requires user interaction beyond opening the PDF. No memory-safety vulnerabilities are directly triggerable by a crafted PDF file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
