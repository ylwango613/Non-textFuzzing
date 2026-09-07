I have now read through all 5,539 lines of `Gfx.cc` in batches and cross-checked key supporting types and functions. Here is my consolidated analysis:

**Batch summaries:**
- Lines 1–500: Operator table, GfxResources setup. No allocations with attacker-controlled sizes.
- Lines 500–1000: Gfx constructors, `go()` loop (numArgs bounded at maxArgs=33), `opSetDash` (gmallocn with overflow protection).
- Lines 1000–1500: ExtGState handling, blend mode parsing. No array OOB.
- Lines 1500–2000: Color operators `opSetFillColor`/`opSetStrokeColorN`. The loop guard `&& i < gfxColorMaxComps` is present in `opSetFillColorN`; `opSetFillColor` requires `numArgs == getNComps()`, and `getNComps()` ≤ 32 = `gfxColorMaxComps` for all supported colorspaces (DeviceN capped at 32, ICCBased defaults to 1/3/4 without alternate, with alternate bounded by alt's capped value).
- Lines 2000–2500: Pattern/shading fills. Recursion bounded by `functionMaxDepth=6`, `gouraudMaxDepth=6`, `patchMaxDepth=6`.
- Lines 2500–3000: Axial/radial shading. No OOB array accesses.
- Lines 3000–3500: Gouraud/patch mesh shading subdivision. Bounded depth.
- Lines 3500–4000: Path/text operators, Type3 char rendering. `display()` is recursive without an explicit depth limit for Type3→Type3 chains, but each iteration reads one char stream to completion; the content-stream loop detector in `checkForContentStreamLoop()` covers circular *references*, not circular Type3 fonts.
- Lines 4000–4500: `doShowText` bulk path, `opXObject`, `doImage` image header parsing. Integer arithmetic `n = height * ((width+7)/8)` (line 4400) may underflow to negative, causing the skip loop to execute 0 iterations rather than corrupting memory. `n = height * (width * nComps * bits + 7)/8` (line 4723) can overflow to a negative `int`, which when cast to `Guint` for `discardChars(Guint n)` gives a large unsigned value — but `discardChars` breaks at EOF, so no memory corruption results.
- Lines 4500–5000: SMask/colormap parsing, `doForm`, `drawForm`. `formDepth > 100` guard prevents stack overflow via Form XObject recursion.
- Lines 5000–5539: `buildImageStream`, annotation drawing, state save/restore. `drawAnnot` writes `color.c[0..3]` (GfxColor has 32 slots) and reads `borderColor[0..3]` (AnnotBorderStyle always allocates 4 doubles). Both are in-bounds.

**Key checks verified:**
- `gfxColorMaxComps = funcMaxOutputs = 32`; `maxArgs = 33`; all colorspace `getNComps()` implementations are bounded ≤ 32.
- `gmallocn` has explicit integer-overflow protection (`nObjs >= INT_MAX / objSize` → abort).
- `GfxColor color` stack-local structs are always large enough for the validated `numArgs` value.
- Annotation border color array is always 4-element (initialized to zeros) regardless of reported component count.
- Stream skip computations can produce wrong values via signed integer overflow but the downstream effect is EOF-terminated loop (DoS-class), not memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
