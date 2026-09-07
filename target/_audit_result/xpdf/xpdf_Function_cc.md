Analysis complete. I've now read all 1598 lines of Function.cc in four passes, checked the header, gmallocn/greallocn implementations, and all caller sites. Here is my consolidated finding:

**Batch 1 (lines 1–500):** SampledFunction — `nSamples` overflow check is correct; `idx0 + idxOffset[j] + i` is bounded within `nSamples - 1`; `gmallocn` validates product before allocation. No exploitable issue.

**Batch 2 (lines 500–999):** ExponentialFunction/StitchingFunction — all arrays fixed-sized and bounded by funcMaxInputs/funcMaxOutputs. `IdentityFunction(nInputs)` loop over `domain[]` could theoretically overflow but `nInputs` is always a small constant from callers (never > 32 = funcMaxInputs). No exploitable issue.

**Batch 3 (lines 999–1226):** PostScriptFunction constructor + `parseCode` + helpers. **CONFIRMED:** `parseCode` recurses without any depth counter when it encounters `{` tokens (lines 1063, 1078). The `recursionLimit = 8` guard only covers `Function::parse`; `parseCode` is completely unprotected. Deeply-nested `{ ... if }` blocks in a Type-4 function stream cause unbounded stack growth → SIGSEGV.

**Batch 4 (lines 1227–1598):** `exec()` — stack bounds checked correctly for all 40+ opcodes; branch targets are always set to valid code positions by `parseCode`; `psOpRoll`/`psOpCopy`/`psOpIndex` bounds arithmetic all sound. `addCode` size-doubling would need 2^29 * sizeof(PSCode) ≈ 8 GB of code, not feasible. No exploitable issue.

---

## VULN: Unbounded Recursion in PostScriptFunction::parseCode Causes Stack Exhaustion
- **漏洞类别**: memory-safety
- **函数**: `PostScriptFunction::parseCode()`
- **行号**: 1044–1135 (recursive calls at lines 1063, 1078)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium (reliable DoS, crash without code execution)
- **攻击向量**: crafted PDF file containing a Type-4 (PostScript) function stream
- **外部触发路径**: `pdftotext input.pdf` → PDF object parsing → color-space/shading/pattern that references a Type-4 function → `Function::parse()` → `new PostScriptFunction(funcObj, dict)` → `parseCode(tokens, &tokPtr, &codePtr)` → recursive `parseCode(...)` calls (lines 1063, 1078) without depth limit
- **描述**: `PostScriptFunction::parseCode()` is a recursive descent parser for embedded PostScript code. When it encounters a `{` token, it recursively calls itself to parse the nested block (lines 1063, 1078) before consuming the trailing `if` or `{...} ifelse` token. There is no recursion-depth counter or limit: the `recursionLimit = 8` guard (line 28) applies only to `Function::parse()` (line 47), which controls nesting of *function objects*, not the nesting of PS control-flow constructs within a single function stream. A PS stream consisting of N deeply nested `{ ... } if` constructs triggers N stack frames of `parseCode`, each consuming ~80–160 bytes of C call stack. On Linux with a default 8 MB stack, approximately 50,000–100,000 nesting levels exhaust the stack and produce SIGSEGV. The required stream is approximately 3 × N tokens × ~5 bytes/token, i.e., ~250 KB for N = 50,000 — easily embeddable in a PDF.
- **触发条件**: 攻击者构造 PDF，其中包含一个 Type-4 函数流（`/FunctionType 4`），流内容为深度嵌套的 `{ { { { ... } if } if } if }` 结构（约 5 万层或以上）。该函数可挂接在 shading、color space（ICCBased/DeviceN/Separation 的 tintTransform）或 pattern 上，使 pdftotext 在解析时触发。
- **安全影响**: 进程必然 crash（SIGSEGV），构成可靠的 DoS。在极少数无 stack canary / guard page 的环境下，覆盖 guard page 旁边的堆或其他映射区域存在理论上的 RCE 风险，但实践中通常为纯崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
