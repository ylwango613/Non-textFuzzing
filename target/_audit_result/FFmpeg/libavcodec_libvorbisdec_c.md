I now have full context. Let me confirm the `bytestream_get_be16` macro has no bounds check (the `DEF` macro at line 42-46 shows it just blindly reads and advances), then write the final report.

**Batch analysis summary:**

**Lines 54–67 (`p[0]==0 && p[1]==30` format branch):**
- Line 54: `p[1]` accessed unconditionally; if `extradata_size == 1` and `extradata[0] == 0`, reading `p[1]` is a 1-byte heap OOB read.
- Loop at line 57: for i=2, `bytestream_get_be16` (no-bounds-check macro, confirmed from `DEF` macro at bytestream.h:42–46) reads 2 bytes from `p`. The guard `sizesum > extradata_size` is evaluated **after** the read. If `4 + hsizes[0] + hsizes[1] == extradata_size` exactly (i.e., the two headers exhaust the extradata), the check at i=1 passes (`sizesum == extradata_size`, not `>`), so we proceed and read 2 bytes past the end for the third header's size. The resulting sizesum then triggers the error, but the OOB bytes have already been read.

**Lines 72–89 (`*p == 2` format branch):**
- While condition `(*p == 0xFF) && (sizesum < extradata_size)`: after the while body increments `p`, the while condition is re-checked. If `p` was on the last valid byte (`extradata + extradata_size - 1`) before the body's `p++`, p becomes `extradata + extradata_size` (past end). The condition then dereferences `*p` (OOB) **before** short-circuiting via the sizesum check. Minimal PoC: extradata = `[0x02, 0xFF]`, `extradata_size = 2`. After one while iteration for i=0, `p = extradata+2` (OOB), and the condition `*p == 0xFF` reads `extradata[2]` — a 1-byte heap OOB read. Then `hsizes[0] += *p` (line 80) reads the same OOB byte again.

**Lines 156–179 (`oggvorbis_decode_frame` while loop):**
- `total_samples` has no upper-bound check against the `8192*4 = 32768` pre-allocated frame size. However, in normal libvorbis operation one `vorbis_synthesis_blockin` per packet produces at most one block (max 8192 samples) and `vorbis_synthesis_read` fully drains each iteration, making overflow impractical. Not reported.

---

## VULN: Heap OOB Read via bytestream_get_be16 Without Remaining-Bytes Guard in Vorbis Extradata Parser
- **漏洞类别**: memory-safety
- **函数**: oggvorbis_decode_init()
- **行号**: 54-67
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted media file (Ogg/MKV/WebM with Vorbis codec)
- **外部触发路径**: `ffmpeg -i <crafted.ogg> -f null -` → `avformat_open_input()` → `avcodec_open2()` → `oggvorbis_decode_init()` → `bytestream_get_be16()` for i=2 at line 57 reads 2 bytes past end of `avccontext->extradata`
- **描述**: In the `p[0]==0 && p[1]==30` extradata format branch, the loop at lines 55–67 calls the no-bounds-check macro `bytestream_get_be16` (which simply dereferences and advances the pointer without checking remaining bytes) for each of three headers. The out-of-bounds guard `if (sizesum > avccontext->extradata_size)` is evaluated **after** the read. When `extradata_size` equals exactly `4 + hsizes[0] + hsizes[1]` (both prior checks pass because sizesum equals — not exceeds — extradata_size), the i=2 iteration calls `bytestream_get_be16` with `p == extradata + extradata_size`, reading 2 bytes past the allocation. The resulting inflated sizesum then triggers the error branch, but the 2-byte heap OOB read has already occurred.
- **触发条件**: Attacker supplies a Vorbis codec extradata beginning with `[0x00, 0x1E, ...]` (the "two-byte size fields" format) with a total `extradata_size` of exactly `4 + hsizes[0] + hsizes[1]` (i.e., all bytes consumed by the first two size-fields and their payload, leaving no room for the third size field). Example: `extradata = [0x00, 0x1E, <30 bytes>, 0x00, 0x00]`, `extradata_size = 34` (hsizes[0]=30, hsizes[1]=0).
- **安全影响**: 2-byte out-of-bounds heap read from adjacent heap memory. Directly yields up to 2 bytes of heap layout information; in a multi-step exploit against a browser-embedded or server-side FFmpeg instance this constitutes an info-leak primitive that can assist heap-layout fingerprinting. No write occurs and the error path is always taken, limiting severity to confidentiality impact.

## VULN: Heap OOB Read in while-Condition Dereference in Vorbis Extradata XiphLacing Parser
- **漏洞类别**: memory-safety
- **函数**: oggvorbis_decode_init()
- **行号**: 72-82
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted media file (Ogg/MKV/WebM with Vorbis codec)
- **外部触发路径**: `ffmpeg -i <crafted.ogg> -f null -` → `avformat_open_input()` → `avcodec_open2()` → `oggvorbis_decode_init()` → `while((*p == 0xFF) && (sizesum < avccontext->extradata_size))` at line 74 re-evaluates `*p` after `p++` has advanced the pointer past `extradata + extradata_size`
- **描述**: In the Xiph lacing (`*p == 2`) format branch, the while loop at lines 74–79 accumulates header sizes by consuming 0xFF continuation bytes. The loop condition is `(*p == 0xFF) && (sizesum < extradata_size)`. After the loop body executes `p++` (line 78), control returns to the top of the loop and evaluates `*p` first (before the short-circuiting sizesum guard). When `p` has just been incremented to `extradata + extradata_size` (one byte past the allocated buffer), the dereference `*p` constitutes a 1-byte heap OOB read. A second OOB read of the same byte occurs at line 80 (`hsizes[i] += *p`) when the while terminates. Although the subsequent sizesum check at line 83 always triggers an error (sizesum grows by 256 per iteration, far exceeding extradata_size), the two OOB dereferences have already occurred.
- **触发条件**: Attacker constructs a Vorbis extradata with the leading byte `0x02` followed by a single `0xFF` byte, and sets `extradata_size = 2`. Example: `extradata = [0x02, 0xFF]`, `extradata_size = 2`. After one while iteration, `p` advances to `extradata[2]` (one past the end), and the condition re-evaluates `*p = extradata[2]` — OOB. Line 80 then reads `extradata[2]` a second time.
- **安全影响**: Two 1-byte out-of-bounds heap reads from the byte immediately following the `extradata` allocation. Leaks up to 1 byte of adjacent heap content, usable as a heap-layout oracle. No write corruption occurs; execution always reaches the error path after the OOB reads.

<!-- AUDIT_PROMPT_VERSION: 1 -->
