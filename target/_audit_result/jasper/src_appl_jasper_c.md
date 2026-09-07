Both vulnerabilities confirmed. Here is the final audit report:

## VULN: Heap OOB read — CDEF/CMAP numchans mismatch in jp2_dec.c:403
**File:** `src/libjasper/jp2/jp2_dec.c`
**Lines:** 403–413
**Function:** `jp2_decode`
**CWE:** CWE-125 (Out-of-Bounds Read)
**CVSS 3.1:** 7.1 · AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H

**Root cause:** At line 403 the code loops `for (i = 0; i < dec->numchans; ++i)` and reads `dec->cdef->data.cdef.ents[i]`. `dec->numchans` is populated from the CMAP box (`cmapd->numchans`, set in `jp2_cmap_getdata`), while `dec->cdef->data.cdef.ents` is heap-allocated in `jp2_cdef_getdata` with a size of `cdef->numchans` read from the CDEF box. These two values are independently parsed from attacker-controlled input and never cross-validated. When the CDEF box specifies `M` channels and the CMAP box specifies `N > M` channels, the loop reads `ents[M]` through `ents[N-1]` beyond the end of the heap buffer.

**Trigger:** Craft a JP2 file containing:
1. A CMAP box with `numchans = N` (e.g., 3 channels)
2. A CDEF box with `numchans = M` where `M < N` (e.g., 1 channel)
3. Pass the file to `jasper --input <file>` or any program calling `jas_image_decode()` with format `jp2`.

**Impact:** Up to `(N - M) * sizeof(jp2_cdefchan_t)` bytes of heap memory following the CDEF `ents` buffer are read and used as `channo`, `type`, and `assoc` fields. This leaks adjacent heap allocations (info-disclosure) and, if the out-of-range `channo` value passes the `>= dec->numchans` guard, causes further memory corruption via `jas_image_setcmpttype`. At minimum the process crashes (DoS).

---

## VULN: Heap OOB read — CMAP pcol unchecked against PCLR numchans in jp2_dec.c:372
**File:** `src/libjasper/jp2/jp2_dec.c`
**Lines:** 372, 377
**Function:** `jp2_decode`
**CWE:** CWE-125 (Out-of-Bounds Read)
**CVSS 3.1:** 7.1 · AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H

**Root cause:** When processing a palette-mapped channel (`cmapent->map == JP2_CMAP_PALETTE`), `cmapent->pcol` — a field read directly from the CMAP box (type `uint_fast8_t`, range 0–255) — is used as a column index into `pclrd->lutdata` (line 372) and `pclrd->bpc` (line 377) without any bounds check against `pclrd->numchans`. `pclrd->lutdata` is allocated as `numlutents * numchans` entries and `pclrd->bpc` as `numchans` entries. Both are populated from the PCLR box, which is parsed independently. If an attacker sets `pcol >= pclrd->numchans`, both accesses go out of bounds.

**Trigger:** Craft a JP2 file containing:
1. A PCLR box with `numchans = 1` (so `bpc` has 1 entry, `lutdata` has `numlutents * 1` entries)
2. A CMAP box with at least one entry where `map = JP2_CMAP_PALETTE` and `pcol = 200` (any value ≥ 1)
3. Pass the file to `jasper --input <file>` or any program calling `jas_image_decode()` with format `jp2`.

**Impact:** Line 372 reads `pclrd->lutdata[200 + i * 1]` for `i` in `[0, numlutents)`, reading 200 entries past the start of the `lutdata` buffer. Line 377 reads `pclrd->bpc[200]`, reading 200 bytes past the 1-entry `bpc` array. Both reads consume adjacent heap memory. The values obtained are passed to `jas_image_depalettize` and used as pixel data, potentially enabling heap info-disclosure or crash.

<!-- AUDIT_PROMPT_VERSION: 1 -->
