I have now read and analyzed all 2340 lines of `sonymn_int.cpp` in multiple batches, plus the 158-line header `sonymn_int.hpp`. Here is a structured summary of what I checked and why each candidate was ruled out:

**Batch 1 (1–400):** Lookup table definitions — statically initialized, no runtime allocations.

**Batch 2 (400–816):** More lookup tables; no runtime logic.

**Batch 3 (816–1220):** Helper functions (`getModel`, `getAFAreaModeSetting`, `getMetaVersion`, `getFocusMode2`) — all use iterator-safe ExifData lookups; print functions (`printWhiteBalanceFineTune`, `printAutoHDRStd`, `printWBShiftABGM`, `printFocusMode2`, `printAFAreaModeSetting`, `printFlexibleSpotPosition`, `printAFPointSelected`, `printAFPointsUsed`, `printAFTracking`, `printFocalPlaneAFPointsUsed`, `printWBShiftABGMPrecise`, `printExposureStandardAdjustment`, `printPixelShiftInfo`, `printFocusFrameSize`, `printColorTemperature`) — all properly guard with `value.count()` before accessing elements.

**Batch 4 (1220–1618):** `printLensSpec` + `findLensSpecFlags` — guarded by `count() != 8` check; indices 0–7 safe. Rest: tag tables.

**Batch 5 (1618–1870):** Camera settings tag tables — static const data.

**Batch 6 (1850–2230):** Remaining print functions (`printSony2FpAmbientTemperature`, `printSony2FpFocusMode`, `printSony2FpFocusPosition2`, `printSonyMisc1CameraTemperature`, `printSonyMisc2bLensZoomPosition`, `printSonyMisc2bFocusPosition2`, `printSonyMisc3c*`) — all use Value API with `.at(n)` internally (throws `std::out_of_range`, not memory corruption); Sony2010e tag table.

**Batch 7 (2230–2340):** `sonyTagCipher` / `sonyTagDecipher` / `sonyTagEncipher`:
- `code[256]` fully initialized: cubing mod 249 is a bijection on Z/249Z (249 = 3×83, gcd(3, φ(83)) = gcd(3,82) = 1 ⟹ bijection on Z/83Z; identity on Z/3Z; by CRT full bijection), so indices 0–248 all written exactly once; indices 249–255 covered by second loop.
- `write_uint8` throws `std::out_of_range` on OOB — no memory corruption.
- `bytes[i]` (uint8_t) is always in [0,255] — valid index into `code[256]`.
- Loop `uint32_t i < size_t size`: potential infinite loop if `size > UINT32_MAX`, but DataBuf allocation of > 4 GB would fail (std::bad_alloc) before this code is reached; not practically exploitable.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
