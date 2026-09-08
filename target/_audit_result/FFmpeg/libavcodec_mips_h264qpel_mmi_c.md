After completing a full 6-batch read of the entire 3132-line file and tracing every buffer access pattern, here is my analysis summary:

**Functions audited:**
- `copy_block{4,8,16}_mmi` — loop over `h` parameter, no internal allocation
- `put/avg_h264_qpel{4,8,16}_{h,v,hv}_lowpass_mmi` — internal stack buffers
- `put_h264_qpel8or16_hv1_lowpass_mmi` / `hv2_lowpass_mmi` — key high-complexity routines
- `put/avg_pixels{8,16}_l2_shift5_mmi` — reads from hv1-written `int16_t` buffer

**Key buffer size verification:**
| Caller | Buffer | Size (bytes) | Max write/read | Status |
|---|---|---|---|---|
| mc22 (size=8) | `temp[192]` uint16_t | 384 | byte 367 | ✓ |
| mc22 (size=16) | `temp[384]` uint16_t | 768 | byte 767 | ✓ |
| mc12/mc21 (size=8) | `temp[448]` uint8_t, halfV=temp+64 | 448 | byte 407 (hv1), 275 (shift5) | ✓ |
| mc12/mc21 (size=16) | `temp[1024]` uint8_t, halfV=temp+256 | 1024 | byte 1023 (hv1), 675 (shift5) | ✓ |

**Additional checks:**
- `put_h264_qpel4_hv_lowpass_mmi`: `_tmp[36]` (72 bytes) — asm writes at most byte 71, C loop accesses at most `_tmp[35]` ✓
- `full[336]` buffers with `full_mid = full+32`: `copy_block16_mmi` writes exactly 336 bytes; vertical lowpass reads up to byte 327 ✓
- `do-while(w--)` logic: executes exactly 1× for size=8 (w=0) and 2× for size=16 (w=1) ✓
- H-lowpass reads `src[-2..+3]` per row — standard H.264 padded frame assumption, safe ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
