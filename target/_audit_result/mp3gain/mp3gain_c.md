## VULN: apetag.c heap buffer over-read — MP3GAIN_UNDO value too short
- **category**: heap-buffer-over-read
- **function**: ReadMP3APETag
- **lines**: apetag.c:228–242
- **CWE**: CWE-125
- **CVSS**: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L (5.4 Medium)
- **severity**: Medium
- **attack vector**: crafted MP3 with APE tag containing an "MP3GAIN_UNDO" item whose value size field (vsize) is set to 0–9
- **call chain**: main() → ReadMP3APETag() → malloc(vsize+1) → memcpy(tmpString, vp, 4) [line 231] / memcpy(tmpString, vp+5, 4) [line 235] / *vp dereference [line 238]
- **description**: ReadMP3APETag allocates `value = malloc(vsize+1)` (line 222) and copies `vsize` bytes from the APE tag item into it. When the item name matches "MP3GAIN_UNDO", the code reads fixed-width fields assuming the value is at least 10 bytes: `memcpy(tmpString, vp, 4)` requires vsize≥3; `vp += 5` then `memcpy(tmpString, vp, 4)` requires vsize≥8; `*vp` dereference requires vsize≥9. With a crafted tag setting vsize=0, the first memcpy reads 4 bytes from a 1-byte allocation, reading past the heap buffer into adjacent heap metadata or other allocations.
- **trigger conditions**: APE tag item name = "MP3GAIN_UNDO", vsize set to any value 0–9. The bounds check at line 202 (`isize + 1 + vsize > remaining`) prevents overread of the raw `buff` buffer but does NOT protect the separately allocated `value` buffer.
- **security impact**: Heap over-read of up to 9 bytes from a heap-allocated buffer. Can read heap metadata or adjacent allocations (information disclosure). May cause crash if the adjacent region is unmapped.

## VULN: apetag.c heap buffer over-read — MP3GAIN_MINMAX / MP3GAIN_ALBUM_MINMAX value too short
- **category**: heap-buffer-over-read
- **function**: ReadMP3APETag
- **lines**: apetag.c:244–265
- **CWE**: CWE-125
- **CVSS**: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L (5.4 Medium)
- **severity**: Medium
- **attack vector**: crafted MP3 with APE tag containing a "MP3GAIN_MINMAX" or "MP3GAIN_ALBUM_MINMAX" item whose vsize is set to 0–6
- **call chain**: main() → ReadMP3APETag() → malloc(vsize+1) → memcpy(tmpString, vp, 3) [line 248] / memcpy(tmpString, vp+4, 3) [line 252]
- **description**: Same allocation pattern as the UNDO case. For MP3GAIN_MINMAX the expected value is "NNN,NNN" (7 bytes). First `memcpy(tmpString, vp, 3)` requires vsize≥2; `vp += 4` then `memcpy(tmpString, vp, 3)` requires vsize≥6. With vsize=0 through 5 the respective memcpy reads past the 1-to-6-byte allocation. MP3GAIN_ALBUM_MINMAX (lines 255–265) has the same code pattern and the same vulnerability.
- **trigger conditions**: APE tag item name = "MP3GAIN_MINMAX" or "MP3GAIN_ALBUM_MINMAX", vsize < 6. Bounds check at line 202 protects `buff` but not the individually allocated `value` buffer.
- **security impact**: Heap over-read of up to 5 bytes per occurrence. Same impact as UNDO case (information disclosure, potential crash).

## VULN: interface.c — bsspace stack buffer overflow via oversized dsize
- **category**: stack-buffer-overflow
- **function**: decodeMP3
- **lines**: mpglibDBL/interface.c:585–618
- **CWE**: CWE-121
- **CVSS**: AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (7.8 High)
- **severity**: High
- **attack vector**: crafted MP3 file with side-info `part2_3_length` fields summing to 16380 (each 12-bit field set to 4095, MPEG1 stereo 2-granule) and `main_data_begin` = 0
- **call chain**: main() [MPSTR mp on stack] → analyzeFile() → decodeMP3() → do_layer3_sideinfo() sets mp->dsize = (16380+7)/8 = 2048 → copy_mp(mp, mp->dsize=2048, wordpointer=bsspace[bsnum]+512) overflows bsspace
- **description**: `mp->dsize` is computed as `(bits+7)/8` from the sum of `part2_3_length` values (each up to 4095) minus `8*main_data_begin` (line 585–591). For MPEG1 stereo with 4 granule/channel combinations, maximum databits = 4×4095 = 16380; with `main_data_begin`=0, dsize = 2048. The sole guard at line 610 (`if(mp->dsize > mp->bsize) return MP3_NEED_MORE`) only checks that the ring-buffer has enough bytes, not that dsize fits in bsspace. `wordpointer` is set to `mp->bsspace[mp->bsnum]+512` (line 556); `copy_mp(mp, 2048, wordpointer)` at line 618 writes 2048 bytes starting at offset 512, reaching bsspace offset 2560. But `bsspace[bsnum]` is declared as `unsigned char bsspace[2][MAXFRAMESIZE+512]` = `[2][2304]`, so valid indices end at 2303. The overflow of 256 bytes corrupts `bsspace[1-bsnum]`. MPSTR `mp` is a stack-allocated local in main(), so this corrupts adjacent stack data. After two frames of accumulation, `mp->bsize` reaches ≥2048, triggering the overflow.
- **trigger conditions**: (1) At least two preceding frames to accumulate bsize ≥ 2048; (2) Frame with all four `part2_3_length` fields = 4095 and `main_data_begin` = 0; (3) MPEG1 stereo (stereo=2, granules=2). The check `if(size > MAXFRAMESIZE)` at interface.c:689 is present but only prints a message and continues without returning.
- **security impact**: 256-byte stack buffer overflow within the MPSTR struct; corrupts the alternate bsspace buffer and potentially cascades to hybrid_block and other MPSTR fields used in subsequent frame decoding. On systems where MPSTR is large enough that adjacent stack frames are nearby, deeper overflow is possible, potentially reaching a return address.

## VULN: layer3.c — bandInfo.longIdx out-of-bounds read causes negative loop count and xrpnt stack corruption
- **category**: oob-read-leading-to-stack-corruption
- **function**: III_get_side_info_1 / III_get_side_info_2 / III_dequantize_sample
- **lines**: mpglibDBL/layer3.c:399–403 (III_get_side_info_1), 494–498 (III_get_side_info_2), 750–900 (III_dequantize_sample loop)
- **CWE**: CWE-125 (OOB read) → CWE-121 (stack buffer overflow)
- **CVSS**: AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (7.8 High)
- **severity**: High
- **attack vector**: crafted MP3 frame with window-switching-flag=0 (normal block), `region_address1`=15 (4-bit field, max), `region_address2`=7 (3-bit field, max), producing r0c=15 r1c=7
- **call chain**: main() → decodeMP3() → do_layer3() → III_get_side_info_1() → bandInfo[sfreq].longIdx[r0c+1+r1c+1] OOB read at index 24 → region2start gets value from longDiff[] → negative l[1] in III_dequantize_sample → `for(;lp;lp--)` loop with lp=-79 runs ~2³² iterations advancing `xrpnt` far past `xr[SBLIMIT][SSLIMIT]`
- **description**: `bandInfoStruct.longIdx` is declared as `short longIdx[23]` (valid indices 0–22). At line 403, `gr_infos->region2start = bandInfo[sfreq].longIdx[r0c+1+r1c+1] >> 1`. With r0c=15 (4-bit max) and r1c=7 (3-bit max), the index is 24, reading two elements past the array end into `longDiff[]` (the next field in the struct, which is in read-only data). For sfreq=0 (44100 Hz), longDiff[1]=4, so region2start=2. Meanwhile region1start = longIdx[16]>>1 = 81 (for sfreq=0). In III_dequantize_sample with big_values≥82: l[0]=81 (region1), `l[1] = region2 - l[0] = 2 - 81 = -79` (negative), `l[2] = bv - 2`. The inner loop `for(;lp;lp--)` treats lp as a signed int; starting at -79 it decrements through INT_MIN, wraps to INT_MAX, and counts to zero — approximately 2³² iterations. Each iteration does `*xrpnt++ = ...; *xrpnt++ = ...;` writing two doubles per iteration. After exhausting `xr[32][18]` (576 doubles = 4608 bytes), xrpnt overflows into the rest of MPSTR on the stack: hybrid_block, hybrid_blc, synth_buffs, saved registers, and ultimately the return address. The same OOB pattern exists identically in III_get_side_info_2 (lines 497–498) for LSF/MPEG2 frames.
- **trigger conditions**: (1) Normal block (window-switching-flag bit = 0 in the side info); (2) region_address1 = 15, region_address2 = 7 (maximum values of their respective bitfields); (3) big_values > region1start (≥82 for sfreq=0) — controlled by the attacker via the big_values field (12-bit, 0–288); (4) sfreq determines region1start — any of the 9 supported sample rates is triggerable with suitable r0c/r1c values. No validation of r0c+r1c exists in the code.
- **security impact**: Effectively unbounded stack write (up to ~64 GB of writes before SIGSEGV). Values written are derived from Huffman decoding of attacker-controlled bitstream bytes, giving significant control over the write content. Reachable from a crafted local MP3 file; leads to arbitrary code execution or guaranteed crash.

<!-- AUDIT_PROMPT_VERSION: 1 -->
