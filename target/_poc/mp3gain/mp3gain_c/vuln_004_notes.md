# VULN 004 – mp3gain: bandInfo.longIdx OOB Read → Negative Loop Count → hybridIn Overflow

## Vulnerability

**File:** `mpglibDBL/layer3.c`  
**Functions:** `III_get_side_info_1` (line 403), `III_dequantize_sample` (line 899)  
**Category:** OOB-read leading to global-buffer-overflow

## Root Cause

`struct bandInfoStruct` declares `short longIdx[23]` (valid indices 0–22).  
At line 403:

```c
gr_infos->region2start = bandInfo[sfreq].longIdx[r0c+1+r1c+1] >> 1;
```

With `region0_count=15` (r0c=15) and `region1_count=7` (r1c=7) — both at their
4-bit and 3-bit maximums respectively — the index evaluates to
`15+1+7+1 = 24`, which is **two past the end** of `longIdx[23]`.

For `sfreq=0` (44100 Hz), this reads into `longDiff[1] = 4`, giving
`region2start = 4 >> 1 = 2`, while:

```
region1start = bandInfo[0].longIdx[16] >> 1 = 162 >> 1 = 81
```

## Exploitation

In `III_dequantize_sample` with `big_values = 150`:

```c
l[0] = region1start  = 81
l[1] = region2start - region1start = 2 - 81 = -79   // NEGATIVE
l[2] = big_values   - region2start = 150 - 2 = 148
```

The inner loop at line 899:

```c
for(;lp;lp--)  // lp starts at -79
```

Because `int` underflow wraps to `0x80000001` → `0x80000000` → ... → `1` → `0`,
the loop executes approximately **2³² iterations**, each writing two `double`
values to `xrpnt` (a pointer into the static buffer `hybridIn[2][SBLIMIT][SSLIMIT]`
= `hybridIn[2][32][18]`).

After ≈ 495 iterations of the negative loop the pointer surpasses the 1152-element
`hybridIn` array and enters the ASAN red zone, triggering a
**global-buffer-overflow** error and abort.

## Trigger Conditions

| Field | Value | Reason |
|---|---|---|
| MPEG version | MPEG1 | uses `III_get_side_info_1` |
| Sample rate | 44100 Hz (`sfreq=0`) | specific `longIdx` values |
| `window_switching_flag` | 0 | enters the normal-block `else` branch |
| `region0_count` | 15 (max 4-bit) | r0c=15 |
| `region1_count` | 7 (max 3-bit) | r1c=7 |
| `big_values` | 150 | > region1start (81) to reach `l[1]` |

## PoC Construction

The malicious MP3 consists of 4 frames (417 bytes each, MPEG1 Layer3
128 kbps 44100 Hz joint stereo):

- 3 priming frames with `big_values=0` (safe, initialise the bitstream reservoir)
- 1 malicious frame with the crafted side info above

The data portion is filled with `0xFF` bytes.  With `table_select=0` (tab0
in huffman.h — first table entry is 0, no bits consumed), `xrpnt` advances
by 2 doubles per loop iteration unconditionally until the buffer overflows.

## Expected Crash (ASAN-instrumented binary)

```
==PID==ERROR: AddressSanitizer: global-buffer-overflow on address ...
WRITE of size 8 at ... thread T0
    in III_dequantize_sample mpglibDBL/layer3.c:935
```
