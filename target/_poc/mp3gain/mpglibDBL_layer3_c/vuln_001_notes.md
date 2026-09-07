# VULN 001 – OOB Read in bandInfo.longIdx / OOB Write in III_dequantize_sample

## PoC Strategy

Craft a minimal MPEG1 Layer3 MP3 frame (mono, 128 kbps, 44100 Hz) with the
side-information bits set so that:

1. `window_switching_flag = 0` — forces the non-switched-block code path in
   `III_get_side_info_1()` (lines 395-409 of `mpglibDBL/layer3.c`) where
   `r0c` and `r1c` are read from the bitstream.

2. `r0c = 15` (4-bit field, maximum value) and `r1c = 7` (3-bit field, maximum
   value) — causes the array index `r0c + 1 + r1c + 1 = 24` to exceed the
   bounds of `bandInfo[sfreq].longIdx[23]` (valid indices 0–22).

3. `big_values = 100` — ensures `bv > region2` so that the negative `l[1]`
   path is taken in `III_dequantize_sample()`.

## Trigger Path

```
mp3gain main()
  -> analyzeOneFile()
      -> do_layer3_sideinfo()
          -> III_get_side_info_1()           # OOB READ here
      -> do_layer3()
          -> III_dequantize_sample()         # OOB WRITE here
```

## Vulnerability Mechanics

### OOB Read (layer3.c line 403)

```c
r0c = getbits_fast(4);       // 0–15
r1c = getbits_fast(3);       // 0–7
gr_infos->region2start =
    bandInfo[sfreq].longIdx[r0c+1+r1c+1] >> 1;
```

With `r0c=15` and `r1c=7` the index is `15+1+7+1 = 24`.
`longIdx` has 23 elements (indices 0–22).  Index 24 aliases into the
immediately adjacent `longDiff` field:

```
struct bandInfoStruct {
  short longIdx[23];   // [0]–[22]
  short longDiff[22];  // [23]–[44]  <- longIdx[24] = longDiff[1]
  ...
};
```

For 44100 Hz (`sfreq=0`): `longDiff[1] = 4`, so `region2start = 4 >> 1 = 2`.

### Cascade to OOB Write (layer3.c ~lines 686–697, 895–956)

In `III_dequantize_sample()`:

```c
int bv      = gr_infos->big_values;   // 100
int region1 = gr_infos->region1start; // longIdx[16]>>1 = 162>>1 = 81
int region2 = gr_infos->region2start; // 2  (corrupted)

// bv(100) > region1(81) > region2(2):
l[0] = region1;                       // 81
l[1] = region2 - l[0];               // 2 - 81 = -79  *** NEGATIVE ***
l[2] = bv - region2;                 // 98
```

The outer decode loop for region i=1:

```c
int lp = l[1];   // -79
for(; lp; lp--, mc--) {
    *xrpnt++ = ...;  // write to stack float xr[32][18]
    *xrpnt++ = ...;
}
```

`lp` starts at -79 and is decremented each iteration (signed int, UB wraparound
in practice wraps through INT_MIN back to INT_MAX).  The loop runs ≈ 2^32 − 79
iterations while `xrpnt` advances unchecked past the 576-element `xr` buffer
(2304 bytes), causing a massive stack-buffer-overflow caught by ASAN.

## Expected ASAN/UBSAN Output

```
==NNNNN==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
WRITE of size 4 at 0x... thread T0
    #0 ... III_dequantize_sample
    #1 ... do_layer3
    #2 ... analyzeOneFile
    ...
```

or a UBSAN signed-integer-overflow report for the `lp--` wraparound, followed
immediately by the ASAN stack-overflow.
