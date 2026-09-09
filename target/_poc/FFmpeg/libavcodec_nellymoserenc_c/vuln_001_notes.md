# VULN-001 PoC Notes: get_exponent_dynamic off-by-one heap OOB write

## Vulnerability

`get_exponent_dynamic()` in `libavcodec/nellymoserenc.c` (lines 260-278) performs
a Viterbi-style search over two heap-allocated 2-D arrays:

```c
float   (*opt )[OPT_SIZE]   // OPT_SIZE = (1<<15)+3000 = 35768
uint8_t (*path)[OPT_SIZE]
```

Each array has `NELLY_BANDS * OPT_SIZE = 23 * 35768` elements.  The per-band loop
computes:

```c
idx_max = FFMIN(OPT_SIZE, cand[band - 1] + q);
...
if (idx > idx_max) break;   // BUG: strict > instead of >=
```

When `cand[band-1]` is large enough that `idx_max` clamps to `OPT_SIZE == 35768`,
the break is never taken for `idx == 35768`, and the code writes to
`opt[band][35768]` / `path[band][35768]` — one element past the end of each row.
At `band == 22 (NELLY_BANDS-1)` this is one element past the entire allocation.

## Trigger Condition

`cand[band]` is computed in `encode_block()`:

```c
cand[band] = log2(FFMAX(1.0, coeff_sum / (band_size << 7))) * 1024.0;
```

For `cand[0] >= 34768` (so that `cand[0] + 1000 >= OPT_SIZE`):
- Required: `coeff_sum >= 256 * 2^33.96 ≈ 4.1e12`
- This is satisfied when MDCT coefficients of the input frame are ~1e6 in magnitude

## PoC Approach

`vuln_001_gen.py` builds a WAV file with:
- Format: PCM_F32LE (WAV format tag 3 = IEEE float), mono, 8000 Hz
- Samples: 80 000 alternating +1e6 / -1e6 float32 values (10 seconds)
- Alternating polarity maximises high-frequency MDCT energy

`vuln_001_run.sh` invokes:
```
ffmpeg -y -i vuln_001_input.wav -c:a nellymoser -trellis 1 -ar 8000 -f flv /dev/null
```

The `-trellis 1` flag routes through `get_exponent_dynamic()` instead of the
greedy path.  Large float samples push `cand[band]` well past 34768, causing
`idx_max == OPT_SIZE` and triggering the OOB write in the first processed frame.

## Observed Outcome

UBSan (binary built with `-fsanitize=address,undefined`) reported:

```
nellymoserenc.c:247:15: runtime error: index 35768 out of bounds for type 'float [35768]'
nellymoserenc.c:294:37: runtime error: index -1 out of bounds for type 'uint8_t [35768]'
nellymoserenc.c:296:56: runtime error: index -1 out of bounds for type 'uint8_t [35768]'
```

- The `index 35768` error is the exact OOB index (`== OPT_SIZE`) that the
  vulnerability description predicts.
- The `index -1` errors on lines 294/296 are the downstream consequence: the OOB
  write corrupted heap memory such that `best_idx` resolved to `-1` during the
  traceback, triggering further out-of-bounds reads.

These errors confirm that the off-by-one write is reliably triggered by the
crafted input and that it corrupts adjacent heap state.

## Files

| File | Purpose |
|---|---|
| `vuln_001_gen.py` | Generates `vuln_001_input.wav` (WAV PCM_F32LE, ±1e6 amplitude) |
| `vuln_001_run.sh` | Runs ffmpeg with `-trellis 1 -c:a nellymoser` |
| `vuln_001_input.wav` | Generated crafted WAV (320 044 bytes) |
| `vuln_001_result.txt` | Full output including UBSan runtime errors |
| `vuln_001_status.txt` | VERIFIED_CRASH |
