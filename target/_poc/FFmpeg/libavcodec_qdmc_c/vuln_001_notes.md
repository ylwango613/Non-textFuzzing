# VULN-001: QDMC add_wave() off-by-one OOB write

## Vulnerability

**File:** `libavcodec/qdmc.c`
**Function:** `add_wave()`, lines 561–576
**Type:** Off-by-one out-of-bounds write

### Root Cause

`add_wave()` computes a starting pointer into `fft_buffer[stereo_mode]`:

```c
imptr = &s->fft_buffer[stereo_mode][s->fft_offset + s->subframe_size * offset + pos];
```

Then in the loop it writes to `imptr[0]` and `imptr[1]`, advancing `imptr` by `subframe_size` each iteration. With `group=0`, `group_bits=4`, the loop runs `(1<<5)-1 = 31` iterations. If `imptr` lands on `fft_buffer[stereo_mode][16383]`, then `imptr[1]` accesses index 16384, which is one past the end of `fft_buffer[4][8192*2]`.

### Guard at Line 476

```c
if ((freq >> group_bits) + 1 < s->subframe_size)
```

For `group=0`, `group_bits=4`, `subframe_size=256`: a tone with `pos=255` (i.e., `freq` in 4080–4094) would have `(255)+1=256`, which is not `<256`, so the guard blocks it. The theoretical maximum reachable `pos` is 254.

## PoC Strategy

The PoC targets `pos=254` (`freq=4079`, `group=0`) — the highest allowed value:

- `(4079 >> 4) + 1 = 254 + 1 = 255 < 256` → guard passes, `add_tone()` is called
- `offset=16` (one while-loop trip in `read_wave_data`)
- `stereo_mode=1` (stereo channel 1)

This exercises `add_wave()` with the pointer offset as close to the buffer boundary as possible. Whether the loop itself overflows depends on runtime `fft_offset` alignment and the iteration count.

## File Format

- **Container:** QuickTime MOV
- **Codec:** QDMC (QDesign Music Codec 1)
- **Parameters:** 44100 Hz, stereo, `fft_size=256`, `checksum_size=512`
- **Extradata:** `frmaQDMC` + `QDCA` block (scanned by `qdmc_decode_init`)

## Packet Structure

```
bytes[0..3]  = 0x51 0x4D 0x43 0x01  (label: MKTAG('Q','M','C',1))
bytes[4..5]  = checksum (uint16 LE): 226 + sum(bytes[6..511]) mod 65536
bytes[6..]   = LE-bit-order bitstream: noise data + wave data
```

## Bitstream Contents

- **Noise:** 2 channels × 4 bands (band_index=4, noise_bands_size[4]=4)
- **Wave group 0:** one tone with `freq=4079`, `stereo_mode=1`, `amp=17`, `phase=0`; then a break-trigger frequency
- **Wave groups 1–4:** single large frequency value causing the while-loop to accumulate `pos2 >= frame_size` immediately

## Expected Result

Because the guard at line 476 prevents `pos=255` but allows `pos=254`, the OOB write described in the vulnerability report is **not directly triggerable** via a valid bitstream. The PoC will exercise the near-boundary path but is expected to complete without an ASAN crash. Status: **UNVERIFIED** (guard prevents exact trigger).
