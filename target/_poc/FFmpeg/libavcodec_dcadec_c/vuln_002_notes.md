# VULN 002 – OOB Read on `dca2wav[]` in `ff_dca_set_channel_layout`

## Vulnerability Location

File: `libavcodec/dcadec.c`  
Function: `ff_dca_set_channel_layout()`  
Arrays: `dca2wav_norm[28]` and `dca2wav_wide[28]` (both size 28)  

In the `CHANNEL_ORDER_CODED` path the function iterates `dca_ch` from 0 to
`DCA_SPEAKER_COUNT-1` (31) and accesses `dca2wav[dca_ch]` for every bit set
in `dca_mask`. If `dca_mask` has any of bits 28–31 set (corresponding to the
enum values `DCA_SPEAKER_RSV1..RSV4`), the array is read out-of-bounds.

## Trigger Mechanism

`-channel_order coded` sets `output_channel_order = CHANNEL_ORDER_CODED` in
the decoder. The `dca_mask` passed to `ff_dca_set_channel_layout` is
`s->request_mask`, which is derived from `s->ch_mask` of the core decoder.

By crafting the XXCH extension to add speakers at positions 28 and 29, the
combined `s->ch_mask` becomes `0x30000001`, which causes the OOB read.

## PoC Strategy

### File Format

```
[Core Frame 512 bytes][EXSS 130 bytes]
```

### Core Frame (512 bytes)

- MONO audio (audio_mode=0), 48 kHz sample rate, 1 subframe
- `ext_audio_present = 0` — prevents the CSS XXCH extension search in
  `parse_optional_info()`, which performs a **mandatory** CRC check that
  would reject the crafted data
- All subband `bit_allocation = 0` → no audio sample bits needed
- DSYNC marker `0xffff` at end of the single sub-subframe

### EXSS + XXCH Extension (130 bytes)

An EXSS header at offset 512 with `static_fields_present=0` and
`coding_mode=0` / `extension_mask=DCA_EXSS_XXCH` points to a 100-byte XXCH
asset at offset 542.

Inside the XXCH frame:
- `xxch_mask_nbits = 32`
- `xxch_core_mask = 0x00000001` (matches MONO core `ch_mask`)
- `xxch_nchsets = 1`
- Channel set: `nchannels = 2`, `xxch_spkr_mask = 0x30000000` (raw 26-bit
  field = `0xC00000`, shifted left 6 → bits 28 and 29 set)
- `popcount(xxch_spkr_mask) == 2 == nchannels` ✓  (≤ DCA_XXCH_CHANNELS_MAX)
- No overlap between `xxch_core_mask` and `xxch_spkr_mask` ✓

After successful XXCH parse:
```
s->ch_mask = xxch_core_mask | xxch_spkr_mask = 0x01 | 0x30000000 = 0x30000001
```

### CRC Avoidance

All CRC checks in the EXSS and XXCH paths use `ff_dca_check_crc()`, which
immediately returns 0 unless `avctx->err_recognition & (AV_EF_CRCCHECK |
AV_EF_CAREFUL)`. FFmpeg's default is `err_recognition = 0`, so every CRC
check is a no-op.

The mandatory `av_crc()` in the CSS XXCH search (`parse_optional_info()`) is
avoided entirely by setting `ext_audio_present = 0` in the core header.

### OOB Read

`ff_dca_set_channel_layout` is called from `ff_dca_core_filter_frame()` with
`dca_mask = s->request_mask` derived from `s->ch_mask = 0x30000001`:

```c
for (int dca_ch = 0; dca_ch < DCA_SPEAKER_COUNT; dca_ch++) {  // 0..31
    if (dca_mask & (1 << dca_ch)) {
        ch_remap[nchannels++] = dca2wav[dca_ch];  // OOB when dca_ch=28,29
    }
}
```

`dca2wav` (either `dca2wav_norm` or `dca2wav_wide`) has only 28 elements.
Accessing indices 28 and 29 reads memory past the array.

## Reproduction

```bash
# Generate crafted input
python3 vuln_002_gen.py

# Run with ASAN
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg \
  -channel_order coded -i vuln_002_input.dca -f null -
```

Or simply:
```bash
bash vuln_002_run.sh
```
