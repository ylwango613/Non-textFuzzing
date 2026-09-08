# PoC Notes: VULN-001 OOB Read in parse_avs3_nal_units

## Vulnerability Summary

In `libavcodec/avs3_parser.c`, function `parse_avs3_nal_units()` at line 68 checks
`buf_size < 5` before entering the sequence-header branch. With `buf_size == 5` (the
minimum that passes the check), there is only 1 byte of payload after the 4-byte start
code (`0x00 0x00 0x01 0xB0`).

At line 77, the code calls:
```c
init_get_bits(&gb, buf + 4, 100);
```

This declares a `GetBitContext` covering 100 bits (12.5 bytes) starting at `buf + 4`.
The subsequent `get_bits()` and `skip_bits()` calls consume:
- `get_bits(&gb, 8)` — profile (8 bits)
- `skip_bits(&gb, 47)` — 47 bits
- `get_bits(&gb, 3)` — sample_precision (3 bits, conditional)
- `skip_bits(&gb, 5)` — 5 bits
- `get_bits(&gb, 4)` — ratecode (4 bits)
- `skip_bits(&gb, 32)` — 32 bits
- `get_bits(&gb, 1)` — low_delay (1 bit)

Total: up to 100 bits = 12.5 bytes from `buf+4` through `buf+16`.
With only 1 byte of payload, bytes `buf+5` through `buf+16` are outside the buffer.

## Trigger Approach

The crafted file `vuln_001_input.avs3` contains exactly 5 bytes:
```
00 00 01 B0 20
```

- `00 00 01` — AVS3 start code prefix
- `B0` — AVS3_SEQ_START_CODE (Sequence Header unit type)
- `20` — 1 byte of payload

The key path to trigger the OOB without `ff_combine_frame` zero-padding is the
`PARSER_FLAG_COMPLETE_FRAMES` path, activated by using `-f avs3` (the raw AVS3 demuxer).
In this path, `avs3_parse()` sets `next = buf_size` and skips `ff_combine_frame`, passing
the raw unpadded buffer directly to `parse_avs3_nal_units()`.

## Expected ASAN Output

With the ASAN build at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`,
ASAN should report a `heap-buffer-overflow` or `global-buffer-overflow` on the
`get_bits`/`skip_bits` reads beyond the 1-byte payload buffer.
