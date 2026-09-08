The file `mjpegdec_common.c` is only 58 lines long. The two functions are:

1. **`build_huffman_codes`** (lines 29-39): Fills a `uint8_t huff_size[256]` with code lengths. Has `av_assert1(nb_codes <= 256)` which is a no-op in release builds. However, all callers of `ff_mjpeg_build_vlc` validate `n > 256` before calling (line 278, `ff_mjpeg_decode_dht`), and the `init_default_huffman_tables` path uses only fixed static tables with known-good sums.

2. **`ff_mjpeg_build_vlc`** (lines 41-57): Uses `huff_size[256]` and `huff_sym[256]` stack arrays, iterated 0..nb_codes-1. Since `nb_codes ≤ 256` is guaranteed by all callers, no OOB access is possible.

All callers of `ff_mjpeg_build_vlc` are:
- `ff_mjpeg_decode_dht` → validates `n > 256` before calling (line 278 of `mjpegdec.c`)
- `init_default_huffman_tables` → uses compile-time static Huffman tables
- `g2meet.c` → uses compile-time static Huffman tables

No reachable path allows attacker-controlled data to bypass the `n > 256` guard and reach the stack arrays with an out-of-bounds index.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
