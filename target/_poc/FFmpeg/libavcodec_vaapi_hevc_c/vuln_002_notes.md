# VULN 002 - SKIPPED

## Vulnerability
**VAAPI HEVC tile row-height OOB heap write** in `vaapi_hevc_start_frame()` (libavcodec/vaapi_hevc.c, lines 223-224), CWE-787.

## Reason for Skipping

VAAPI hardware acceleration is not available on this system. The PoC requires:

1. A `/dev/dri/renderD*` device backed by a VAAPI-capable GPU (Intel or AMD with VAAPI support)
2. The `vainfo` tool (or equivalent) reporting at least one VAAPI profile
3. The FFmpeg binary compiled with VAAPI support and the `vaapi` entry visible in `-hwaccels`

### Checks performed

```
$ ls /dev/dri/
by-path  card0  card1  card2  renderD128  renderD129

$ vainfo 2>/dev/null || echo "NO VAAPI"
NO VAAPI

$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels 2>&1 | grep vaapi || echo "NO VAAPI IN FFMPEG"
NO VAAPI IN FFMPEG
```

Although `/dev/dri/` DRI render nodes exist (renderD128, renderD129), `vainfo` produced no output indicating no VAAPI-capable driver is installed or functioning. Additionally, the pre-built FFmpeg binary was not compiled with VAAPI support (`vaapi` absent from `-hwaccels` output).

## How to Reproduce (on a VAAPI-capable system)

The trigger command is:
```
ffmpeg -hwaccel vaapi -i malicious.hevc -f null -
```

where `malicious.hevc` is a crafted bitstream with:
- `tiles_enabled_flag = 1`
- `num_tile_rows_minus1 = 21` (num_tile_rows = 22)
- Resolution at least 704 pixels tall so `ctb_height = ceil(704/32) = 22`

This causes `vaapi_hevc_start_frame()` to iterate `i < pps->num_tile_rows` (22 iterations) writing into `pic_param->row_height_minus1[]`, which has only 21 elements (indices 0-20), resulting in a one-element out-of-bounds write of a `uint16_t` value at index 21.

## Affected Code

File: `libavcodec/vaapi_hevc.c`, lines 223-224:
```c
for (i = 0; i < pps->num_tile_rows; i++)
    pic_param->row_height_minus1[i] = pps->row_height[i] - 1;
```

The VA-API `VAPictureParameterBufferHEVC` struct defines `row_height_minus1[21]`, but `num_tile_rows` can reach 22 when `num_tile_rows_minus1 = 21` is set in the PPS without a bounds check against `HEVC_MAX_TILE_ROWS`.
