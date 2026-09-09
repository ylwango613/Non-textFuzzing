# VULN 001 - qsv_export_film_grain OOB Write - PoC Notes

## Status: SKIPPED

## Reason

This vulnerability cannot be triggered on the current system. The following conditions explain why:

### 1. Vulnerable Code Path Requires Intel QSV Hardware

The vulnerable function `qsv_export_film_grain()` (lines 654-672 in `libavcodec/qsvdec.c`) is only reachable through the `av1_qsv` hardware decoder. This decoder is part of Intel's Quick Sync Video (QSV) framework and requires:

- An Intel GPU (6th generation "Skylake" or later) with hardware video decode capabilities
- The Intel oneVPL (Video Processing Library) runtime version >= 1.34, or the legacy Intel Media SDK (MFX SDK) installed on the system

### 2. QSV Not Available in This Build

Verification commands confirm absence of QSV support:

```
$ ffmpeg -codecs 2>/dev/null | grep -i qsv
(no output)

$ ffmpeg -hwaccels 2>/dev/null
Hardware acceleration methods:
(empty list)
```

Neither `av1_qsv` nor any other QSV codec appears in the available codec list, and no hardware accelerators are registered. This means FFmpeg was either built without QSV support, or the required Intel runtime libraries are absent at runtime.

### 3. Software AV1 Decoders Do Not Call the Vulnerable Function

The standard software AV1 decoders available in FFmpeg (such as the built-in `av1` decoder or `libdav1d`) do not invoke `qsv_export_film_grain()`. That function is defined in `qsvdec.c` and is specific to the QSV decoder pipeline. The call chain is:

```
av1_qsv decoder (QSV hardware path only)
  -> qsv_decode_frame()
    -> qsv_export_film_grain()   <-- VULNERABLE FUNCTION
```

Passing a crafted AV1 file with `num_y_points=15` (exceeding the AV1 spec maximum of 14) through a software decoder would not reach this code.

### 4. Root Cause Summary

The bug is an out-of-bounds write (CWE-787). The `num_y_points` field in the AV1 film grain parameters is a 4-bit value allowing values 0-15, but the AV1 specification caps valid values at 14. The QSV export function allocates a fixed-size array indexed by this field without validating against the spec maximum, so a value of 15 causes a one-element write beyond the array bounds.

## Trigger Command (if QSV were available)

```bash
ffmpeg -export_side_data +film_grain -c:v av1_qsv -i crafted.av1 -f null -
```

where `crafted.av1` contains a film grain OBU with `num_y_points = 0b1111` (15).

## Prerequisites to Reproduce

1. A host machine with an Intel GPU (Skylake/Gen9 or newer)
2. Intel oneVPL runtime >= 1.34 installed (package `intel-media-va-driver-non-free` or equivalent)
3. FFmpeg built with `--enable-libvpl` or `--enable-libmfx`
4. A crafted AV1 stream with `num_y_points=15` in a film grain metadata OBU
