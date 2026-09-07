# VULN-001: GdkPixdata RAW Decoder Heap OOB Read

## Summary

A heap out-of-bounds read in `gdk_pixdata_deserialize()` / `gdk_pixbuf_from_pixdata()` can be triggered by a crafted `.gdkp` (GdkPixdata) file with `length` set equal to `GDK_PIXDATA_HEADER_LENGTH` (24). The subsequent `memcpy` in `gdk_pixbuf_from_pixdata()` reads past the end of the allocated stream buffer.

## Affected Files

- `gdk-pixbuf/gdk-pixdata.c` — lines 235 (bounds check), 506 (memcpy)

## Root Cause

```c
// gdk-pixdata.c:235
if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)
    return_pixel_corrupt(error);
```

When `pixdata->length == 24` (= `GDK_PIXDATA_HEADER_LENGTH`), the subtraction `24 - 24 = 0`, so the guard becomes:

```
stream_length < 0   // always FALSE for an unsigned or non-negative stream_length
```

The check is bypassed even though zero pixel bytes were supplied. Then:

```c
// gdk-pixdata.c:506 (approximate)
memcpy(data, pixdata->pixel_data, rowstride * height);
```

`pixdata->pixel_data` points to offset 24 in the 24-byte buffer — one byte past the end. Reading `rowstride * height` bytes from that address is a heap buffer overflow (read).

## PoC File Layout (24 bytes, big-endian)

| Offset | Field         | Value      | Notes                          |
|--------|---------------|------------|--------------------------------|
| 0–3    | magic         | 0x47646b50 | "GdkP"                         |
| 4–7    | length        | 24         | = header only; triggers bypass |
| 8–11   | pixdata_type  | 0x01010001 | RGB, RAW, 8-bit                |
| 12–15  | rowstride     | 3          | width * 3 bytes                |
| 16–19  | width         | 1          |                                |
| 20–23  | height        | 1          |                                |
| 24+    | pixel_data    | (none)     | 0 bytes present                |

`memcpy` attempts to read `rowstride * height = 3` bytes from offset 24 of a 24-byte buffer.

## Crash Type

ASAN: **heap-buffer-overflow** (READ, 3 bytes past end of a 24-byte allocation)

## Reproduction

```bash
python3 vuln_001_gen.py   # writes vuln_001.gdkp (24 bytes)
bash vuln_001_run.sh      # runs gdk-pixbuf-pixdata under ASAN and captures result
```

## Impact

Attacker-controlled file path → heap OOB read. Depending on allocator layout, this can leak heap metadata or adjacent allocations, or be combined with other primitives for further exploitation. Affects any application that loads `.gdkp` files via gdk-pixbuf (e.g., GTK image viewers, GNOME applications).
