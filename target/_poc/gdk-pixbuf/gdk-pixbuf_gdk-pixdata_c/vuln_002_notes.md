# VULN-002: Integer Overflow in gdk_pixdata_from_pixbuf() — Heap Buffer Overflow

**File:** `gdk-pixbuf/gdk-pixdata.c`, lines 349, 371–373, 375–377  
**CWE:** CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow)  
**Severity:** High (heap corruption via overflow)

---

## Vulnerability Description

### Root Cause (gdk-pixdata.c)

```c
// Line 349
guint pad, n_bytes = rowstride * height;   // OVERFLOW: guint * guint (32-bit)

// If n_bytes % bpp != 0 (alternate path, lines 353-369):
//   rowstride = pixbuf->width * bpp;      // potential signed int overflow (UBSAN)
//   n_bytes   = rowstride * height;       // recalculated; may wrap again
//   data      = g_malloc (n_bytes);       // allocates wrapped (tiny) size
//   gdk_pixbuf_copy_area(pixbuf, ...);    // READS full pixbuf into tiny buffer → OOB

// OR else path (lines 370-377):
//   pad  = rowstride;
//   pad  = MAX (pad, 130 + n_bytes / 127);
//   data = g_new (guint8, pad + n_bytes); // OVERFLOW: pad+n_bytes wraps, tiny allocation
//   rl_encode_rgbx(img_buffer,            // WRITES pixbuf pixels (n_bytes) to tiny buffer
//                  buf->pixels,
//                  buf->pixels + n_bytes,
//                  bpp);                  // → heap buffer overflow WRITE
```

### Why the Bug Exists

Both `rowstride` and `height` are `guint` (unsigned 32-bit). Their product can overflow
32-bit integer arithmetic, producing a value smaller than the actual number of bytes in the
image. Downstream operations then allocate a buffer based on the wrapped (small) `n_bytes`
but attempt to process the full image — causing either an OOB read or OOB write.

On 64-bit platforms, `g_try_malloc_n(height, rowstride)` uses `gsize` (64-bit), so the
allocation itself can be large (several GB) and succeed; however, the `guint * guint`
multiplication in `gdk_pixdata_from_pixbuf` uses only 32-bit arithmetic, creating the
incorrect smaller value.

---

## Exploit Chain (via `gdk-pixbuf-pixdata --rle`)

### Input Format

The binary accepts **GdkPixdata** (`.gdkp` / `.pixdata`) files — BMP is not compiled in.
The `--rle` flag is **required** to enter the vulnerable RLE encoding path.

### Trigger Parameters

| Field      | Value           | Notes                                              |
|------------|-----------------|-----------------------------------------------------|
| width      | 2               | Actual image width in pixels                        |
| height     | 3               | Actual image height                                 |
| rowstride  | 0x55555556      | = 1 431 655 766  (rowstride ≥ width: valid)         |
| bpp        | 4 (RGBA)        | has_alpha = True                                    |
| encoding   | RAW             | GDK_PIXDATA_ENCODING_RAW = 0x01000000               |

### Integer Overflow Calculation

```
rowstride * height  [32-bit unsigned]
  = 1431655766 * 3
  = 4294967298
  = 0x1_00000002           (64-bit)
  = 0x00000002   (mod 2^32, 32-bit truncation)   <-- n_bytes = 2
```

### Step-by-Step Crash Path

1. **File load** (`gdk_pixbuf_new_from_file` → pixdata loader → `gdk_pixbuf_from_pixdata`):
   - `g_try_malloc_n(height=3, rowstride=0x55555556)` = `malloc(~4 GB)` — virtual allocation
     succeeds on 64-bit Linux with overcommit (confirmed: 32 GB swap available on test machine)
   - `memcpy(data, pixel_data, rowstride * height [32-bit] = 2)` — copies only **2 bytes**
   - `gdk_pixbuf_new_from_data(data, ..., width=2, height=3, rowstride=0x55555556, ...)`
   - **Result:** pixbuf with `pixels` pointing to a **2-byte buffer** but claiming 3 rows × 0x55555556 rowstride

2. **gdk_pixdata_from_pixbuf(pixbuf, use_rle=TRUE)** called by the binary:
   - `n_bytes = rowstride * height [guint32] = 2`  (same 32-bit wrap)
   - `n_bytes % bpp = 2 % 4 = 2 ≠ 0`  → **alternate path** taken (lines 353–369)
   - `new_n_bytes = pixbuf->width * bpp * height = 2 * 4 * 3 = 24`
   - `data = g_malloc(24)` — allocates 24-byte RLE workspace buffer
   - `gdk_pixbuf_copy_area(pixbuf, 0, 0, 2, 3, buf, 0, 0)`:
     - Tries to read `width * height * bpp = 24` bytes from `pixbuf->pixels`
     - `pixbuf->pixels` only holds **2 bytes**
     - **→ ASAN: heap-buffer-overflow READ of size 22** (reads 24, allocated 2)

### Memory Layout at Crash

```
pixbuf->pixels  [ASAN-tracked: 2 bytes]
  [0x00] 0xDE
  [0x01] 0xAD
  ~~~ ASAN RED ZONE ~~~
  [0x02] <-- gdk_pixbuf_copy_area reads here: HEAP BUFFER OVERFLOW
  ...
  [0x17] <-- gdk_pixbuf_copy_area reads here: OOB +22 bytes
```

---

## File Format

The GdkPixdata binary format (all fields big-endian / network byte order):

```
Offset  Size  Field
     0     4  magic        = 0x47646b50  ('GdkP')
     4     4  length       = 26  (header 24 + pixel_data 2)
     8     4  pixdata_type = 0x01010002  (RGBA, 8-bit, RAW)
    12     4  rowstride    = 0x55555556
    16     4  width        = 2
    20     4  height       = 3
    24     2  pixel_data   = 0xDE 0xAD   (2 bytes of arbitrary pixel data)
```

**Total file size: 26 bytes.**

---

## Limitations / Notes

- The crash is in `gdk_pixbuf_copy_area` (called from `gdk_pixdata_from_pixbuf`'s alternate
  path), triggered by the integer overflow in line 349 of gdk-pixdata.c.
- The ~4 GB virtual allocation from `g_try_malloc_n` must succeed. This is typical on 64-bit
  Linux with overcommit enabled and sufficient swap space.  If the allocation fails (e.g. on
  a constrained system), `gdk_pixbuf_from_pixdata` returns NULL and the binary exits cleanly
  with "failed to load".
- The binary does **not** support BMP format. Only GdkPixdata (`.gdkp`) files work.
- The `--rle` flag **must** be passed to enter `gdk_pixdata_from_pixbuf`'s RLE path; without
  it, `gdk_pixdata_from_pixbuf` uses RAW encoding and returns without touching any buffer.

---

## PoC Files

| File                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `vuln_002_gen.py`     | Generates `vuln_002.pixdata` (26 bytes)          |
| `vuln_002.pixdata`    | The crafted trigger file                         |
| `vuln_002_run.sh`     | Runs the binary and captures ASAN output         |
| `vuln_002_result.txt` | stdout/stderr from the binary                    |
| `asan_002.log.*`      | ASAN report (if crash occurred)                  |
| `vuln_002_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR              |
| `vuln_002_notes.md`   | This file                                        |
