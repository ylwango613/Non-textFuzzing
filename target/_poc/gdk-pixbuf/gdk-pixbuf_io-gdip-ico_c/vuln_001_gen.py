#!/usr/bin/env python3
# VULN 001 - Heap OOB Read in gdip_bitmap_get_frame_delay via Wrong item_count Calculation
# File: gdk-pixbuf/io-gdip-utils.c lines 493-497
#
# STATUS: SKIPPED
#
# REASON: The io-gdip-ico.c / io-gdip-utils.c loaders use the Windows GDI+ API
# (GdipGetPropertyItemSize, GdipGetPropertyItem, etc.) which is not available
# on Linux. This vulnerability is Windows-only.
#
# On this Linux build, gdk-pixbuf uses its native ICO loader (io-ico.c) instead
# of the GDI+ ICO loader. The symbols for gdip_bitmap_get_frame_delay and
# related GDI+ functions are absent from the compiled library.
#
# What the PoC would do (Windows only):
#   - Craft an animated ICO or GIF with N frames
#   - Embed a PropertyTagFrameDelay EXIF property with fewer than N delay entries
#   - Trigger gdip_bitmap_get_frame_delay() for a frame index >= actual delay count
#   - The bug: item_count = item_size / sizeof(long) uses the total PropertyItem
#     struct size (header + data), not just the data length (item->length),
#     inflating item_count beyond the actual number of delay entries.
#   - With a crafted file where frame < inflated_item_count but
#     frame >= actual_delay_count, the code reads ((long*)item->value)[frame]
#     past the end of the allocated delay array => heap OOB read.
#
# This file is a stub. No file is generated because the loader is not present.

import sys

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_io-gdip-ico_c"

print("SKIPPED: io-gdip-ico / io-gdip-utils GDI+ loader is not compiled into this Linux build.")
print("The vulnerability (VULN 001) requires Windows GDI+ (GdipGetPropertyItemSize, etc.).")
print("No test file generated.")
sys.exit(0)
