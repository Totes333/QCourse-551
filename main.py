# Hashing a block header and checking valid
# Bitcoin block hashes using hashlib package.
# This will be used to check if hashes from
# Grover Search is valid
#
# Advaith Cheruvu
import hashlib

# Block header data (80 bytes)
block_header = b'\x00\x00\x00\x20'  # Version
block_header += bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')  # Previous Block Hash
block_header += bytes.fromhex('0b09e8fbdce74a149b54f07e53e45ea0b785c2d25a292a21c92737d6d943bb25')  # Merkle Root
block_header += b'\x63d96b5c'  # Timestamp
block_header += b'\x1a0944e3'  # Bits (Difficulty)
block_header += b'\x1c504c2f'  # 32 bit Nonce

# Calculate double SHA-256 hash
first_sha256 = hashlib.sha256(block_header).digest()
block_hash = hashlib.sha256(first_sha256).digest()

# Define the current target value (as a hexadecimal string)
current_target = '00000000000000000123456789abcdef1234567890abcdef0000000000000000'

# Compare the hash to the target
if int.from_bytes(block_hash, byteorder='big') <= int(current_target, 16):
    print("Valid Bitcoin block hash.")
else:
    print("Invalid Bitcoin block hash.")
