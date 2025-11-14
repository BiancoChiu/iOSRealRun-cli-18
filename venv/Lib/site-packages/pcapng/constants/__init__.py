"""Generic contsnts"""

# Byte order magic numbers
# ----------------------------------------

ORDER_MAGIC_LE = 0x1A2B3C4D
ORDER_MAGIC_BE = 0x4D3C2B1A

SIZE_NOTSET = 0xFFFFFFFFFFFFFFFF  # 64bit "-1"

# Endianness constants

ENDIAN_NATIVE = 0  # '='
ENDIAN_LITTLE = 1  # '<'
ENDIAN_BIG = 2  # '>'
