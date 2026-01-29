"""Ladon encryption module for X-Ladon header generation."""
from typing import Dict, Optional, Union
from os import urandom
import base64
import ctypes
import hashlib
import time


class Ladon:
    """Ladon encryption class for generating X-Ladon authentication headers."""
    
    @staticmethod
    def _md5bytes(data: bytes) -> str:
        """Generate MD5 hex digest from bytes."""
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def _padding_size(size: int, block_size: int = 16) -> int:
        """Calculate padded size for block alignment."""
        return ((size + block_size - 1) // block_size) * block_size
    
    @staticmethod
    def _pkcs7_pad(buffer: bytearray, data_size: int, padded_size: int, block_size: int) -> None:
        """Apply PKCS7 padding to buffer."""
        padding_value = padded_size - data_size
        for i in range(data_size, padded_size):
            buffer[i] = padding_value
    
    @staticmethod
    def _validate(num: int) -> int:
        """Mask integer to 64-bit unsigned."""
        return num & 0xFFFFFFFFFFFFFFFF
    
    @staticmethod
    def _ror(value: ctypes.c_ulonglong, count: int) -> int:
        """Rotate right operation for 64-bit value."""
        nbits = ctypes.sizeof(value) * 8
        count %= nbits
        low = ctypes.c_ulonglong(value.value << (nbits - count)).value
        value = ctypes.c_ulonglong(value.value >> count).value
        return value or low
    
    @staticmethod
    def _encrypt_ladon_input(hash_table: bytes, input_data: bytes) -> bytes:
        """Encrypt 16-byte input block using Ladon algorithm."""
        data0 = int.from_bytes(input_data[:8], byteorder="little")
        data1 = int.from_bytes(input_data[8:], byteorder="little")
        for i in range(0x22):
            hash_val = int.from_bytes(hash_table[i * 8 : (i + 1) * 8], byteorder="little")
            data1 = Ladon._validate(hash_val ^ (data0 + ((data1 >> 8) | (data1 << (64 - 8)))))
            data0 = Ladon._validate(data1 ^ ((data0 >> 0x3D) | (data0 << (64 - 0x3D))))
        output_data = bytearray(26)
        output_data[:8] = data0.to_bytes(8, byteorder="little")
        output_data[8:] = data1.to_bytes(8, byteorder="little")
        return bytes(output_data)
    
    @staticmethod
    def _encrypt_ladon(md5hex: bytes, data: bytes, size: int) -> bytearray:
        """Core Ladon encryption routine."""
        hash_table = bytearray(272 + 16)
        hash_table[:32] = md5hex
        temp = []
        for i in range(4):
            temp.append(int.from_bytes(hash_table[i * 8 : (i + 1) * 8], byteorder="little"))
        buffer_b0 = temp[0]
        buffer_b8 = temp[1]
        temp.pop(0)
        temp.pop(0)
        for i in range(0x22):
            x9 = buffer_b0
            x8 = buffer_b8
            x8 = Ladon._validate(Ladon._ror(ctypes.c_ulonglong(x8), 8))
            x8 = Ladon._validate(x8 + x9)
            x8 = Ladon._validate(x8 ^ i)
            temp.append(x8)
            x8 = Ladon._validate(x8 ^ Ladon._ror(ctypes.c_ulonglong(x9), 61))
            hash_table[i * 8 + 8 : (i + 1) * 8 + 8] = x8.to_bytes(8, byteorder="little")
            buffer_b0 = x8
            buffer_b8 = temp[0]
            temp.pop(0)
        new_size = Ladon._padding_size(size)
        input_buf = bytearray(new_size)
        input_buf[:size] = data
        Ladon._pkcs7_pad(input_buf, size, new_size, 16)
        output = bytearray(new_size)
        for i in range(new_size // 16):
            output[i * 16 : (i + 1) * 16] = Ladon._encrypt_ladon_input(
                hash_table, input_buf[i * 16 : (i + 1) * 16]
            )
        return output
    
    @staticmethod
    def encrypt(
        aid: Union[int, str] = 1233,
        lc_id: Union[int, str] = 2142840551,
        unix: Optional[int] = None
    ) -> Dict[str, str]:
        """Generate X-Ladon header for TikTok API authentication.
        
        Args:
            aid: Application ID, can be int or str. Defaults to 1233.
            lc_id: License ID for authentication. Defaults to 2142840551.
            timestamp: Unix timestamp in seconds. Defaults to current time.
        
        Returns:
            Dictionary containing 'x-ladon' header value.
        """
        aid = int(aid) if isinstance(aid, str) else aid
        lc_id = int(lc_id) if isinstance(lc_id, str) else lc_id
        ts = unix if unix is not None else int(time.time())
        data = f"{ts}-{lc_id}-{aid}"
        random_bytes = urandom(4)
        keygen = random_bytes + str(aid).encode()
        md5hex = Ladon._md5bytes(keygen)
        size = len(data)
        new_size = Ladon._padding_size(size)
        output = bytearray(new_size + 4)
        output[:4] = random_bytes
        output[4:] = Ladon._encrypt_ladon(md5hex.encode(), data.encode(), size)
        return {"x-ladon": base64.b64encode(bytes(output)).decode()}