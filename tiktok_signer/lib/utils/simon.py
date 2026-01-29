"""Simon block cipher implementation for TikTok encryption."""
from typing import List
from ctypes import c_ulonglong


class Simon:
    """Simon 128/256 block cipher implementation."""
    
    CONSTANT: int = 0x3DC94C3A046D678B
    ROUNDS: int = 72
    
    @staticmethod
    def get_bit(val: int, pos: int) -> int:
        """Extract bit at position from value."""
        return 1 if val & (1 << pos) else 0
    
    @staticmethod
    def rotate_left(v: int, n: int) -> int:
        """Rotate 64-bit value left by n positions."""
        r = (v << n) | (v >> (64 - n))
        return r & 0xffffffffffffffff
    
    @staticmethod
    def rotate_right(v: int, n: int) -> int:
        """Rotate 64-bit value right by n positions."""
        r = (v << (64 - n)) | (v >> n)
        return r & 0xffffffffffffffff
    
    @staticmethod
    def key_expansion(key: List[int]) -> List[int]:
        """Expand 256-bit key to 72 round keys."""
        tmp = 0
        for i in range(4, Simon.ROUNDS):
            tmp = Simon.rotate_right(key[i - 1], 3)
            tmp = tmp ^ key[i - 3]
            tmp = tmp ^ Simon.rotate_right(tmp, 1)
            key[i] = c_ulonglong(~key[i - 4]).value ^ tmp ^ Simon.get_bit(Simon.CONSTANT, (i - 4) % 62) ^ 3
        return key
    
    @staticmethod
    def decrypt(ct: List[int], k: List[int], c: int = 0) -> List[int]:
        """Decrypt ciphertext block using Simon cipher.
        
        Args:
            ct: Ciphertext block as [x0, x1].
            k: Key as [k0, k1, k2, k3].
            c: Mode flag. Defaults to 0.
        
        Returns:
            Plaintext block as [x0, x1].
        """
        key = [0] * Simon.ROUNDS
        key[0] = k[0]
        key[1] = k[1]
        key[2] = k[2]
        key[3] = k[3]
        key = Simon.key_expansion(key)
        x_i = ct[0]
        x_i1 = ct[1]
        for i in range(Simon.ROUNDS - 1, -1, -1):
            tmp = x_i
            if c == 1:
                f = Simon.rotate_left(x_i, 1)
            else:
                f = Simon.rotate_left(x_i, 1) & Simon.rotate_left(x_i, 8)
            x_i = x_i1 ^ f ^ Simon.rotate_left(x_i, 2) ^ key[i]
            x_i1 = tmp
        return [x_i, x_i1]
    
    @staticmethod
    def encrypt(pt: List[int], k: List[int], c: int = 0) -> List[int]:
        """Encrypt plaintext block using Simon cipher.
        
        Args:
            pt: Plaintext block as [x0, x1].
            k: Key as [k0, k1, k2, k3].
            c: Mode flag. Defaults to 0.
        
        Returns:
            Ciphertext block as [x0, x1].
        """
        key = [0] * Simon.ROUNDS
        key[0] = k[0]
        key[1] = k[1]
        key[2] = k[2]
        key[3] = k[3]
        key = Simon.key_expansion(key)
        x_i = pt[0]
        x_i1 = pt[1]
        for i in range(Simon.ROUNDS):
            tmp = x_i1
            if c == 1:
                f = Simon.rotate_left(x_i1, 1)
            else:
                f = Simon.rotate_left(x_i1, 1) & Simon.rotate_left(x_i1, 8)
            x_i1 = x_i ^ f ^ Simon.rotate_left(x_i1, 2) ^ key[i]
            x_i = tmp
        return [x_i, x_i1]