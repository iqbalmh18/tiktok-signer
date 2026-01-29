"""SM3 cryptographic hash function implementation."""
from typing import List, Union


class SM3:
    """SM3 hash algorithm implementation (Chinese national standard GB/T 32905-2016)."""
    
    IV: List[int] = [
        1937774191, 1226093241, 388252375, 3666478592,
        2842636476, 372324522, 3817729613, 2969243214
    ]
    TJ: List[int] = [
        2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042
    ]
    
    def __init__(self) -> None:
        """Initialize SM3 hash instance."""
        pass
    
    def _rotate_left(self, a: int, k: int) -> int:
        """Rotate 32-bit integer left by k positions."""
        k = k % 32
        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))
    
    def _ffj(self, x: int, y: int, z: int, j: int) -> int:
        """FF function for SM3 compression."""
        if 0 <= j < 16:
            return x ^ y ^ z
        return (x & y) | (x & z) | (y & z)
    
    def _ggj(self, x: int, y: int, z: int, j: int) -> int:
        """GG function for SM3 compression."""
        if 0 <= j < 16:
            return x ^ y ^ z
        return (x & y) | ((~x) & z)
    
    def _p0(self, x: int) -> int:
        """P0 permutation function."""
        return x ^ self._rotate_left(x, 9) ^ self._rotate_left(x, 17)
    
    def _p1(self, x: int) -> int:
        """P1 permutation function."""
        return x ^ self._rotate_left(x, 15) ^ self._rotate_left(x, 23)
    
    def _cf(self, v_i: List[int], b_i: bytearray) -> List[int]:
        """Compression function for one 512-bit block."""
        w = []
        for i in range(16):
            weight = 0x1000000
            data = 0
            for k in range(i * 4, (i + 1) * 4):
                data = data + b_i[k] * weight
                weight = int(weight / 0x100)
            w.append(data)
        for j in range(16, 68):
            w.append(0)
            w[j] = (
                self._p1(w[j - 16] ^ w[j - 9] ^ self._rotate_left(w[j - 3], 15))
                ^ self._rotate_left(w[j - 13], 7)
                ^ w[j - 6]
            )
        w_1 = []
        for j in range(64):
            w_1.append(w[j] ^ w[j + 4])
        a, b, c, d, e, f, g, h = v_i
        for j in range(64):
            ss1 = self._rotate_left(
                (self._rotate_left(a, 12) + e + self._rotate_left(self.TJ[j], j)) & 0xFFFFFFFF,
                7,
            )
            ss2 = ss1 ^ self._rotate_left(a, 12)
            tt1 = (self._ffj(a, b, c, j) + d + ss2 + w_1[j]) & 0xFFFFFFFF
            tt2 = (self._ggj(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = self._rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = self._rotate_left(f, 19)
            f = e
            e = self._p0(tt2)
        return [
            a & 0xFFFFFFFF ^ v_i[0],
            b & 0xFFFFFFFF ^ v_i[1],
            c & 0xFFFFFFFF ^ v_i[2],
            d & 0xFFFFFFFF ^ v_i[3],
            e & 0xFFFFFFFF ^ v_i[4],
            f & 0xFFFFFFFF ^ v_i[5],
            g & 0xFFFFFFFF ^ v_i[6],
            h & 0xFFFFFFFF ^ v_i[7],
        ]
    
    def encrypt(self, msg: Union[bytes, bytearray]) -> bytes:
        """Compute SM3 hash of message.
        
        Args:
            msg: Message to hash as bytes or bytearray.
        
        Returns:
            32-byte hash digest.
        """
        msg = bytearray(msg)
        len1 = len(msg)
        reserve1 = len1 % 64
        msg.append(0x80)
        reserve1 = reserve1 + 1
        range_end = 56
        if reserve1 > range_end:
            range_end += 64
        for _ in range(reserve1, range_end):
            msg.append(0x00)
        bit_length = len1 * 8
        bit_length_str = [bit_length % 0x100]
        for _ in range(7):
            bit_length = int(bit_length / 0x100)
            bit_length_str.append(bit_length % 0x100)
        for i in range(8):
            msg.append(bit_length_str[7 - i])
        group_count = round(len(msg) / 64)
        b = []
        for i in range(group_count):
            b.append(msg[i * 64 : (i + 1) * 64])
        v = [self.IV]
        for i in range(group_count):
            v.append(self._cf(v[i], b[i]))
        y = v[group_count]
        res = b""
        for item in y:
            res += int(item).to_bytes(4, "big")
        return res