"""Gorgon encryption module for X-Gorgon header generation."""
from typing import Dict, Optional, Union
from urllib.parse import urlencode
from copy import deepcopy
import hashlib
import time


class Gorgon:
    """Gorgon encryption class for generating X-Gorgon and X-Khronos headers."""
    
    LENGTH: int = 20
    HEX_STR: list = [30, 64, 224, 217, 147, 69, 0, 180]
    
    @staticmethod
    def _encryption() -> list:
        """Generate encryption lookup table."""
        tmp = ""
        hex_zu = list(range(256))
        for i in range(256):
            A = 0 if i == 0 else (tmp if tmp else hex_zu[i - 1])
            B = Gorgon.HEX_STR[i % 8]
            if A == 85 and i != 1 and tmp != 85:
                A = 0
            C = (A + i + B) % 256
            tmp = C if C < i else ""
            D = hex_zu[C]
            hex_zu[i] = D
        return hex_zu
    
    @staticmethod
    def _initialize(input_data: list, hex_zu: list) -> list:
        """Initialize input data with encryption table."""
        tmp_add = []
        tmp_hex = deepcopy(hex_zu)
        for i in range(Gorgon.LENGTH):
            A = input_data[i]
            B = tmp_add[-1] if tmp_add else 0
            C = (hex_zu[i + 1] + B) % 256
            tmp_add.append(C)
            D = tmp_hex[C]
            tmp_hex[i + 1] = D
            E = (D + D) % 256
            F = tmp_hex[E]
            G = A ^ F
            input_data[i] = G
        return input_data
    
    @staticmethod
    def _reverse(num: int) -> int:
        """Reverse nibbles in byte."""
        tmp_string = hex(num)[2:].zfill(2)
        return int(tmp_string[1:] + tmp_string[:1], 16)
    
    @staticmethod
    def _rbit(num: int) -> int:
        """Reverse bits in byte."""
        tmp_string = bin(num)[2:].zfill(8)
        return int("".join(reversed(tmp_string)), 2)
    
    @staticmethod
    def _handle(input_data: list) -> list:
        """Apply final transformation to input data."""
        for i in range(Gorgon.LENGTH):
            A = input_data[i]
            B = Gorgon._reverse(A)
            C = input_data[(i + 1) % Gorgon.LENGTH]
            D = B ^ C
            E = Gorgon._rbit(D)
            F = E ^ Gorgon.LENGTH
            G = ~F
            while G < 0:
                G += 4294967296
            H = int(hex(G)[-2:], 16)
            input_data[i] = H
        return input_data
    
    @staticmethod
    def _hex2string(num: int) -> str:
        """Convert number to 2-digit hex string."""
        return hex(num)[2:].zfill(2)
    
    @staticmethod
    def _calculate(gorgon: list) -> str:
        """Calculate final Gorgon signature."""
        result = ""
        for item in Gorgon._handle(Gorgon._initialize(gorgon, Gorgon._encryption())):
            result += Gorgon._hex2string(item)
        return "8404{}{}{}{}{}".format(
            Gorgon._hex2string(Gorgon.HEX_STR[7]),
            Gorgon._hex2string(Gorgon.HEX_STR[3]),
            Gorgon._hex2string(Gorgon.HEX_STR[1]),
            Gorgon._hex2string(Gorgon.HEX_STR[6]),
            result,
        )
    
    @staticmethod
    def encrypt(
        params: Union[str, Dict],
        headers: Optional[Dict] = None,
        cookie: Optional[str] = None,
        unix: Optional[int] = None
    ) -> Dict[str, str]:
        """Generate X-Gorgon and X-Khronos headers for TikTok API.
        
        Args:
            params: URL query parameters as string or dict.
            headers: Request headers dict containing x-ss-stub and/or cookie.
            cookie: Cookie string. If not provided, will use headers["cookie"].
            unix: Unix timestamp in seconds. If None, uses current time.
        
        Returns:
            Dictionary containing 'x-gorgon' and 'x-khronos' header values.
        """
        if isinstance(params, dict):
            params_str = urlencode(params)
        else:
            params_str = str(params)
        headers = headers if headers is not None else {}
        headers_lower = {k.lower(): v for k, v in headers.items()}
        if cookie is not None:
            headers_lower["cookie"] = cookie
        gorgon = []
        ts = unix if unix is not None else int(time.time())
        khronos = hex(ts)[2:]
        url_md5 = hashlib.md5(params_str.encode()).hexdigest()
        for i in range(4):
            gorgon.append(int(url_md5[2 * i : 2 * i + 2], 16))
        if "x-ss-stub" in headers_lower:
            data_md5 = headers_lower["x-ss-stub"]
            for i in range(4):
                gorgon.append(int(data_md5[2 * i : 2 * i + 2], 16))
        else:
            gorgon.extend([0] * 4)
        if "cookie" in headers_lower:
            cookie_md5 = hashlib.md5(headers_lower["cookie"].encode()).hexdigest()
            for i in range(4):
                gorgon.append(int(cookie_md5[2 * i : 2 * i + 2], 16))
        else:
            gorgon.extend([0] * 4)
        gorgon.extend([0] * 4)
        for i in range(4):
            gorgon.append(int(khronos[2 * i : 2 * i + 2], 16))
        return {"x-gorgon": Gorgon._calculate(gorgon), "x-khronos": str(ts)}

