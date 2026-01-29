"""Argus encryption module for X-Argus header generation."""
from typing import Dict, Optional, Union
from urllib.parse import parse_qs, urlencode
from hashlib import md5
from struct import unpack
from random import randint
from base64 import b64encode
from time import time
from uuid import uuid4
from Crypto.Util.Padding import pad
from Crypto.Cipher.AES import MODE_CBC, block_size, new
from tiktok_signer.lib.utils.protobuf import ProtoBuf
from tiktok_signer.lib.utils.simon import Simon
from tiktok_signer.lib.utils.sm3 import SM3


class Argus:
    """Argus encryption class for generating X-Argus authentication headers."""
    
    _simon = Simon()
    _sm3 = SM3()

    DEFAULT_AID: int = 1233
    DEFAULT_LC_ID: int = 2142840551
    DEFAULT_SDK_VER: str = "v05.01.02-alpha.7-ov-android"
    DEFAULT_SDK_VER_CODE: int = 83952160
    DEFAULT_APP_VER: str = "37.0.4"
    DEFAULT_VERSION_CODE: int = 2023700040
    DEFAULT_CHANNEL: str = "googleplay"
    DEFAULT_DEVICE_TYPE = "unknown"
    DEFAULT_OS_VERSION: str = "9"
    
    @staticmethod
    def _encrypt_enc_pb(data: bytes, length: int) -> bytes:
        """Encrypt protobuf data with XOR pattern."""
        data_list = list(data)
        xor_array = data_list[:8]
        for i in range(8, length):
            data_list[i] ^= xor_array[i % 8]
        return bytes(data_list[::-1])
    
    @staticmethod
    def _get_bodyhash(stub: Optional[str] = None) -> bytes:
        """Generate body hash from stub using SM3."""
        if stub is None or len(stub) == 0:
            return Argus._sm3.encrypt(bytes(16))[0:6]
        return Argus._sm3.encrypt(bytes.fromhex(stub))[0:6]
    
    @staticmethod
    def _get_queryhash(query: str) -> bytes:
        """Generate query hash using SM3."""
        if query is None or len(query) == 0:
            return Argus._sm3.encrypt(bytes(16))[0:6]
        return Argus._sm3.encrypt(query.encode())[0:6]
    
    @staticmethod
    def _calculate_xargus(xargus_bean: dict) -> str:
        """Calculate X-Argus signature from bean data."""
        protobuf = pad(bytes.fromhex(ProtoBuf(xargus_bean).toBuf().hex()), block_size)
        new_len = len(protobuf)
        sign_key = b"\xac\x1a\xda\xae\x95\xa7\xaf\x94\xa5\x11J\xb3\xb3\xa9}\xd8\x00P\xaa\n91L@R\x8c\xae\xc9RV\xc2\x8c"
        sm3_output = b"\xfcx\xe0\xa9ez\x0ct\x8c\xe5\x15Y\x90<\xcf\x03Q\x0eQ\xd3\xcf\xf22\xd7\x13C\xe8\x8a2\x1cS\x04"
        key = sm3_output[:32]
        key_list = []
        enc_pb = bytearray(new_len)
        for i in range(2):
            key_list.extend(list(unpack("<QQ", key[i * 16 : i * 16 + 16])))
        for i in range(int(new_len / 16)):
            pt = list(unpack("<QQ", protobuf[i * 16 : i * 16 + 16]))
            ct = Argus._simon.encrypt(pt, key_list)
            enc_pb[i * 16 : i * 16 + 8] = ct[0].to_bytes(8, byteorder="little")
            enc_pb[i * 16 + 8 : i * 16 + 16] = ct[1].to_bytes(8, byteorder="little")
        b_buffer = Argus._encrypt_enc_pb((b"\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff" + enc_pb), new_len + 8)
        b_buffer = b"\xa6n\xad\x9fw\x01\xd0\x0c\x18" + b_buffer + b"ao"
        cipher = new(md5(sign_key[:16]).digest(), MODE_CBC, md5(sign_key[16:]).digest())
        return b64encode(b"\xf2\x81" + cipher.encrypt(pad(b_buffer, block_size))).decode("utf-8")
    
    @staticmethod
    def _calculate_app_version(app_ver: str) -> int:
        """Calculate app version hash from version string.
        
        Args:
            app_ver: App version string in format "major.minor.patch" (e.g., "37.0.4").
        
        Returns:
            Calculated version hash.
        """
        parts = app_ver.split(".")
        app_version_hash = bytes.fromhex(
            "{:x}{:x}{:x}00".format(
                int(parts[2]) * 4,
                int(parts[1]) * 16,
                int(parts[0]) * 4
            ).zfill(8)
        )
        return int.from_bytes(app_version_hash, byteorder="big") << 1
    
    @staticmethod
    def encrypt(
        params: Union[str, Dict],
        data: Optional[Union[str, Dict, bytes]] = None,
        unix: Optional[int] = None,
        device_id: Optional[str] = None,
        aid: Union[str, int] = 1233,
        lc_id: Union[str, int] = 2142840551,
        sdk_ver: str = "v05.01.02-alpha.7-ov-android",
        sdk_ver_code: Union[str, int] = 83952160,
        app_ver: str = "37.0.4",
        version_code: Union[str, int] = 2023700040,
    ) -> Dict[str, str]:
        """Generate X-Argus header for TikTok API authentication.
        
        Args:
            params (str | dict): URL query parameters.
            data (str | dict | bytes): Request body for POST requests.
            unix (int): Unix timestamp in seconds. Defaults to current time.
            device_id (str): Device identifier.
            aid (str | int): Application ID.
            lc_id (str | int): License ID.
            sdk_ver (str): SDK version (e.g., "v05.01.02-alpha.7-ov-android").
            sdk_ver_code (str | int): SDK version code.
            app_ver (str): App version (e.g., "37.0.4").
            version_code (str | int): App version code (e.g., 2023700040).
        
        Returns:
            dict: 'x-argus' header value.
        """
        aid = int(aid) if isinstance(aid, str) else aid
        lc_id = int(lc_id) if isinstance(lc_id, str) else lc_id
        sdk_ver_code = int(sdk_ver_code) if isinstance(sdk_ver_code, str) else sdk_ver_code
        version_code = int(version_code) if isinstance(version_code, str) else version_code
        ts = unix if unix is not None else int(time())
        if isinstance(params, dict):
            params_str = urlencode(params)
        else:
            params_str = str(params)
        params_dict = parse_qs(params_str)
        channel = params_dict.get("channel", [Argus.DEFAULT_CHANNEL])[0]
        device_id = params_dict.get("device_id", uuid4().hex[:16])[0]
        device_type = params_dict.get("device_type", [Argus.DEFAULT_DEVICE_TYPE])[0]
        os_version = params_dict.get("os_version", [Argus.DEFAULT_OS_VERSION])[0]
        # Get app_version from params or use provided/default value
        app_ver = params_dict.get("app_version", [app_ver])[0]
        stub = None
        if data is not None:
            from tiktok_signer.lib.stub import generate_stub
            stub_hash = generate_stub(data)
            stub = stub_hash
        xargus_bean = {
            1: 0x20200929 << 1,
            2: 2,
            3: randint(0, 0x7FFFFFFF),
            4: str(aid),
            5: device_id,
            6: str(lc_id),
            7: sdk_ver,
            8: sdk_ver,
            9: sdk_ver_code,
            10: bytes(8),
            11: "android",
            12: ts << 1,
            13: Argus._get_bodyhash(stub),
            14: Argus._get_queryhash(params_str),
            15: {1: 85, 2: 85, 3: 85, 5: 85, 6: 170, 7: (ts << 1) - 310},
            16: device_id,
            20: "none",
            21: 738,
            23: {
                1: device_type,
                2: os_version,
                3: channel,
                4: Argus._calculate_app_version(app_ver),
            },
            25: 2,
        }
        return {"x-argus": Argus._calculate_xargus(xargus_bean)}