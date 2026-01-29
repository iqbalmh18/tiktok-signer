"""Argus encryption module for X-Argus header generation."""
from typing import Dict, Optional, Union
from urllib.parse import parse_qs, urlencode
from hashlib import md5
from struct import unpack
from random import randint
from base64 import b64encode
from time import time
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
    DEFAULT_LICENSE_ID: int = 1611921764
    DEFAULT_SDK_VERSION_STR: str = "v05.00.03-ov-android"
    DEFAULT_SDK_VERSION: int = 167773760
    DEFAULT_VERSION_NAME: str = "37.0.4"
    DEFAULT_CHANNEL: str = "googleplay"
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
    def _calculate_app_version(version_name: str) -> int:
        """Calculate app version hash from version string."""
        parts = version_name.split(".")
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
        data: Optional[Union[str, bytes, Dict]] = None,
        timestamp: Optional[int] = None,
        aid: Union[int, str] = 1233,
        license_id: Union[int, str] = 1611921764,
        sec_device_id: str = "",
        sdk_version_str: str = "v05.00.03-ov-android",
        sdk_version: Union[int, str] = 167773760
    ) -> Dict[str, str]:
        """Generate X-Argus header for TikTok API authentication.
        
        Args:
            params: URL query parameters as string or dict.
            data: Request body data as string, bytes, or dict.
            timestamp: Unix timestamp in seconds. Defaults to current time.
            aid: Application ID. Defaults to 1233.
            license_id: License ID. Defaults to 1611921764.
            sec_device_id: Secure device identifier. Defaults to empty string.
            sdk_version_str: SDK version string. Defaults to "v05.00.03-ov-android".
            sdk_version: SDK version number. Defaults to 167773760.
        
        Returns:
            Dictionary containing 'x-argus' header value.
        """
        aid = int(aid) if isinstance(aid, str) else aid
        license_id = int(license_id) if isinstance(license_id, str) else license_id
        sdk_version = int(sdk_version) if isinstance(sdk_version, str) else sdk_version
        ts = timestamp if timestamp is not None else int(time())
        if isinstance(params, dict):
            params_str = urlencode(params)
        else:
            params_str = str(params)
        params_dict = parse_qs(params_str)
        channel = params_dict.get("channel", [Argus.DEFAULT_CHANNEL])[0]
        device_id = params_dict.get("device_id", [""])[0]
        device_type = params_dict.get("device_type", [""])[0]
        os_version = params_dict.get("os_version", [Argus.DEFAULT_OS_VERSION])[0]
        version_name = params_dict.get("version_name", [Argus.DEFAULT_VERSION_NAME])[0]
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
            6: str(license_id),
            7: version_name,
            8: sdk_version_str,
            9: sdk_version,
            10: bytes(8),
            11: "android",
            12: ts << 1,
            13: Argus._get_bodyhash(stub),
            14: Argus._get_queryhash(params_str),
            15: {1: 85, 2: 85, 3: 85, 5: 85, 6: 170, 7: (ts << 1) - 310},
            16: sec_device_id,
            20: "none",
            21: 738,
            23: {
                1: device_type,
                2: os_version,
                3: channel,
                4: Argus._calculate_app_version(version_name),
            },
            25: 2,
        }
        return {"x-argus": Argus._calculate_xargus(xargus_bean)}