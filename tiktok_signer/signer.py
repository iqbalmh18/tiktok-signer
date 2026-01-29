"""TikTok Signer - Main module for TikTok API authentication."""
from typing import Dict, Optional, Union
from urllib.parse import urlencode
from random import choice
from time import time

from tiktok_signer.lib.argus import Argus
from tiktok_signer.lib.ladon import Ladon
from tiktok_signer.lib.gorgon import Gorgon
from tiktok_signer.lib.stub import generate_stub
from tiktok_signer.lib.ttencrypt import TTEncrypt


class TikTokSigner:
    """TikTok API authentication signer with encryption support.
    
    This class provides complete TikTok Android API authentication including:
    - Request signing (Ladon, Gorgon, Argus)
    - Data encryption/decryption (TTEncrypt)
    """
    
    DEFAULT_AID: int = 1233
    DEFAULT_LC_ID: int = 2142840551
    DEFAULT_SDK_VER: str = "v05.01.02-alpha.7-ov-android"
    DEFAULT_SDK_VER_CODE: int = 83952160
    DEFAULT_APP_VER: str = "37.0.4"
    DEFAULT_VERSION_CODE: int = 2023700040
    
    _encryptor: Optional[TTEncrypt] = None
    
    @classmethod
    def _get_encryptor(cls) -> TTEncrypt:
        """Get or create TTEncrypt instance."""
        if cls._encryptor is None:
            cls._encryptor = TTEncrypt()
        return cls._encryptor
    
    @staticmethod
    def generate_headers(
        params: Union[str, Dict],
        data: Optional[Union[str, Dict, bytes]] = None,
        device_id: Optional[str] = None,
        aid: Union[str, int] = 1233,
        lc_id: Union[str, int] = 2142840551,
        sdk_ver: str = "v05.01.02-alpha.7-ov-android",
        sdk_ver_code: Union[str, int] = 83952160,
        app_ver: str = "37.0.4",
        version_code: Union[str, int] = 2023700040,
        cookie: Optional[str] = None,
        unix: Optional[int] = None
    ) -> Dict[str, str]:
        """Generate complete authentication headers for TikTok API requests.
        
        Combines Ladon, Gorgon, and Argus encryption to produce all required
        signature headers for TikTok Android API authentication.
        
        Args:
            params (str | dict): URL query parameters.
            data (str | dict | bytes): Request body for POST requests.
            device_id (str): Device identifier.
            aid (str | int): Application ID.
            lc_id (str | int): License ID.
            sdk_ver (str): SDK version (e.g., "v05.01.02-alpha.7-ov-android").
            sdk_ver_code (str | int): SDK version code.
            app_ver (str): App version (e.g., "37.0.4").
            version_code (str | int): App version code (e.g., 2023700040).
            cookie (str): Cookie string.
            unix (int): Unix timestamp in seconds. If None, uses current time.
        
        Returns:
            headers (dict):
            - x-ss-req-ticket: Request timestamp in milliseconds
            - x-tt-trace-id: Trace identifier
            - x-ss-stub: MD5 hash of request body (only if data provided)
            - x-ladon: Ladon authentication token
            - x-gorgon: Gorgon signature
            - x-khronos: Unix timestamp
            - x-argus: Argus authentication token
            - cookie: Cookie string (only if provided)
        """
        aid = int(aid) if isinstance(aid, str) else aid
        lc_id = int(lc_id) if isinstance(lc_id, str) else lc_id
        sdk_ver_code = int(sdk_ver_code) if isinstance(sdk_ver_code, str) else sdk_ver_code
        version_code = int(version_code) if isinstance(version_code, str) else version_code
        
        if unix is None:
            ticket = time()
            unix = int(ticket)
        else:
            ticket = float(unix)
        
        if device_id:
            trace = (
                hex(int(device_id))[2:]
                + "".join(choice("0123456789abcdef") for _ in range(2))
                + "0"
                + hex(aid)[2:]
            )
        else:
            trace = (
                str("%x" % (round(ticket * 1000) & 0xffffffff))
                + "10"
                + "".join(choice("0123456789abcdef") for _ in range(16))
            )
        
        headers: Dict[str, str] = {
            "x-ss-req-ticket": str(int(time() * 1000)),
            "x-tt-trace-id": f"00-{trace}-{trace[:16]}-01",
        }
        
        if data is not None:
            headers["x-ss-stub"] = generate_stub(data=data)
        
        headers.update(Ladon.encrypt(
            aid=aid,
            lc_id=lc_id,
            unix=unix,
        ))
        
        headers.update(Gorgon.encrypt(
            params=params,
            headers=headers,
            cookie=cookie,
            unix=unix,
        ))
        
        headers.update(Argus.encrypt(
            params=params,
            data=data,
            unix=unix,
            aid=aid,
            lc_id=lc_id,
            device_id=device_id,
            sdk_ver=sdk_ver,
            sdk_ver_code=sdk_ver_code,
            app_ver=app_ver,
            version_code=version_code,
        ))
        
        if cookie is not None:
            headers["cookie"] = cookie
        
        return headers
    
    @classmethod
    def encrypt(cls, data: Union[str, bytes, Dict]) -> bytes:
        """Encrypt data using TikTok TTEncrypt algorithm.
        
        Args:
            data: Data to encrypt (str, bytes, or dict).
        
        Returns:
            Encrypted bytes.
        """
        import json
        if isinstance(data, dict):
            data = json.dumps(data, separators=(",", ":")).encode()
        elif isinstance(data, str):
            data = data.encode()
        return cls._get_encryptor().encrypt(data)
    
    @classmethod
    def decrypt(cls, data: bytes) -> str:
        """Decrypt TikTok TTEncrypt encrypted data.
        
        Args:
            data: Encrypted bytes to decrypt.
        
        Returns:
            Decrypted string.
        """
        return cls._get_encryptor().decrypt(data)


def generate_headers(
    params: Union[str, Dict],
    data: Optional[Union[str, bytes, Dict]] = None,
    device_id: str = "",
    aid: Union[int, str] = 1233,
    lc_id: Union[int, str] = 2142840551,
    sdk_ver: str = "v05.01.02-alpha.7-ov-android",
    sdk_ver_code: Union[int, str] = 83952160,
    app_ver: str = "37.0.4",
    version_code: Union[int, str] = 2023700040,
    cookie: Optional[str] = None,
    unix: Optional[int] = None
) -> Dict[str, str]:
    """Generate authentication headers for TikTok API requests.
    
    Args:
        params (str | dict): URL query parameters.
        data (str | dict | bytes): Request body for POST requests.
        device_id (str): Device identifier.
        aid (str | int): Application ID.
        lc_id (str | int): License ID.
        sdk_ver (str): SDK version (e.g., "v05.01.02-alpha.7-ov-android").
        sdk_ver_code (str | int): SDK version code.
        app_ver (str): App version (e.g., "37.0.4").
        version_code (str | int): App version code (e.g., 2023700040).
        cookie (str): Cookie string.
        unix (int): Unix timestamp in seconds. If None, uses current time.
    
    Returns:
        dict: Authentication headers for TikTok API.
    """
    return TikTokSigner.generate_headers(
        params=params,
        data=data,
        device_id=device_id or None,
        aid=aid,
        lc_id=lc_id,
        sdk_ver=sdk_ver,
        sdk_ver_code=sdk_ver_code,
        app_ver=app_ver,
        version_code=version_code,
        cookie=cookie,
        unix=unix,
    )


def encrypt(data: Union[str, bytes, Dict]) -> bytes:
    """Encrypt data using TikTok TTEncrypt algorithm."""
    return TikTokSigner.encrypt(data)


def decrypt(data: bytes) -> str:
    """Decrypt TikTok TTEncrypt encrypted data."""
    return TikTokSigner.decrypt(data)
