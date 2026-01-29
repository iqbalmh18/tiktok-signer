"""TikTok request signer for generating authentication headers."""
from typing import Dict, Optional, Union
from urllib.parse import urlencode
from random import choice
from time import time
from tiktok_signer.lib.argus import Argus
from tiktok_signer.lib.ladon import Ladon
from tiktok_signer.lib.gorgon import Gorgon
from tiktok_signer.lib.stub import generate_stub


class Signer:
    """Main signer class for generating TikTok API authentication headers."""
    
    DEFAULT_AID: int = 1233
    DEFAULT_LICENSE_ID: int = 1611921764
    DEFAULT_SDK_VERSION_STR: str = "v05.00.03-ov-android"
    DEFAULT_SDK_VERSION: int = 167773760
    
    @staticmethod
    def generate_headers(
        params: Union[str, Dict],
        data: Optional[Union[str, bytes, Dict]] = None,
        sec_device_id: str = "",
        aid: Union[int, str] = 1233,
        license_id: Union[int, str] = 1611921764,
        sdk_version_str: str = "v05.00.03-ov-android",
        sdk_version: Union[int, str] = 167773760,
        cookie: Optional[str] = None
    ) -> Dict[str, str]:
        """Generate complete authentication headers for TikTok API requests.
        
        Combines Ladon, Gorgon, and Argus encryption to produce all required
        signature headers for TikTok Android API authentication.
        
        Args:
            params: URL query parameters as string or dict.
            data: Request body data as string, bytes, or dict. Used for POST requests.
            sec_device_id: Secure device identifier. Defaults to empty string.
            aid: Application ID. Can be int or str. Defaults to 1233.
            license_id: License ID. Can be int or str. Defaults to 1611921764.
            sdk_version_str: SDK version string. Defaults to "v05.00.03-ov-android".
            sdk_version: SDK version number. Can be int or str. Defaults to 167773760.
            cookie: Cookie string to include in signature calculation. Defaults to None.
        
        Returns:
            Dictionary containing all required authentication headers:
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
        license_id = int(license_id) if isinstance(license_id, str) else license_id
        sdk_version = int(sdk_version) if isinstance(sdk_version, str) else sdk_version
        ticket = time()
        unix = int(ticket)
        if sec_device_id:
            trace = (
                hex(int(sec_device_id))[2:]
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
            license_id=license_id,
            timestamp=unix,
        ))
        headers.update(Gorgon.encrypt(
            params=params,
            headers=headers,
            cookie=cookie,
        ))
        headers.update(Argus.encrypt(
            params=params,
            data=data,
            timestamp=unix,
            aid=aid,
            license_id=license_id,
            sec_device_id=sec_device_id,
            sdk_version_str=sdk_version_str,
            sdk_version=sdk_version,
        ))
        if cookie is not None:
            headers["cookie"] = cookie
        return headers
