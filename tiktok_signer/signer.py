"""TikTok Signer - Main module for TikTok API authentication."""
from typing import Dict, Optional, Union
from tiktok_signer.lib.signer import Signer
from tiktok_signer.lib.ttencrypt import TTEncrypt


class TikTokSigner:
    """TikTok API authentication signer with encryption support."""
    
    _encryptor: TTEncrypt = None
    
    @classmethod
    def _get_encryptor(cls) -> TTEncrypt:
        """Get or create TTEncrypt instance."""
        if cls._encryptor is None:
            cls._encryptor = TTEncrypt()
        return cls._encryptor
    
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
        """Generate authentication headers for TikTok API requests.
        
        Args:
            params: URL query parameters as string or dict.
            data: Request body for POST requests (str, bytes, or dict).
            sec_device_id: Secure device identifier.
            aid: Application ID.
            license_id: License ID.
            sdk_version_str: SDK version string.
            sdk_version: SDK version number.
            cookie: Cookie string.
        
        Returns:
            Dictionary containing authentication headers:
            x-ss-req-ticket, x-tt-trace-id, x-ladon, x-gorgon, x-khronos, x-argus
        """
        return Signer.generate_headers(
            params=params,
            data=data,
            sec_device_id=sec_device_id,
            aid=aid,
            license_id=license_id,
            sdk_version_str=sdk_version_str,
            sdk_version=sdk_version,
            cookie=cookie,
        )
    
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
    sec_device_id: str = "",
    aid: Union[int, str] = 1233,
    license_id: Union[int, str] = 1611921764,
    sdk_version_str: str = "v05.00.03-ov-android",
    sdk_version: Union[int, str] = 167773760,
    cookie: Optional[str] = None
) -> Dict[str, str]:
    """Generate authentication headers for TikTok API requests."""
    return TikTokSigner.generate_headers(
        params=params,
        data=data,
        sec_device_id=sec_device_id,
        aid=aid,
        license_id=license_id,
        sdk_version_str=sdk_version_str,
        sdk_version=sdk_version,
        cookie=cookie,
    )


def encrypt(data: Union[str, bytes, Dict]) -> bytes:
    """Encrypt data using TikTok TTEncrypt algorithm."""
    return TikTokSigner.encrypt(data)


def decrypt(data: bytes) -> str:
    """Decrypt TikTok TTEncrypt encrypted data."""
    return TikTokSigner.decrypt(data)
