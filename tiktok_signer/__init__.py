"""TikTok Signer - TikTok Android API authentication signature generator."""
from tiktok_signer.signer import TikTokSigner
from tiktok_signer.signer import generate_headers, encrypt, decrypt, encode, decode

__all__ = ["TikTokSigner", "generate_headers", "encrypt", "decrypt", "encode", "decode"]
__version__ = "1.2.0"
