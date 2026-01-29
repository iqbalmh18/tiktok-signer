"""TikTok Signer - TikTok Android API authentication signature generator."""
from tiktok_signer.signer import TikTokSigner
from tiktok_signer.signer import generate_headers, encrypt, decrypt

__all__ = ["TikTokSigner", "generate_headers", "encrypt", "decrypt"]
__version__ = "1.1.0"
