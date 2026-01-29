"""Stub generation utility for TikTok request body hashing."""
from typing import Dict, Optional, Union
from urllib.parse import urlencode
import gzip
import hashlib


def generate_stub(data: Optional[Union[Dict, str, bytes]] = None) -> str:
    """Generate MD5 stub hash from request body data.
    
    Args:
        data: Request body data. Can be dict (will be urlencoded and gzipped),
              str (will be gzipped), bytes (used as-is), or None.
    
    Returns:
        Uppercase MD5 hash string of the processed data.
    """
    if data is None:
        return hashlib.md5(b"undefined").hexdigest().upper()
    if isinstance(data, dict):
        data_bytes = gzip.compress(urlencode(data).encode(), compresslevel=9, mtime=0)
    elif isinstance(data, str):
        data_bytes = gzip.compress(data.encode(), compresslevel=9, mtime=0)
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        return hashlib.md5(b"undefined").hexdigest().upper()
    return hashlib.md5(data_bytes).hexdigest().upper()