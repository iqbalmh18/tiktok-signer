# TikTok Signer

Python library for generating TikTok Android API authentication signatures. Implements required encryption algorithms (Argus, Gorgon, Ladon, TTEncrypt) for authenticating requests to TikTok's private API.

## Installation

### From PyPI
```bash
pip install tiktok-signer
```

### From GitHub
```bash
pip install git+https://github.com/iqbalmh18/tiktok-signer.git
```

### From Source
```bash
git clone https://github.com/iqbalmh18/tiktok-signer.git
cd tiktok-signer
pip install .
```

### Development
```bash
git clone https://github.com/iqbalmh18/tiktok-signer.git
cd tiktok-signer
pip install -e ".[dev]"
```

## Requirements

- Python 3.10 or higher
- pycryptodome 3.20.0 or higher

## Quick Start

```python
from tiktok_signer import TikTokSigner

# Generate authentication headers
headers = TikTokSigner.generate_headers(params="aid=1233&app_name=musical_ly")

# Encrypt device registration payload
encrypted = TikTokSigner.encrypt({"device_id": "123456", "os": "android"})

# Decrypt response
decrypted = TikTokSigner.decrypt(encrypted_bytes)

# Encode dict to protobuf format
protobuf_data = TikTokSigner.encode({1: "value", 2: 123})

# Decode protobuf response
dict_data = TikTokSigner.decode(protobuf_bytes)
```

## API Reference

### TikTokSigner.generate_headers()

Generates all authentication headers required for TikTok API requests.

```python
headers = TikTokSigner.generate_headers(
    params,                                      # Required: URL query parameters (str or dict)
    data=None,                                   # Optional: Request body for POST (str, bytes, or dict)
    device_id="",                                # Optional: Device identifier
    aid=1233,                                    # Optional: Application ID (int or str)
    lc_id=2142840551,                            # Optional: License ID (int or str)
    sdk_ver="v05.01.02-alpha.7-ov-android",      # Optional: SDK version name
    sdk_ver_code=83952160,                       # Optional: SDK version code (int or str)
    version_name="37.0.4",                       # Optional: App version name
    version_code=2023700040,                     # Optional: App version code (int or str)
    cookie=None,                                 # Optional: Cookie string
    unix=None                                    # Optional: Unix timestamp in seconds
)
```

**Returns:** Dict containing authentication headers (x-ss-req-ticket, x-tt-trace-id, x-ss-stub, x-ladon, x-gorgon, x-khronos, x-argus, cookie)

### TikTokSigner.encrypt()

Encrypts data using the TTEncrypt algorithm for device registration.

```python
encrypted = TikTokSigner.encrypt(data)  # data: str, bytes, or dict
```

**Returns:** Encrypted bytes

### TikTokSigner.decrypt()

Decrypts data encrypted with TTEncrypt.

```python
decrypted = TikTokSigner.decrypt(encrypted_bytes)
```

**Returns:** Decrypted string (typically JSON)

### TikTokSigner.encode()

Encodes a dictionary to protobuf format.

```python
protobuf_data = TikTokSigner.encode(data)  # data: dict with int keys
```

**Returns:** Protobuf encoded bytes

### TikTokSigner.decode()

Decodes protobuf data to dictionary.

```python
dict_data = TikTokSigner.decode(protobuf_bytes)
```

**Returns:** Dictionary with field numbers as keys

### Shortcut Functions

```python
from tiktok_signer import generate_headers, encrypt, decrypt, encode, decode

headers = generate_headers(params="aid=1233")
encrypted = encrypt({"key": "value"})
decrypted = decrypt(encrypted_bytes)
protobuf_data = encode({1: "value", 2: 123})
dict_data = decode(protobuf_bytes)
```

## Usage Examples

### GET Request

```python
import requests
from tiktok_signer import TikTokSigner

params = {
    "aid": 1233,
    "app_name": "musical_ly",
    "device_platform": "android",
    "os_version": "9",
    "device_type": "2203121C",
    "device_brand": "Xiaomi",
    "language": "id",
    "region": "ID",
}

query_string = "&".join(f"{k}={v}" for k, v in params.items())
auth_headers = TikTokSigner.generate_headers(params=query_string)

headers = {
    "User-Agent": "com.zhiliaoapp.musically/2023700040 (Linux; U; Android 9; in_ID; 2203121C; Build/PQ3A.190705.09121607;tt-ok/3.12.13.4-tiktok)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}
headers.update(auth_headers)

url = f"https://api.tiktokv.com/aweme/v1/feed/?{query_string}"
response = requests.get(url, headers=headers)
```

### POST Request with Body

```python
import requests
from tiktok_signer import TikTokSigner

params = "aid=1233&app_name=musical_ly"
data = {
    "username": "example",
    "password": "encrypted_password",
    "mix_mode": 1,
}

auth_headers = TikTokSigner.generate_headers(
    params=params,
    data=data,
    cookie="sessionid=abc123; tt_csrf_token=xyz789"
)

headers = {
    "User-Agent": "com.zhiliaoapp.musically/2023700040 (Linux; U; Android 9; in_ID; 2203121C)",
    "Content-Type": "application/x-www-form-urlencoded",
}
headers.update(auth_headers)

url = f"https://api.tiktokv.com/passport/user/login/?{params}"
response = requests.post(url, headers=headers, data=data)
```

### Device Registration with TTEncrypt

```python
import requests
from tiktok_signer import TikTokSigner

device_info = {
    "magic_tag": "ss_app_log",
    "header": {
        "display_name": "TikTok",
        "update_version_code": 2023700040,
        "manifest_version_code": 2023700040,
        "app_version_minor": "",
        "aid": 1233,
        "channel": "googleplay",
        "package": "com.zhiliaoapp.musically",
        "version_name": "37.0.4",
        "version_code": 2023700040,
        "sdk_ver_code": "3.9.17-bugfix.9",
        "os": "Android",
        "os_version": "9",
        "os_api": 28,
        "device_model": "2203121C",
        "device_brand": "Xiaomi",
        "device_manufacturer": "Xiaomi",
        "cpu_abi": "arm64-v8a",
        "release_build": "7e6048c_20231219",
        "density_dpi": 320,
        "display_density": "mdpi",
        "resolution": "720*1280",
        "language": "id",
        "timezone": 7,
        "access": "wifi",
        "not_request_sender": 0,
        "rom": "MIUI-V12.5.6.0.QDLMIXM",
        "rom_version": "miui_V12_V12.5.6.0.QDLMIXM",
        "sig_hash": "194326e82c84a639a52e5c023116f12a",
        "google_aid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "openudid": "xxxxxxxxxxxxxxxx",
        "clientudid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    },
    "_gen_time": 1706789012345,
}

encrypted_payload = TikTokSigner.encrypt(device_info)
auth_headers = TikTokSigner.generate_headers(params="aid=1233&app_name=musical_ly", data=encrypted_payload)

headers = {
    "User-Agent": "com.zhiliaoapp.musically/2023700040 (Linux; U; Android 9; in_ID; 2203121C)",
    "Content-Type": "application/octet-stream",
}
headers.update(auth_headers)

url = "https://log.tiktokv.com/service/2/device_register/?aid=1233&app_name=musical_ly"
response = requests.post(url, headers=headers, data=encrypted_payload)
```

## Encryption Algorithms

This library implements four main encryption algorithms used by TikTok's Android API:

- **Argus**: Primary signature using Simon cipher and SM3 hash (x-argus header)
- **Gorgon**: Request integrity signature with timestamp (x-gorgon, x-khronos headers)
- **Ladon**: License-based authentication token (x-ladon header)
- **TTEncrypt**: Payload encryption for device registration

## Default Values

Based on TikTok Android app version 37.0.4:

- aid: 1233
- lc_id: 2142840551
- sdk_ver: v05.01.02-alpha.7-ov-android
- sdk_ver_code: 83952160
- version_name: 37.0.4
- version_code: 2023700040

## Project Structure

```
tiktok-signer/
├── pyproject.toml
├── README.md
├── LICENSE
├── MANIFEST.in
└── tiktok_signer/
    ├── __init__.py
    ├── signer.py
    ├── example.py
    └── lib/
        ├── __init__.py
        ├── argus.py
        ├── gorgon.py
        ├── ladon.py
        ├── stub.py
        ├── ttencrypt.py
        ├── data/
        │   └── dword.json
        └── utils/
            ├── __init__.py
            ├── protobuf.py
            ├── simon.py
            └── sm3.py
```

## Changelog

### v1.3.0
- Changed app_ver to version_name in generate headers parameters
- Updated version to 1.3.0

### v1.2.1
- Published to PyPI
- Added GitHub workflow for automatic PyPI publishing

### v1.2.0
- Added protobuf encode/decode support
- Exposed ProtoBuf class
- Added shortcut functions for encode/decode

### v1.1.0
- Consolidated signer into single module
- Added unix parameter for custom timestamp support
- Added version_name and version_code parameters
- Separated SDK version from App version
- Added default values from TikTok App

### v1.0.0
- Initial release
- Implemented Argus, Gorgon, Ladon encryption
- Implemented TTEncrypt for device registration

## License

MIT License. See LICENSE file for details.

## Disclaimer

This library is for educational and research purposes only. Use must comply with TikTok's Terms of Service and applicable laws. The author is not responsible for any misuse.