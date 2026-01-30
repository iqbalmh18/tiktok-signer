# TikTok Signer

[![tiktok-signer-github.png](https://i.postimg.cc/VvDkF4BG/tiktok-signer-github.png)](https://postimg.cc/sGGzjYL7)

Python library for generating TikTok Android API authentication signatures. This library implements the required encryption algorithms (Argus, Gorgon, Ladon, TTEncrypt) for authenticating requests to TikTok's private API.

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

- Python >= 3.10
- pycryptodome >= 3.20.0

## Quick Start

```python
from tiktok_signer import TikTokSigner

# Generate authentication headers
headers = TikTokSigner.generate_headers(params="aid=1233&app_name=musical_ly")
print(headers)

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

### TikTokSigner

Main class for signature generation and encryption.

#### TikTokSigner.generate_headers()

Generates all authentication headers required for TikTok API requests.

```python
headers = TikTokSigner.generate_headers(
    params,                                      # Required: URL query parameters (str or dict)
    data=None,                                   # Optional: Request body for POST (str, bytes, or dict)
    device_id="",                                # Optional: Device identifier
    aid=1233,                                    # Optional: Application ID (int or str)
    lc_id=2142840551,                            # Optional: License ID (int or str)
    sdk_ver="v05.01.02-alpha.7-ov-android",      # Optional: SDK version string
    sdk_ver_code=83952160,                       # Optional: SDK version code (int or str)
    app_ver="37.0.4",                            # Optional: App version string
    version_code=2023700040,                         # Optional: App version code (int or str)
    cookie=None,                                 # Optional: Cookie string
    unix=None                                    # Optional: Unix timestamp in seconds
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `params` | `str` or `dict` | Required | URL query parameters |
| `data` | `str`, `bytes`, `dict`, or `None` | `None` | Request body for POST requests |
| `device_id` | `str` | `""` | Device identifier |
| `aid` | `int` or `str` | `1233` | Application ID |
| `lc_id` | `int` or `str` | `2142840551` | License ID |
| `sdk_ver` | `str` | `"v05.01.02-alpha.7-ov-android"` | SDK version string |
| `sdk_ver_code` | `int` or `str` | `83952160` | SDK version code |
| `app_ver` | `str` | `"37.0.4"` | App version string |
| `version_code` | `int` or `str` | `2023700040` | App version code |
| `cookie` | `str` or `None` | `None` | Cookie string |
| `unix` | `int` or `None` | `None` | Unix timestamp in seconds. If None, uses current time. |

**Returns:** `Dict[str, str]`

```python
{
    "x-ss-req-ticket": "1706789012345",      # Request timestamp (milliseconds)
    "x-tt-trace-id": "00-abc123...-01",       # Trace identifier
    "x-ss-stub": "ABC123...",                 # Body hash (only if data is provided)
    "x-ladon": "base64_encoded_token",        # Ladon authentication
    "x-gorgon": "8404...",                    # Gorgon signature
    "x-khronos": "1706789012",                # Unix timestamp
    "x-argus": "base64_encoded_token",        # Argus authentication
    "cookie": "..."                           # Cookie (only if provided)
}
```

#### TikTokSigner.encrypt()

Encrypts data using the TTEncrypt algorithm for device registration.

```python
encrypted = TikTokSigner.encrypt(data)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `str`, `bytes`, or `dict` | Data to encrypt. Dict will be converted to JSON. |

**Returns:** `bytes` - Encrypted data

#### TikTokSigner.decrypt()

Decrypts data encrypted with TTEncrypt.

```python
decrypted = TikTokSigner.decrypt(encrypted_bytes)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` | Encrypted data |

**Returns:** `str` - Decrypted data (typically a JSON string)

#### TikTokSigner.encode()

Encodes a dictionary to protobuf format.

```python
protobuf_data = TikTokSigner.encode(data)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `dict` | Dictionary to encode. Keys should be field numbers (int). |

**Returns:** `bytes` - Protobuf encoded data

#### TikTokSigner.decode()

Decodes protobuf data to dictionary.

```python
dict_data = TikTokSigner.decode(protobuf_bytes)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` or `ProtoBuf` | Protobuf data to decode |

**Returns:** `dict` - Decoded dictionary with field numbers as keys

### Shortcut Functions

The library also provides shortcut functions for convenience:

```python
from tiktok_signer import generate_headers, encrypt, decrypt, encode, decode

# Same as TikTokSigner.generate_headers()
headers = generate_headers(params="aid=1233")

# Same as TikTokSigner.encrypt()
encrypted = encrypt({"key": "value"})

# Same as TikTokSigner.decrypt()
decrypted = decrypt(encrypted_bytes)

# Same as TikTokSigner.encode()
protobuf_data = encode({1: "value", 2: 123})

# Same as TikTokSigner.decode()
dict_data = decode(protobuf_bytes)
```

## Usage Examples

### GET Request

```python
import requests
from tiktok_signer import TikTokSigner

# Define parameters
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

# Convert to query string
query_string = "&".join(f"{k}={v}" for k, v in params.items())

# Generate authentication headers
auth_headers = TikTokSigner.generate_headers(params=query_string)

# Base headers
headers = {
    "User-Agent": "com.zhiliaoapp.musically/2023700040 (Linux; U; Android 9; in_ID; 2203121C; Build/PQ3A.190705.09121607;tt-ok/3.12.13.4-tiktok)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}
headers.update(auth_headers)

# Send request
url = f"https://api.tiktokv.com/aweme/v1/feed/?{query_string}"
response = requests.get(url, headers=headers)
print(response.json())
```

### POST Request with Body

```python
import requests
from tiktok_signer import TikTokSigner

params = "aid=1233&app_name=musical_ly"

# Request body
data = {
    "username": "example",
    "password": "encrypted_password",
    "mix_mode": 1,
}

# Generate headers with data body
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
print(response.json())
```

### Using Custom Unix Timestamp

```python
import time
from tiktok_signer import TikTokSigner

# Use custom unix timestamp (useful for replay or testing)
custom_unix = int(time.time()) - 60  # 1 minute ago

headers = TikTokSigner.generate_headers(
    params="aid=1233&app_name=musical_ly",
    unix=custom_unix
)

# x-khronos will reflect the custom timestamp
print(f"x-khronos: {headers['x-khronos']}")  # Will show custom_unix value
```

### Device Registration with TTEncrypt

```python
import requests
from tiktok_signer import TikTokSigner

# Device info payload
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
        "app_version": "37.0.4",
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

# Encrypt payload
encrypted_payload = TikTokSigner.encrypt(device_info)

# Send encrypted request
params = "aid=1233&app_name=musical_ly"
auth_headers = TikTokSigner.generate_headers(params=params, data=encrypted_payload)

headers = {
    "User-Agent": "com.zhiliaoapp.musically/2023700040 (Linux; U; Android 9; in_ID; 2203121C)",
    "Content-Type": "application/octet-stream",
}
headers.update(auth_headers)

url = f"https://log.tiktokv.com/service/2/device_register/?{params}"
response = requests.post(url, headers=headers, data=encrypted_payload)
print(response.json())
```

### Using Dict for Parameters

```python
from tiktok_signer import TikTokSigner

# Parameters can be a dict
params = {
    "aid": 1233,
    "app_name": "musical_ly",
    "device_platform": "android",
}

# Library will automatically convert to query string
headers = TikTokSigner.generate_headers(params=params)
```

### Custom App and SDK Versions

```python
from tiktok_signer import TikTokSigner

headers = TikTokSigner.generate_headers(
    params="aid=1233&app_name=musical_ly",
    sdk_ver="v05.01.02-alpha.7-ov-android",  # SDK version
    sdk_ver_code=83952160,                    # SDK version code
    app_ver="38.0.0",                         # App version
    version_code=380000                       # App version code
)
```

## Encryption Algorithms

This library implements 4 main encryption algorithms:

| Algorithm | Header Output | Description |
|-----------|---------------|-------------|
| **Argus** | `x-argus` | Primary signature using Simon cipher and SM3 hash |
| **Gorgon** | `x-gorgon`, `x-khronos` | Request integrity signature with timestamp |
| **Ladon** | `x-ladon` | License-based authentication token |
| **TTEncrypt** | - | Payload encryption for device registration |

### Internal Components

| Module | Description |
|--------|-------------|
| `protobuf.py` | Protocol Buffer encoding/decoding for Argus payload |
| `simon.py` | Simon 128/256 block cipher implementation |
| `sm3.py` | SM3 cryptographic hash (Chinese national standard GB/T 32905-2016) |
| `stub.py` | MD5 stub generation for request body |

## Default Values

The library uses the following default values based on the TikTok Android app:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| `aid` | `1233` | Application ID |
| `lc_id` | `2142840551` | License ID |
| `sdk_ver` | `"v05.01.02-alpha.7-ov-android"` | SDK version string |
| `sdk_ver_code` | `83952160` | SDK version code |
| `app_ver` | `"37.0.4"` | App version string |
| `version_code` | `2023700040` | App version code |

## Project Structure

```
tiktok-signer/
├── pyproject.toml              # Project configuration
├── README.md                   # Documentation
├── LICENSE                     # MIT License
├── MANIFEST.in                 # Package manifest
└── tiktok_signer/              # Main package
    ├── __init__.py             # Package exports
    ├── signer.py               # TikTokSigner class
    ├── example.py              # Usage examples
    └── lib/                    # Internal library
        ├── __init__.py
        ├── argus.py            # X-Argus encryption
        ├── gorgon.py           # X-Gorgon encryption
        ├── ladon.py            # X-Ladon encryption
        ├── stub.py             # Body hash generation
        ├── ttencrypt.py        # Device payload encryption
        ├── data/
        │   └── dword.json      # Lookup tables
        └── utils/
            ├── __init__.py
            ├── protobuf.py     # Protocol Buffer
            ├── simon.py        # Simon cipher
            └── sm3.py          # SM3 hash
```

## Error Handling

```python
from tiktok_signer import TikTokSigner

try:
    headers = TikTokSigner.generate_headers(params=params)
except Exception as e:
    print(f"Signature generation failed: {e}")
```

## Type Annotations

All public functions include complete type annotations:

```python
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
    ...
```

## Changelog

### v1.2.1

- Published to PyPI (`pip install tiktok-signer`)
- Added GitHub workflow for automatic PyPI publishing on release

### v1.2.0

- Added protobuf encode/decode support (`encode`, `decode`)
- Exposed `ProtoBuf` class from `tiktok_signer.lib.utils.protobuf`
- Added shortcut functions for encode/decode

### v1.1.0

- Consolidated signer into single robust module
- Added `unix` parameter for custom timestamp support
- Added `app_ver` and `version_code` parameters
- Added default value from TikTok App (`2026`)
- Separated SDK version (`sdk_ver`, `sdk_ver_code`) from App version (`app_ver`, `version_code`)

### v1.0.0

- Initial release
- Implement Argus, Gorgon, Ladon encryption
- Implement TTEncrypt for device registration
- Full type annotations

## License

MIT License. See LICENSE file for details.

## Disclaimer

This library is provided for educational and research purposes only. Use of this library must comply with TikTok's Terms of Service and applicable laws. The author is not responsible for any misuse of this library.
