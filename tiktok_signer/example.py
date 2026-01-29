"""
TikTok Signer Example

Usage:
    python3 -m tiktok_signer.example
    python3 tiktok_signer/example.py
"""
import sys
import json
from pathlib import Path

if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from tiktok_signer import TikTokSigner, generate_headers, encrypt, __version__


def main() -> None:
    print("=" * 60)
    print(f"TikTok Signer v{__version__}")
    print("=" * 60)
    print()
    params = {
        "aid": "1233",
        "app_name": "musical_ly",
        "device_platform": "android",
        "os_version": "9",
        "device_type": "2203121C",
        "device_brand": "Xiaomi",
        "channel": "googleplay",
        "language": "id",
        "region": "ID",
    }
    print("[1] Generate Headers")
    print("-" * 60)
    print(f"Input params: {json.dumps(params, indent=2)}")
    print()
    headers = TikTokSigner.generate_headers(params=params)
    print("Output headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()
    print("[2] Generate Headers with POST Data")
    print("-" * 60)
    post_data = {"username": "test_user", "password": "test_pass"}
    print(f"Input data: {json.dumps(post_data)}")
    print()
    headers_post = TikTokSigner.generate_headers(
        params="aid=1233&app_name=musical_ly",
        data=post_data,
    )
    print("Output headers:")
    for key, value in headers_post.items():
        print(f"  {key}: {value}")
    print()
    print("[3] TTEncrypt")
    print("-" * 60)
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
    print(f"Input: {json.dumps(device_info)}")
    print()
    encrypted = TikTokSigner.encrypt(device_info)
    print(f"Encrypted: {len(encrypted)} bytes")
    print(f"Hex preview: {encrypted.hex()}")
    print()
    print("[4] Shortcut Functions")
    print("-" * 60)
    headers_shortcut = generate_headers(params="aid=1233")
    print(f"generate_headers(): {list(headers_shortcut.keys())}")
    encrypted_shortcut = encrypt({"test": "data"})
    print(f"encrypt(): {len(encrypted_shortcut)} bytes")
    print()
    print("[5] Generate Headers with Custom Unix Timestamp")
    print("-" * 60)
    import time
    custom_unix = int(time.time()) - 60  # 1 minute ago
    print(f"Custom unix timestamp: {custom_unix}")
    print()
    headers_unix = TikTokSigner.generate_headers(
        params=params,
        unix=custom_unix
    )
    print("Output headers:")
    for key, value in headers_unix.items():
        print(f"  {key}: {value}")
    print(f"Note: x-khronos should be {custom_unix}")
    print()
    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
