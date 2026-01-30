"""Protocol Buffer encoding/decoding utilities for TikTok API."""
from enum import IntEnum, unique
from typing import Any, Dict, List, Optional, Union


class ProtoError(Exception):
    """Exception raised for Protocol Buffer errors."""
    
    def __init__(self, msg: str) -> None:
        self.msg = msg
    
    def __str__(self) -> str:
        return repr(self.msg)


@unique
class ProtoFieldType(IntEnum):
    """Protocol Buffer wire types."""
    VARINT = 0
    INT64 = 1
    STRING = 2
    GROUPSTART = 3
    GROUPEND = 4
    INT32 = 5
    ERROR1 = 6
    ERROR2 = 7


class ProtoField:
    """Single Protocol Buffer field."""
    
    def __init__(self, idx: int, field_type: ProtoFieldType, val: Any) -> None:
        self.idx = idx
        self.type = field_type
        self.val = val
    
    def is_ascii_str(self) -> bool:
        """Check if value is printable ASCII string."""
        if not isinstance(self.val, bytes):
            return False
        for b in self.val:
            if b < 0x20 or b > 0x7e:
                return False
        return True
    
    def __str__(self) -> str:
        if self.type in (ProtoFieldType.INT32, ProtoFieldType.INT64, ProtoFieldType.VARINT):
            return f"{self.idx}({self.type.name}): {self.val}"
        elif self.type == ProtoFieldType.STRING:
            if self.is_ascii_str():
                return f'{self.idx}({self.type.name}): "{self.val.decode("ascii")}"'
            return f'{self.idx}({self.type.name}): h"{self.val.hex()}"'
        return f"{self.idx}({self.type.name}): {self.val}"


class ProtoReader:
    """Protocol Buffer binary reader."""
    
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
    
    def seek(self, pos: int) -> None:
        """Move read position."""
        self.pos = pos
    
    def is_remain(self, length: int) -> bool:
        """Check if enough bytes remain."""
        return self.pos + length <= len(self.data)
    
    def read0(self) -> int:
        """Read single byte."""
        assert self.is_remain(1)
        ret = self.data[self.pos]
        self.pos += 1
        return ret & 0xFF
    
    def read(self, length: int) -> bytes:
        """Read multiple bytes."""
        assert self.is_remain(length)
        ret = self.data[self.pos:self.pos + length]
        self.pos += length
        return ret
    
    def read_int32(self) -> int:
        """Read 32-bit little-endian integer."""
        return int.from_bytes(self.read(4), byteorder="little", signed=False)
    
    def read_int64(self) -> int:
        """Read 64-bit little-endian integer."""
        return int.from_bytes(self.read(8), byteorder="little", signed=False)
    
    def read_varint(self) -> int:
        """Read variable-length integer."""
        vint = 0
        n = 0
        while True:
            byte = self.read0()
            vint |= (byte & 0x7F) << (7 * n)
            if byte < 0x80:
                break
            n += 1
        return vint
    
    def read_string(self) -> bytes:
        """Read length-prefixed string."""
        length = self.read_varint()
        return self.read(length)


class ProtoWriter:
    """Protocol Buffer binary writer."""
    
    def __init__(self) -> None:
        self.data = bytearray()
    
    def write0(self, byte: int) -> None:
        """Write single byte."""
        self.data.append(byte & 0xFF)
    
    def write(self, data: bytes) -> None:
        """Write multiple bytes."""
        self.data.extend(data)
    
    def write_int32(self, int32: int) -> None:
        """Write 32-bit little-endian integer."""
        self.write(int32.to_bytes(4, byteorder="little", signed=False))
    
    def write_int64(self, int64: int) -> None:
        """Write 64-bit little-endian integer."""
        self.write(int64.to_bytes(8, byteorder="little", signed=False))
    
    def write_varint(self, vint: int) -> None:
        """Write variable-length integer."""
        vint = vint & 0xFFFFFFFF
        while vint > 0x80:
            self.write0((vint & 0x7F) | 0x80)
            vint >>= 7
        self.write0(vint & 0x7F)
    
    def write_string(self, data: bytes) -> None:
        """Write length-prefixed string."""
        self.write_varint(len(data))
        self.write(data)
    
    def to_bytes(self) -> bytes:
        """Get written bytes."""
        return bytes(self.data)


class ProtoBuf:
    """Protocol Buffer message encoder/decoder."""
    
    def __init__(self, data: Optional[Union[bytes, Dict]] = None) -> None:
        """Initialize ProtoBuf from bytes or dict.
        
        Args:
            data: Raw protobuf bytes or dict to encode.
        
        Raises:
            ProtoError: If data type is not supported.
        """
        self.fields: List[ProtoField] = []
        if data is None:
            return
        if isinstance(data, bytes) and len(data) > 0:
            self._parse_buf(data)
        elif isinstance(data, dict) and len(data) > 0:
            self._parse_dict(data)
        elif not isinstance(data, (bytes, dict)):
            raise ProtoError(f"unsupport type({type(data)}) to protobuf")
    
    def __getitem__(self, idx: int) -> Any:
        pf = self.get(int(idx))
        if pf is None:
            return None
        if pf.type != ProtoFieldType.STRING:
            return pf.val
        if not isinstance(idx, int):
            return pf.val
        if pf.val is None:
            return None
        if pf.is_ascii_str():
            return pf.val.decode("utf-8")
        return ProtoBuf(pf.val)
    
    def _parse_buf(self, data: bytes) -> None:
        """Parse protobuf binary data."""
        reader = ProtoReader(data)
        while reader.is_remain(1):
            key = reader.read_varint()
            field_type = ProtoFieldType(key & 0x7)
            field_idx = key >> 3
            if field_idx == 0:
                break
            if field_type == ProtoFieldType.INT32:
                self.put(ProtoField(field_idx, field_type, reader.read_int32()))
            elif field_type == ProtoFieldType.INT64:
                self.put(ProtoField(field_idx, field_type, reader.read_int64()))
            elif field_type == ProtoFieldType.VARINT:
                self.put(ProtoField(field_idx, field_type, reader.read_varint()))
            elif field_type == ProtoFieldType.STRING:
                self.put(ProtoField(field_idx, field_type, reader.read_string()))
            else:
                raise ProtoError(f"parse protobuf error, unexpected field type: {field_type.name}")
    
    def toBuf(self) -> bytes:
        """Encode to protobuf binary format."""
        writer = ProtoWriter()
        for field in self.fields:
            key = (field.idx << 3) | (field.type & 7)
            writer.write_varint(key)
            if field.type == ProtoFieldType.INT32:
                writer.write_int32(field.val)
            elif field.type == ProtoFieldType.INT64:
                writer.write_int64(field.val)
            elif field.type == ProtoFieldType.VARINT:
                writer.write_varint(field.val)
            elif field.type == ProtoFieldType.STRING:
                writer.write_string(field.val)
            else:
                raise ProtoError(f"encode to protobuf error, unexpected field type: {field.type.name}")
        return writer.to_bytes()
    
    def dump(self) -> None:
        """Print all fields for debugging."""
        for field in self.fields:
            print(field)
    
    def get_list(self, idx: int) -> List[ProtoField]:
        """Get all fields with given index."""
        return [field for field in self.fields if field.idx == idx]
    
    def get(self, idx: int) -> Optional[ProtoField]:
        """Get first field with given index."""
        for field in self.fields:
            if field.idx == idx:
                return field
        return None
    
    def get_int(self, idx: int, default: int = 0) -> int:
        """Get integer field value.
        
        Args:
            idx: Field index.
            default: Default value if field not found.
        
        Returns:
            Integer value or default.
        """
        pf = self.get(idx)
        if pf is None:
            return default
        if pf.type in (ProtoFieldType.INT32, ProtoFieldType.INT64, ProtoFieldType.VARINT):
            return pf.val
        raise ProtoError(f"getInt({idx}) -> {pf.type}")
    
    def get_bytes(self, idx: int, default: Optional[bytes] = None) -> Optional[bytes]:
        """Get bytes field value.
        
        Args:
            idx: Field index.
            default: Default value if field not found.
        
        Returns:
            Bytes value or default.
        """
        pf = self.get(idx)
        if pf is None:
            return default
        if pf.type == ProtoFieldType.STRING:
            return pf.val
        raise ProtoError(f"getBytes({idx}) -> {pf.type}")
    
    def get_utf8(self, idx: int, default: Optional[str] = None) -> Optional[str]:
        """Get UTF-8 string field value.
        
        Args:
            idx: Field index.
            default: Default value if field not found.
        
        Returns:
            String value or default.
        """
        bs = self.get_bytes(idx)
        if bs is None:
            return default
        return bs.decode("utf-8")
    
    def get_protobuf(self, idx: int, default: Optional["ProtoBuf"] = None) -> Optional["ProtoBuf"]:
        """Get nested ProtoBuf field value.
        
        Args:
            idx: Field index.
            default: Default value if field not found.
        
        Returns:
            ProtoBuf instance or default.
        """
        bs = self.get_bytes(idx)
        if bs is None:
            return default
        return ProtoBuf(bs)
    
    def put(self, field: ProtoField) -> None:
        """Add field to message."""
        self.fields.append(field)
    
    def put_int32(self, idx: int, int32: int) -> None:
        """Add INT32 field."""
        self.put(ProtoField(idx, ProtoFieldType.INT32, int32))
    
    def put_int64(self, idx: int, int64: int) -> None:
        """Add INT64 field."""
        self.put(ProtoField(idx, ProtoFieldType.INT64, int64))
    
    def put_varint(self, idx: int, vint: int) -> None:
        """Add VARINT field."""
        self.put(ProtoField(idx, ProtoFieldType.VARINT, vint))
    
    def put_bytes(self, idx: int, data: bytes) -> None:
        """Add bytes field."""
        self.put(ProtoField(idx, ProtoFieldType.STRING, data))
    
    def put_utf8(self, idx: int, data: str) -> None:
        """Add UTF-8 string field."""
        self.put(ProtoField(idx, ProtoFieldType.STRING, data.encode("utf-8")))
    
    def put_protobuf(self, idx: int, data: "ProtoBuf") -> None:
        """Add nested ProtoBuf field."""
        self.put(ProtoField(idx, ProtoFieldType.STRING, data.toBuf()))
    
    def _parse_dict(self, data: Dict) -> None:
        """Parse dict to protobuf fields."""
        for k, v in data.items():
            if isinstance(v, int):
                self.put_varint(k, v)
            elif isinstance(v, str):
                self.put_utf8(k, v)
            elif isinstance(v, bytes):
                self.put_bytes(k, v)
            elif isinstance(v, dict):
                self.put_protobuf(k, ProtoBuf(v))
            else:
                raise ProtoError(f"unsupport type({type(v)}) to protobuf")
    
    def to_dict(self, out: Dict) -> Dict:
        """Convert to dict using template.
        
        Args:
            out: Template dict with expected types.
        
        Returns:
            Populated dict.
        """
        for k, v in out.items():
            if isinstance(v, int):
                out[k] = self.get_int(k)
            elif isinstance(v, str):
                out[k] = self.get_utf8(k)
            elif isinstance(v, bytes):
                out[k] = self.get_bytes(k)
            elif isinstance(v, dict):
                pb = self.get_protobuf(k)
                if pb is not None:
                    out[k] = pb.to_dict(v)
            else:
                raise ProtoError(f"unsupport type({type(v)}) to protobuf")
        return out

def protobuf_encode(data: Dict) -> bytes:
    """Encode protobuf dict to bytes

    Args:
        data (dict): Request body

    Returns:
        bytes: protobuf format
    """
    body = ProtoBuf(data).toBuf()
    return body

def protobuf_decode(data: Union[bytes, ProtoBuf]) -> Dict:
    """Decode protobuf to dict

    Args:
        data (ProtoBuf): protobuf data

    Returns:
        dict: protobuf data
    """
    out = {}
    if not isinstance(data, ProtoBuf):
        data = ProtoBuf(data=data)
    for f in data.fields:
        k = f.idx
        if f.type in (
            ProtoFieldType.VARINT,
            ProtoFieldType.INT32,
            ProtoFieldType.INT64,
        ):
            v = f.val
        elif f.type == ProtoFieldType.STRING:
            b = f.val
            try:
                s = b.decode("utf-8")
                if all(0x20 <= ord(ch) <= 0x7E or ch in "\r\n\t" for ch in s):
                    v = s
                else:
                    try:
                        v = protobuf_decode(ProtoBuf(b))
                    except Exception:
                        v = {"__bytes_hex__": b.hex()}
            except Exception:
                try:
                    v = protobuf_decode(ProtoBuf(b))
                except Exception:
                    v = {"__bytes_hex__": b.hex()}
        else:
            v = f.val
        if k in out:
            if not isinstance(out[k], list):
                out[k] = [out[k]]
            out[k].append(v)
        else:
            out[k] = v
    return out