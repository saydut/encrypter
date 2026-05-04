"""
.saydut dosya formatı.

Layout:
  offset  size  alan
  0       6     magic    "SAYDUT"
  6       1     version  (uint8) — şimdilik 1
  7       1     reserved (uint8) — 0
  8       16    argon2id salt
  24      4     argon2id ops_limit (uint32 BE)
  28      4     argon2id mem_limit MB (uint32 BE)
  32      24    libsodium secretstream header
  56      ...   AEAD chunked stream (libsodium secretstream)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"SAYDUT"
VERSION = 1

HEADER_STRUCT = struct.Struct(">6sBB16sII24s")
HEADER_SIZE = HEADER_STRUCT.size  # 56

CHUNK_SIZE = 64 * 1024  # 64 KB veri (libsodium tag yok bu sayıya)

EXTENSION = ".saydut"


@dataclass(frozen=True)
class Header:
    salt: bytes
    ops_limit: int
    mem_limit_mb: int
    secretstream_header: bytes

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            MAGIC,
            VERSION,
            0,
            self.salt,
            self.ops_limit,
            self.mem_limit_mb,
            self.secretstream_header,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        if len(data) < HEADER_SIZE:
            raise ValueError("Dosya başlığı eksik veya bozuk.")
        magic, version, _reserved, salt, ops, mem, ss_header = HEADER_STRUCT.unpack(
            data[:HEADER_SIZE]
        )
        if magic != MAGIC:
            raise ValueError("Bu dosya bir .saydut dosyası değil.")
        if version != VERSION:
            raise ValueError(f"Desteklenmeyen format sürümü: {version}")
        return cls(
            salt=salt,
            ops_limit=ops,
            mem_limit_mb=mem,
            secretstream_header=ss_header,
        )
