"""
Yüksek seviyeli dosya/klasör şifreleme — libsodium üzerine ince bir sarmal.

KDF:    Argon2id (libsodium pwhash)
AEAD:   crypto_secretstream_xchacha20poly1305 (chunked, sıralı)
Format: bkz. format.py
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import nacl.bindings as nb
import nacl.pwhash

from .format import CHUNK_SIZE, EXTENSION, HEADER_SIZE, Header

KEY_BYTES = nb.crypto_secretstream_xchacha20poly1305_KEYBYTES  # 32
TAG_BYTES = nb.crypto_secretstream_xchacha20poly1305_ABYTES    # 17
TAG_MESSAGE = nb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = nb.crypto_secretstream_xchacha20poly1305_TAG_FINAL

# Argon2id INTERACTIVE varsayılanları (~0.5 sn, 64 MB) — masaüstü uygulaması için makul.
DEFAULT_OPS = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE
DEFAULT_MEM_BYTES = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE


def _derive_key(password: str, salt: bytes, ops: int, mem_bytes: int) -> bytes:
    return nacl.pwhash.argon2id.kdf(
        size=KEY_BYTES,
        password=password.encode("utf-8"),
        salt=salt,
        opslimit=ops,
        memlimit=mem_bytes,
    )


ProgressCb = Callable[[int, int], None]  # (yazılan_bayt, toplam_bayt)


class WrongPasswordError(Exception):
    """Parola yanlış veya dosya bozuk."""


class FormatError(Exception):
    """Dosya .saydut formatında değil ya da başlık bozuk."""


@dataclass
class CryptoResult:
    output_path: Path
    bytes_processed: int


def encrypt_file(
    src: Path,
    password: str,
    *,
    dst: Path | None = None,
    delete_src: bool = True,
    progress: ProgressCb | None = None,
) -> CryptoResult:
    """src dosyasını şifrele, src.saydut olarak yaz.

    Atomik: önce .tmp'e yazılır, fsync edilir, sonra rename.
    """
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)
    dst = Path(dst) if dst else src.with_name(src.name + EXTENSION)

    salt = os.urandom(nacl.pwhash.argon2id.SALTBYTES)
    ops = DEFAULT_OPS
    mem_bytes = DEFAULT_MEM_BYTES
    mem_mb = max(1, mem_bytes // (1024 * 1024))
    key = _derive_key(password, salt, ops, mem_bytes)

    state = nb.crypto_secretstream_xchacha20poly1305_state()
    ss_header = nb.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    header = Header(
        salt=salt,
        ops_limit=ops,
        mem_limit_mb=mem_mb,
        secretstream_header=ss_header,
    )

    total = src.stat().st_size
    written = 0

    tmp = dst.with_name(dst.name + ".tmp")
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header.pack())
            while True:
                chunk = fin.read(CHUNK_SIZE)
                next_byte = fin.read(1)
                is_final = not next_byte
                if next_byte:
                    # geri sar — bir byte fazla okuduk
                    fin.seek(-1, os.SEEK_CUR)
                tag = TAG_FINAL if is_final else TAG_MESSAGE
                ct = nb.crypto_secretstream_xchacha20poly1305_push(
                    state, chunk, None, tag
                )
                fout.write(ct)
                written += len(chunk)
                if progress:
                    progress(written, total)
                if is_final:
                    break
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, dst)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise

    if delete_src:
        try:
            src.unlink()
        except OSError:
            pass

    return CryptoResult(output_path=dst, bytes_processed=total)


def decrypt_file(
    src: Path,
    password: str,
    *,
    dst: Path | None = None,
    delete_src: bool = True,
    progress: ProgressCb | None = None,
) -> CryptoResult:
    """src.saydut dosyasını çöz, .saydut uzantısını kaldırarak yaz.

    Yanlış parolada veya bozuk dosyada WrongPasswordError fırlatır,
    yarım dosya bırakmaz.
    """
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)

    if dst is None:
        if src.suffix == EXTENSION:
            dst = src.with_suffix("")
        else:
            dst = src.with_name(src.name + ".decrypted")

    with open(src, "rb") as fin:
        raw_header = fin.read(HEADER_SIZE)
        try:
            header = Header.unpack(raw_header)
        except ValueError as exc:
            raise FormatError(str(exc)) from exc

        mem_bytes = header.mem_limit_mb * 1024 * 1024
        try:
            key = _derive_key(password, header.salt, header.ops_limit, mem_bytes)
        except Exception as exc:
            raise WrongPasswordError("Anahtar türetilemedi.") from exc

        state = nb.crypto_secretstream_xchacha20poly1305_state()
        try:
            nb.crypto_secretstream_xchacha20poly1305_init_pull(
                state, header.secretstream_header, key
            )
        except Exception as exc:
            raise WrongPasswordError("Başlık doğrulanamadı.") from exc

        total = src.stat().st_size - HEADER_SIZE
        read_bytes = 0
        ct_chunk_size = CHUNK_SIZE + TAG_BYTES

        tmp = dst.with_name(dst.name + ".tmp")
        try:
            with open(tmp, "wb") as fout:
                while True:
                    chunk = fin.read(ct_chunk_size)
                    if not chunk:
                        # final tag göremeden bitti
                        raise WrongPasswordError(
                            "Dosya beklenmedik şekilde bitti (bozuk olabilir)."
                        )
                    try:
                        plain, tag = nb.crypto_secretstream_xchacha20poly1305_pull(
                            state, chunk, None
                        )
                    except Exception as exc:
                        raise WrongPasswordError(
                            "Parola yanlış veya dosya bozuk."
                        ) from exc
                    fout.write(plain)
                    read_bytes += len(chunk)
                    if progress:
                        progress(read_bytes, total)
                    if tag == TAG_FINAL:
                        break
                fout.flush()
                os.fsync(fout.fileno())
            os.replace(tmp, dst)
        except Exception:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise

    if delete_src:
        try:
            src.unlink()
        except OSError:
            pass

    return CryptoResult(output_path=dst, bytes_processed=total)


# ---- Klasör işlemleri ----

@dataclass
class FolderReport:
    succeeded: list[Path]
    failed: list[tuple[Path, str]]

    @property
    def total(self) -> int:
        return len(self.succeeded) + len(self.failed)


def iter_files(folder: Path, *, only_ext: str | None = None) -> Iterable[Path]:
    for root, _, files in os.walk(folder):
        for f in files:
            p = Path(root) / f
            if only_ext is None:
                if not p.name.endswith(EXTENSION):
                    yield p
            elif p.suffix == only_ext:
                yield p


def encrypt_folder(
    folder: Path, password: str, *, progress: ProgressCb | None = None
) -> FolderReport:
    folder = Path(folder)
    targets = list(iter_files(folder))
    return _process_many(targets, password, encrypt_file, progress)


def decrypt_folder(
    folder: Path, password: str, *, progress: ProgressCb | None = None
) -> FolderReport:
    folder = Path(folder)
    targets = list(iter_files(folder, only_ext=EXTENSION))
    return _process_many(targets, password, decrypt_file, progress)


def _process_many(
    targets: list[Path],
    password: str,
    op,
    progress: ProgressCb | None,
) -> FolderReport:
    succeeded: list[Path] = []
    failed: list[tuple[Path, str]] = []
    total = len(targets)
    for i, p in enumerate(targets, start=1):
        try:
            op(p, password)
            succeeded.append(p)
        except Exception as exc:
            failed.append((p, str(exc)))
        if progress:
            progress(i, total)
    return FolderReport(succeeded=succeeded, failed=failed)
