import os
from pathlib import Path

import pytest

from encrypter.crypto import (
    FormatError,
    WrongPasswordError,
    decrypt_file,
    decrypt_folder,
    encrypt_file,
    encrypt_folder,
)
from encrypter.format import EXTENSION


def test_roundtrip_small(tmp_path: Path):
    src = tmp_path / "a.txt"
    src.write_text("merhaba dünya")
    encrypt_file(src, "p4r0la")
    enc = src.with_name(src.name + EXTENSION)
    assert enc.exists() and not src.exists()

    decrypt_file(enc, "p4r0la")
    assert src.exists() and src.read_text() == "merhaba dünya"
    assert not enc.exists()


def test_roundtrip_chunked(tmp_path: Path):
    # CHUNK_SIZE'dan büyük dosya — birden fazla chunk
    src = tmp_path / "big.bin"
    payload = os.urandom(200 * 1024)
    src.write_bytes(payload)

    encrypt_file(src, "x")
    decrypt_file(src.with_name(src.name + EXTENSION), "x")
    assert src.read_bytes() == payload


def test_wrong_password(tmp_path: Path):
    src = tmp_path / "a.txt"
    src.write_text("gizli")
    encrypt_file(src, "dogru")
    enc = src.with_name(src.name + EXTENSION)

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, "yanlis")
    # yanlış parola çıkışta tmp bırakmamalı, src de hâlâ yok olmalı
    assert not src.exists()
    assert enc.exists()
    assert not (tmp_path / (src.name + ".tmp")).exists()


def test_bad_format(tmp_path: Path):
    bogus = tmp_path / "x.saydut"
    bogus.write_bytes(b"NOT A SAYDUT FILE")
    with pytest.raises(FormatError):
        decrypt_file(bogus, "any")


def test_folder_roundtrip(tmp_path: Path):
    (tmp_path / "a.txt").write_text("1")
    (tmp_path / "b.txt").write_text("2")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.txt").write_text("3")

    rep = encrypt_folder(tmp_path, "p")
    assert len(rep.succeeded) == 3 and not rep.failed

    rep = decrypt_folder(tmp_path, "p")
    assert len(rep.succeeded) == 3 and not rep.failed
    assert (tmp_path / "a.txt").read_text() == "1"
    assert (tmp_path / "sub" / "c.txt").read_text() == "3"
