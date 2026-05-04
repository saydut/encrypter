"""Saydut Launcher cross-platform discovery + uzaktan sürüm kontrolü."""
from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from pathlib import Path

import requests

from encrypter import __version__

PROGRAMS_URL = "https://www.saydut.com/static/programs.json"
PROGRAM_ID = "saydut-kripto"
SAYDUT_URL = "https://www.saydut.com"


def _semver_tuple(v: str) -> tuple[int, int, int]:
    v = (v or "").strip().lstrip("v")
    parts = v.split(".")
    out = []
    for i in range(3):
        try:
            out.append(int(parts[i]))
        except (ValueError, IndexError):
            out.append(0)
    return tuple(out)  # type: ignore


def find_launcher() -> Path | None:
    if sys.platform.startswith("win"):
        candidates = [
            Path(r"C:\Saydut\SaydutLauncher\SaydutLauncher.exe"),
            Path(r"C:\Saydut\Saydut Launcher\SaydutLauncher.exe"),
            Path(r"C:\Saydut\SaydutLauncher\Saydut Launcher.exe"),
        ]
        hint = Path(r"C:\Saydut\launcher_path.txt")
        if hint.exists():
            try:
                hinted = Path(hint.read_text(encoding="utf-8").strip())
                if hinted.exists():
                    return hinted
            except OSError:
                pass
    else:
        candidates = [
            Path.home() / ".local/bin/saydut-launcher",
            Path("/usr/bin/saydut-launcher"),
            Path("/usr/local/bin/saydut-launcher"),
            Path("/opt/saydut/launcher"),
        ]

    return next((p for p in candidates if p.exists()), None)


def fetch_latest_version(timeout: int = 10) -> str | None:
    try:
        r = requests.get(PROGRAMS_URL, timeout=timeout)
        r.raise_for_status()
        for item in r.json().get("programs", []):
            if item.get("id") == PROGRAM_ID:
                return item.get("version") or None
    except Exception:
        return None
    return None


def update_available(latest: str | None) -> bool:
    if not latest:
        return False
    return _semver_tuple(latest) > _semver_tuple(__version__)


def open_launcher_or_site() -> tuple[bool, str]:
    """Launcher varsa aç, yoksa web tarayıcıda saydut.com aç.

    Dönüş: (başarılı_mı, kullanıcıya_gösterilecek_mesaj)
    """
    path = find_launcher()
    if path:
        try:
            if path.suffix.lower() == ".py":
                subprocess.Popen([sys.executable, str(path)])
            else:
                subprocess.Popen([str(path)])
            return True, "Saydut Launcher açılıyor..."
        except OSError as exc:
            return False, f"Launcher açılamadı: {exc}"
    webbrowser.open(SAYDUT_URL)
    return False, "Launcher bulunamadı, saydut.com açıldı."
