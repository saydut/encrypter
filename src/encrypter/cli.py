"""Komut satırı arayüzü."""
from __future__ import annotations

import getpass
import sys
from pathlib import Path

import typer

from encrypter import __version__
from encrypter.crypto import (
    FormatError,
    WrongPasswordError,
    decrypt_file,
    decrypt_folder,
    encrypt_file,
    encrypt_folder,
)

app = typer.Typer(
    help="Saydut Encrypter — dosya/klasör şifreleme aracı.",
    invoke_without_command=True,
    no_args_is_help=False,
)


BANNER = f"""\
╭──────────────────────────────────────────────╮
│  SAYDUT ENCRPTER  v{__version__:<8}                  │
│  XChaCha20-Poly1305 + Argon2id              │
│  .saydut formatında dosya/klasör şifreleme  │
╰──────────────────────────────────────────────╯

Komutlar:
  encrpter                 Grafik arayüzü açar (varsayılan)
  encrpter encrypt FILE    Dosya şifrele
  encrpter decrypt FILE    .saydut dosyası çöz
  encrpter encrypt-dir DIR Klasör şifrele
  encrpter decrypt-dir DIR Klasör çöz
  encrpter --help          Tüm seçenekleri göster

Grafik arayüz açılıyor...
"""


@app.callback()
def _root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(BANNER)
        from encrypter.gui import run
        run()


def _ask_password(confirm: bool) -> str:
    pwd = getpass.getpass("Parola: ")
    if not pwd:
        typer.echo("Parola boş olamaz.", err=True)
        raise typer.Exit(2)
    if confirm:
        again = getpass.getpass("Parola (tekrar): ")
        if pwd != again:
            typer.echo("Parolalar eşleşmedi.", err=True)
            raise typer.Exit(2)
    return pwd


def _print_progress(label: str):
    last = [-1]

    def cb(done: int, total: int) -> None:
        if total <= 0:
            return
        pct = int(done * 100 / total)
        if pct != last[0]:
            last[0] = pct
            sys.stdout.write(f"\r{label} {pct:3d}%")
            sys.stdout.flush()
            if done >= total:
                sys.stdout.write("\n")

    return cb


@app.command()
def encrypt(path: Path = typer.Argument(..., exists=True, readable=True)):
    """Bir dosyayı şifrele."""
    pwd = _ask_password(confirm=True)
    res = encrypt_file(path, pwd, progress=_print_progress("Şifreleniyor"))
    typer.echo(f"Tamam: {res.output_path}")


@app.command()
def decrypt(path: Path = typer.Argument(..., exists=True, readable=True)):
    """Bir .saydut dosyasını çöz."""
    pwd = _ask_password(confirm=False)
    try:
        res = decrypt_file(path, pwd, progress=_print_progress("Çözülüyor"))
    except WrongPasswordError:
        typer.echo("Parola yanlış veya dosya bozuk.", err=True)
        raise typer.Exit(1)
    except FormatError as exc:
        typer.echo(f"Format hatası: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Tamam: {res.output_path}")


@app.command("encrypt-dir")
def encrypt_dir(
    folder: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True)
):
    """Klasördeki tüm dosyaları şifrele."""
    pwd = _ask_password(confirm=True)
    rep = encrypt_folder(folder, pwd, progress=_print_progress("İşleniyor"))
    typer.echo(f"{len(rep.succeeded)}/{rep.total} başarılı.")
    for path, err in rep.failed:
        typer.echo(f"  hata: {path}: {err}", err=True)


@app.command("decrypt-dir")
def decrypt_dir(
    folder: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True)
):
    """Klasördeki tüm .saydut dosyalarını çöz."""
    pwd = _ask_password(confirm=False)
    rep = decrypt_folder(folder, pwd, progress=_print_progress("İşleniyor"))
    typer.echo(f"{len(rep.succeeded)}/{rep.total} başarılı.")
    for path, err in rep.failed:
        typer.echo(f"  hata: {path}: {err}", err=True)


@app.command()
def gui():
    """GUI'yi aç."""
    from encrypter.gui import run

    run()


@app.command()
def version():
    """Sürüm bilgisini yazdır."""
    typer.echo(f"encrypter {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
