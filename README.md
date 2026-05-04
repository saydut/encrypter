# Saydut Encrypter

Dosyaları ve klasörleri **XChaCha20-Poly1305** + **Argon2id** ile güvenli biçimde şifreleyen masaüstü uygulaması. Şifrelenmiş dosyalar `.saydut` uzantısı alır.

## Özellikler

- **Modern kripto**: libsodium tabanlı (PyNaCl). XChaCha20-Poly1305 streaming AEAD, Argon2id KDF.
- **Büyük dosya desteği**: 64 KB chunk'larla streaming — dosya boyutundan bağımsız çalışır.
- **Atomik yazma**: yarım kalmış işlem dosyayı bozmaz.
- **GUI ve CLI**: customtkinter arayüz veya komut satırı.
- **Klasör işlemleri**: tek tıkla bütün klasörü şifrele/çöz, hatalı dosya raporu.
- **Cross-platform**: Linux ve Windows.

## Kurulum

### Arch Linux (AUR)

```bash
yay -S encrypter
```

### pip ile

```bash
pip install git+https://github.com/saydut/encrypter
```

## Kullanım

### GUI

```bash
encrypter gui
# veya
python -m encrypter
```

### CLI

```bash
encrypter encrypt dosya.txt          # → dosya.txt.saydut
encrypter decrypt dosya.txt.saydut   # → dosya.txt
encrypter encrypt-dir klasor/
encrypter decrypt-dir klasor/
encrypter version
```

## Dosya Formatı (`.saydut` v1)

| Offset | Boyut | İçerik |
|--------|-------|--------|
| 0      | 6     | Magic `SAYDUT` |
| 6      | 1     | Sürüm (1) |
| 7      | 1     | Reserved |
| 8      | 16    | Argon2id salt |
| 24     | 4     | Argon2id ops_limit |
| 28     | 4     | Argon2id mem_limit (MB) |
| 32     | 24    | secretstream header |
| 56     | ...   | AEAD chunked stream (64 KB chunk + 17 byte tag) |

## Lisans

GPL-3.0
