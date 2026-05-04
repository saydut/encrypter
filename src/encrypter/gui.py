"""customtkinter tabanlı GUI."""
from __future__ import annotations

import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from encrypter import __version__
from encrypter.crypto import (
    FolderReport,
    FormatError,
    WrongPasswordError,
    decrypt_file,
    decrypt_folder,
    encrypt_file,
    encrypt_folder,
)
from encrypter.launcher import (
    fetch_latest_version,
    open_launcher_or_site,
    update_available,
)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


def _password_strength(pwd: str) -> tuple[int, str]:
    """0-100 arası bir puan ve etiket döndür."""
    if not pwd:
        return 0, ""
    score = 0
    if len(pwd) >= 8:
        score += 25
    if len(pwd) >= 12:
        score += 15
    if len(pwd) >= 16:
        score += 10
    if any(c.islower() for c in pwd):
        score += 10
    if any(c.isupper() for c in pwd):
        score += 10
    if any(c.isdigit() for c in pwd):
        score += 10
    if any(not c.isalnum() for c in pwd):
        score += 20
    score = min(score, 100)
    if score < 40:
        return score, "Zayıf"
    if score < 70:
        return score, "Orta"
    return score, "Güçlü"


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Saydut Encrypter")
        self.geometry("520x640")
        self.resizable(False, False)
        self.is_busy = False
        self._update_prompted = False

        self._build_ui()
        self.after(1500, self._check_update_async)

    # ---- UI ----

    def _build_ui(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(pady=(20, 8), padx=20, fill="x")
        ctk.CTkLabel(
            header,
            text="SAYDUT ENCRYPTER",
            font=ctk.CTkFont(family="Inter", size=22, weight="bold"),
        ).pack()
        ctk.CTkLabel(
            header,
            text="XChaCha20-Poly1305 + Argon2id",
            font=ctk.CTkFont(family="Inter", size=11),
            text_color="gray",
        ).pack()

        # Parola alanı
        pf = ctk.CTkFrame(self, corner_radius=14)
        pf.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(pf, text="Parola", font=ctk.CTkFont(size=12, weight="bold")).pack(
            pady=(10, 4), padx=12, anchor="w"
        )
        self.pw_entry = ctk.CTkEntry(pf, placeholder_text="Parolanız...", show="*", height=38)
        self.pw_entry.pack(pady=(0, 6), padx=12, fill="x")
        self.pw_entry.bind("<KeyRelease>", lambda _e: self._refresh_strength())

        self.pw_confirm = ctk.CTkEntry(
            pf, placeholder_text="Parola tekrar (sadece şifrelerken)", show="*", height=38
        )
        self.pw_confirm.pack(pady=(0, 6), padx=12, fill="x")

        self.strength_bar = ctk.CTkProgressBar(pf, height=6)
        self.strength_bar.set(0)
        self.strength_bar.pack(pady=(0, 4), padx=12, fill="x")
        self.strength_label = ctk.CTkLabel(
            pf, text="", font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.strength_label.pack(pady=(0, 10), padx=12, anchor="w")

        # Sekmeler
        self.tabs = ctk.CTkTabview(self, width=480, height=240)
        self.tabs.pack(pady=10, padx=20)
        self.tabs.add("Dosya")
        self.tabs.add("Klasör")
        self._build_file_tab()
        self._build_folder_tab()

        # İlerleme
        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0)
        self.progress.pack(pady=(8, 0), padx=22, fill="x")

        self.status = ctk.CTkLabel(
            self, text="Hazır", text_color="gray", font=ctk.CTkFont(size=11)
        )
        self.status.pack(pady=(4, 0))

        self.update_btn = ctk.CTkButton(
            self,
            text="Güncellemeleri Kontrol Et",
            command=self._on_update_clicked,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "#DCE4EE"),
        )
        self.update_btn.pack(side="bottom", pady=14)
        ctk.CTkLabel(
            self, text=f"v{__version__}", font=ctk.CTkFont(size=10), text_color="gray"
        ).pack(side="bottom")

    def _build_file_tab(self) -> None:
        tab = self.tabs.tab("Dosya")
        ctk.CTkLabel(
            tab,
            text="Tek bir dosyayı şifreleyin veya çözün.",
            text_color="gray",
        ).pack(pady=12)

        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=4)
        self.btn_enc = ctk.CTkButton(
            row,
            text="Dosya Şifrele",
            command=self._encrypt_file,
            height=44,
            fg_color="#ef4444",
            hover_color="#b91c1c",
        )
        self.btn_enc.pack(side="left", expand=True, padx=4, fill="x")
        self.btn_dec = ctk.CTkButton(
            row,
            text="Dosya Çöz",
            command=self._decrypt_file,
            height=44,
            fg_color="#22c55e",
            hover_color="#15803d",
        )
        self.btn_dec.pack(side="right", expand=True, padx=4, fill="x")

    def _build_folder_tab(self) -> None:
        tab = self.tabs.tab("Klasör")
        ctk.CTkLabel(
            tab,
            text="Klasördeki TÜM dosyaları işler.\nDikkatli kullanın!",
            text_color="gray",
        ).pack(pady=12)

        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=4)
        self.btn_enc_dir = ctk.CTkButton(
            row,
            text="Klasör Şifrele",
            command=self._encrypt_folder,
            height=44,
            fg_color="#ef4444",
            hover_color="#b91c1c",
        )
        self.btn_enc_dir.pack(side="left", expand=True, padx=4, fill="x")
        self.btn_dec_dir = ctk.CTkButton(
            row,
            text="Klasör Çöz",
            command=self._decrypt_folder,
            height=44,
            fg_color="#22c55e",
            hover_color="#15803d",
        )
        self.btn_dec_dir.pack(side="right", expand=True, padx=4, fill="x")

    # ---- Yardımcılar ----

    def _all_buttons(self):
        return (
            self.btn_enc,
            self.btn_dec,
            self.btn_enc_dir,
            self.btn_dec_dir,
            self.update_btn,
        )

    def _set_busy(self, busy: bool) -> None:
        self.is_busy = busy
        state = "disabled" if busy else "normal"
        for b in self._all_buttons():
            b.configure(state=state)

    def _set_status(self, text: str, error: bool = False) -> None:
        self.after(0, self.status.configure, {
            "text": text,
            "text_color": "#ef4444" if error else "gray",
        })

    def _set_progress(self, pct: float) -> None:
        self.after(0, self.progress.set, max(0.0, min(1.0, pct)))

    def _refresh_strength(self) -> None:
        score, label = _password_strength(self.pw_entry.get())
        self.strength_bar.set(score / 100)
        color = "#ef4444" if score < 40 else "#eab308" if score < 70 else "#22c55e"
        self.strength_label.configure(text=label, text_color=color if label else "gray")

    def _get_password(self, *, confirm: bool) -> str | None:
        pwd = self.pw_entry.get()
        if not pwd:
            messagebox.showwarning("Uyarı", "Lütfen bir parola girin.")
            return None
        if confirm:
            again = self.pw_confirm.get()
            if pwd != again:
                messagebox.showerror("Hata", "Parolalar eşleşmiyor.")
                return None
        return pwd

    def _run_async(self, work, on_done) -> None:
        if self.is_busy:
            return
        self._set_busy(True)
        self._set_progress(0)

        def runner() -> None:
            try:
                result = work()
                self.after(0, lambda: self._finish(on_done, result, None))
            except Exception as exc:
                err = exc
                self.after(0, lambda e=err: self._finish(on_done, None, e))

        threading.Thread(target=runner, daemon=True).start()

    def _finish(self, on_done, result, error) -> None:
        self._set_busy(False)
        self._set_progress(0)
        on_done(result, error)

    def _progress_cb(self, done: int, total: int) -> None:
        if total > 0:
            self._set_progress(done / total)

    # ---- Aksiyonlar ----

    def _encrypt_file(self) -> None:
        pwd = self._get_password(confirm=True)
        if not pwd:
            return
        path = filedialog.askopenfilename()
        if not path:
            return
        path = Path(path)
        self._set_status(f"Şifreleniyor: {path.name}")

        def work():
            return encrypt_file(path, pwd, progress=self._progress_cb)

        def done(res, err):
            if err:
                self._set_status("Hata oluştu", error=True)
                messagebox.showerror("Hata", str(err))
            else:
                self._set_status(f"Tamam: {res.output_path.name}")
                messagebox.showinfo("Başarılı", "Dosya şifrelendi.")

        self._run_async(work, done)

    def _decrypt_file(self) -> None:
        pwd = self._get_password(confirm=False)
        if not pwd:
            return
        path = filedialog.askopenfilename(
            filetypes=[("Saydut", "*.saydut"), ("Tümü", "*.*")]
        )
        if not path:
            return
        path = Path(path)
        self._set_status(f"Çözülüyor: {path.name}")

        def work():
            return decrypt_file(path, pwd, progress=self._progress_cb)

        def done(res, err):
            if isinstance(err, WrongPasswordError):
                self._set_status("Parola yanlış", error=True)
                messagebox.showerror("Hata", "Parola yanlış veya dosya bozuk.")
            elif isinstance(err, FormatError):
                self._set_status("Format hatası", error=True)
                messagebox.showerror("Hata", f"Geçersiz dosya: {err}")
            elif err:
                self._set_status("Hata oluştu", error=True)
                messagebox.showerror("Hata", str(err))
            else:
                self._set_status(f"Tamam: {res.output_path.name}")
                messagebox.showinfo("Başarılı", "Dosya çözüldü.")

        self._run_async(work, done)

    def _encrypt_folder(self) -> None:
        pwd = self._get_password(confirm=True)
        if not pwd:
            return
        folder = filedialog.askdirectory()
        if not folder:
            return
        folder = Path(folder)
        if not messagebox.askyesno(
            "Onay",
            f"'{folder.name}' içindeki tüm dosyalar şifrelenecek.\nDevam edilsin mi?",
        ):
            return
        self._set_status(f"Şifreleniyor: {folder.name}")

        def work():
            return encrypt_folder(folder, pwd, progress=self._progress_cb)

        self._run_async(work, lambda r, e: self._folder_done(r, e, "şifrelendi"))

    def _decrypt_folder(self) -> None:
        pwd = self._get_password(confirm=False)
        if not pwd:
            return
        folder = filedialog.askdirectory()
        if not folder:
            return
        folder = Path(folder)
        if not messagebox.askyesno(
            "Onay",
            f"'{folder.name}' içindeki tüm .saydut dosyaları çözülecek.\nDevam edilsin mi?",
        ):
            return
        self._set_status(f"Çözülüyor: {folder.name}")

        def work():
            return decrypt_folder(folder, pwd, progress=self._progress_cb)

        self._run_async(work, lambda r, e: self._folder_done(r, e, "çözüldü"))

    def _folder_done(self, rep: FolderReport | None, err, verb: str) -> None:
        if err:
            self._set_status("Hata oluştu", error=True)
            messagebox.showerror("Hata", str(err))
            return
        ok = len(rep.succeeded)
        bad = len(rep.failed)
        self._set_status(f"{ok} dosya {verb}, {bad} hata.")
        if bad:
            details = "\n".join(f"• {p.name}: {msg}" for p, msg in rep.failed[:8])
            if len(rep.failed) > 8:
                details += f"\n...ve {len(rep.failed) - 8} dosya daha."
            messagebox.showwarning(
                "Rapor", f"{ok} {verb}, {bad} hata:\n\n{details}"
            )
        else:
            messagebox.showinfo("Rapor", f"{ok} dosya {verb}.")

    # ---- Güncelleme ----

    def _check_update_async(self) -> None:
        def worker():
            latest = fetch_latest_version()
            if update_available(latest):
                self.after(0, lambda: self._show_update_prompt(latest))

        threading.Thread(target=worker, daemon=True).start()

    def _show_update_prompt(self, latest: str) -> None:
        if self._update_prompted:
            return
        self._update_prompted = True
        top = ctk.CTkToplevel(self)
        top.title("Güncelleme mevcut")
        top.geometry("440x200")
        top.resizable(False, False)
        top.grab_set()
        ctk.CTkLabel(top, text="Güncelleme mevcut", font=("Inter", 16, "bold")).pack(
            pady=(18, 8)
        )
        ctk.CTkLabel(
            top, text=f"Mevcut: {__version__}\nYeni: {latest}", font=("Inter", 12)
        ).pack(pady=(0, 14))
        row = ctk.CTkFrame(top, fg_color="transparent")
        row.pack(pady=4)
        ctk.CTkButton(
            row,
            text="Launcher Aç",
            width=130,
            command=lambda: (top.destroy(), self._on_update_clicked()),
        ).pack(side="left", padx=6)
        ctk.CTkButton(row, text="Sonra", width=100, command=top.destroy).pack(
            side="left", padx=6
        )

    def _on_update_clicked(self) -> None:
        ok, msg = open_launcher_or_site()
        self._set_status(msg, error=not ok)


def run() -> None:
    App().mainloop()


if __name__ == "__main__":
    run()
