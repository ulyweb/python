
#!/usr/bin/env python3
"""
Seed Vault GUI - Secure per-word storage for 12/24 seed phrases.

Features:
- AES-GCM per-word encryption with scrypt KDF (memory-hard)
- Secured tier (per-word codes) + View tier (single view PIN or master-only) + Plaintext (NOT recommended)
- Require master PIN (non-empty)
- Runtime auto-install for 'cryptography' if missing (pip/ensurepip)
- Windows DPAPI wrapping option (prefer on Windows): binds vault to the current user profile
- GUI tabs: Encrypt, Show, Decrypt, List
- Selection methods for secured words (first N, specific indices, by text, random)
- Final masked preview (secured shown as [LOCKED: #i]) before saving
- Rate limiting & attempt limits per index/session (progressive backoff)

DISCLAIMER:
- Electronic storage of recovery phrases is risky; use strong passphrases and keep vaults offline.
- Attempt limiting in the app cannot protect against offline brute-force; scrypt and DPAPI help harden storage.
"""

import os
import sys
import json
import base64
import time
import random
import ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Dict, Any, Tuple, Set, Optional

# -------------------- Auto-dependency installer --------------------

import subprocess
import importlib

def run_pip_install(pkg: str, user: bool = False, extra_args: Optional[List[str]] = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "pip", "install", pkg]
    if user:
        cmd.append("--user")
    if extra_args:
        cmd.extend(extra_args)
    print(f"[*] Running: {' '.join(cmd)}")
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def ensure_pip() -> bool:
    try:
        import pip  # noqa: F401
        return True
    except Exception:
        try:
            import ensurepip
            ensurepip.bootstrap()
            import pip  # noqa: F401
            return True
        except Exception:
            return False

def ensure_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
        return
    except Exception:
        print("[*] 'cryptography' not found. Attempting automatic installation...")
        print(f"    Using Python interpreter: {sys.executable}")
    if not ensure_pip():
        messagebox.showerror("Dependency error",
                             "Unable to initialize pip automatically.\n"
                             "Please install pip manually and rerun.")
        raise SystemExit(1)
    proc = run_pip_install("cryptography", user=False, extra_args=["--quiet"])
    if proc.returncode != 0:
        print("[*] System-level install failed. Retrying with '--user' ...")
        proc = run_pip_install("cryptography", user=True, extra_args=["--quiet"])
    if proc.returncode != 0:
        messagebox.showerror("Dependency error",
                             "Automatic installation of 'cryptography' failed.\n\n"
                             f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}\n\n"
                             "Try manually:\n"
                             f"{sys.executable} -m pip install cryptography\n"
                             f"{sys.executable} -m pip install --user cryptography\n"
                             f"{sys.executable} -m pip install --only-binary=:all: cryptography")
        raise SystemExit(1)
    importlib.invalidate_caches()
    try:
        import cryptography  # noqa: F401
        print("[+] 'cryptography' installed successfully.")
    except Exception as e:
        messagebox.showerror("Dependency error",
                             "Installation seemed to succeed but import failed.\n"
                             f"Interpreter: {sys.executable}\nError: {e}")
        raise SystemExit(1)

# Ensure dependency before importing crypto modules
ensure_cryptography()
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

VERSION = "GUI-1.1"

# -------------------- Crypto helpers --------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def derive_key_scrypt(secret: bytes, salt: bytes, length: int = 32) -> bytes:
    # Tune n/r/p for your environment
    kdf = Scrypt(salt=salt, length=length, n=32768, r=8, p=2, backend=default_backend())
    return kdf.derive(secret)

def derive_secured_key(master_pin: str, word_code: str, index: int, salt: bytes) -> bytes:
    if not word_code:
        raise ValueError("Per-word code/PIN is required.")
    secret = f"{master_pin}|{word_code}|idx:{index}".encode("utf-8")
    return derive_key_scrypt(secret, salt)

def derive_view_key(master_pin: str, view_pin: str, index: int, salt: bytes) -> bytes:
    secret = f"{master_pin}|view:{view_pin}|idx:{index}".encode("utf-8")
    return derive_key_scrypt(secret, salt)

def encrypt_word(index: int, word: str, key: bytes) -> Dict[str, str]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = f"seedword:{index}".encode("utf-8")
    pt = word.encode("utf-8")
    ct = aesgcm.encrypt(nonce, pt, aad)
    return {"nonce": b64e(nonce), "aad": b64e(aad), "ciphertext": b64e(ct)}

def decrypt_entry(entry: Dict[str, Any], key: bytes) -> str:
    nonce = b64d(entry["nonce"])
    aad = b64d(entry["aad"])
    ct = b64d(entry["ciphertext"])
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")

# -------------------- Windows DPAPI (optional) --------------------

IS_WINDOWS = (os.name == "nt")

if IS_WINDOWS:
    import ctypes.wintypes as wintypes
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    CryptProtectData = ctypes.windll.crypt32.CryptProtectData
    CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
    LocalFree = ctypes.windll.kernel32.LocalFree

    def _bytes_to_blob(data: bytes) -> DATA_BLOB:
        arr = (ctypes.c_byte * len(data)).from_buffer_copy(data)
        return DATA_BLOB(len(data), ctypes.cast(arr, ctypes.POINTER(ctypes.c_byte)))

    def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            LocalFree(blob.pbData)

    def dpapi_protect(data: bytes, description: str = "SeedVault") -> bytes:
        in_blob = _bytes_to_blob(data)
        out_blob = DATA_BLOB()
        if not CryptProtectData(ctypes.byref(in_blob), description, None, None, None, 0, ctypes.byref(out_blob)):
            raise RuntimeError("CryptProtectData failed")
        return _blob_to_bytes(out_blob)

    def dpapi_unprotect(blob_bytes: bytes) -> bytes:
        in_blob = _bytes_to_blob(blob_bytes)
        out_blob = DATA_BLOB()
        # description out not used
        if not CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            raise RuntimeError("CryptUnprotectData failed")
        return _blob_to_bytes(out_blob)

def wrap_with_dpapi_if_enabled(vault_dict: Dict[str, Any], enable_dpapi: bool, path: str) -> None:
    """
    Save vault to path. If enable_dpapi and on Windows, wrap bytes with DPAPI
    and store a small wrapper JSON containing the base64 blob.
    """
    raw = json.dumps(vault_dict, indent=2).encode("utf-8")
    if enable_dpapi and IS_WINDOWS:
        try:
            blob = dpapi_protect(raw, description="SeedVault")
        except Exception as e:
            messagebox.showerror("DPAPI error", f"Failed to protect with DPAPI:\n{e}\nSaving without DPAPI.")
            blob = None
        if blob:
            wrapper = {"dpapi": True, "version": VERSION, "blob_b64": b64e(blob)}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(wrapper, f, indent=2)
            messagebox.showinfo("Saved", f"Vault saved with DPAPI (user-bound):\n{path}")
            return
    # fallback: plain JSON
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault_dict, f, indent=2)
    messagebox.showinfo("Saved", f"Vault saved:\n{path}")

def load_vault_any(path: str) -> Dict[str, Any]:
    """
    Load vault from path. If a DPAPI wrapper is detected (dpapi=True),
    unprotect and return the inner vault dict.
    """
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if isinstance(obj, dict) and obj.get("dpapi") is True:
        if not IS_WINDOWS:
            raise RuntimeError("This vault is DPAPI-wrapped and can only be unwrapped on Windows.")
        blob_b64 = obj.get("blob_b64")
        if not blob_b64:
            raise RuntimeError("DPAPI wrapper missing blob_b64.")
        blob = b64d(blob_b64)
        raw = dpapi_unprotect(blob)
        return json.loads(raw.decode("utf-8"))
    return obj

# -------------------- UI helpers --------------------

def ensure_json_extension(path: str) -> str:
    path = path.strip()
    if not path:
        return "seed_vault.json"
    if not path.lower().endswith(".json"):
        path += ".json"
    return path

def parse_words_from_text(text: str) -> List[str]:
    tokens = [t.strip() for t in text.replace("\n", " ").split(" ") if t.strip()]
    return tokens

def indices_from_text(s: str, total: int) -> List[int]:
    parts = [p.strip() for p in s.replace(",", " ").split() if p.strip()]
    idxs = []
    for p in parts:
        if not p.isdigit():
            raise ValueError(f"Invalid index: {p}")
        i = int(p)
        if not (1 <= i <= total):
            raise ValueError(f"Index out of range: {i} (1..{total})")
        idxs.append(i)
    return sorted(set(idxs))

# -------------------- Rate limiting --------------------

class RateLimiter:
    """
    Progressive backoff per key (e.g., per index or action).
    - Each failed attempt increases delay: min(60s, 2^(n-1))
    - Enforces next-allowed timestamps; refuses attempts before that time.
    - Optional max attempts -> impose a cooldown (e.g., 5 minutes).
    """
    def __init__(self, max_attempts: int = 10, cooldown_seconds: int = 300):
        self.attempts: Dict[str, int] = {}
        self.next_allowed: Dict[str, float] = {}
        self.max_attempts = max_attempts
        self.cooldown = cooldown_seconds

    def can_attempt(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        t = self.next_allowed.get(key, 0)
        if now < t:
            return False, int(t - now)
        return True, 0

    def register_failure(self, key: str) -> int:
        n = self.attempts.get(key, 0) + 1
        self.attempts[key] = n
        if n >= self.max_attempts:
            delay = self.cooldown
        else:
            delay = min(60, 2 ** (n - 1))  # 1,2,4,8,16,32,60...
        self.next_allowed[key] = time.time() + delay
        return delay

    def register_success(self, key: str) -> None:
        self.attempts.pop(key, None)
        self.next_allowed.pop(key, None)

# -------------------- Per-word code dialog --------------------

class CodesDialog(tk.Toplevel):
    def __init__(self, master, indices: List[int]):
        super().__init__(master)
        self.title("Per-word codes")
        self.resizable(False, False)
        self.codes: Dict[int, str] = {}
        ttk.Label(self, text="Enter per-word code/PIN (8+ chars recommended):").grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        self.entries: Dict[int, tk.Entry] = {}
        for r, idx in enumerate(indices, start=1):
            ttk.Label(self, text=f"#{idx}").grid(row=r, column=0, sticky="e", padx=10, pady=5)
            e = ttk.Entry(self, show="*")
            e.grid(row=r, column=1, sticky="we", padx=10, pady=5)
            self.entries[idx] = e
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=len(indices)+1, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="OK", command=self.on_ok).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(row=0, column=1, padx=5)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.transient(master)
        self.grab_set()
        self.wait_window(self)

    def on_ok(self):
        for idx, entry in self.entries.items():
            val = entry.get().strip()
            if not val:
                messagebox.showerror("Missing code", f"Code/PIN required for word #{idx}.")
                return
            self.codes[idx] = val
        self.destroy()

    def on_cancel(self):
        self.codes = {}
        self.destroy()

# -------------------- Main App --------------------

class SeedVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSeed Vault")
        self.geometry("940x720")

        # Rate limiter
        self.ratelimiter = RateLimiter(max_attempts=10, cooldown_seconds=300)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.tab_encrypt = ttk.Frame(notebook)
        self.tab_show = ttk.Frame(notebook)
        self.tab_decrypt = ttk.Frame(notebook)
        self.tab_list = ttk.Frame(notebook)

        notebook.add(self.tab_encrypt, text="Encrypt")
        notebook.add(self.tab_show, text="Show")
        notebook.add(self.tab_decrypt, text="Decrypt")
        notebook.add(self.tab_list, text="List")

        self.build_encrypt_tab()
        self.build_show_tab()
        self.build_decrypt_tab()
        self.build_list_tab()

    # -------- Encrypt Tab --------

    def build_encrypt_tab(self):
        frm = self.tab_encrypt

        # Master PIN (REQUIRED)
        ttk.Label(frm, text="Master PIN/passphrase (REQUIRED):").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.master_pin_e = ttk.Entry(frm, show="*")
        self.master_pin_e.grid(row=0, column=1, sticky="we", padx=10, pady=5)
        frm.columnconfigure(1, weight=1)

        # DPAPI toggle (Windows only, default ON)
        ttk.Label(frm, text="Windows DPAPI wrapping:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.dpapi_var = tk.BooleanVar(value=IS_WINDOWS)  # prefer DPAPI on Windows
        self.dpapi_chk = ttk.Checkbutton(frm, text=("Enable DPAPI (binds vault to current Windows user)" if IS_WINDOWS
                                                    else "DPAPI not available on this OS"), variable=self.dpapi_var)
        self.dpapi_chk.grid(row=1, column=1, sticky="w", padx=10, pady=5)
        if not IS_WINDOWS:
            self.dpapi_chk.state(["disabled"])

        # Remaining words storage mode
        ttk.Label(frm, text="Remaining words storage:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.storage_mode = tk.StringVar(value="view")
        self.view_pin_e = ttk.Entry(frm, show="*")
        rb1 = ttk.Radiobutton(frm, text="Encrypt with view PIN (recommended)", variable=self.storage_mode, value="view", command=self.on_storage_mode_change)
        rb2 = ttk.Radiobutton(frm, text="Encrypt with master only (no view PIN)", variable=self.storage_mode, value="view_master", command=self.on_storage_mode_change)
        rb3 = ttk.Radiobutton(frm, text="Plaintext (NOT recommended)", variable=self.storage_mode, value="plaintext", command=self.on_storage_mode_change)
        rb1.grid(row=2, column=1, sticky="w", padx=10, pady=5)
        rb2.grid(row=3, column=1, sticky="w", padx=10, pady=2)
        rb3.grid(row=4, column=1, sticky="w", padx=10, pady=2)

        ttk.Label(frm, text="View PIN (if using view PIN):").grid(row=5, column=0, sticky="w", padx=10, pady=5)
        self.view_pin_e.grid(row=5, column=1, sticky="we", padx=10, pady=5)

        # Vault filename
        ttk.Label(frm, text="Vault filename (.json):").grid(row=6, column=0, sticky="w", padx=10, pady=5)
        self.vault_name_e = ttk.Entry(frm)
        self.vault_name_e.insert(0, "seed_vault.json")
        self.vault_name_e.grid(row=6, column=1, sticky="we", padx=10, pady=5)

        # Seed words input
        ttk.Label(frm, text="Seed words (paste or type; exactly 12 or 24 words):").grid(row=7, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.words_text = tk.Text(frm, height=8)
        self.words_text.grid(row=8, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)
        frm.rowconfigure(8, weight=1)

        parse_btn = ttk.Button(frm, text="Parse & Preview", command=self.on_parse_preview)
        parse_btn.grid(row=9, column=0, padx=10, pady=5, sticky="w")

        # Preview list
        ttk.Label(frm, text="Preview of entered words:").grid(row=10, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.preview_list = tk.Listbox(frm, height=10)
        self.preview_list.grid(row=11, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)
        frm.rowconfigure(11, weight=1)

        # Secured selection controls
        ttk.Label(frm, text="How many words to secure with per-word codes:").grid(row=12, column=0, sticky="w", padx=10, pady=5)
        self.secure_count_var = tk.IntVar(value=0)
        self.secure_count_spin = ttk.Spinbox(frm, from_=0, to=24, textvariable=self.secure_count_var)
        self.secure_count_spin.grid(row=12, column=1, sticky="w", padx=10, pady=5)

        ttk.Label(frm, text="Selection method:").grid(row=13, column=0, sticky="w", padx=10, pady=5)
        self.select_method_var = tk.StringVar(value="first")
        self.select_method_cb = ttk.Combobox(frm, textvariable=self.select_method_var, values=["first", "indices", "words", "random"], state="readonly")
        self.select_method_cb.grid(row=13, column=1, sticky="w", padx=10, pady=5)

        ttk.Label(frm, text="Selection details (indices e.g. 1,3,5 or words on new lines):").grid(row=14, column=0, sticky="w", padx=10, pady=5)
        self.select_details_text = tk.Text(frm, height=4)
        self.select_details_text.grid(row=14, column=1, sticky="we", padx=10, pady=5)

        preview_sel_btn = ttk.Button(frm, text="Preview Secured Masking", command=self.on_preview_masking)
        preview_sel_btn.grid(row=15, column=0, padx=10, pady=5, sticky="w")

        ttk.Label(frm, text="Final masked preview:").grid(row=16, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.masked_list = tk.Listbox(frm, height=10)
        self.masked_list.grid(row=17, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)
        frm.rowconfigure(17, weight=1)

        encrypt_btn = ttk.Button(frm, text="Encrypt & Save Vault", command=self.on_encrypt_save)
        encrypt_btn.grid(row=18, column=0, columnspan=2, padx=10, pady=10, sticky="e")

        # State
        self.parsed_words: List[str] = []
        self.secured_indices: List[int] = []

    def on_storage_mode_change(self):
        mode = self.storage_mode.get()
        if mode == "view":
            self.view_pin_e.configure(state="normal")
        else:
            self.view_pin_e.delete(0, "end")
            self.view_pin_e.configure(state="disabled")

    def on_parse_preview(self):
        text = self.words_text.get("1.0", "end").strip()
        words = parse_words_from_text(text)
        if len(words) not in (12, 24):
            messagebox.showerror("Invalid count", f"You entered {len(words)} words. Please enter exactly 12 or 24.")
            return
        self.parsed_words = words
        self.preview_list.delete(0, "end")
        for i, w in enumerate(words, start=1):
            self.preview_list.insert("end", f"{i:2d}. {w}")
        self.secure_count_var.set(len(words))
        messagebox.showinfo("Parsed", f"Parsed {len(words)} words successfully.")

    def compute_secured_indices(self) -> Optional[List[int]]:
        if not self.parsed_words:
            messagebox.showerror("No words", "Please parse your words first.")
            return None
        total = len(self.parsed_words)
        n = self.secure_count_var.get()
        if n < 0 or n > total:
            messagebox.showerror("Invalid number", f"Secure count must be between 0 and {total}.")
            return None
        method = self.select_method_var.get()
        if n == 0:
            return []
        if n == total:
            return list(range(1, total+1))
        if method == "first":
            return list(range(1, n+1))
        elif method == "indices":
            s = self.select_details_text.get("1.0", "end").strip()
            try:
                idxs = indices_from_text(s, total)
            except Exception as e:
                messagebox.showerror("Indices error", str(e))
                return None
            if len(idxs) != n:
                messagebox.showerror("Count mismatch", f"Provide exactly {n} unique indices.")
                return None
            return idxs
        elif method == "words":
            lines = [ln.strip() for ln in self.select_details_text.get("1.0", "end").splitlines() if ln.strip()]
            selected: List[int] = []
            used: Set[int] = set()
            for w in lines:
                found = None
                for i, candidate in enumerate(self.parsed_words, start=1):
                    if candidate == w and i not in used:
                        found = i
                        break
                if found is not None:
                    selected.append(found)
                    used.add(found)
            if len(selected) != n:
                messagebox.showerror("Count mismatch", f"Matched {len(selected)} words; need {n}. Ensure exact spelling and provide {n} lines.")
                return None
            return sorted(selected)
        elif method == "random":
            idxs = list(range(1, total+1))
            random.shuffle(idxs)
            return sorted(idxs[:n])
        else:
            messagebox.showerror("Method", "Unknown selection method.")
            return None

    def on_preview_masking(self):
        idxs = self.compute_secured_indices()
        if idxs is None:
            return
        self.secured_indices = idxs
        secured_set = set(idxs)
        self.masked_list.delete(0, "end")
        for i, w in enumerate(self.parsed_words, start=1):
            if i in secured_set:
                self.masked_list.insert("end", f"{i:2d}. [LOCKED: #{i}]")
            else:
                self.masked_list.insert("end", f"{i:2d}. {w}")

    def on_encrypt_save(self):
        # Require master PIN not empty
        master_pin = self.master_pin_e.get().strip()
        if not master_pin:
            messagebox.showerror("Master PIN required", "Master PIN/passphrase cannot be empty.")
            return

        if not self.parsed_words:
            messagebox.showerror("No words", "Parse words first.")
            return
        if not self.secured_indices and self.secure_count_var.get() > 0:
            messagebox.showwarning("Missing selection", "Preview masking first to compute selection.")
            return

        mode = self.storage_mode.get()
        view_pin = self.view_pin_e.get().strip() if mode == "view" else ""
        if mode == "view" and not view_pin:
            if not messagebox.askyesno("No view PIN", "No view PIN entered. Proceed using empty view PIN? (Not recommended)"):
                return
        if mode == "plaintext":
            ok = messagebox.askyesno(
                "Plaintext Warning",
                "Storing remaining words in plaintext is highly risky.\n"
                "Anyone who obtains the file can read those words.\n\nProceed?"
            )
            if not ok:
                return

        vault_name = ensure_json_extension(self.vault_name_e.get().strip() or "seed_vault.json")
        dpapi_enabled = self.dpapi_var.get()

        total = len(self.parsed_words)
        secured_set = set(self.secured_indices)
        remaining_indices = [i for i in range(1, total+1) if i not in secured_set]

        # Collect per-word codes
        codes = {}
        if secured_set:
            dlg = CodesDialog(self, sorted(list(secured_set)))
            codes = dlg.codes
            if not codes or len(codes) != len(secured_set):
                messagebox.showerror("Cancelled", "Encryption cancelled or missing codes.")
                return

        # Build entries
        entries: List[Dict[str, Any]] = []

        # Secured
        for idx in sorted(list(secured_set)):
            word = self.parsed_words[idx-1]
            code = codes[idx]
            if len(code) < 6:
                messagebox.showwarning("Weak code", f"Code for #{idx} is short; consider 8+ chars.")
            salt = os.urandom(16)
            key = derive_secured_key(master_pin, code, idx, salt)
            enc = encrypt_word(idx, word, key)
            entries.append({"index": idx, "tier": "secured", "salt": b64e(salt), **enc})

        # Remaining
        if remaining_indices:
            if mode == "plaintext":
                for idx in remaining_indices:
                    word = self.parsed_words[idx-1]
                    entries.append({"index": idx, "tier": "plaintext", "plaintext": word})
            elif mode in ("view", "view_master"):
                vp = view_pin if mode == "view" else ""
                for idx in remaining_indices:
                    word = self.parsed_words[idx-1]
                    salt = os.urandom(16)
                    key = derive_view_key(master_pin, vp, idx, salt)
                    enc = encrypt_word(idx, word, key)
                    entries.append({"index": idx, "tier": "view", "salt": b64e(salt), **enc})
            else:
                messagebox.showerror("Mode", "Unknown storage mode.")
                return

        vault = {
            "version": VERSION,
            "created_at": int(time.time()),
            "cipher": "AES-GCM",
            "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 2, "length": 32},
            "count": total,
            "entries": sorted(entries, key=lambda e: e["index"]),
            "notes": "tier: secured (per-word code), view (view/master PIN), plaintext (NOT recommended)"
        }

        # Final masked preview confirmation
        preview = "\n".join([f"{i:2d}. {'[LOCKED: #'+str(i)+']' if i in secured_set else self.parsed_words[i-1]}"
                             for i in range(1, total+1)])
        ok = messagebox.askyesno("Confirm Save",
                                 f"Final masked preview:\n\n{preview}\n\n"
                                 f"Proceed to encrypt and save to:\n{vault_name}")
        if not ok:
            return

        try:
            wrap_with_dpapi_if_enabled(vault, dpapi_enabled, vault_name)
        except Exception as e:
            messagebox.showerror("Save error", f"Failed to save vault:\n{e}")

    # -------- Show Tab --------

    def build_show_tab(self):
        frm = self.tab_show
        ttk.Label(frm, text="Vault file:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.show_path_e = ttk.Entry(frm)
        self.show_path_e.grid(row=0, column=1, sticky="we", padx=10, pady=5)
        ttk.Button(frm, text="Browse...", command=lambda: self.browse_to_entry(self.show_path_e)).grid(row=0, column=2, padx=5, pady=5)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Master PIN (REQUIRED):").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.show_master_e = ttk.Entry(frm, show="*")
        self.show_master_e.grid(row=1, column=1, sticky="we", padx=10, pady=5)

        ttk.Label(frm, text="View PIN (blank if not set):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.show_view_e = ttk.Entry(frm, show="*")
        self.show_view_e.grid(row=2, column=1, sticky="we", padx=10, pady=5)

        ttk.Button(frm, text="Show All", command=self.on_show_all).grid(row=3, column=0, padx=10, pady=10, sticky="w")
        ttk.Button(frm, text="Decrypt Secured...", command=self.on_decrypt_secured_batch).grid(row=3, column=1, padx=10, pady=10, sticky="w")

        self.show_list = tk.Listbox(frm, height=24)
        self.show_list.grid(row=4, column=0, columnspan=3, sticky="nsew", padx=10, pady=5)
        frm.rowconfigure(4, weight=1)

    def browse_to_entry(self, entry: ttk.Entry):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json"),("All files","*.*")])
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def on_show_all(self):
        path = self.show_path_e.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing vault", "Vault file not found.")
            return
        master = self.show_master_e.get().strip()
        if not master:
            messagebox.showerror("Master PIN required", "Master PIN/passphrase cannot be empty.")
            return
        view = self.show_view_e.get().strip()
        try:
            vault = load_vault_any(path)
        except Exception as e:
            messagebox.showerror("Load error", str(e))
            return
        entries = sorted(vault.get("entries", []), key=lambda e: e["index"])
        self.show_list.delete(0, "end")
        for e in entries:
            idx = e["index"]
            tier = e.get("tier","?")
            if tier == "plaintext":
                self.show_list.insert("end", f"{idx:2d}. {e['plaintext']} (plaintext)")
            elif tier == "view":
                try:
                    salt = b64d(e["salt"])
                    key = derive_view_key(master, view, idx, salt)
                    word = decrypt_entry(e, key)
                    self.show_list.insert("end", f"{idx:2d}. {word} (view-tier)")
                except Exception:
                    # Rate-limit view-tier failures by index
                    delay = self.ratelimiter.register_failure(f"view-{idx}")
                    self.show_list.insert("end", f"{idx:2d}. [FAILED VIEW DECRYPT | next attempt in ~{delay}s]")
            elif tier == "secured":
                self.show_list.insert("end", f"{idx:2d}. [LOCKED: #{idx}] (secured)")
            else:
                self.show_list.insert("end", f"{idx:2d}. [UNKNOWN TIER]")

    def on_decrypt_secured_batch(self):
        path = self.show_path_e.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing vault", "Vault file not found.")
            return
        master = self.show_master_e.get().strip()
        if not master:
            messagebox.showerror("Master PIN required", "Master PIN/passphrase cannot be empty.")
            return
        try:
            vault = load_vault_any(path)
        except Exception as e:
            messagebox.showerror("Load error", str(e))
            return
        secured = [e for e in vault.get("entries", []) if e.get("tier") == "secured"]
        if not secured:
            messagebox.showinfo("None", "No secured words in this vault.")
            return
        idxs = [e["index"] for e in secured]
        dlg = CodesDialog(self, sorted(idxs))
        codes = dlg.codes
        if not codes:
            return
        self.show_list.insert("end", "---- Secured decryption results ----")
        for e in sorted(secured, key=lambda x: x["index"]):
            idx = e["index"]
            keyname = f"sec-{idx}"
            can, remain = self.ratelimiter.can_attempt(keyname)
            if not can:
                self.show_list.insert("end", f"{idx:2d}. [RATE LIMITED | wait ~{remain}s]")
                continue
            code = codes.get(idx, "")
            if not code:
                self.show_list.insert("end", f"{idx:2d}. [SKIPPED]")
                continue
            try:
                salt = b64d(e["salt"])
                key = derive_secured_key(master, code, idx, salt)
                word = decrypt_entry(e, key)
                self.show_list.insert("end", f"{idx:2d}. {word} (secured)")
                self.ratelimiter.register_success(keyname)
            except Exception as ex:
                delay = self.ratelimiter.register_failure(keyname)
                self.show_list.insert("end", f"{idx:2d}. [FAILED: {ex} | next attempt in ~{delay}s]")

    # -------- Decrypt Tab --------

    def build_decrypt_tab(self):
        frm = self.tab_decrypt
        ttk.Label(frm, text="Vault file:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.dec_path_e = ttk.Entry(frm)
        self.dec_path_e.grid(row=0, column=1, sticky="we", padx=10, pady=5)
        ttk.Button(frm, text="Browse...", command=lambda: self.browse_to_entry(self.dec_path_e)).grid(row=0, column=2, padx=5, pady=5)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Index (1-based):").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.dec_idx_var = tk.IntVar(value=1)
        ttk.Spinbox(frm, from_=1, to=24, textvariable=self.dec_idx_var).grid(row=1, column=1, sticky="w", padx=10, pady=5)

        ttk.Label(frm, text="Master PIN (REQUIRED):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.dec_master_e = ttk.Entry(frm, show="*")
        self.dec_master_e.grid(row=2, column=1, sticky="we", padx=10, pady=5)

        ttk.Label(frm, text="Word code / View PIN:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.dec_code_e = ttk.Entry(frm, show="*")
        self.dec_code_e.grid(row=3, column=1, sticky="we", padx=10, pady=5)

        ttk.Button(frm, text="Decrypt", command=self.on_decrypt_one).grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.dec_result_lbl = ttk.Label(frm, text="", foreground="blue")
        self.dec_result_lbl.grid(row=5, column=0, columnspan=3, sticky="w", padx=10, pady=5)

    def on_decrypt_one(self):
        path = self.dec_path_e.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing vault", "Vault file not found.")
            return
        idx = self.dec_idx_var.get()
        master = self.dec_master_e.get().strip()
        if not master:
            messagebox.showerror("Master PIN required", "Master PIN/passphrase cannot be empty.")
            return
        code = self.dec_code_e.get().strip()
        keyname = f"dec-one-{idx}"
        can, remain = self.ratelimiter.can_attempt(keyname)
        if not can:
            self.dec_result_lbl.configure(text=f"Rate limited — try again in ~{remain}s.")
            return
        try:
            vault = load_vault_any(path)
        except Exception as e:
            self.dec_result_lbl.configure(text=f"Load error: {e}")
            return
        entry = next((e for e in vault.get("entries", []) if e.get("index")==idx), None)
        if not entry:
            self.dec_result_lbl.configure(text=f"No entry for index {idx}")
            return
        tier = entry.get("tier")
        try:
            if tier == "plaintext":
                self.dec_result_lbl.configure(text=f"#{idx}: {entry['plaintext']} (plaintext)")
                self.ratelimiter.register_success(keyname)
                return
            salt = b64d(entry["salt"])
            if tier == "secured":
                if not code:
                    self.dec_result_lbl.configure(text="Code/PIN required for secured entry.")
                    return
                key = derive_secured_key(master, code, idx, salt)
            elif tier == "view":
                key = derive_view_key(master, code, idx, salt)  # code may be blank if master-only
            else:
                self.dec_result_lbl.configure(text="Unknown tier")
                return
            word = decrypt_entry(entry, key)
            self.dec_result_lbl.configure(text=f"#{idx}: {word} ({tier})")
            self.ratelimiter.register_success(keyname)
        except Exception as e:
            delay = self.ratelimiter.register_failure(keyname)
            self.dec_result_lbl.configure(text=f"Failed to decrypt: {e} | next attempt in ~{delay}s")

    # -------- List Tab --------

    def build_list_tab(self):
        frm = self.tab_list
        ttk.Label(frm, text="Vault file:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.list_path_e = ttk.Entry(frm)
        self.list_path_e.grid(row=0, column=1, sticky="we", padx=10, pady=5)
        ttk.Button(frm, text="Browse...", command=lambda: self.browse_to_entry(self.list_path_e)).grid(row=0, column=2, padx=5, pady=5)
        frm.columnconfigure(1, weight=1)
        ttk.Button(frm, text="List Entries", command=self.on_list_entries).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.list_box = tk.Listbox(frm, height=24)
        self.list_box.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=10, pady=5)
        frm.rowconfigure(2, weight=1)

    def on_list_entries(self):
        path = self.list_path_e.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Missing vault", "Vault file not found.")
            return
        try:
            vault = load_vault_any(path)
        except Exception as e:
            messagebox.showerror("Load error", str(e))
            return
        entries = sorted(vault.get("entries", []), key=lambda e: e["index"])
        self.list_box.delete(0, "end")
        self.list_box.insert("end", f"Vault version: {vault.get('version')} | total words: {vault.get('count')}")
        for e in entries:
            self.list_box.insert("end", f" - index {e['index']:2d} | tier: {e['tier']}")

# -------------------- run --------------------

if __name__ == "__main__":
    app = SeedVaultApp()
    app.mainloop()
