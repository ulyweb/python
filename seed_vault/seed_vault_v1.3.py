
#!/usr/bin/env python3
"""
seed_vault.py - Per-word encryption for 12/24-word recovery phrases.

v1.3 Enhancements:
- Store ALL seed words in the vault:
  - Selected "secured" words use per-word codes (AES-GCM + scrypt).
  - Remaining "view-tier" words are also encrypted (AES-GCM + scrypt) with a single view PIN or master PIN.
  - Optional (NOT RECOMMENDED): store remaining words as plaintext.
- New 'show' command:
  - Displays all words: decrypts view-tier with master/view PIN.
  - Optionally decrypt secured words (requires per-word codes).
- Custom vault filename prompt during encrypt.
- Flexible selection methods (first N, specific indices, by text, random).
- Friendly missing-vault messages for list/decrypt/show.

---USAGE:

# Encrypt (with filename prompt and selection options)
python .\seed_vault.py encrypt

# List stored entries with tiers
python .\seed_vault.py list --vault .\my_vault.json

# Decrypt a single word by index
python .\seed_vault.py decrypt --vault .\my_vault.json --index 7

# Show all words (view-tier auto-decrypt; secured optional)
python .\seed_vault.py show --vault .\my_vault.json


"""

import os
import json
import base64
import time
import argparse
import getpass
import random
from typing import List, Dict, Any, Tuple, Set, Optional

# Requires: pip install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

VERSION = "1.3"

# -------------------- helpers --------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def ensure_json_extension(path: str) -> str:
    path = path.strip()
    if not path:
        return "seed_vault.json"
    if not path.lower().endswith(".json"):
        path += ".json"
    return path

def derive_key_scrypt(secret: bytes, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=32768,
        r=8,
        p=2,
        backend=default_backend()
    )
    return kdf.derive(secret)

def derive_secured_key(master_pin: str, word_code: str, index: int, salt: bytes) -> bytes:
    if not word_code:
        raise ValueError("Per-word code/PIN is required.")
    secret = f"{master_pin}|{word_code}|idx:{index}".encode("utf-8")
    return derive_key_scrypt(secret, salt)

def derive_view_key(master_pin: str, view_pin: str, index: int, salt: bytes) -> bytes:
    # Bind to index so keys differ per word even with same view PIN
    secret = f"{master_pin}|view:{view_pin}|idx:{index}".encode("utf-8")
    return derive_key_scrypt(secret, salt)

# -------------------- file I/O --------------------

def load_vault(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_vault(vault: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)
    print(f"\nSaved encrypted vault to: {path}")

# -------------------- encrypt/decrypt primitives --------------------

def encrypt_word_aesgcm(index: int, word: str, key: bytes) -> Dict[str, str]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = f"seedword:{index}".encode("utf-8")
    pt = word.encode("utf-8")
    ct = aesgcm.encrypt(nonce, pt, aad)  # returns ciphertext||tag
    return {
        "nonce": b64e(nonce),
        "aad": b64e(aad),
        "ciphertext": b64e(ct)
    }

def decrypt_entry(entry: Dict[str, Any], key: bytes) -> str:
    nonce = b64d(entry["nonce"])
    aad = b64d(entry["aad"])
    ct = b64d(entry["ciphertext"])
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")

# -------------------- prompts --------------------

def prompt_vault_filename() -> str:
    s = input("\nEnter vault filename (press Enter for 'seed_vault.json'): ").strip()
    return ensure_json_extension(s or "seed_vault.json")

def prompt_word_count() -> int:
    while True:
        try:
            count = int(input("Enter number of words (12 or 24): ").strip())
            if count in (12, 24):
                return count
            print("Please enter 12 or 24.")
        except ValueError:
            print("Please enter a valid number (12 or 24).")

def prompt_words(count: int) -> List[str]:
    words = []
    for i in range(1, count + 1):
        w = input(f"Word #{i}: ").strip()
        if not w:
            print("Empty word not allowed. Try again.")
            return prompt_words(count)
        words.append(w)
    return words

def preview_words(words: List[str]) -> None:
    print("\nYou entered the following words:")
    for i, w in enumerate(words, start=1):
        print(f" {i:2d}. {w}")

def prompt_encrypt_count(total: int) -> int:
    while True:
        s = input(
            f"\nHow many of these {total} words do you want to encrypt with per-word codes? "
            f"(Press Enter to encrypt all {total}): "
        ).strip()
        if s == "":
            return total
        try:
            n = int(s)
            if 1 <= n <= total:
                return n
            print(f"Please enter a number between 1 and {total}, or press Enter for all.")
        except ValueError:
            print("Please enter a valid number.")

def parse_indices_input(s: str, total: int) -> List[int]:
    parts = [p.strip() for p in s.replace(",", " ").split() if p.strip()]
    indices = []
    for p in parts:
        if not p.isdigit():
            raise ValueError(f"Invalid index: {p}")
        i = int(p)
        if not (1 <= i <= total):
            raise ValueError(f"Index out of range: {i} (1..{total})")
        indices.append(i)
    return sorted(set(indices))

def choose_selection_method(n: int, words: List[str]) -> List[int]:
    total = len(words)
    while True:
        print("\nSelect how to choose which words to encrypt (secured tier):")
        print("  1) First N by index order (1..N)")
        print("  2) Specific indices (e.g., 1,3,5,12)")
        print("  3) By word text (enter the exact words)")
        print("  4) Random N selection")
        choice = input("Enter choice (1-4): ").strip()
        if choice == "1":
            return list(range(1, n + 1))
        elif choice == "2":
            s = input(f"Enter {n} indices (1..{total}), comma/space-separated: ").strip()
            try:
                idxs = parse_indices_input(s, total)
            except Exception as e:
                print(f"Error: {e}")
                continue
            if len(idxs) != n:
                print(f"Please provide exactly {n} unique indices.")
                continue
            return idxs
        elif choice == "3":
            print("Enter words to encrypt (exactly as typed earlier).")
            selected: List[int] = []
            used: Set[int] = set()
            for k in range(1, n + 1):
                w = input(f"  Word {k}/{n}: ").strip()
                found_idx = None
                for i, candidate in enumerate(words, start=1):
                    if candidate == w and i not in used:
                        found_idx = i
                        break
                if found_idx is None:
                    print("  Not found or already selected; please try again.")
                    selected = []
                    break
                selected.append(found_idx)
                used.add(found_idx)
            if selected and len(selected) == n:
                return selected
        elif choice == "4":
            idxs = list(range(1, total + 1))
            random.shuffle(idxs)
            return sorted(idxs[:n])
        else:
            print("Please enter a valid choice (1-4).")

def prompt_view_tier_choice(remaining_count: int) -> Tuple[str, Optional[str]]:
    """
    Ask how to store remaining words:
      - 'view'  -> encrypt with a single view PIN (recommended)
      - 'plaintext' -> store as plaintext (NOT recommended)
    Returns (mode, view_pin)
    """
    print(f"\nYou have {remaining_count} remaining words.")
    print("How should these be stored?")
    print("  1) Encrypt with a single view PIN (recommended)")
    print("  2) Encrypt with master PIN only (no separate view PIN)")
    print("  3) Store as plaintext (NOT recommended)")
    while True:
        choice = input("Enter choice (1-3): ").strip()
        if choice == "1":
            vp = getpass.getpass("Enter view PIN (8+ chars recommended): ")
            if len(vp) < 6:
                print("  [!] Warning: short PINs are weak against offline brute-force.")
            return ("view", vp)
        elif choice == "2":
            return ("view", "")  # empty string means "use only master"
        elif choice == "3":
            print("\n[!] Strong warning: plaintext storage is highly risky.")
            print("    Anyone who obtains this file can read those words.")
            confirm = input("    Are you sure? Type 'YES' to proceed: ").strip()
            if confirm == "YES":
                return ("plaintext", None)
            else:
                print("    Aborted plaintext choice. Please pick another option.")
        else:
            print("Please enter 1, 2, or 3.")

def final_review(words: List[str], secured_indices: Set[int], vault_path: str) -> bool:
    """
    Show all words; secured ones masked as [LOCKED: #index].
    Ask for confirmation to proceed.
    """
    print("\nFinal review before saving:")
    for i, w in enumerate(words, start=1):
        if i in secured_indices:
            print(f" {i:2d}. [LOCKED: #{i}]")
        else:
            print(f" {i:2d}. {w}")
    while True:
        s = input(f"\nProceed to encrypt and save to '{vault_path}'? (Y/N): ").strip().lower()
        if s in ("y", "yes"):
            return True
        elif s in ("n", "no"):
            return False
        else:
            print("Please answer Y or N.")

# -------------------- CLI operations --------------------

def do_encrypt():
    print("\n=== Encrypt seed words ===")
    master_pin = getpass.getpass("Enter master PIN/passphrase (optional but highly recommended): ")

    count = prompt_word_count()
    words_all = prompt_words(count)

    preview_words(words_all)

    n_secured = prompt_encrypt_count(count)
    if n_secured < count:
        secured_indices = choose_selection_method(n_secured, words_all)
        while not secured_indices or len(secured_indices) != n_secured:
            print("Selection invalid. Let's try again.")
            secured_indices = choose_selection_method(n_secured, words_all)
    else:
        secured_indices = list(range(1, count + 1))

    secured_set = set(secured_indices)
    remaining_indices = [i for i in range(1, count + 1) if i not in secured_set]

    vault_path = prompt_vault_filename()

    # Final review (secured masked, remaining visible pre-save)
    proceed = final_review(words_all, secured_set, vault_path)
    if not proceed:
        print("Aborted. Nothing was saved.")
        return

    # Build entries and encrypt accordingly
    entries: List[Dict[str, Any]] = []

    # Secured-tier encryption (per-word codes)
    for idx in secured_indices:
        word = words_all[idx - 1]
        print(f"\nSecured word #{idx}:")
        code = getpass.getpass("  Enter per-word code/PIN (recommended 8+ chars): ")
        if len(code) < 6:
            print("  [!] Warning: short codes are weak against offline brute-force.")
        salt = os.urandom(16)
        key = derive_secured_key(master_pin, code, idx, salt)
        enc = encrypt_word_aesgcm(idx, word, key)
        entries.append({
            "index": idx,
            "tier": "secured",
            "salt": b64e(salt),
            **enc
        })

    # Remaining words: choose storage mode
    if remaining_indices:
        mode, view_pin = prompt_view_tier_choice(len(remaining_indices))
        if mode == "plaintext":
            # Store plaintext (NOT recommended)
            for idx in remaining_indices:
                word = words_all[idx - 1]
                entries.append({
                    "index": idx,
                    "tier": "plaintext",
                    "plaintext": word
                })
        else:
            # View-tier encryption
            for idx in remaining_indices:
                word = words_all[idx - 1]
                salt = os.urandom(16)
                key = derive_view_key(master_pin, view_pin or "", idx, salt)
                enc = encrypt_word_aesgcm(idx, word, key)
                entries.append({
                    "index": idx,
                    "tier": "view",
                    "salt": b64e(salt),
                    **enc
                })

    vault = {
        "version": VERSION,
        "created_at": int(time.time()),
        "cipher": "AES-GCM",
        "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 2, "length": 32},
        "count": count,
        "entries": sorted(entries, key=lambda e: e["index"]),
        "notes": "Entries have tier: 'secured' (per-word code), 'view' (view/master PIN), or 'plaintext' (NOT recommended)."
    }

    save_vault(vault, vault_path)
    print("Done. Keep the vault and your codes safe.")

def do_list(vault_path: str):
    if not os.path.exists(vault_path):
        print(f"\n[!] Vault file not found at '{vault_path}'.")
        print("    Create one first by running: python seed_vault.py encrypt")
        return
    vault = load_vault(vault_path)
    print(f"\nVault version: {vault.get('version')} | total words: {vault.get('count')}")
    for e in vault["entries"]:
        print(f" - index {e['index']:2d} | tier: {e['tier']}")

def do_decrypt(vault_path: str, index: int):
    if not os.path.exists(vault_path):
        print(f"\n[!] Vault file not found at '{vault_path}'.")
        print("    Create one first by running: python seed_vault.py encrypt")
        return
    vault = load_vault(vault_path)
    entry = next((e for e in vault["entries"] if e["index"] == index), None)
    if not entry:
        print(f"No entry for index {index}.")
        return

    tier = entry["tier"]
    print(f"\n=== Decrypt word #{index} (tier: {tier}) ===")

    if tier == "plaintext":
        print(f"Word #{index}: {entry['plaintext']}")
        return

    master_pin = getpass.getpass("Enter master PIN/passphrase (if set during encryption): ")
    if tier == "secured":
        word_code = getpass.getpass("Enter per-word code/PIN: ")
        salt = b64d(entry["salt"])
        key = derive_secured_key(master_pin, word_code, index, salt)
    elif tier == "view":
        # Ask for view PIN; blank means use only master PIN
        view_pin = getpass.getpass("Enter view PIN (blank if none was set): ")
        salt = b64d(entry["salt"])
        key = derive_view_key(master_pin, view_pin, index, salt)
    else:
        print("Unknown tier.")
        return

    try:
        word = decrypt_entry(entry, key)
        print(f"\nWord #{index}: {word}")
    except Exception as e:
        print(f"Failed to decrypt: {e}")

def do_show(vault_path: str):
    """
    Show all words:
      - View-tier: decrypt with master/view PIN.
      - Plaintext-tier: show directly.
      - Secured-tier: show as [LOCKED: #i], or optionally decrypt one by one.
    """
    if not os.path.exists(vault_path):
        print(f"\n[!] Vault file not found at '{vault_path}'.")
        print("    Create one first by running: python seed_vault.py encrypt")
        return

    vault = load_vault(vault_path)
    entries = sorted(vault["entries"], key=lambda e: e["index"])
    print(f"\n=== Show all words from '{vault_path}' ===")

    # Prepare master/view pin once for batch decryption of view-tier
    master_pin = getpass.getpass("Enter master PIN/passphrase (if set during encryption): ")
    view_pin = getpass.getpass("Enter view PIN for remaining words (blank if none was set): ")

    # First pass: show view/plaintext, mark secured
    for e in entries:
        idx = e["index"]
        tier = e["tier"]
        if tier == "plaintext":
            print(f" {idx:2d}. {e['plaintext']} (plaintext)")
        elif tier == "view":
            try:
                salt = b64d(e["salt"])
                key = derive_view_key(master_pin, view_pin, idx, salt)
                word = decrypt_entry(e, key)
                print(f" {idx:2d}. {word} (view-tier)")
            except Exception:
                print(f" {idx:2d}. [FAILED VIEW DECRYPT]")
        elif tier == "secured":
            print(f" {idx:2d}. [LOCKED: #{idx}] (secured)")
        else:
            print(f" {idx:2d}. [UNKNOWN TIER]")

    # Optional: attempt secured words
    choice = input("\nTry to decrypt secured words now? (Y/N): ").strip().lower()
    if choice in ("y", "yes"):
        for e in entries:
            if e["tier"] == "secured":
                idx = e["index"]
                print(f"\nSecured word #{idx}:")
                code = getpass.getpass("  Enter per-word code/PIN: ")
                try:
                    salt = b64d(e["salt"])
                    key = derive_secured_key(master_pin, code, idx, salt)
                    word = decrypt_entry(e, key)
                    print(f"  -> #{idx}: {word}")
                except Exception as ex:
                    print(f"  -> Failed to decrypt: {ex}")

# -------------------- main --------------------

def main():
    parser = argparse.ArgumentParser(description="Per-word seed phrase vault")
    parser.add_argument("command", choices=["encrypt", "decrypt", "list", "show"], help="Operation")
    parser.add_argument("--vault", default="seed_vault.json", help="Path to vault JSON")
    parser.add_argument("--index", type=int, help="Word index (1-based) for decryption")
    args = parser.parse_args()

    if args.command == "encrypt":
        do_encrypt()
    elif args.command == "list":
        do_list(args.vault)
    elif args.command == "decrypt":
        if not args.index:
            print("Please provide --index for decrypt (e.g., --index 7)")
            return
        do_decrypt(args.vault, args.index)
    elif args.command == "show":
        do_show(args.vault)

if __name__ == "__main__":
    main()
