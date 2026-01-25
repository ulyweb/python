import os
import platform
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, simpledialog
import shutil
import re
import json
from pathlib import Path

APP_DIR = Path(__file__).parent
PROFILES_FILE = APP_DIR / "backup_profiles.json"
SETTINGS_FILE = APP_DIR / "backup_settings.json"


# -------------------------------------------------------
# Helpers: load/save JSON
# -------------------------------------------------------
def load_json(path, default):
    if path.exists():
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default
    return default


def save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save {path.name}:\n{e}")


# -------------------------------------------------------
# Locate rsync binary depending on OS
# -------------------------------------------------------
def find_rsync():
    system = platform.system()

    if system in ["Linux", "Darwin"]:
        return shutil.which("rsync")

    if system == "Windows":
        git_rsync = r"C:\Program Files\Git\usr\bin\rsync.exe"
        if os.path.exists(git_rsync):
            return git_rsync

        path_rsync = shutil.which("rsync")
        if path_rsync:
            return path_rsync

        messagebox.showerror("Error", "rsync not found.\nInstall Git for Windows to enable rsync.")
        return None

    messagebox.showerror("Error", "Unsupported OS")
    return None


# -------------------------------------------------------
# Test SSH connectivity (non‑interactive)
# -------------------------------------------------------
def test_ssh_connection(ssh_target):
    ssh_bin = shutil.which("ssh")
    if not ssh_bin:
        messagebox.showerror("Error", "ssh command not found.\nInstall OpenSSH client.")
        return False

    try:
        cmd = [ssh_bin, "-o", "BatchMode=yes", ssh_target, "exit"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


# -------------------------------------------------------
# Main Application
# -------------------------------------------------------
class BackupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Backup Tool (rsync GUI)")
        self.root.geometry("900x650")

        # For cancel support
        self.current_process = None
        self.is_running = False

        # Load config
        self.profiles = load_json(PROFILES_FILE, {"profiles": []})
        self.settings = load_json(SETTINGS_FILE, {"rsync_extra_args": ""})

        self.theme = "light"

        self.rsync_bin = find_rsync()
        if not self.rsync_bin:
            return

        self.build_ui()
        self.apply_theme()
        self.configure_grid()

    # ---------------------------------------------------
    # UI construction
    # ---------------------------------------------------
    def build_ui(self):
        # Menu
        menubar = tk.Menu(self.root)
        profile_menu = tk.Menu(menubar, tearoff=0)
        profile_menu.add_command(label="Save Current as Profile", command=self.save_profile)
        profile_menu.add_command(label="Delete Selected Profile", command=self.delete_profile)
        menubar.add_cascade(label="Profiles", menu=profile_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Settings", command=self.open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        theme_menu = tk.Menu(menubar, tearoff=0)
        theme_menu.add_command(label="Toggle Dark/Light", command=self.toggle_theme)
        menubar.add_cascade(label="Theme", menu=theme_menu)

        self.root.config(menu=menubar)

        # Top frame for source/dest
        top_frame = tk.Frame(self.root)
        top_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        tk.Label(top_frame, text="Source Folder:").grid(row=0, column=0, sticky="w")
        self.src_entry = tk.Entry(top_frame, width=60)
        self.src_entry.grid(row=0, column=1, sticky="ew", padx=5)
        tk.Button(top_frame, text="Browse", command=self.pick_source).grid(row=0, column=2, padx=5)

        tk.Label(top_frame, text="Destination:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        self.dst_entry = tk.Entry(top_frame, width=60)
        self.dst_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=(5, 0))
        tk.Button(top_frame, text="Browse", command=self.pick_destination).grid(row=1, column=2, padx=5, pady=(5, 0))

        ssh_help = (
            "Local example: /mnt/storage or Z:\\Backups\n"
            "Remote SSH example: rbackup@10.17.76.15:/TM-NAS/media/DATA/Recent-Transfer/2026\n"
            "Remote mode requires SSH key auth (no password prompts)."
        )
        self.help_label = tk.Label(top_frame, text=ssh_help, justify="left", fg="#555")
        self.help_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(5, 0))

        # Profile selection
        profile_frame = tk.Frame(self.root)
        profile_frame.grid(row=1, column=0, sticky="ew", padx=10)

        tk.Label(profile_frame, text="Profile:").pack(side=tk.LEFT)
        self.profile_var = tk.StringVar()
        self.profile_combo = ttk.Combobox(profile_frame, textvariable=self.profile_var, state="readonly", width=40)
        self.profile_combo.pack(side=tk.LEFT, padx=5, fill="x", expand=True)
        self.profile_combo.bind("<<ComboboxSelected>>", self.load_selected_profile)

        self.refresh_profile_list()

        # Buttons + progress
        control_frame = tk.Frame(self.root)
        control_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)

        self.start_btn = tk.Button(control_frame, text="Start Backup", command=self.start_backup, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_btn = tk.Button(control_frame, text="Cancel Backup", command=self.cancel_backup, width=15, state="disabled")
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        self.quit_btn = tk.Button(control_frame, text="Quit", command=self.root.quit, width=10)
        self.quit_btn.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(control_frame, mode="indeterminate", length=250)
        self.progress.pack(side=tk.RIGHT, padx=5)

        # Log
        log_frame = tk.Frame(self.root)
        log_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))

        tk.Label(log_frame, text="Backup Log:").pack(anchor="w")
        self.log = scrolledtext.ScrolledText(log_frame, width=100, height=25)
        self.log.pack(fill="both", expand=True)

    def configure_grid(self):
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    # ---------------------------------------------------
    # Theme
    # ---------------------------------------------------
    def apply_theme(self):
        bg_light = "#f0f0f0"
        fg_light = "#000000"
        bg_dark = "#1e1e1e"
        fg_dark = "#dcdcdc"

        if self.theme == "dark":
            bg = bg_dark
            fg = fg_dark
            entry_bg = "#2b2b2b"
            entry_fg = fg_dark
        else:
            bg = bg_light
            fg = fg_light
            entry_bg = "white"
            entry_fg = fg_light

        self.root.configure(bg=bg)
        for widget in self.root.winfo_children():
            self._apply_theme_recursive(widget, bg, fg, entry_bg, entry_fg)

    def _apply_theme_recursive(self, widget, bg, fg, entry_bg, entry_fg):
        cls = widget.__class__.__name__
        if cls in ("Frame", "LabelFrame"):
            widget.configure(bg=bg)
        elif cls == "Label":
            widget.configure(bg=bg, fg=fg)
        elif cls == "Button":
            widget.configure(bg="#4CAF50" if "Start" in widget.cget("text") else widget.cget("bg"), fg="white")
        elif cls == "TCombobox":
            pass
        elif cls == "Entry":
            widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        elif cls == "Text" or cls == "ScrolledText":
            widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)

        for child in widget.winfo_children():
            self._apply_theme_recursive(child, bg, fg, entry_bg, entry_fg)

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        self.apply_theme()

    # ---------------------------------------------------
    # Profiles
    # ---------------------------------------------------
    def refresh_profile_list(self):
        names = [p["name"] for p in self.profiles.get("profiles", [])]
        self.profile_combo["values"] = names

    def save_profile(self):
        src = self.src_entry.get().strip()
        dst = self.dst_entry.get().strip()
        if not src or not dst:
            messagebox.showwarning("Missing Data", "Source and destination must be set to save a profile.")
            return

        name = simpledialog.askstring("Profile Name", "Enter a name for this profile:")
        if not name:
            return

        # Overwrite if same name exists
        profiles = self.profiles.get("profiles", [])
        for p in profiles:
            if p["name"] == name:
                p["source"] = src
                p["destination"] = dst
                break
        else:
            profiles.append({"name": name, "source": src, "destination": dst})

        self.profiles["profiles"] = profiles
        save_json(PROFILES_FILE, self.profiles)
        self.refresh_profile_list()
        self.profile_var.set(name)

    def load_selected_profile(self, event=None):
        name = self.profile_var.get()
        for p in self.profiles.get("profiles", []):
            if p["name"] == name:
                self.src_entry.delete(0, tk.END)
                self.src_entry.insert(0, p["source"])
                self.dst_entry.delete(0, tk.END)
                self.dst_entry.insert(0, p["destination"])
                break

    def delete_profile(self):
        name = self.profile_var.get()
        if not name:
            return
        confirm = messagebox.askyesno("Delete Profile", f"Delete profile '{name}'?")
        if not confirm:
            return
        profiles = [p for p in self.profiles.get("profiles", []) if p["name"] != name]
        self.profiles["profiles"] = profiles
        save_json(PROFILES_FILE, self.profiles)
        self.profile_var.set("")
        self.refresh_profile_list()

    # ---------------------------------------------------
    # Settings
    # ---------------------------------------------------
    def open_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("400x150")

        tk.Label(win, text="Extra rsync arguments (optional):").pack(anchor="w", padx=10, pady=(10, 0))
        entry = tk.Entry(win, width=50)
        entry.pack(padx=10, pady=5)
        entry.insert(0, self.settings.get("rsync_extra_args", ""))

        def save_settings():
            self.settings["rsync_extra_args"] = entry.get().strip()
            save_json(SETTINGS_FILE, self.settings)
            win.destroy()

        tk.Button(win, text="Save", command=save_settings).pack(pady=10)

        # Apply theme to settings window
        self._apply_theme_recursive(win, self.root["bg"], "#dcdcdc" if self.theme == "dark" else "#000000",
                                    "#2b2b2b" if self.theme == "dark" else "white",
                                    "#dcdcdc" if self.theme == "dark" else "#000000")

    # ---------------------------------------------------
    # Folder pickers
    # ---------------------------------------------------
    def pick_source(self):
        folder = filedialog.askdirectory()
        if folder:
            self.src_entry.delete(0, tk.END)
            self.src_entry.insert(0, folder)

    def pick_destination(self):
        folder = filedialog.askdirectory()
        if folder:
            self.dst_entry.delete(0, tk.END)
            self.dst_entry.insert(0, folder)

    # ---------------------------------------------------
    # Backup logic
    # ---------------------------------------------------
    def start_backup(self):
        if self.is_running:
            messagebox.showinfo("Backup Running", "A backup is already in progress.")
            return

        src = self.src_entry.get().strip()
        dst = self.dst_entry.get().strip()

        if not src or not dst:
            messagebox.showwarning("Missing Input", "Please select both source and destination.")
            return

        if not os.path.exists(src):
            messagebox.showerror("Error", f"Source folder does not exist:\n{src}")
            return

        is_ssh = bool(re.match(r"(.+@.+):(.+)", dst))

        if is_ssh:
            self.handle_remote_backup(src, dst)
        else:
            self.handle_local_backup(src, dst)

    def handle_local_backup(self, src, dst):
        if not os.path.exists(dst):
            create = messagebox.askyesno(
                "Destination Missing",
                f"Destination does not exist:\n{dst}\n\nCreate it?"
            )
            if create:
                try:
                    os.makedirs(dst, exist_ok=True)
                except PermissionError:
                    messagebox.showerror(
                        "Permission Error",
                        "Cannot create destination folder.\nRun as administrator or root."
                    )
                    return
            else:
                return

        self.run_rsync_threaded(src, dst)

    def handle_remote_backup(self, src, dst):
        match = re.match(r"(.+@.+):(.+)", dst)
        if not match:
            messagebox.showerror("Error", "Invalid remote destination format.\nUse: user@server:/path/to/backup")
            return

        ssh_target = match.group(1)

        self.append_log(f"Detected remote SSH destination: {dst}\n")
        self.append_log("Testing SSH connection...\n")

        if not test_ssh_connection(ssh_target):
            messagebox.showerror(
                "SSH Error",
                "Cannot connect via SSH without a password prompt.\n"
                "Fix SSH key authentication first."
            )
            self.append_log("SSH test failed. Aborting.\n\n")
            return

        self.append_log("SSH test OK. Starting rsync...\n\n")
        self.run_rsync_threaded(src, dst)

    # ---------------------------------------------------
    # Run rsync in background thread
    # ---------------------------------------------------
    def run_rsync_threaded(self, src, dst):
        self.is_running = True
        self.start_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.progress.start(50)
        thread = threading.Thread(target=self.run_rsync, args=(src, dst), daemon=True)
        thread.start()

    def cancel_backup(self):
        if self.current_process and self.is_running:
            try:
                self.current_process.terminate()
                self.append_log("\nBackup cancelled by user.\n")
            except Exception as e:
                self.append_log(f"\nError cancelling backup: {e}\n")
        self.finish_backup_state()

    def run_rsync(self, src, dst):
        extra_args = self.settings.get("rsync_extra_args", "").split()
        cmd = [
            self.rsync_bin,
            "-avh",
            "--progress",
            src + "/",
            dst
        ]
        if extra_args:
            cmd[1:1] = extra_args  # insert after rsync binary

        self.append_log(f"Running: {' '.join(cmd)}\n\n")

        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in self.current_process.stdout:
                self.append_log(line)

            self.current_process.wait()
            if self.current_process.returncode == 0:
                self.append_log("\nBackup Completed.\n")
            else:
                self.append_log(f"\nBackup finished with errors (code {self.current_process.returncode}).\n")

        except Exception as e:
            self.append_log(f"\nError: {e}\n")

        self.finish_backup_state()

    def finish_backup_state(self):
        self.is_running = False
        self.current_process = None
        self.start_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")
        self.progress.stop()

    # ---------------------------------------------------
    # Thread‑safe log updater
    # ---------------------------------------------------
    def append_log(self, text):
        self.log.after(0, lambda: (self.log.insert(tk.END, text), self.log.see(tk.END)))


# -------------------------------------------------------
# Run App
# -------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()
