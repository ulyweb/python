# -*- coding: utf-8 -*-
r"""
WPR Assist – Performance Trace Collector (Python/Tk)
- Windows-only; auto-elevates Admin
- Strict Mode (default ON) starts exactly: GeneralProfile, CPU, Heap, Pool, FileIO, VirtualAllocation
- Optional Disk I/O, Network (Network / Networking), Custom profiles when Strict OFF
- Live WPR output, Verbose logging, Auto-stop timer, Perf CSV logging (CPU%, AvailableMemory_MB)
- Top-N processes snapshot at Stop (CPU / Memory / Disk I/O)
- Create ZIP bundle + Box URL + Open Box + Copy Summary
- Diagnostics tab with live Top-N processes (CPU%, RSS, Disk B/s) while recording (optional)
- Auto-upload ZIP to Box (Box Drive path) after "Create ZIP" (optional)
- 'Recording in progress…' non-modal pop-up with spinner & quick Stop
- 'Creating ZIP…' modal pop-up with spinner (covers ZIP + optional Box copy)
- One-click Post-Save Macro (ZIP → upload → open Box → copy summary)
- Version shown in title, banner, and Help → About
- Dark/Light mode; modern pro UI with banner + live clock
- Settings persisted in %APPDATA%\WprTraceGUI\settings.json (incl. window geometry & new settings)
- Output folder: C:\Temp
"""

import os
import sys
import json
import time
import queue
import socket
import psutil
import ctypes
import zipfile
import webbrowser
import threading
import subprocess
import datetime
import shutil
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import tkinter.font as tkfont

# ------------------------- App Version -------------------------
APP_VERSION = "1.5.3"  # includes: summary+README+settings in ZIP, summary generated on Stop

# ------------------------- Admin Elevation -------------------------
def is_user_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def relaunch_as_admin():
    """Relaunch current script/EXE with elevation. Handles both .py and PyInstaller EXE."""
    try:
        is_frozen = getattr(sys, "frozen", False)
        program = sys.executable  # python.exe or <yourapp>.exe
        params = " ".join(f'"{a}"' for a in (sys.argv[1:] if is_frozen else sys.argv))
        ctypes.windll.shell32.ShellExecuteW(None, "runas", program, params, None, 1)
    except Exception as e:
        try:
            messagebox.showerror("Elevation failed", f"Could not re-launch with admin rights.\n\n{e}")
        except Exception:
            pass
        sys.exit(0)

# ------------------------- WPR Path Helper -------------------------
def get_wpr_path() -> str:
    windir = os.environ.get("WINDIR", r"C:\Windows")
    wpr_sysnative = os.path.join(windir, "sysnative", "wpr.exe")
    wpr_system32 = os.path.join(windir, "system32", "wpr.exe")
    if os.path.exists(wpr_sysnative):
        return wpr_sysnative
    if os.path.exists(wpr_system32):
        return wpr_system32
    raise FileNotFoundError("wpr.exe not found. Install Windows Performance Recorder (WPT/ADK).")

# ------------------------- Subprocess (live output) -------------------------
def stream_process_output(proc, log_queue, prefix=""):
    try:
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            log_queue.put(f"{prefix}{line.rstrip()}")
    except Exception as e:
        log_queue.put(f"[reader-stdout error] {e}")


def stream_process_error(proc, log_queue):
    try:
        for line in iter(proc.stderr.readline, ''):
            if not line:
                break
            log_queue.put(f"[stderr] {line.rstrip()}")
    except Exception as e:
        log_queue.put(f"[reader-stderr error] {e}")


def run_process_live(exe, args, log_queue, show_wait=None, hide_wait=None):
    full_cmd = [exe] + args
    log_queue.put(f">>> {' '.join(full_cmd)}")
    if show_wait:
        show_wait()
    try:
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
    except Exception as e:
        if hide_wait:
            hide_wait()
        log_queue.put(f"[error] Failed to start process: {e}")
        return 99999

    t_out = threading.Thread(target=stream_process_output, args=(proc, log_queue, ""), daemon=True)
    t_err = threading.Thread(target=stream_process_error, args=(proc, log_queue), daemon=True)
    t_out.start(); t_err.start()
    proc.wait()
    t_out.join(timeout=1.0); t_err.join(timeout=1.0)

    if hide_wait:
        hide_wait()
    return proc.returncode

# ------------------------- Utility -------------------------
def fmt_bytes(n):
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    n = float(n)
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.1f} {units[i]}"

# ------------------------- Perf Logger Thread -------------------------
def perf_logger(stop_event, interval_sec, path: Path, log_queue: queue.Queue):
    try:
        psutil.cpu_percent(interval=None)  # prime
        with path.open("a", encoding="utf-8") as f:
            while not stop_event.is_set():
                time.sleep(max(1, interval_sec))
                cpu = psutil.cpu_percent(interval=None)
                avail_mb = int(psutil.virtual_memory().available / (1024 * 1024))
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                f.write(f"{ts},{cpu:.1f},{avail_mb}\n")
                f.flush()
    except Exception as e:
        log_queue.put(f"[perf-logger error] {e}")

# ------------------------- Snapshots: Top N Processes -------------------------
def take_top_process_snapshot(top_n: int, sample_seconds: int = 2) -> dict:
    procs = []
    io_p1 = {}
    rss_map = {}
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            pid = p.info["pid"]
            name = p.info.get("name") or f"pid-{pid}"
            _ = p.cpu_percent(interval=None)  # prime
            try:
                io1 = p.io_counters()
                io_p1[pid] = (io1.read_bytes, io1.write_bytes)
            except Exception:
                pass
            try:
                rss_map[pid] = p.memory_info().rss
            except Exception:
                rss_map[pid] = 0
            procs.append((pid, name))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    time.sleep(max(1, sample_seconds))

    cpu_list, mem_list, disk_list = [], [], []
    for pid, name in procs:
        try:
            p = psutil.Process(pid)
            cpu2 = p.cpu_percent(interval=None)
            cpu_list.append((pid, name, cpu2))
            try:
                rss = p.memory_info().rss
            except Exception:
                rss = rss_map.get(pid, 0)
            mem_list.append((pid, name, rss))
            bps = 0.0
            try:
                io2 = p.io_counters()
                r1, w1 = io_p1.get(pid, (io2.read_bytes, io2.write_bytes))
                r2, w2 = io2.read_bytes, io2.write_bytes
                delta = (r2 - r1) + (w2 - w1)
                if sample_seconds > 0:
                    bps = max(0.0, delta / float(sample_seconds))
            except Exception:
                bps = 0.0
            disk_list.append((pid, name, bps))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    cpu_list.sort(key=lambda t: t[2], reverse=True)
    mem_list.sort(key=lambda t: t[2], reverse=True)
    disk_list.sort(key=lambda t: t[2], reverse=True)
    return {"cpu": cpu_list[:top_n], "mem": mem_list[:top_n], "disk": disk_list[:top_n]}

# ------------------------- Settings persistence -------------------------
def get_settings_path() -> Path:
    appdata = os.getenv("APPDATA") or str(Path.home())
    cfg_dir = Path(appdata) / "WprTraceGUI"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "settings.json"

DEFAULT_SETTINGS = {
    "strict_mode": True,
    "verbose": False,
    "dark_mode": False,
    "top_n": 10,
    "auto_stop_minutes": 0,
    "perf_interval": 5,
    "preset_general": True,
    "preset_diskio": False,
    "preset_network": False,
    "custom_enabled": False,
    "custom_profiles": "",
    "custom_extra_args": "",
    "box_url": "",
    # Optional features
    "auto_upload_box": False,
    "box_drive_path": "",
    "diagnostics_enabled": True,
    "enable_post_save_macro": True,
    "window": {"width": 980, "height": 880, "x": None, "y": None}
}

def load_settings() -> dict:
    sp = get_settings_path()
    if sp.exists():
        try:
            data = json.loads(sp.read_text(encoding="utf-8"))
            merged = DEFAULT_SETTINGS.copy()
            merged.update(data)
            w = DEFAULT_SETTINGS["window"].copy()
            w.update(merged.get("window", {}))
            merged["window"] = w
            for k, v in DEFAULT_SETTINGS.items():
                if k not in merged:
                    merged[k] = v
            return merged
        except Exception:
            return DEFAULT_SETTINGS.copy()
    return DEFAULT_SETTINGS.copy()

def save_settings(data: dict):
    sp = get_settings_path()
    try:
        sp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

# ------------------------- Tooltip helper -------------------------
class Tooltip:
    def __init__(self, widget, text, delay=450):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after = None
        self.tip = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)

    def _schedule(self, _e):
        self._after = self.widget.after(self.delay, self._show)

    def _show(self):
        if self.tip or not self.widget.winfo_viewable():
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        frm = ttk.Frame(tw, padding=6, relief="solid")
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text=self.text, justify="left", wraplength=360).pack()

    def _hide(self, _e=None):
        if self._after:
            try:
                self.widget.after_cancel(self._after)
            except Exception:
                pass
            self._after = None
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None

# ------------------------- GUI Application -------------------------
class WprGuiApp:
    ACCENT = "#0a64ad"  # banner blue
    BG_LIGHT = "#f7f8fa"
    FG_LIGHT = "#222222"
    BG_DARK = "#1e1e1e"
    FG_DARK = "#e6e6e6"

    ISSUE_TEMPLATE = (
        "Environment/Context:\n"
        "- User reports performance issues impacting daily workflows.\n"
        "- Network type (VPN/Office/Wi‑Fi/Cellular): __________\n"
        "- Machine hostname: (auto in filenames) OS: Windows 10/11 Uptime: __________\n\n"
        "Repro steps (what to try while recording):\n"
        "1) Zoom scenario: join a meeting, start/stop screen share, switch cameras, enable/disable virtual background.\n"
        "   - Observe: audio/video freezes, UI lag, CPU spikes, fan noise, dropped frames.\n"
        "2) Microsoft Office scenario: open large Word/Excel/PowerPoint files, copy/paste, save, search in document, switch windows.\n"
        "   - Observe: UI stutters, 'Not Responding', slow open/save, delayed typing.\n"
        "3) General: launch apps, open File Explorer, switch desktops, download/upload a file.\n"
        "   - Observe: overall slowness, disk thrashing, high memory usage.\n\n"
        "Notes (fill during capture):\n"
        "- Approx time bad behavior occurs: __________\n"
        "- External devices connected (dock, monitors, USB): __________\n"
        "- Any recent changes (updates, new apps, new peripherals): __________\n"
    )

    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = load_settings()

        # Theme & fonts
        self.style = ttk.Style(root)
        self._prepare_base_theme()
        self._font_base = tkfont.Font(family="Segoe UI", size=10)
        self._font_banner = tkfont.Font(family="Segoe UI", size=14, weight="bold")
        self._apply_fonts()
        self._apply_palette(self.settings.get("dark_mode", False))

        # Restore window size/pos
        wcfg = self.settings.get("window", {})
        w = int(wcfg.get("width", 980)); h = int(wcfg.get("height", 880))
        x = wcfg.get("x"); y = wcfg.get("y")
        if x is not None and y is not None:
            self.root.geometry(f"{w}x{h}+{int(x)}+{int(y)}")
        else:
            self.root.geometry(f"{w}x{h}")
        self.root.title(f"WPR Assist – Performance Trace Collector v{APP_VERSION}")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Menubar (Help → About)
        self._build_menubar()

        # State
        self.output_dir = Path(r"C:\Temp")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.hostname = socket.gethostname()
        self.wpr_path = None
        self.recording = False
        self.busy_saving = False
        self.auto_stop_after_id = None
        self.start_stamp = None
        self.prefix = None
        self.etl_path = None
        self.desc_path = None
        self.perf_path = None
        self.snapshot_path = None
        self.summary_path = None
        self.readme_path = None
        self.settings_snapshot_path = None
        self.bundle_zip_path = None

        # Threads/Events
        self.perf_stop_event = None
        self.perf_thread = None

        # Diagnostics thread
        self.diag_stop_event = None
        self.diag_thread = None

        # Log queue
        self.log_q = queue.Queue()

        # Pop-ups
        self._recording_win = None
        self._wait_zip_win = None
        self._wait_macro_win = None

        # Build UI
        self.build_ui()

        # Resolve WPR
        try:
            self.wpr_path = get_wpr_path()
            self.log(f"wpr.exe found at: {self.wpr_path}")
        except Exception as e:
            messagebox.showerror("WPR Missing", str(e))
            self.log(f"[error] {e}")

        # Cancel prior session quietly
        threading.Thread(target=self._cancel_prior_session_quiet, daemon=True).start()

        # Pump logs & clock
        self.root.after(100, self.flush_logs_to_ui)
        self.root.after(1000, self._tick_clock)

        # Apply saved settings to UI
        self._apply_settings_to_ui()

        # Seed issue template if empty
        if not self.txt_desc.get("1.0", "end").strip():
            self.txt_desc.insert("1.0", self.ISSUE_TEMPLATE)

    # ---------- Menubar ----------
    def _build_menubar(self):
        m = tk.Menu(self.root)
        self.root.config(menu=m)
        m_help = tk.Menu(m, tearoff=False)
        m.add_cascade(label="Help", menu=m_help)
        m_help.add_command(label="About", command=self._show_about)

    def _show_about(self):
        messagebox.showinfo(
            "About",
            f"WPR Assist – Performance Trace Collector\n"
            f"Version {APP_VERSION}\n\n"
            f"Windows Performance Recorder helper to collect ETL traces with presets, perf logs, diagnostics, and sharing aids."
        )

    # ---------- Theme ----------
    def _prepare_base_theme(self):
        for theme in ("vista", "xpnative", "clam"):
            try:
                self.style.theme_use(theme)
                break
            except tk.TclError:
                continue
        self.style.configure("Banner.TFrame", background=self.ACCENT)
        self.style.configure("Banner.TLabel", background=self.ACCENT, foreground="white")

    def _apply_fonts(self):
        self.style.configure(".", font=("Segoe UI", 10))
        self.style.configure("Banner.TLabel", font=("Segoe UI", 14, "bold"))

    def _apply_palette(self, dark: bool):
        if dark:
            bg = "#1e1e1e"; fg = "#e6e6e6"; entry_bg = "#2a2a2a"; entry_fg = "#e6e6e6"
        else:
            bg = "#f7f8fa"; fg = "#222222"; entry_bg = "white"; entry_fg = "#222222"
        self.root.configure(bg=bg)
        self.style.configure(".", background=bg, foreground=fg, fieldbackground=entry_bg)
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TFrame", background=bg)
        self.style.configure("TLabelframe", background=bg, foreground=fg)
        self.style.configure("TLabelframe.Label", background=bg, foreground=fg)
        self.style.configure("TCheckbutton", background=bg, foreground=fg)
        self.style.configure("TButton", background=bg, foreground=fg)
        self.style.configure("TEntry", fieldbackground=entry_bg, foreground=entry_fg)
        if dark:
            self.style.configure("Treeview", background="#1e1e1e", foreground="#e6e6e6",
                                 fieldbackground="#1e1e1e")
            self.style.configure("Treeview.Heading", background="#2a2a2a", foreground="#e6e6e6")

    # ---------- UI ----------
    def build_ui(self):
        pad = 12

        # Banner
        banner = ttk.Frame(self.root, style="Banner.TFrame")
        banner.pack(fill="x")
        self.lbl_title = ttk.Label(banner, text="WPR Assist – Performance Trace Collector", style="Banner.TLabel")
        self.lbl_title.pack(side="left", padx=10, pady=10)
        self.lbl_clock = ttk.Label(banner, text="", style="Banner.TLabel")
        self.lbl_clock.pack(side="right", padx=10)
        self.lbl_version = ttk.Label(banner, text=f"v{APP_VERSION}", style="Banner.TLabel")
        self.lbl_version.pack(side="right", padx=10)

        # Row 1: toggles + actions
        row_toggles = ttk.Frame(self.root); row_toggles.pack(fill="x", padx=pad, pady=(pad, 4))
        self.verbose_var = tk.BooleanVar(value=False)
        chk_verbose = ttk.Checkbutton(row_toggles, text="Verbose logging", variable=self.verbose_var,
                                      command=self._save_settings_now)
        chk_verbose.pack(side="left")

        self.var_strict = tk.BooleanVar(value=True)
        chk_strict = ttk.Checkbutton(row_toggles, text="Strict Mode (only required base profiles)",
                                     variable=self.var_strict, command=self.on_toggle_strict)
        chk_strict.pack(side="left", padx=(20,0))

        self.var_dark = tk.BooleanVar(value=False)
        chk_dark = ttk.Checkbutton(row_toggles, text="Dark Mode", variable=self.var_dark, command=self.on_toggle_dark)
        chk_dark.pack(side="left", padx=(20,0))

        ttk.Label(row_toggles, text="Top N processes in snapshot:").pack(side="left", padx=(20, 5))
        self.spin_topn = ttk.Spinbox(row_toggles, from_=3, to=50, width=5, command=self._save_settings_now)
        self.spin_topn.set("10"); self.spin_topn.pack(side="left", padx=(0, 20))

        self.btn_zip = ttk.Button(row_toggles, text="Create ZIP (ETL + logs)", command=self.on_create_zip, state="disabled")
        self.btn_zip.pack(side="left")

        self.btn_copy_summary = ttk.Button(row_toggles, text="Copy Summary", command=self.on_copy_summary, state="disabled")
        self.btn_copy_summary.pack(side="left", padx=(10,0))

        self.btn_macro = ttk.Button(row_toggles, text="Run Post-Save Macro", command=self.on_run_macro, state="disabled")
        self.btn_macro.pack(side="left", padx=(10,0))

        self.btn_reset = ttk.Button(row_toggles, text="Reset to defaults", command=self.on_reset_defaults)
        self.btn_reset.pack(side="left", padx=(10,0))

        # Row 2: Box URL
        row_box = ttk.Frame(self.root); row_box.pack(fill="x", padx=pad, pady=(0, 4))
        ttk.Label(row_box, text="Box folder URL:").pack(side="left")
        self.ent_box_url = ttk.Entry(row_box); self.ent_box_url.pack(side="left", fill="x", expand=True, padx=(8,8))
        self.ent_box_url.bind("<FocusOut>", lambda e: self._save_settings_now())
        btn_open_box = ttk.Button(row_box, text="Open Box", command=self.on_open_box)
        btn_open_box.pack(side="left")

        # Row 2b: Auto-upload to Box (Box Drive path)
        row_upload = ttk.Frame(self.root); row_upload.pack(fill="x", padx=pad, pady=(0, 4))
        self.var_auto_upload = tk.BooleanVar(value=False)
        chk_auto_upload = ttk.Checkbutton(row_upload, text="Auto-upload ZIP to Box (Box Drive path)",
                                          variable=self.var_auto_upload, command=self._save_settings_now)
        chk_auto_upload.pack(side="left")
        ttk.Label(row_upload, text="Box Drive folder:").pack(side="left", padx=(20, 5))
        self.ent_box_drive = ttk.Entry(row_upload, width=48)
        self.ent_box_drive.pack(side="left", fill="x", expand=True)
        btn_browse_drive = ttk.Button(row_upload, text="Browse…", command=self.on_browse_box_drive)
        btn_browse_drive.pack(side="left", padx=(6,0))
        self.ent_box_drive.bind("<FocusOut>", lambda e: self._save_settings_now())

        # Issue description
        lf_desc = ttk.LabelFrame(self.root, text="Issue description")
        lf_desc.pack(fill="x", padx=pad, pady=(pad, 0))
        self.txt_desc = scrolledtext.ScrolledText(lf_desc, height=10)
        self.txt_desc.pack(fill="x", padx=8, pady=8)

        # Profiles
        lf_profiles = ttk.LabelFrame(self.root, text="Profile presets")
        lf_profiles.pack(fill="x", padx=pad, pady=(pad, 0))
        self.var_general = tk.BooleanVar(value=True)
        self.var_diskio = tk.BooleanVar(value=False)
        self.var_network = tk.BooleanVar(value=False)
        self.chk_general = ttk.Checkbutton(lf_profiles, text="General", variable=self.var_general, command=self._save_settings_now)
        self.chk_diskio = ttk.Checkbutton(lf_profiles, text="Disk I/O", variable=self.var_diskio, command=self._save_settings_now)
        self.chk_network = ttk.Checkbutton(lf_profiles, text="Network", variable=self.var_network, command=self._save_settings_now)
        self.chk_general.grid(row=0, column=0, sticky="w", padx=10, pady=6)
        self.chk_diskio.grid( row=0, column=1, sticky="w", padx=10, pady=6)
        self.chk_network.grid(row=0, column=2, sticky="w", padx=10, pady=6)

        # Custom profiles
        lf_custom = ttk.LabelFrame(self.root, text="Custom profiles (applied only when Strict Mode is OFF)")
        lf_custom.pack(fill="x", padx=pad, pady=(pad, 0))
        self.var_custom_enabled = tk.BooleanVar(value=False)
        self.chk_custom = ttk.Checkbutton(lf_custom, text="Enable custom profiles", variable=self.var_custom_enabled,
                                          command=self._on_custom_toggle)
        self.chk_custom.grid(row=0, column=0, sticky="w", padx=10, pady=(8,4), columnspan=4)
        ttk.Label(lf_custom, text="Profiles (comma-separated):").grid(row=1, column=0, sticky="e", padx=10, pady=4)
        self.ent_custom_profiles = ttk.Entry(lf_custom, width=65)
        self.ent_custom_profiles.grid(row=1, column=1, sticky="we", padx=(6,10), pady=4, columnspan=3)
        ttk.Label(lf_custom, text="Extra WPR args (advanced):").grid(row=2, column=0, sticky="e", padx=10, pady=(4,10))
        self.ent_custom_args = ttk.Entry(lf_custom, width=65)
        self.ent_custom_args.grid(row=2, column=1, sticky="we", padx=(6,10), pady=(4,10), columnspan=3)
        lf_custom.columnconfigure(1, weight=1)
        self.ent_custom_profiles.bind("<FocusOut>", lambda e: self._save_settings_now())
        self.ent_custom_args.bind("<FocusOut>", lambda e: self._save_settings_now())

        # Recording options
        lf_opts = ttk.LabelFrame(self.root, text="Recording options")
        lf_opts.pack(fill="x", padx=pad, pady=(pad, 0))
        ttk.Label(lf_opts, text="Auto-stop after (minutes): (0 = manual stop)").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        self.spin_autostop = ttk.Spinbox(lf_opts, from_=0, to=240, width=5, command=self._save_settings_now)
        self.spin_autostop.set("0"); self.spin_autostop.grid(row=0, column=1, padx=(5, 20))
        ttk.Label(lf_opts, text="Perf sample interval (seconds):").grid(row=0, column=2, sticky="w")
        self.spin_interval = ttk.Spinbox(lf_opts, from_=1, to=60, width=5, command=self._save_settings_now)
        self.spin_interval.set("5"); self.spin_interval.grid(row=0, column=3, padx=(5, 0))

        # Diagnostics toggle
        self.var_diag_enabled = tk.BooleanVar(value=True)
        chk_diag = ttk.Checkbutton(lf_opts, text="Diagnostics (live Top‑N)", variable=self.var_diag_enabled,
                                   command=self._save_settings_now)
        chk_diag.grid(row=0, column=4, padx=(20,0))

        # Buttons
        row_btns = ttk.Frame(self.root); row_btns.pack(fill="x", padx=pad, pady=(pad, 0))
        self.btn_start = ttk.Button(row_btns, text="Start Recording", command=self.on_start)
        self.btn_stop = ttk.Button(row_btns, text="Stop & Save", command=self.on_stop, state="disabled")
        self.btn_open = ttk.Button(row_btns, text="Open Output Folder", command=self.on_open_folder)
        self.btn_exit = ttk.Button(row_btns, text="Exit", command=self.on_close)
        self.btn_start.grid(row=0, column=0, padx=(0, 10))
        self.btn_stop.grid(row=0, column=1, padx=(0, 10))
        self.btn_open.grid(row=0, column=2, padx=(0, 10))
        self.btn_exit.grid(row=0, column=3)

        # Status + Diagnostics tabs
        lf_status = ttk.LabelFrame(self.root, text="Status & Diagnostics")
        lf_status.pack(fill="both", expand=True, padx=pad, pady=(pad, pad))
        self.nb_status = ttk.Notebook(lf_status)
        self.nb_status.pack(fill="both", expand=True, padx=6, pady=6)

        tab_status = ttk.Frame(self.nb_status)
        self.nb_status.add(tab_status, text="Status")
        self.txt_log = scrolledtext.ScrolledText(tab_status, height=18, state="normal")
        self.txt_log.pack(fill="both", expand=True, padx=4, pady=4)

        tab_diag = ttk.Frame(self.nb_status)
        self.nb_status.add(tab_diag, text="Diagnostics")
        cols = ("pid", "name", "cpu", "rss", "disk")
        self.tree_diag = ttk.Treeview(tab_diag, columns=cols, show="headings", height=16)
        self.tree_diag.heading("pid", text="PID");  self.tree_diag.column("pid", width=80, anchor="e")
        self.tree_diag.heading("name", text="Process"); self.tree_diag.column("name", width=260, anchor="w")
        self.tree_diag.heading("cpu", text="CPU %"); self.tree_diag.column("cpu", width=80, anchor="e")
        self.tree_diag.heading("rss", text="RSS");   self.tree_diag.column("rss", width=120, anchor="e")
        self.tree_diag.heading("disk", text="Disk B/s"); self.tree_diag.column("disk", width=120, anchor="e")
        self.tree_diag.pack(fill="both", expand=True, padx=4, pady=4)

        # Status bar with progress
        row_bar = ttk.Frame(self.root); row_bar.pack(fill="x", padx=pad, pady=(0, pad))
        self.lbl_bar = ttk.Label(row_bar, text="Ready"); self.lbl_bar.pack(side="left")
        self.pb = ttk.Progressbar(row_bar, mode="determinate", maximum=100)
        self.pb.pack(side="right", fill="x", expand=True, padx=(10, 0))

        self._apply_text_widget_palette()

    def _apply_text_widget_palette(self):
        dark = self.var_dark.get()
        entry_bg = "#2a2a2a" if dark else "white"
        entry_fg = self.FG_DARK if dark else self.FG_LIGHT
        for w in (self.txt_desc, self.txt_log):
            try:
                w.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
            except Exception:
                pass

    # ---------- Clock ----------
    def _tick_clock(self):
        now = datetime.datetime.now().strftime("%a, %b %d, %Y %I:%M:%S %p")
        self.lbl_clock.config(text=now)
        self.root.after(1000, self._tick_clock)

    # ---------- Palette / Modes ----------
    def on_toggle_dark(self):
        self._apply_palette(self.var_dark.get())
        self._apply_text_widget_palette()
        self._save_settings_now()

    def on_toggle_strict(self):
        strict = self.var_strict.get()
        if strict:
            self.var_general.set(True)
            self.var_diskio.set(False)
            self.var_network.set(False)
            self.var_custom_enabled.set(False)
            self.chk_general.configure(state="disabled")
            self.chk_diskio.configure(state="disabled")
            self.chk_network.configure(state="disabled")
            self.chk_custom.configure(state="disabled")
            self.ent_custom_profiles.configure(state="disabled")
            self.ent_custom_args.configure(state="disabled")
            self.log("Strict Mode ON: limiting to required base profiles only (GeneralProfile, CPU, Heap, Pool, FileIO, VirtualAllocation).")
        else:
            self.chk_general.configure(state="normal")
            self.chk_diskio.configure(state="normal")
            self.chk_network.configure(state="normal")
            self.chk_custom.configure(state="normal")
            state = "normal" if self.var_custom_enabled.get() else "disabled"
            self.ent_custom_profiles.configure(state=state)
            self.ent_custom_args.configure(state=state)
            self.log("Strict Mode OFF: optional Disk I/O, Network, and custom profiles available.")
        self._save_settings_now()

    def _on_custom_toggle(self):
        if self.var_strict.get():
            self.var_custom_enabled.set(False)
            return
        state = "normal" if self.var_custom_enabled.get() else "disabled"
        self.ent_custom_profiles.configure(state=state)
        self.ent_custom_args.configure(state=state)
        self._save_settings_now()

    # ---------- Busy / Ready ----------
    def set_busy(self, message: str, saving: bool = False, starting: bool = False):
        self.lbl_bar.config(text=message)
        self.pb.config(mode="indeterminate")
        self.pb.start(30)
        self.btn_start.config(state=("disabled" if (saving or starting or self.recording) else "normal"))
        self.btn_stop.config(state=("normal" if (self.recording and not saving) else "disabled"))
        self.btn_exit.config(state=("disabled" if (saving or starting) else "normal"))
        self.btn_open.config(state=("disabled" if (saving or starting) else "normal"))
        self.btn_zip.config(state=("disabled" if (saving or starting or self.recording or not self._outputs_exist()) else "normal"))
        self.btn_copy_summary.config(state=("disabled" if (saving or starting or self.recording) else "normal"))
        self.btn_macro.config(state=("disabled" if (saving or starting or not self._outputs_exist()) else "normal"))
        self.txt_desc.config(state=("disabled" if (self.recording or saving or starting) else "normal"))
        self.spin_autostop.config(state=("disabled" if (self.recording or saving or starting) else "normal"))
        self.spin_interval.config(state=("disabled" if (self.recording or saving or starting) else "normal"))

    def clear_busy(self, force_ready_text: bool = False):
        if force_ready_text:
            self.lbl_bar.config(text="Ready")
        self.pb.stop()
        self.pb.config(mode="determinate", value=0)
        self.btn_start.config(state=("disabled" if self.recording else "normal"))
        self.btn_stop.config(state=("normal" if self.recording else "disabled"))
        self.btn_exit.config(state="normal")
        self.btn_open.config(state="normal")
        self.btn_zip.config(state=("normal" if (not self.recording and self._outputs_exist()) else "disabled"))
        self.btn_copy_summary.config(state=("normal" if (not self.recording) else "disabled"))
        self.btn_macro.config(state=("normal" if (not self.recording and self._outputs_exist() and self.settings.get('enable_post_save_macro', True)) else "disabled"))
        self.txt_desc.config(state=("disabled" if self.recording else "normal"))
        self.spin_autostop.config(state=("disabled" if self.recording else "normal"))
        self.spin_interval.config(state=("disabled" if self.recording else "normal"))

    # ---------- Logging ----------
    def log(self, msg: str):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_q.put(f"[{timestamp}] {msg}")

    def flush_logs_to_ui(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.txt_log.insert("end", line + "\n")
                self.txt_log.see("end")
        except queue.Empty:
            pass
        self.root.after(100, self.flush_logs_to_ui)

    # ---------- Pop-ups ----------
    def _show_recording_popup(self):
        if self._recording_win:
            return
        win = tk.Toplevel(self.root)
        win.title("Recording in progress…")
        win.resizable(False, False)
        win.attributes("-topmost", True)
        frm = ttk.Frame(win, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(
            frm,
            text=("Recording is in progress.\n"
                  "Please reproduce the issue now.\n\n"
                  "This can take several minutes…"),
            justify="left", wraplength=360
        ).pack(anchor="w", pady=(0, 8))
        pb = ttk.Progressbar(frm, mode="indeterminate")
        pb.pack(fill="x", pady=(0, 10))
        pb.start(30)
        ttk.Button(frm, text="Stop & Save Now", command=self.on_stop).pack(anchor="e")
        self._recording_win = (win, pb)

        def _on_close():
            try: pb.stop()
            except Exception: pass
            try: win.destroy()
            except Exception: pass
            self._recording_win = None
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _hide_recording_popup(self):
        if not self._recording_win:
            return
        win, pb = self._recording_win
        try: pb.stop()
        except Exception: pass
        try: win.destroy()
        except Exception: pass
        self._recording_win = None

    def _show_zip_wait(self):
        if self._wait_zip_win:
            return
        self._wait_zip_win = tk.Toplevel(self.root)
        self._wait_zip_win.title("Creating ZIP…")
        self._wait_zip_win.resizable(False, False)
        self._wait_zip_win.grab_set()
        self._wait_zip_win.transient(self.root)
        frm = ttk.Frame(self._wait_zip_win, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Creating ZIP bundle…\nPlease wait, this may take a minute for large ETL files.", wraplength=360).pack(anchor="w", pady=(0, 8))
        pb = ttk.Progressbar(frm, mode="indeterminate")
        pb.pack(fill="x")
        pb.start(30)
        self._wait_zip_pb = pb
        self._wait_zip_win.update_idletasks()

    def _hide_zip_wait(self):
        if not self._wait_zip_win:
            return
        try: self._wait_zip_pb.stop()
        except Exception: pass
        try:
            self._wait_zip_win.grab_release()
            self._wait_zip_win.destroy()
        except Exception:
            pass
        self._wait_zip_win = None

    def _show_macro_wait(self):
        if self._wait_macro_win:
            return
        self._wait_macro_win = tk.Toplevel(self.root)
        self._wait_macro_win.title("Running Post-Save Macro…")
        self._wait_macro_win.resizable(False, False)
        self._wait_macro_win.grab_set()
        self._wait_macro_win.transient(self.root)
        frm = ttk.Frame(self._wait_macro_win, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Creating ZIP → copying to Box (if enabled) → opening Box → copying Summary…", wraplength=360).pack(anchor="w", pady=(0, 8))
        pb = ttk.Progressbar(frm, mode="indeterminate")
        pb.pack(fill="x")
        pb.start(30)
        self._wait_macro_pb = pb
        self._wait_macro_win.update_idletasks()

    def _hide_macro_wait(self):
        if not self._wait_macro_win:
            return
        try: self._wait_macro_pb.stop()
        except Exception: pass
        try:
            self._wait_macro_win.grab_release()
            self._wait_macro_win.destroy()
        except Exception:
            pass
        self._wait_macro_win = None

    # ---------- Modal Wait (Stop/Save) ----------
    def show_wait(self, title="Saving trace…", message="Please wait… This can take several minutes."):
        if getattr(self, "_wait_win", None):
            return
        self._wait_win = tk.Toplevel(self.root)
        self._wait_win.title(title)
        self._wait_win.resizable(False, False)
        self._wait_win.grab_set()
        self._wait_win.transient(self.root)
        frm = ttk.Frame(self._wait_win, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text=message, wraplength=360).pack(anchor="w", pady=(0, 8))
        pb = ttk.Progressbar(frm, mode="indeterminate")
        pb.pack(fill="x")
        pb.start(30)
        self._wait_pb = pb
        self._wait_win.update_idletasks()

    def hide_wait(self):
        if getattr(self, "_wait_win", None):
            try: self._wait_pb.stop()
            except Exception: pass
            try:
                self._wait_win.grab_release()
                self._wait_win.destroy()
            except Exception:
                pass
            self._wait_win = None

    # ---------- WPR helpers ----------
    def _cancel_prior_session_quiet(self):
        if not self.wpr_path:
            return
        if self.verbose_var.get():
            run_process_live(self.wpr_path, ["-cancel"], self.log_q); return
        temp_q = queue.Queue()
        rc = run_process_live(self.wpr_path, ["-cancel"], temp_q)
        # Be quiet unless it's an unexpected error
        if rc == 0:
            self.log("Canceled any prior WPR session (if present).")
        else:
            # ignore typical 'no profiles running' chatter
            self.log("No prior WPR session or already clean.")

    def _try_start_profiles_group(self, profiles, critical=True):
        if not profiles: return 0
        args = []
        for p in profiles:
            args += ["-start", p]
        rc = run_process_live(self.wpr_path, args, self.log_q)
        if rc != 0 and critical:
            raise RuntimeError(f"Failed to start required profiles (exit code {rc}).")
        return rc

    def _try_start_optional_profile_with_aliases(self, aliases):
        for prof in aliases:
            rc = run_process_live(self.wpr_path, ["-start", prof], self.log_q)
            if rc == 0:
                self.log(f"Optional profile '{prof}' started.")
                return True
        self.log(f"[warning] Optional profile not available (tried: {', '.join(aliases)}).")
        return False

    def _stop_wpr(self, etl_path: Path) -> int:
        return run_process_live(self.wpr_path, ["-stop", str(etl_path)], self.log_q,
                                show_wait=self.show_wait, hide_wait=self.hide_wait)

    # ---------- Start / Stop ----------
    def on_start(self):
        if self.busy_saving: return
        self.bundle_zip_path = None
        self.btn_zip.config(state="disabled")
        self.btn_copy_summary.config(state="disabled")
        self.btn_macro.config(state="disabled")
        self.set_busy("Initializing WPR...", starting=True)
        threading.Thread(target=self._do_start, daemon=True).start()

    def _do_start(self):
        try:
            if not self.wpr_path:
                self.wpr_path = get_wpr_path()

            # Unique names per run
            self.start_stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            self.prefix = f"{self.start_stamp}-{self.hostname}"
            self.etl_path = self.output_dir / f"{self.prefix}_output-result.etl"
            self.desc_path = self.output_dir / f"{self.prefix}_issue-description.txt"
            self.perf_path = self.output_dir / f"{self.prefix}_perf-log.csv"
            self.snapshot_path = self.output_dir / f"{self.prefix}_stop-snapshot.txt"
            self.summary_path = self.output_dir / f"{self.prefix}_summary.txt"
            self.readme_path = self.output_dir / f"{self.prefix}_README.txt"
            self.settings_snapshot_path = self.output_dir / f"{self.prefix}_settings.json"
            self.bundle_zip_path = self.output_dir / f"{self.prefix}_bundle.zip"

            # Save description
            try:
                desc = self.txt_desc.get("1.0", "end").strip()
                self.desc_path.write_text(desc, encoding="utf-8")
                self.log(f"Issue description saved to: {self.desc_path}")
            except Exception as e:
                self.log(f"[warn] Failed to save issue description: {e}")

            # Init perf log
            try:
                self.perf_path.write_text("Timestamp,CPU_Percent,AvailableMemory_MB\n", encoding="utf-8")
                self.log(f"Perf log initialized: {self.perf_path}")
            except Exception as e:
                self.log(f"[warn] Failed to initialize perf log: {e}")

            # Ensure no prior WPR session
            self._cancel_prior_session_quiet()

            # Required base profiles
            base_profiles = ["GeneralProfile", "CPU", "Heap", "Pool", "FileIO", "VirtualAllocation"]
            self.log("Starting required profiles: " + ", ".join(base_profiles))
            self._try_start_profiles_group(base_profiles, critical=True)

            # Optional when not strict
            if not self.var_strict.get():
                if self.var_diskio.get():
                    self.log("Starting optional profile: Disk I/O")
                    self._try_start_profiles_group(["DiskIO"], critical=False)
                if self.var_network.get():
                    self.log("Starting optional profile: Network")
                    self._try_start_optional_profile_with_aliases(["Network", "Networking"])
                if self.var_custom_enabled.get():
                    names_raw = self.ent_custom_profiles.get().strip()
                    extra_raw = self.ent_custom_args.get().strip()
                    custom_names = [n.strip() for n in names_raw.split(",") if n.strip()]
                    if custom_names:
                        self.log("Starting custom profiles: " + ", ".join(custom_names))
                        self._try_start_profiles_group(custom_names, critical=False)
                    if extra_raw:
                        rc = run_process_live(self.wpr_path, extra_raw.split(), self.log_q)
                        if rc != 0:
                            self.log(f"[warning] Extra WPR args returned exit code {rc}. Check syntax.")
            else:
                self.log("Strict Mode active: skipping optional Disk I/O, Network, and custom profiles.")

            # Start perf logging
            try:
                interval = int(self.spin_interval.get())
            except Exception:
                interval = 5
            self.perf_stop_event = threading.Event()
            self.perf_thread = threading.Thread(target=perf_logger,
                                                args=(self.perf_stop_event, interval, self.perf_path, self.log_q),
                                                daemon=True)
            self.perf_thread.start()
            self.log(f"Perf sampling every {interval} seconds.")

            # Start Diagnostics sampler if enabled
            if self.var_diag_enabled.get():
                self.start_diagnostics(interval)

            # Auto-stop
            try:
                minutes = int(self.spin_autostop.get())
            except Exception:
                minutes = 0
            if minutes > 0:
                ms = minutes * 60 * 1000
                stop_at = (datetime.datetime.now() + datetime.timedelta(minutes=minutes)).strftime('%H:%M:%S')
                self.log(f"Auto-stop enabled: will stop at {stop_at}.")
                self.auto_stop_after_id = self.root.after(ms, self.on_stop)
            else:
                self.log("Auto-stop disabled: click 'Stop & Save' when the issue is reproduced.")

            # Show recording pop-up
            self.root.after(0, self._show_recording_popup)
            self.root.after(0, self._set_recording_state, True)

        except Exception as e:
            self.log(f"ERROR starting recording: {e}")
            try:
                messagebox.showerror("Start Error", str(e))
            except Exception:
                pass
            try:
                self._cancel_prior_session_quiet()
            except Exception:
                pass
            self.root.after(0, self._set_recording_state, False)

    def _set_recording_state(self, is_recording: bool):
        self.recording = is_recording
        self.clear_busy(force_ready_text=not self.recording)
        self.btn_stop.config(state=("normal" if self.recording else "disabled"))
        self.btn_start.config(state=("disabled" if self.recording else "normal"))
        self.txt_desc.config(state=("disabled" if self.recording else "normal"))
        self.spin_autostop.config(state=("disabled" if self.recording else "normal"))
        self.spin_interval.config(state=("disabled" if self.recording else "normal"))
        self.btn_zip.config(state=("normal" if (not self.recording and self._outputs_exist()) else "disabled"))
        self.btn_copy_summary.config(state=("normal" if (not self.recording) else "disabled"))
        self.btn_macro.config(state=("normal" if (not self.recording and self._outputs_exist() and self.settings.get('enable_post_save_macro', True)) else "disabled"))
        self._save_settings_now()

    def on_stop(self):
        if not self.recording or self.busy_saving: return
        self.busy_saving = True
        self.set_busy("Finalizing trace (this can take a few minutes)...", saving=True)
        if self.auto_stop_after_id is not None:
            try:
                self.root.after_cancel(self.auto_stop_after_id)
            except Exception:
                pass
        self.auto_stop_after_id = None
        threading.Thread(target=self._do_stop, daemon=True).start()

    def _do_stop(self):
        try:
            # Snapshot BEFORE stopping WPR
            try:
                top_n = int(self.spin_topn.get())
            except Exception:
                top_n = 10
            self.log(f"Capturing Top {top_n} processes (CPU, Memory, Disk I/O)...")
            snapshot = take_top_process_snapshot(top_n=top_n, sample_seconds=2)
            self._write_snapshot_file(snapshot, self.snapshot_path)
            self.log(f"Snapshot saved: {self.snapshot_path}")

            # Stop perf logging
            if self.perf_stop_event: self.perf_stop_event.set()
            if self.perf_thread: self.perf_thread.join(timeout=5.0)

            # Stop diagnostics sampler
            self.stop_diagnostics()

            # Stop WPR
            if not self.etl_path:
                raise RuntimeError("Internal error: ETL path not set.")
            self.log(f"Stopping WPR and saving to: {self.etl_path}")
            rc = self._stop_wpr(self.etl_path)
            if rc != 0:
                self.log("WPR stop returned a non-zero code; if no profiles were running, it may already be stopped.")

            # Ensure summary/README/settings are created on disk right after Stop
            self._ensure_summary_file()
            self._ensure_readme_file()
            self._ensure_settings_snapshot()

            # Summaries
            if Path(self.etl_path).exists():
                size_mb = round(Path(self.etl_path).stat().st_size / (1024 * 1024), 2)
                self.log(f"ETL saved: {self.etl_path} ({size_mb} MB)")
            else:
                self.log(f"WARNING: Expected ETL not found at {self.etl_path}")
            if self.perf_path and Path(self.perf_path).exists():
                self.log(f"Perf log saved: {self.perf_path}")
            if self.desc_path and Path(self.desc_path).exists():
                self.log(f"Issue description file: {self.desc_path}")

            if self._outputs_exist():
                self.log("Outputs ready. You can Create ZIP or run the Post-Save Macro.")
                self.root.after(0, lambda: (self.btn_zip.config(state="normal"),
                                            self.btn_copy_summary.config(state="normal"),
                                            self.btn_macro.config(state=("normal" if self.settings.get("enable_post_save_macro", True) else "disabled"))))
                try:
                    os.startfile(str(self.output_dir))
                except Exception:
                    subprocess.Popen(["explorer", str(self.output_dir)])
                self.root.after(0, lambda: messagebox.showinfo("WPR Trace", f"Trace finalization complete.\n\nFolder: {self.output_dir}"))

        except Exception as e:
            self.log(f"ERROR stopping recording: {e}")
            try:
                self.root.after(0, lambda: messagebox.showerror("Stop Error", str(e)))
            except Exception:
                pass
            try:
                self._cancel_prior_session_quiet()
            except Exception:
                pass
        finally:
            self.root.after(0, self._after_stop_cleanup)

    def _after_stop_cleanup(self):
        # Close recording popup if open
        self._hide_recording_popup()

        self.busy_saving = False
        self.recording = False
        try:
            self.hide_wait()
        except Exception:
            pass
        self.clear_busy(force_ready_text=True)
        self.btn_stop.config(state="disabled")
        self.btn_start.config(state="normal")
        self.txt_desc.config(state="normal")
        self.spin_autostop.config(state="normal")
        self.spin_interval.config(state="normal")
        if self._outputs_exist():
            self.btn_zip.config(state="normal")
            self.btn_copy_summary.config(state="normal")
            self.btn_macro.config(state=("normal" if self.settings.get("enable_post_save_macro", True) else "disabled"))

    # ---------- Diagnostics live sampler ----------
    def start_diagnostics(self, interval_sec: int):
        try:
            top_n = int(self.spin_topn.get())
        except Exception:
            top_n = 10
        if self.diag_thread and self.diag_thread.is_alive():
            return
        self.diag_stop_event = threading.Event()

        def _diag_worker():
            # Prime CPU% on first iteration
            for p in psutil.process_iter(attrs=["pid"]):
                try:
                    psutil.Process(p.info["pid"]).cpu_percent(interval=None)
                except Exception:
                    continue
            while not self.diag_stop_event.is_set():
                snap = take_top_process_snapshot(top_n=top_n, sample_seconds=1)
                self.root.after(0, lambda s=snap: self._update_diag_table(s))
                sleep_left = max(1, interval_sec) - 1
                for _ in range(sleep_left):
                    if self.diag_stop_event.is_set():
                        break
                    time.sleep(1)

        self.diag_thread = threading.Thread(target=_diag_worker, daemon=True)
        self.diag_thread.start()
        self.log("Diagnostics live view started.")

    def stop_diagnostics(self):
        if self.diag_stop_event:
            self.diag_stop_event.set()
        if self.diag_thread:
            try:
                self.diag_thread.join(timeout=3.0)
            except Exception:
                pass
        self.log("Diagnostics live view stopped.")

    def _update_diag_table(self, snapshot: dict):
        metrics = {}
        for pid, name, cpu in snapshot.get("cpu", []):
            metrics[pid] = {"pid": pid, "name": name, "cpu": cpu, "rss": None, "disk": None}
        for pid, name, rss in snapshot.get("mem", []):
            metrics.setdefault(pid, {"pid": pid, "name": name, "cpu": 0.0, "rss": None, "disk": None})["rss"] = rss
        for pid, name, bps in snapshot.get("disk", []):
            metrics.setdefault(pid, {"pid": pid, "name": name, "cpu": 0.0, "rss": None, "disk": None})["disk"] = bps

        rows = list(metrics.values())
        rows.sort(key=lambda r: (r["cpu"], r["rss"] or 0, r["disk"] or 0), reverse=True)

        self.tree_diag.delete(*self.tree_diag.get_children())
        for r in rows[:max(3, int(self.spin_topn.get() or 10))]:
            cpu = f"{r['cpu']:.1f}"
            rss = fmt_bytes(r["rss"] or 0.0)
            disk = fmt_bytes(r["disk"] or 0.0) + "/s"
            self.tree_diag.insert("", "end", values=(r["pid"], r["name"], cpu, rss, disk))

    # ---------- ZIP ----------
    def on_create_zip(self):
        if not self._outputs_exist():
            messagebox.showwarning("ZIP", "Output files are not ready yet.")
            return
        self._show_zip_wait()
        threading.Thread(target=self._do_create_zip, daemon=True).start()

    def _do_create_zip(self):
        try:
            zip_path = self._create_zip_core()
            if zip_path:
                try:
                    os.startfile(str(Path(zip_path).parent))
                except Exception:
                    subprocess.Popen(["explorer", str(Path(zip_path).parent)])
                self.root.after(0, lambda: messagebox.showinfo("ZIP created", f"ZIP created:\n{zip_path}\n\nYou can now upload to Box."))
        except Exception as e:
            self.log(f"[error] Failed to create ZIP: {e}")
            self.root.after(0, lambda: messagebox.showerror("ZIP error", str(e)))
        finally:
            self.root.after(0, self._hide_zip_wait)

    def _ensure_summary_file(self):
        """Create/update the capture summary text file on disk."""
        try:
            if not self.summary_path:
                self.summary_path = self.output_dir / f"{self.prefix}_summary.txt"
            text = self._generate_summary_text()
            Path(self.summary_path).write_text(text, encoding="utf-8")
            self.log(f"Summary file saved: {self.summary_path}")
        except Exception as e:
            self.log(f"[warning] Failed to write summary file: {e}")

    def _ensure_readme_file(self):
        """Create a simple README with quick instructions."""
        try:
            if not self.readme_path:
                self.readme_path = self.output_dir / f"{self.prefix}_README.txt"
            lines = []
            lines.append("WPR Assist – Capture Bundle README")
            lines.append(f"Version: {APP_VERSION}")
            lines.append(f"Host: {self.hostname}")
            lines.append("")
            lines.append("Contents:")
            lines.append(" - *_output-result.etl  → Open with Windows Performance Analyzer (WPA).")
            lines.append(" - *_perf-log.csv       → CPU% and AvailableMemory_MB samples.")
            lines.append(" - *_issue-description.txt → User-entered context and repro steps.")
            lines.append(" - *_stop-snapshot.txt  → Top-N processes at stop (CPU/Mem/Disk).")
            lines.append(" - *_summary.txt        → Capture summary & file list.")
            lines.append(" - *_settings.json      → App settings snapshot for this run.")
            lines.append("")
            lines.append("Tips:")
            lines.append(" - Upload the ZIP to your Box folder (or let auto-upload copy it).")
            lines.append(" - To analyze ETL, install Windows Performance Analyzer (WPA) from ADK.")
            lines.append(" - Share the Box link + paste the summary for triage.")
            Path(self.readme_path).write_text("\n".join(lines), encoding="utf-8")
            self.log(f"README saved: {self.readme_path}")
        except Exception as e:
            self.log(f"[warning] Failed to write README: {e}")

    def _ensure_settings_snapshot(self):
        """Write a JSON snapshot of current settings."""
        try:
            if not self.settings_snapshot_path:
                self.settings_snapshot_path = self.output_dir / f"{self.prefix}_settings.json"
            # Prefer collecting from UI so the latest toggles are captured
            try:
                data = self._collect_settings_from_ui()
            except Exception:
                data = self.settings
            Path(self.settings_snapshot_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.log(f"Settings snapshot saved: {self.settings_snapshot_path}")
        except Exception as e:
            self.log(f"[warning] Failed to write settings snapshot: {e}")

    def _create_zip_core(self):
        # Always (re)generate files before zipping
        self._ensure_summary_file()
        self._ensure_readme_file()
        self._ensure_settings_snapshot()

        zip_path = self.bundle_zip_path or (self.output_dir / f"{self.prefix}_bundle.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            z.write(self.etl_path, arcname=Path(self.etl_path).name)
            z.write(self.perf_path, arcname=Path(self.perf_path).name)
            z.write(self.desc_path, arcname=Path(self.desc_path).name)
            z.write(self.snapshot_path, arcname=Path(self.snapshot_path).name)
            if self.summary_path and Path(self.summary_path).exists():
                z.write(self.summary_path, arcname=Path(self.summary_path).name)
            if self.readme_path and Path(self.readme_path).exists():
                z.write(self.readme_path, arcname=Path(self.readme_path).name)
            if self.settings_snapshot_path and Path(self.settings_snapshot_path).exists():
                z.write(self.settings_snapshot_path, arcname=Path(self.settings_snapshot_path).name)
        size_mb = round(Path(zip_path).stat().st_size / (1024 * 1024), 2)
        self.log(f"ZIP created: {zip_path} ({size_mb} MB)")
        self.bundle_zip_path = zip_path

        # Auto-upload to Box Drive (optional)
        if self.var_auto_upload.get():
            dest_dir = self.ent_box_drive.get().strip()
            try:
                self._try_auto_upload_to_box_drive(zip_path, dest_dir)
            except Exception as e:
                self.log(f"[warning] Auto-upload failed: {e}")
        return zip_path

    # ---------- Auto-upload helper ----------
    def _try_auto_upload_to_box_drive(self, zip_path: Path, dest_dir_str: str):
        """
        Copy the created ZIP to a Box Drive folder.
        - If dest file exists, append a timestamp suffix to avoid overwrite.
        - Logs warnings instead of raising, to keep the UI flow smooth.
        """
        try:
            if not dest_dir_str:
                self.log("[warning] Auto-upload enabled but Box Drive folder is empty.")
                return

            dest_dir = Path(dest_dir_str)
            if not dest_dir.exists() or not dest_dir.is_dir():
                self.log(f"[warning] Auto-upload enabled but folder is invalid: {dest_dir}")
                return

            src = Path(zip_path)
            if not src.exists():
                self.log(f"[warning] Auto-upload skipped: ZIP not found: {src}")
                return

            dest = dest_dir / src.name
            if dest.exists():
                ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                dest = dest_dir / f"{src.stem}-{ts}{src.suffix}"

            shutil.copy2(src, dest)
            self.log(f"Auto-upload: ZIP copied to Box Drive folder: {dest}")
        except Exception as e:
            self.log(f"[warning] Auto-upload failed: {e}")

    # ---------- Post-Save Macro ----------
    def on_run_macro(self):
        if not self._outputs_exist():
            messagebox.showwarning("Post-Save Macro", "Output files are not ready yet.")
            return
        if not self.settings.get("enable_post_save_macro", True):
            messagebox.showinfo("Post-Save Macro", "Macro is disabled in settings.")
            return
        self._show_macro_wait()
        threading.Thread(target=self._do_post_save_macro, daemon=True).start()

    def _do_post_save_macro(self):
        try:
            # 1) Create ZIP (and auto-upload if enabled)
            try:
                _ = self._create_zip_core()
            except Exception as e:
                self.log(f"[error] Macro: ZIP failed: {e}")
                self.root.after(0, lambda: messagebox.showerror("Post-Save Macro", f"ZIP failed:\n{e}"))
                return

            # 2) Open Box URL (if provided), else open folder
            url = self.ent_box_url.get().strip()
            if url:
                try:
                    webbrowser.open(url, new=2)
                    self.log(f"Macro: Opened Box URL: {url}")
                except Exception as e:
                    self.log(f"[warning] Macro: Failed to open Box URL: {e}")
            else:
                try:
                    os.startfile(str(self.output_dir))
                except Exception:
                    subprocess.Popen(["explorer", str(self.output_dir)])

            # 3) Copy Summary to clipboard (also saved to file & included in ZIP)
            try:
                text = self._generate_summary_text()
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.root.update()
                self.log("Macro: Summary copied to clipboard.")
            except Exception as e:
                self.log(f"[warning] Macro: Failed to copy summary: {e}")

            self.root.after(0, lambda: messagebox.showinfo("Post-Save Macro", "Done: ZIP created (incl. summary/README/settings), uploaded (if enabled), Box opened, Summary copied."))
        finally:
            self.root.after(0, self._hide_macro_wait)

    # ---------- Browse / Open helpers ----------
    def on_browse_box_drive(self):
        try:
            path = filedialog.askdirectory(
                parent=self.root,
                title="Select Box Drive folder (ZIP will be copied here)"
            )
            if not path:
                return
            self.ent_box_drive.delete(0, "end")
            self.ent_box_drive.insert(0, path)
            self._save_settings_now()
            self.log(f"Box Drive folder set to: {path}")
        except Exception as e:
            messagebox.showerror("Box Drive Folder", f"Unable to select folder:\n{e}")
            self.log(f"[error] Box Drive browse failed: {e}")

    def on_open_box(self):
        url = self.ent_box_url.get().strip()
        if not url:
            messagebox.showwarning("Box URL", "Please enter your Box folder URL first.")
            return
        try:
            webbrowser.open(url, new=2)
        except Exception as e:
            messagebox.showerror("Box URL", f"Failed to open URL:\n{e}")

    def on_open_folder(self):
        try:
            os.startfile(str(self.output_dir))
        except Exception as e:
            messagebox.showerror("Open Folder", f"Unable to open {self.output_dir}\n\n{e}")

    # ---------- Snapshot, Summary & Outputs ----------
    def _write_snapshot_file(self, snapshot: dict, path: Path):
        try:
            lines = []
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"Top Processes Snapshot @ {now}")
            lines.append(f"Host: {self.hostname}"); lines.append("")
            lines.append("== Top by CPU (%) =="); lines.append("PID\tCPU%\tName")
            for pid, name, cpu in snapshot["cpu"]: lines.append(f"{pid}\t{cpu:.1f}\t{name}")
            lines.append("")
            lines.append("== Top by Memory (RSS) =="); lines.append("PID\tRSS\tName")
            for pid, name, rss in snapshot["mem"]: lines.append(f"{pid}\t{fmt_bytes(float(rss))}\t{name}")
            lines.append("")
            lines.append("== Top by Disk I/O (bytes/sec) =="); lines.append("PID\tBytes/sec\tName")
            for pid, name, bps in snapshot["disk"]: lines.append(f"{pid}\t{fmt_bytes(float(bps))}/s\t{name}")
            lines.append("")
            Path(path).write_text("\n".join(lines), encoding="utf-8")
        except Exception as e:
            self.log(f"[warn] Failed to write snapshot file: {e}")

    def _generate_summary_text(self) -> str:
        def size_str(p: Path):
            try:
                return f"{fmt_bytes(Path(p).stat().st_size)}"
            except Exception:
                return "n/a"

        strict = self.var_strict.get()
        top_n = int(self.spin_topn.get() or 10)
        auto_min = int(self.spin_autostop.get() or 0)
        interval = int(self.spin_interval.get() or 5)

        required = ["GeneralProfile", "CPU", "Heap", "Pool", "FileIO", "VirtualAllocation"]
        optional = []
        if not strict:
            if self.var_diskio.get(): optional.append("DiskIO")
            if self.var_network.get(): optional.append("Network/Networking")
            if self.var_custom_enabled.get():
                names_raw = self.ent_custom_profiles.get().strip()
                if names_raw:
                    optional += [n.strip() for n in names_raw.split(",") if n.strip()]

        files = []
        if self.etl_path and Path(self.etl_path).exists():
            files.append(("ETL", str(self.etl_path), size_str(self.etl_path)))
        if self.perf_path and Path(self.perf_path).exists():
            files.append(("Perf CSV", str(self.perf_path), size_str(self.perf_path)))
        if self.desc_path and Path(self.desc_path).exists():
            files.append(("Issue description", str(self.desc_path), size_str(self.desc_path)))
        if self.snapshot_path and Path(self.snapshot_path).exists():
            files.append(("Stop snapshot", str(self.snapshot_path), size_str(self.snapshot_path)))
        if self.summary_path and Path(self.summary_path).exists():
            files.append(("Capture summary", str(self.summary_path), size_str(self.summary_path)))
        if self.readme_path and Path(self.readme_path).exists():
            files.append(("README", str(self.readme_path), size_str(self.readme_path)))
        if self.settings_snapshot_path and Path(self.settings_snapshot_path).exists():
            files.append(("Settings snapshot", str(self.settings_snapshot_path), size_str(self.settings_snapshot_path)))
        if self.bundle_zip_path and Path(self.bundle_zip_path).exists():
            files.append(("ZIP bundle", str(self.bundle_zip_path), size_str(self.bundle_zip_path)))

        box_url = self.ent_box_url.get().strip()
        ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = []
        lines.append(f"WPR Capture Summary — {ts_now}")
        lines.append(f"Host: {self.hostname}")
        lines.append(f"Strict Mode: {'ON' if strict else 'OFF'}")
        lines.append(f"Required profiles: {', '.join(required)}")
        lines.append(f"Optional/custom profiles: {', '.join(optional) if optional else 'none'}")
        lines.append(f"Verbose logging: {'ON' if self.verbose_var.get() else 'OFF'}")
        lines.append(f"Auto-stop minutes: {auto_min} Perf interval (s): {interval} Snapshot Top N: {top_n}")
        lines.append("")
        lines.append("Files:")
        for label, p, s in files:
            lines.append(f"- {label}: {p} ({s})")
        lines.append("")
        lines.append(f"Box folder: {box_url if box_url else '(not provided)'}")
        return "\n".join(lines)

    def on_copy_summary(self):
        try:
            text = self._generate_summary_text()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()  # keep clipboard after exit
            self.log("Summary copied to clipboard.")
            messagebox.showinfo("Summary", "Capture summary copied to clipboard.")
        except Exception as e:
            self.log(f"[error] Failed to copy summary: {e}")
            messagebox.showerror("Copy Summary", str(e))

    def _outputs_exist(self) -> bool:
        return all([
            self.etl_path and Path(self.etl_path).exists(),
            self.perf_path and Path(self.perf_path).exists(),
            self.desc_path and Path(self.desc_path).exists(),
            self.snapshot_path and Path(self.snapshot_path).exists()
        ])

    # ---------- Settings ----------
    def _apply_settings_to_ui(self):
        s = self.settings
        self.var_strict.set(bool(s.get("strict_mode", True)))
        self.verbose_var.set(bool(s.get("verbose", False)))
        self.var_dark.set(bool(s.get("dark_mode", False)))
        self.on_toggle_dark()
        self.spin_topn.delete(0,"end"); self.spin_topn.insert(0, str(int(s.get("top_n", 10))))
        self.spin_autostop.delete(0,"end"); self.spin_autostop.insert(0, str(int(s.get("auto_stop_minutes", 0))))
        self.spin_interval.delete(0,"end"); self.spin_interval.insert(0, str(int(s.get("perf_interval", 5))))
        self.var_general.set(bool(s.get("preset_general", True)))
        self.var_diskio.set(bool(s.get("preset_diskio", False)))
        self.var_network.set(bool(s.get("preset_network", False)))
        self.var_custom_enabled.set(bool(s.get("custom_enabled", False)))
        self.ent_custom_profiles.delete(0,"end"); self.ent_custom_profiles.insert(0, s.get("custom_profiles",""))
        self.ent_custom_args.delete(0,"end"); self.ent_custom_args.insert(0, s.get("custom_extra_args",""))
        self.ent_box_url.delete(0,"end"); self.ent_box_url.insert(0, s.get("box_url",""))
        self.var_auto_upload.set(bool(s.get("auto_upload_box", False)))
        self.ent_box_drive.delete(0,"end"); self.ent_box_drive.insert(0, s.get("box_drive_path",""))
        self.var_diag_enabled.set(bool(s.get("diagnostics_enabled", True)))
        if s.get("enable_post_save_macro", True):
            self.btn_macro.state(["!disabled"])
        else:
            self.btn_macro.state(["disabled"])
        self.on_toggle_strict()

    def _collect_settings_from_ui(self) -> dict:
        win = self.root.winfo_geometry()  # 'WxH+X+Y'
        width, height, x, y = self._parse_geometry(win)
        return {
            "strict_mode": bool(self.var_strict.get()),
            "verbose": bool(self.verbose_var.get()),
            "dark_mode": bool(self.var_dark.get()),
            "top_n": int(self.spin_topn.get() or 10),
            "auto_stop_minutes": int(self.spin_autostop.get() or 0),
            "perf_interval": int(self.spin_interval.get() or 5),
            "preset_general": bool(self.var_general.get()),
            "preset_diskio": bool(self.var_diskio.get()),
            "preset_network": bool(self.var_network.get()),
            "custom_enabled": bool(self.var_custom_enabled.get()),
            "custom_profiles": self.ent_custom_profiles.get().strip(),
            "custom_extra_args": self.ent_custom_args.get().strip(),
            "box_url": self.ent_box_url.get().strip(),
            "auto_upload_box": bool(self.var_auto_upload.get()),
            "box_drive_path": self.ent_box_drive.get().strip(),
            "diagnostics_enabled": bool(self.var_diag_enabled.get()),
            "enable_post_save_macro": True,
            "window": {"width": width, "height": height, "x": x, "y": y}
        }

    @staticmethod
    def _parse_geometry(geom: str):
        try:
            wh, xy = geom.split("+", 1)
            w, h = wh.split("x")
            x, y = xy.split("+")
            return int(w), int(h), int(x), int(y)
        except Exception:
            return 980, 880, None, None

    def _save_settings_now(self, *_):
        try:
            data = self._collect_settings_from_ui()
            self.settings.update(data)
            save_settings(self.settings)
        except Exception:
            pass

    def on_reset_defaults(self):
        self.settings = DEFAULT_SETTINGS.copy()
        save_settings(self.settings)
        self._apply_settings_to_ui()
        self.txt_desc.delete("1.0","end")
        self.txt_desc.insert("1.0", self.ISSUE_TEMPLATE)
        self.log("Settings reset to defaults.")

    # ---------- Exit ----------
    def on_close(self):
        if self.busy_saving:
            messagebox.showwarning("Saving in progress", "Trace is finalizing. Please wait until saving completes.")
            return
        if self.recording:
            ans = messagebox.askyesnocancel("Recording In Progress", "A recording is in progress. Do you want to stop and save before exiting?")
            if ans is None: return
            if ans is True:
                self.on_stop(); return
            else:
                try: self._cancel_prior_session_quiet()
                except Exception: pass
        self.stop_diagnostics()
        self._save_settings_now()
        self.root.destroy()

# ------------------------- Entrypoint -------------------------
def main():
    if not is_user_admin():
        root_tmp = tk.Tk(); root_tmp.withdraw()
        if not messagebox.askokcancel("Administrator required","This tool needs to run as Administrator.\n\nClick OK to relaunch with elevated permissions."):
            sys.exit(1)
        root_tmp.destroy()
        relaunch_as_admin()

    root = tk.Tk()
    # DPI scaling for high-DPI displays
    try:
        if hasattr(root, 'tk'):
            root.tk.call('tk', 'scaling', 1.25)
    except Exception:
        pass

    app = WprGuiApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()