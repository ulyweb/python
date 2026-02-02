> [!TIP]
> # **Copy‑Ready Prompt Package**
>> The original WPR requirements to the current, professional Python GUI with persistence, dark mode, custom profiles, ZIP, tooltips, and summary copy—plus **dependencies**, **build instructions** (with **.ico** and **version metadata** for the EXE), and a **validation checklist**.

***

# 1) Reusable Prompt (copy/paste into a new conversation)

> **Title:** Continue development on **WPR Assist – Performance Trace Collector** (Python/Tk GUI)

**Context (what exists now)**  
We have a working Windows‑only Python GUI application called **“WPR Assist – Performance Trace Collector”** that:

*   **Runs as Administrator** (auto‑elevates) and targets **Windows 10/11**.
*   Starts **Windows Performance Recorder (WPR)** with these **required profiles** (and shows live output):
        wpr -start GeneralProfile -start CPU -start Heap -start Pool -start FileIO -start VirtualAllocation
*   **Strict Mode** (default **ON**) enforces only the required profiles above.  
    When Strict Mode is **OFF**, optional profiles can be added:
    *   **Disk I/O** → `-start DiskIO`
    *   **Network** → tries `-start Network`, then fallback `-start Networking`
    *   **Custom profiles and extra args**: comma‑separated `-start <name>` entries and raw extra args appended as-is.
*   Supports **Auto‑stop after N minutes**, and **perf logging** to CSV (`CPU%`, `AvailableMemory_MB`) at an adjustable interval.
*   Takes a **Top‑N processes snapshot** at stop time (Top CPU%, Top Memory RSS, Top Disk I/O bytes/sec) and writes to `*_stop-snapshot.txt`.
*   Offers **Verbose logging** (shows exact WPR commands) and quietly suppresses benign `wpr -cancel` noise (`There are no trace profiles running` / `0xC5583000`) when not verbose.
*   Provides **Create ZIP** (ETL + CSV + issue description + snapshot) and **Box folder URL** with **Open Box** button.
*   Adds **Copy Summary** button (manager‑readable, includes profiles, settings, file sizes/paths, and Box URL).
*   Adds **tooltips** for each field/control (hover help).
*   Professional **Tkinter GUI** with banner + live clock, **Light/Dark mode**, and **saved settings** (incl. **window size/position** and **Box URL**) in:
        %APPDATA%\WprTraceGUI\settings.json
*   Output folder: `C:\Temp\`  
    Output files are timestamped + hostname:
        yyyyMMdd-HHmmss-HOSTNAME_output-result.etl
        yyyyMMdd-HHmmss-HOSTNAME_perf-log.csv
        yyyyMMdd-HHmmss-HOSTNAME_issue-description.txt
        yyyyMMdd-HHmmss-HOSTNAME_stop-snapshot.txt
        yyyyMMdd-HHmmss-HOSTNAME_bundle.zip  (on demand)
*   Issue description **prefills a guided template** (Zoom + Microsoft Office repro steps & notes).
*   The final app window title is: **WPR Assist – Performance Trace Collector**.

**Environment / Build details**

*   Python: **3.11+** (64‑bit recommended)
*   Packages:
    *   `psutil`
    *   Tkinter is included with standard Python for Windows (enable **tcl/tk** in installer if missing).
*   EXE packaging (PyInstaller):
    *   Add an application icon: `--icon wpr-assist.ico`
    *   Embed Windows version info: `--version-file version_info.txt`

**Known limitations / expectations**

*   Requires **Admin** privileges (WPR needs elevation).
*   **WPR** must exist: typically `C:\Windows\System32\wpr.exe`, or install **Windows Performance Toolkit (WPT)** from **Windows ADK** if missing.
*   Optional profiles may not exist on all endpoints (we log a warning and continue).
*   Perf counters can be broken on some systems; we log a warning and continue. (Admins can repair counters via `lodctr /r` if needed.)

***

**Your task now**

1.  Read and respect all the above.
2.  Implement the following changes **without breaking existing features**:

**NEW CHANGES / FEATURE REQUESTS**

*   \[Describe the specific enhancement(s) here, e.g., “Add auto‑upload to Box after ZIP” or “Collect GPU counters while recording” or “Add diagnostics tab with top processes live view”.]

**UI/UX ACCEPTANCE CRITERIA**

*   Keep the modern, professional style, fonts, banner, and live clock.
*   Retain tooltips and add new ones for any new controls.
*   Persist any new settings in the same `%APPDATA%\WprTraceGUI\settings.json`.
*   Dark/Light mode should apply to new UI.

**FUNCTIONAL ACCEPTANCE CRITERIA**

*   Maintain **Strict Mode** semantics and default ON.
*   Ensure live WPR output still shows in Status.
*   Confirm auto‑elevation to Admin still works.
*   Don’t regress file naming and output location.
*   Keep `-cancel` suppression logic (unless verbose).
*   Keep `Create ZIP`, `Copy Summary`, and Box URL integration.

**DELIVERABLES**

*   A **single updated Python file** ready to run.
*   Any additional resource files (e.g., new icons, templates) with clear placement instructions.
*   Updated **PyInstaller** command (if packaging changes are required).
*   A short “What changed & how to use” note with testing steps.

**TEST SCENARIOS**

*   Strict Mode **ON**: start → reproduce → stop & save → ZIP → Copy Summary → Open Box.
*   Strict Mode **OFF**: enable Disk I/O + Network + one custom profile → start → stop.
*   Verbose logging ON: confirm full WPR commands show (`>>>`).
*   Dark/Light mode toggles; confirm persisted on relaunch.
*   Resize/move window; confirm geometry persisted on relaunch.
*   Auto‑stop timer triggers as expected.
*   Large ETL behavior: ZIP creation and Summary still work.
*   Failure paths: missing WPR, stop when no profiles running, inaccessible perf counters.

***

# 2) Comprehensive breakdown (from first ask to current solution)

### A. Original goal

*   Provide a **turnkey** way for IT to **record performance traces** using **Windows Performance Recorder (WPR)** when customers report slowness.
*   Start WPR with **exact profiles**:  
    `GeneralProfile, CPU, Heap, Pool, FileIO, VirtualAllocation`
*   Ensure elevated session, save ETL to `C:\Temp` with **timestamp+hostname** naming, and support easy sharing via **Box**.

### B. Evolution path

1.  **PowerShell CLI** script
    *   Self‑elevated to Admin, prompted for description, started WPR, waited for reproduce, stopped and saved ETL.
2.  **PowerShell GUI** (WinForms)
    *   Added GUI, auto‑stop, CPU/Mem CSV logging, error handling around WPR.
    *   Encountered **PS7 event handler/STA** pitfalls (BackgroundWorker handlers, `Tag`, and `&` call operator issues).
3.  **Pivot to Python (Tkinter)**
    *   Implemented a **stable Windows GUI** with:
        *   Admin auto‑elevation
        *   Live stdout/stderr capture from `wpr.exe`
        *   Modal “Saving…” dialog
        *   Auto‑stop, CPU/Mem CSV logging
        *   Benign `-cancel` output suppression
        *   Reliable finalize/unfreeze states even on edge cases
4.  **UX Improvements**
    *   **Issue description template** (Zoom + Office repro steps)
    *   **Profile presets** (General/Disk I/O/Network) + **Strict Mode** (default ON)
    *   **Top‑N snapshot** at stop (CPU, Memory RSS, Disk I/O bytes/sec)
    *   **Verbose logging** (shows exact WPR commands)
    *   **Create ZIP** bundle
    *   **Box URL** with **Open Box**
    *   **Copy Summary** (ticket‑friendly clipboard text)
    *   **Tooltips** on every control
    *   **Dark Mode** and **window geometry persistence**
    *   **Settings persistence** for all options in `%APPDATA%\WprTraceGUI\settings.json`
    *   App name updated to **“WPR Assist – Performance Trace Collector”**
    *   Packaging path: **PyInstaller** with icon and version metadata

### C. Current feature set (snapshot)

*   **Admin** auto‑elevation + **Windows-only** (WPR)
*   **Strict Mode ON** by default → runs exactly:
        wpr -start GeneralProfile -start CPU -start Heap -start Pool -start FileIO -start VirtualAllocation
*   Optional **Disk I/O**, **Network**, **Custom profiles** & **extra args** when Strict OFF
*   **Auto‑stop** timer and **perf logging CSV**
*   **Top‑N snapshot** at stop (CPU/Mem/Disk I/O)
*   **Create ZIP**, **Box URL** + **Open Box**
*   **Copy Summary** → clipboard
*   **Tooltips** everywhere
*   **Verbose logging** (shows `>>>` exact command lines)
*   **Dark/Light mode** toggle
*   **Settings persistence** (including **window size/position**)
*   **Professional GUI** with banner + live clock
*   **Safe finalization** (modal “Saving…”, always re‑enable UI)

***

# 3) Dependencies, OS support, and requirements

*   **OS**: Windows 10/11 (x64 recommended)
*   **Python**: 3.11+ (64‑bit)
*   **Third‑party packages**:
    *   `psutil`
*   **Standard library modules used** (no extra installs):  
    `tkinter`, `tkinter.font`, `subprocess`, `threading`, `queue`, `ctypes`, `zipfile`, `webbrowser`, `datetime`, `os`, `sys`, `json`, `pathlib`.
*   **External requirement**: `wpr.exe` must be present (part of Windows / WPT). If missing, install **Windows Performance Toolkit** via **Windows ADK**.

***

# 4) Folder layout and persistence

*   **Outputs**: `C:\Temp\`
    *   `*_output-result.etl`
    *   `*_perf-log.csv`
    *   `*_issue-description.txt`
    *   `*_stop-snapshot.txt`
    *   `*_bundle.zip` (on Create ZIP)
*   **Settings (persisted)**:  
    `%APPDATA%\WprTraceGUI\settings.json`
    *   `strict_mode`, `verbose`, `dark_mode`, `top_n`, `auto_stop_minutes`, `perf_interval`, presets, custom profiles, `box_url`, and **window geometry**.

***

# 5) How to run (developer machine)

```powershell
# 1) Install Python 3.11+ (64-bit), ensure "tcl/tk" is checked in installer
# 2) Install dependencies:
py -m pip install --upgrade pip
py -m pip install psutil

# 3) Run:
py wpr_performance_trace_gui.py
```

> The app **auto‑elevates**. If not elevated, it prompts and relaunches itself with Admin.

***

# 6) Build a standalone EXE (icon + version metadata)

1.  Place your **icon** (multi‑size ICO; include 16/24/32/48/256 px) next to the script, e.g.:  
    `wpr-assist.ico`

2.  Create a `version_info.txt` file (PyInstaller **VERSIONINFO** format), e.g.:

```python
# version_info.txt (UTF-8)
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 4, 0, 0),
    prodvers=(1, 4, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904b0', [
        StringStruct('CompanyName', 'Your Company, Inc.'),
        StringStruct('FileDescription', 'WPR Assist - Performance Trace Collector'),
        StringStruct('FileVersion', '1.4.0.0'),
        StringStruct('InternalName', 'WPR Assist'),
        StringStruct('LegalCopyright', '© 2026 Your Company'),
        StringStruct('OriginalFilename', 'WPR Assist - Performance Trace Collector.exe'),
        StringStruct('ProductName', 'WPR Assist'),
        StringStruct('ProductVersion', '1.4.0.0'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
```

3.  Build with **PyInstaller**:

```powershell
py -m pip install --upgrade pip psutil pyinstaller

pyinstaller ^
  --noconsole ^
  --onefile ^
  --name "WPR Assist - Performance Trace Collector" ^
  --icon "wpr-assist.ico" ^
  --version-file "version_info.txt" ^
  wpr_performance_trace_gui.py
```

*   Output EXE: `.\dist\WPR Assist - Performance Trace Collector.exe`

***

# 7) Validation checklist (quick QA before release)

*   [ ] **Admin elevation** works; WPR found; missing WPR shows a clear error.
*   [ ] **Strict Mode ON** by default; only required six profiles started.
*   [ ] **Verbose** ON shows `>>>` command line with exact `-start` switches.
*   [ ] **Disk I/O** and **Network** profiles only start when Strict OFF and box checked; network alias fallback works.
*   [ ] **Custom profiles** and **extra args** only apply when Strict OFF and custom enabled.
*   [ ] **Auto‑stop** fires correctly at N minutes.
*   [ ] **Perf CSV** logs at chosen interval; no crashes if perf counters unavailable.
*   [ ] **Stop & Save** finalizes ETL, shows “Saving…” modal, unfreezes UI, re‑enables buttons.
*   [ ] **Top‑N snapshot** file generated.
*   [ ] **Create ZIP** produces expected bundle.
*   [ ] **Box URL** persists and opens.
*   [ ] **Copy Summary** creates a readable, accurate summary.
*   [ ] **Dark/Light mode** switch works and persists.
*   [ ] **Window size/position** persist on relaunch.
*   [ ] **Tooltips** appear for major controls.

***

# 8) Troubleshooting

*   **Benign error after `-cancel`**:  
    “There are no trace profiles running” / `0xC5583000` — this is expected if nothing was running; we suppress unless **Verbose** is enabled.
*   **No WPR**: Install **Windows Performance Toolkit** (WPT) from **Windows ADK**.
*   **Perf counters errors**: Some endpoints need perf counter rebuild (`lodctr /r` as Admin). The app continues logging what it can and notes the error in Status.
*   **Large ETL**: Expected; recommend zipping via **Create ZIP** before upload.

***

# 9) Nice‑to‑have backlog ideas (future work)

*   One‑click **“ZIP → Open Box → copy summary”** post‑save macro.
*   **GPU utilization** capture and snapshot (if available via `psutil`/WMI/PerfMon).
*   **Network/IO live charts** during recording (optional).
*   **Multi‑profile presets** (e.g., “General+Disk”, “General+Network”).
*   **Signature detection**: auto‑flag unusual CPU spikes or disk bursts in the log.
*   **Per‑process ETW** for specific apps (if you standardize a profile pack).

***

> [!TIP]
> ### Paste the **Reusable Prompt** (Section 1) into your next conversation and drop in your new change requests under **NEW CHANGES / FEATURE REQUESTS**, you’ll get targeted improvements while preserving all of the careful work we’ve done.
