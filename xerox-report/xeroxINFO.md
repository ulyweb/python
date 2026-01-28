I built you a Windows‑friendly GUI app (Tkinter) that:

*   ✅ Lets users **browse** for the Xerox audit TXT and optional **LRS CSV**
*   ✅ Pick the **output folder**
*   ✅ Set **duplicate window (sec)**, **login look‑back (hours)**, and **LRS tolerance (± minutes)**
*   ✅ **Verifies and auto‑installs Python dependencies** (`pandas`, `numpy`, `openpyxl`) if missing (using `pip --user`)
*   ✅ Runs in a worker thread so the UI stays responsive; shows a **progress spinner** and a **live log**
*   ✅ **Saves last-used settings** (in `%APPDATA%\XeroxDuplicatesGUI\settings.json`) so your team doesn’t re‑enter values each time
*   ✅ Outputs the **same enhanced workbook** you approved (with **Duplicate Pages** if LRS is provided)

***

## 📦 Download the GUI

*   **`XeroxDuplicatesGUI.py` (console window)** → [Download](blob:https://m365.cloud.microsoft/1617e01c-57c0-4c87-a7ed-2e093a296b74)
*   **`XeroxDuplicatesGUI.pyw` (no console window)** → [Download](blob:https://m365.cloud.microsoft/4e5d3cf6-bd78-4472-8137-254b642c4d94)

> Both files are identical in functionality. `.pyw` hides the console window (nice for end users). Keep it in the same folder as your `auditfile.txt` or browse to wherever your files live.

***

## 🧭 How to run (no CLI needed)

1.  Double‑click **`XeroxDuplicatesGUI.pyw`**
2.  In the window:
    *   **Audit TXT** → click **Browse…** and pick your `auditfile.txt`
    *   **LRS CSV (optional)** → click **Browse…** and pick the export from LRS/SecurePrint
    *   **Output folder** → choose where to save the workbook/CSVs
    *   Leave defaults (**60s**, **8h**, **±5m**) or adjust
    *   Click **Verify/Install Dependencies** (first‑time only)
    *   Click **Run Report**
3.  When it completes, the app shows the full path to the **timestamped Excel workbook** and companion CSVs.

***

## 🛠️ What’s inside the GUI

The GUI embeds the fully‑featured report logic you already tested:

*   **Device attribution**: Each print is mapped to the **nearest earlier** Xerox Secure Access Login by the **same user** within your selected look‑back (default **8h**). If absent, device fields are intentionally left blank (prevents bad assumptions—this is the `DPhan` case you saw).
*   **Duplicate detection**: Same‑user prints within your **window** (default **60s**) are flagged; events are grouped into **bursts**.
*   **Page waste (LRS)**: If you supply an LRS CSV, the app matches device prints to the nearest LRS record for the same user within a **± tolerance** (default **±5 min**). It uses **Pages × Copies** for per‑job pages and computes **DuplicatePages** (sum of pages excluding the first job in each burst).
*   **Tabs in the workbook**: `README`, `User Summary` (**DuplicatePages included**), `Duplicate Bursts` (**DuplicatePages**), `Raw Duplicate Events` (with LRS columns), `Unmapped (No Prior Login)`, `Daily Trend`, `By Device (from Logins)`, `EventCode Legend`.

***

## 🧩 Dependency management (automatic)

The GUI **verifies** and, if needed, **installs**:

*   `pandas`, `numpy`, `openpyxl` (via `pip --user`)

If any installation fails, the **Log** panel shows the exact error (e.g., if the device lacks internet or the corporate proxy blocks PyPI). In that case, you can pre‑install once on the machine:

```powershell
python -m pip install --user pandas numpy openpyxl
```

*(The GUI calls the same under the hood.)*

***

## 🔐 Execution policy / signing (FYI)

The GUI files are plain Python—not PowerShell—so **no PowerShell execution policy** applies. Users just double‑click the `.pyw`. If you later distribute as a compiled `.exe`, we can sign it and ship as a single binary (see **Packaging** below). If your org prefers shortcuts, you can **right‑click → Send to → Desktop** to create a shortcut to `XeroxDuplicatesGUI.pyw`.

***

## 🧪 Sanity run (your current files)

If you want to try immediately with the same dataset:

*   **Audit**: you already have `auditfile.txt` (sample in your working directory) → [reference](blob:https://m365.cloud.microsoft/1fb7a71b-d53d-49cc-9709-c7bffb77b46f)
*   **LRS**: if you don’t have `lrs_export.csv` ready, run without it—the workbook still generates with **duplicate jobs**. Later, re‑run with LRS to add **duplicate pages**.

***

## 🧰 Power features you’ll appreciate

*   **Threaded execution**: UI stays responsive; includes progress spinner and streaming log.
*   **Auto‑persisted settings**: The last audit/LRS paths and parameter values load on startup.
*   **Error dialogs with full trace in log**: If anything blows up, the stack trace lands in the Log for quick triage.
*   **Open Output Folder** button: Pops open the chosen folder after a run.

***

## 🧱 Known constraints (and how to handle them)

*   **Corporate proxy / offline machines**: Auto‑install of Python packages may fail. Pre‑install with your internal mirror or deploy a small **venv** that already includes the packages.
*   **LRS header names**: The code auto‑detects common column names. If your export uses different headers, I can add a field‑mapping panel (or a `Settings…` dialog) so users can map columns once and save them.

***

## 📁 Files I created for you just now

*   **GUI app (with auto‑install logic built in)**
    *   `XeroxDuplicatesGUI.py` → [download here](blob:https://m365.cloud.microsoft/1617e01c-57c0-4c87-a7ed-2e093a296b74)
    *   `XeroxDuplicatesGUI.pyw` → [download here](blob:https://m365.cloud.microsoft/4e5d3cf6-bd78-4472-8137-254b642c4d94)

*(They are the same; `.pyw` just hides the console window.)*

***

## 🚀 Optional: Package as a single EXE for end users

When you’re ready, we can package this as a signed `.exe` so your users don’t need Python at all:

```powershell
# (run in a dev box with Python + pyinstaller installed)
python -m pip install pyinstaller
pyinstaller --noconsole --onefile --name XeroxDuplicatesGUI XeroxDuplicatesGUI.py
```

This will produce `XeroxDuplicatesGUI.exe` in the `dist` folder. We can then code‑sign it and deploy via your software distribution tool.

***


If you give the green light, I’ll add a **Settings…** button and a **Preview** tab next.
