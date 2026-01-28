#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xerox Duplicates GUI
- Desktop GUI to generate enhanced Xerox duplicate print reports.
- Supports optional LRS/SecurePrint CSV to compute duplicate page waste.
- Verifies/installs Python dependencies automatically (pandas, numpy, openpyxl).

Usage: Double-click this file (Windows) or run `python XeroxDuplicatesGUI.py`.

Author: M365 Copilot for Ulysses Francisco
"""

import os
import sys
import threading
import queue
import traceback
import json
from datetime import datetime
from pathlib import Path

# -------- Dependency bootstrap -------------------------------------------------
REQUIRED_PKGS = [
    ("pandas", "pandas"),
    ("numpy", "numpy"),
    ("openpyxl", "openpyxl"),
]

def _try_imports():
    missing = []
    for mod, pkg in REQUIRED_PKGS:
        try:
            __import__(mod)
        except Exception:
            missing.append(pkg)
    return missing


def ensure_dependencies(log_fn=print):
    """Ensure pandas, numpy, openpyxl are installed. Install with pip --user if missing."""
    missing = _try_imports()
    if not missing:
        log_fn("All dependencies already present.")
        return True

    log_fn(f"Missing packages: {', '.join(missing)}. Attempting installation...")
    import subprocess

    for pkg in missing:
        try:
            log_fn(f"Installing {pkg}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])
            log_fn(f"Installed {pkg}.")
        except Exception as e:
            log_fn(f"ERROR: Failed to install {pkg}: {e}")
            return False

    # Re-check
    missing = _try_imports()
    if missing:
        log_fn(f"ERROR: Still missing packages after install: {', '.join(missing)}")
        return False

    log_fn("Dependencies installation complete.")
    return True

# Import after ensuring (lazy import within worker to avoid tkinter import order issues)

# -------- Core report logic (from earlier CLI version, adapted) ---------------

def build_report(audit_path: Path,
                 out_base: Path,
                 window_seconds: int,
                 login_lookback_hours: float,
                 lrs_csv_path: Path | None,
                 lrs_tolerance_minutes: int,
                 log_fn=print):
    """Run the full pipeline and return path to generated xlsx."""
    # Import here after deps are ensured
    import re
    import numpy as np
    import pandas as pd

    def info(msg):
        log_fn(f"[INFO] {msg}")

    def warn(msg):
        log_fn(f"[WARN] {msg}")

    def fail(msg):
        raise RuntimeError(msg)

    # Load audit
    info("Loading and parsing Xerox audit...")
    try:
        text = audit_path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        fail(f"Unable to read audit file '{audit_path}': {e}")

    lines = [ln for ln in text.splitlines() if ln.strip() and 'This Output has been Truncated' not in ln]
    if not lines:
        fail("Audit file appears empty or not in expected format (no usable lines).")

    rows = [re.split('\t+', ln.strip()) for ln in lines]
    max_len = max(len(r) for r in rows)
    for r in rows:
        if len(r) < max_len:
            r += [''] * (max_len - len(r))

    cols = [
        'RecordID','Date','Time','EventCode','EventType',
        'Field6','Field7','Field8','Field9','Field10','Field11','Field12','Field13'
    ]
    try:
        df = pd.DataFrame(rows, columns=cols)
    except Exception as e:
        fail(f"Failed to build DataFrame from audit: {e}")

    df['RecordID'] = pd.to_numeric(df['RecordID'], errors='coerce').astype('Int64')
    df['EventCode'] = pd.to_numeric(df['EventCode'], errors='coerce').astype('Int64')
    df['Timestamp'] = pd.to_datetime(df['Date'] + ' ' + df['Time'], errors='coerce')
    if df['Timestamp'].isna().all():
        warn('All timestamps are NaT; check Date/Time format in audit log.')

    def derive_fields(row):
        et = row['EventType']
        res = {'User':'','Device':'','Serial':'','ResultOrStatus':'','JobNameOrDesc':'','CopiesOrCount':'','RecipientOrDetails':'','Interface':''}
        if et == 'Print Job':
            res.update({'JobNameOrDesc': row['Field6'], 'User': row['Field7'], 'ResultOrStatus': row['Field8']})
        elif et == 'Email Job':
            res.update({'JobNameOrDesc': row['Field6'], 'User': row['Field7'], 'ResultOrStatus': row['Field8'], 'CopiesOrCount': row['Field12'], 'RecipientOrDetails': row['Field13']})
        elif et == 'Copy Job':
            res.update({'JobNameOrDesc': row['Field6'], 'User': row['Field7'], 'ResultOrStatus': row['Field8'], 'CopiesOrCount': row['Field12']})
        elif et in ('Xerox Secure Access Login','Login','Network Login','Xerox Mobile Link Login'):
            res.update({'User': row['Field6'], 'Device': row['Field7'], 'Serial': row['Field8'], 'ResultOrStatus': row['Field9']})
        elif et in ('Logout','Session Timer Logout'):
            res.update({'Device': row['Field6'], 'Serial': row['Field7'], 'Interface': row['Field8'], 'User': row['Field9'], 'ResultOrStatus': et})
        elif 'Fax' in str(et):
            res.update({'JobNameOrDesc': row['Field6'], 'User': row['Field7'], 'ResultOrStatus': row['Field8'], 'CopiesOrCount': row['Field11'], 'RecipientOrDetails': row['Field12']})
        else:
            res.update({'JobNameOrDesc': row['Field6'], 'User': row['Field7'], 'ResultOrStatus': row['Field8']})
        return pd.Series(res)

    norm = df.apply(derive_fields, axis=1)
    df2 = pd.concat([df, norm], axis=1)
    df2['User_norm'] = df2['User'].astype(str).str.strip().str.lower()

    legend = df2.groupby(['EventCode','EventType']).size().reset_index(name='Count').sort_values(['EventCode','Count'], ascending=[True, False])

    prints = df2[(df2['EventType']=='Print Job') & df2['Timestamp'].notna()].copy()
    logins = df2[(df2['EventType']=='Xerox Secure Access Login') & df2['Timestamp'].notna()].copy()

    # Device attribution (per-user asof)
    info("Attributing device via prior Secure Access Login...")
    merged = []
    for user, p in prints.groupby('User_norm'):
        l = logins[logins['User_norm'] == user].copy()
        p = p.sort_values('Timestamp')
        if l.empty:
            p = p.copy()
            p['LoginTime'] = pd.NaT
            p['LoginDevice'] = np.nan
            p['LoginSerial'] = np.nan
            p['hours_from_login'] = np.nan
            merged.append(p)
            continue
        l = l.sort_values('Timestamp')
        m = pd.merge_asof(
            p,
            l[['Timestamp','Device','Serial']].rename(columns={'Timestamp':'LoginTime','Device':'LoginDevice','Serial':'LoginSerial'}),
            left_on='Timestamp', right_on='LoginTime', direction='backward', allow_exact_matches=True
        )
        m['hours_from_login'] = (m['Timestamp'] - m['LoginTime']).dt.total_seconds()/3600.0
        m.loc[m['hours_from_login'] > float(login_lookback_hours), ['LoginTime','LoginDevice','LoginSerial','hours_from_login']] = np.nan
        merged.append(m)
    assigned = pd.concat(merged, ignore_index=True)

    # Optional LRS
    def load_lrs_csv(path: Path) -> 'pd.DataFrame':
        df = pd.read_csv(path)
        if df.empty:
            fail('LRS CSV is empty.')
        colmap = {c: c.lower() for c in df.columns}
        df = df.rename(columns=colmap)
        def pick(df, keys):
            for k in keys:
                if k in df.columns:
                    return k
            return None
        user_col = pick(df, ['userid','user','username','owner','account'])
        time_col = pick(df, ['releasetime','submittime','time','timestamp','completed'])
        pages_col = pick(df, ['pages','totalpages','pagecount'])
        copies_col = pick(df, ['copies','copycount'])
        device_col = pick(df, ['printername','queue','device','destination','printer'])
        missing = []
        if not user_col: missing.append('User (e.g., UserID/Owner)')
        if not time_col: missing.append('Time (e.g., ReleaseTime/SubmitTime)')
        if not pages_col: missing.append('Pages')
        if missing:
            fail('LRS CSV missing required columns: ' + ', '.join(missing))
        out = pd.DataFrame()
        out['LRS_User'] = df[user_col].astype(str)
        out['LRS_User_norm'] = out['LRS_User'].str.strip().str.lower()
        out['LRS_Time'] = pd.to_datetime(df[time_col], errors='coerce')
        if out['LRS_Time'].isna().all():
            fail(f"Could not parse any LRS timestamps from column '{time_col}'.")
        out['LRS_Pages'] = pd.to_numeric(df[pages_col], errors='coerce').fillna(0).astype(float)
        if copies_col and copies_col in df.columns:
            out['LRS_Copies'] = pd.to_numeric(df[copies_col], errors='coerce').fillna(1).astype(float)
        else:
            out['LRS_Copies'] = 1.0
        if device_col and device_col in df.columns:
            out['LRS_Device'] = df[device_col].astype(str)
        else:
            out['LRS_Device'] = ''
        out['LRS_TotalPages'] = (out['LRS_Pages'] * out['LRS_Copies']).round(0)
        out = out.sort_values(['LRS_User_norm','LRS_Time'])
        return out

    def attach_lrs_pages(assigned, lrs, tolerance_minutes: int):
        assigned = assigned.copy()
        assigned['LRS_Time'] = pd.NaT
        assigned['LRS_TotalPages'] = np.nan
        assigned['LRS_Device'] = ''
        assigned['LRS_DeltaSeconds'] = np.nan
        if lrs is None or lrs.empty:
            return assigned
        tol = pd.Timedelta(minutes=int(tolerance_minutes))
        result = []
        for user, p in assigned.groupby('User_norm'):
            L = lrs[lrs['LRS_User_norm']==user]
            if L.empty:
                result.append(p)
                continue
            p = p.sort_values('Timestamp')
            back = pd.merge_asof(
                p[['Timestamp']],
                L[['LRS_Time','LRS_TotalPages','LRS_Device']].rename(columns={'LRS_Time':'KeyTime'}),
                left_on='Timestamp', right_on='KeyTime', direction='backward'
            ).rename(columns={'KeyTime':'BackTime','LRS_TotalPages':'BackPages','LRS_Device':'BackDevice'})
            fwd = pd.merge_asof(
                p[['Timestamp']],
                L[['LRS_Time','LRS_TotalPages','LRS_Device']].rename(columns={'LRS_Time':'KeyTime'}),
                left_on='Timestamp', right_on='KeyTime', direction='forward'
            ).rename(columns={'KeyTime':'FwdTime','LRS_TotalPages':'FwdPages','LRS_Device':'FwdDevice'})
            m = p.reset_index(drop=True)
            m = pd.concat([m, back, fwd], axis=1)
            m['BackDelta'] = (m['Timestamp'] - m['BackTime']).abs()
            m['FwdDelta']  = (m['FwdTime'] - m['Timestamp']).abs()
            def pick(row):
                candidates = []
                if pd.notna(row['BackTime']) and row['BackDelta'] <= tol:
                    candidates.append(('back', row['BackDelta']))
                if pd.notna(row['FwdTime']) and row['FwdDelta'] <= tol:
                    candidates.append(('fwd', row['FwdDelta']))
                if not candidates:
                    return pd.Series({'LRS_Time': pd.NaT, 'LRS_TotalPages': np.nan, 'LRS_Device': '', 'LRS_DeltaSeconds': np.nan})
                winner = min(candidates, key=lambda x: x[1])
                if winner[0]=='back':
                    return pd.Series({'LRS_Time': row['BackTime'], 'LRS_TotalPages': row['BackPages'], 'LRS_Device': row['BackDevice'], 'LRS_DeltaSeconds': row['BackDelta'].total_seconds()})
                else:
                    return pd.Series({'LRS_Time': row['FwdTime'], 'LRS_TotalPages': row['FwdPages'], 'LRS_Device': row['FwdDevice'], 'LRS_DeltaSeconds': row['FwdDelta'].total_seconds()})
            pick_df = m.apply(pick, axis=1)
            m = pd.concat([m, pick_df], axis=1)
            m = m.drop(columns=['BackTime','BackPages','BackDevice','FwdTime','FwdPages','FwdDevice','BackDelta','FwdDelta'])
            result.append(m)
        out = pd.concat(result, ignore_index=True)
        return out

    lrs_df = None
    if lrs_csv_path:
        info("Loading LRS/SecurePrint CSV...")
        lrs_df = load_lrs_csv(lrs_csv_path)
        info("Matching LRS pages to print events...")
        assigned = attach_lrs_pages(assigned, lrs_df, int(lrs_tolerance_minutes))
    else:
        assigned = attach_lrs_pages(assigned, None, int(lrs_tolerance_minutes))

    info("Computing duplicates and building summaries...")
    a = assigned.sort_values(['User_norm','Timestamp']).copy()
    a['prev_time']      = a.groupby('User_norm')['Timestamp'].shift(1)
    a['sec_since_prev'] = (a['Timestamp'] - a['prev_time']).dt.total_seconds()
    a['is_dup_window']  = a['sec_since_prev'].le(int(window_seconds))

    new_burst = (a['sec_since_prev'].isna()) | (a['sec_since_prev'] > int(window_seconds))
    a['burst_seq'] = new_burst.groupby(a['User_norm']).cumsum()
    a['burst_id']  = a['User_norm'].astype(str) + '|' + a['burst_seq'].astype(int).astype(str)

    a['Pages'] = a['LRS_TotalPages'].fillna(0).astype(float)

    def _dup_jobs(s):
        return max(0, int(len(s))-1)

    burst_agg = a.groupby('burst_id').agg(
        User=('User','first'),
        User_norm=('User_norm','first'),
        BurstStart=('Timestamp','min'),
        BurstEnd=('Timestamp','max'),
        Jobs=('RecordID','count'),
        Duplicates=('RecordID', _dup_jobs),
        MinGapSec=('sec_since_prev', lambda s: np.nanmin(s.values[1:]) if len(s)>1 else np.nan),
        MaxGapSec=('sec_since_prev', lambda s: np.nanmax(s.values[1:]) if len(s)>1 else np.nan),
        AnyStatus=('ResultOrStatus', lambda s: ','.join(sorted(pd.Series(s).dropna().unique())[:5])),
        AnyDevice=('LoginDevice', lambda s: ','.join(sorted(pd.Series(s).dropna().unique())[:3])),
        AnySerial=('LoginSerial', lambda s: ','.join(sorted(pd.Series(s).dropna().unique())[:3])),
        PagesTotal=('Pages','sum')
    ).reset_index(drop=False)

    first_pages = a.sort_values(['burst_id','Timestamp']).groupby('burst_id')['Pages'].first().rename('FirstPages')
    burst_agg = burst_agg.merge(first_pages, left_on='burst_id', right_index=True, how='left')
    burst_agg['DuplicatePages'] = (burst_agg['PagesTotal'] - burst_agg['FirstPages']).clip(lower=0)
    burst_dups = burst_agg[burst_agg['Duplicates']>=1].sort_values(['DuplicatePages','Duplicates','BurstStart'], ascending=[False,False,True])

    user_summary = a.groupby('User_norm').agg(
        User=('User','last'),
        Prints=('RecordID','count'),
        DuplicateBursts=('burst_id', lambda s: s.nunique()),
        DuplicateJobs=('is_dup_window','sum'),
        PagesTotal=('Pages','sum')
    ).reset_index(drop=False)

    up = burst_agg.groupby('User_norm')['DuplicatePages'].sum().rename('DuplicatePages')
    user_summary = user_summary.merge(up, on='User_norm', how='left')
    user_summary['DuplicatePages'] = user_summary['DuplicatePages'].fillna(0)
    user_summary['DuplicateRate'] = (user_summary['DuplicateJobs'] / user_summary['Prints']).round(3)

    daily = a.copy(); daily['DateOnly'] = daily['Timestamp'].dt.date
    trend = daily.groupby('DateOnly').agg(Prints=('RecordID','count'), DuplicateJobs=('is_dup_window','sum'), PagesTotal=('Pages','sum')).reset_index()

    device_summary = a.groupby(['LoginDevice','LoginSerial']).agg(Prints=('RecordID','count'), DuplicateJobs=('is_dup_window','sum'), PagesTotal=('Pages','sum')).reset_index().sort_values('DuplicateJobs', ascending=False)

    unmapped = a[(a['is_dup_window']==True) & (a['LoginDevice'].isna())][['Timestamp','User','JobNameOrDesc','ResultOrStatus','sec_since_prev','Pages']].copy()

    dups_detail = a[a['is_dup_window'] == True][['Timestamp','User','JobNameOrDesc','ResultOrStatus','sec_since_prev','LoginTime','LoginDevice','LoginSerial','hours_from_login','LRS_Time','LRS_TotalPages','LRS_Device','LRS_DeltaSeconds']].sort_values(['User','Timestamp'])

    # Write outputs
    import pandas as pd
    from pandas import ExcelWriter
    out_base = Path(out_base)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    xlsx_path = out_base.parent / f"xerox_duplicates_enhanced_{ts}.xlsx"

    info("Writing Excel workbook and CSV companions...")
    with pd.ExcelWriter(xlsx_path, engine='openpyxl', datetime_format='yyyy-mm-dd hh:mm:ss') as xw:
        readme = pd.DataFrame({'What':[f'This workbook summarizes potential duplicate print jobs identified from the Xerox audit log.', f'Duplicate definition: same user prints again within {int(window_seconds)} seconds.', f'Device attribution: nearest prior Xerox Secure Access Login by the same user within {float(login_lookback_hours)} hours.', f'Page attribution: LRS/SecurePrint match within ±{int(lrs_tolerance_minutes)} minutes of the print timestamp.', 'Limitations: page counts come from LRS/SecurePrint; unmatched jobs will show 0 pages.']})
        readme.to_excel(xw, index=False, sheet_name='README')
        user_summary.to_excel(xw, index=False, sheet_name='User Summary')
        burst_dups.to_excel(xw, index=False, sheet_name='Duplicate Bursts')
        dups_detail.to_excel(xw, index=False, sheet_name='Raw Duplicate Events')
        unmapped.to_excel(xw, index=False, sheet_name='Unmapped (No Prior Login)')
        trend.to_excel(xw, index=False, sheet_name='Daily Trend')
        device_summary.to_excel(xw, index=False, sheet_name='By Device (from Logins)')
        legend.to_excel(xw, index=False, sheet_name='EventCode Legend')

    # CSVs
    (out_base.parent / f"xerox_duplicate_bursts_{ts}.csv").write_text(burst_dups.to_csv(index=False), encoding='utf-8')
    (out_base.parent / f"xerox_duplicate_user_summary_{ts}.csv").write_text(user_summary.to_csv(index=False), encoding='utf-8')
    (out_base.parent / f"xerox_duplicate_events_{ts}.csv").write_text(dups_detail.to_csv(index=False), encoding='utf-8')

    info(f"Done. Enhanced workbook: {xlsx_path}")
    return xlsx_path

# -------- Simple settings persistence ----------------------------------------

def settings_path() -> Path:
    base = Path(os.environ.get('APPDATA') or Path.home()/'.config')/ 'XeroxDuplicatesGUI'
    base.mkdir(parents=True, exist_ok=True)
    return base/ 'settings.json'


def load_settings():
    sp = settings_path()
    if sp.exists():
        try:
            return json.loads(sp.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}


def save_settings(obj: dict):
    sp = settings_path()
    try:
        sp.write_text(json.dumps(obj, indent=2), encoding='utf-8')
    except Exception:
        pass

# -------- GUI (tkinter) -------------------------------------------------------

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Xerox Duplicates Report – GUI")
        self.geometry('860x620')
        self.minsize(860, 620)
        try:
            self.iconbitmap(default='')
        except Exception:
            pass

        self.queue = queue.Queue()
        self._worker = None
        self._build_ui()
        self._load_defaults()
        self.after(200, self._poll_queue)

    def _build_ui(self):
        pad = {'padx': 8, 'pady': 6}
        frm = ttk.Frame(self)
        frm.pack(fill='both', expand=True)

        row=0
        # Audit path
        ttk.Label(frm, text='Audit TXT file (Xerox auditfile.txt):').grid(row=row, column=0, sticky='w', **pad)
        self.audit_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.audit_var, width=80).grid(row=row, column=1, sticky='we', **pad)
        ttk.Button(frm, text='Browse…', command=self._pick_audit).grid(row=row, column=2, **pad)
        row+=1
        # LRS CSV
        ttk.Label(frm, text='LRS/SecurePrint CSV (optional):').grid(row=row, column=0, sticky='w', **pad)
        self.lrs_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.lrs_var, width=80).grid(row=row, column=1, sticky='we', **pad)
        ttk.Button(frm, text='Browse…', command=self._pick_lrs).grid(row=row, column=2, **pad)
        row+=1
        # Output dir
        ttk.Label(frm, text='Output folder:').grid(row=row, column=0, sticky='w', **pad)
        self.outdir_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.outdir_var, width=80).grid(row=row, column=1, sticky='we', **pad)
        ttk.Button(frm, text='Browse…', command=self._pick_outdir).grid(row=row, column=2, **pad)
        row+=1

        # Params frame
        pfrm = ttk.LabelFrame(frm, text='Options')
        pfrm.grid(row=row, column=0, columnspan=3, sticky='we', **pad)
        ppad={'padx':10,'pady':6}
        ttk.Label(pfrm, text='Duplicate window (seconds):').grid(row=0, column=0, sticky='w', **ppad)
        self.win_var=tk.IntVar(value=60)
        ttk.Entry(pfrm, textvariable=self.win_var, width=8).grid(row=0, column=1, sticky='w', **ppad)

        ttk.Label(pfrm, text='Login look-back (hours):').grid(row=0, column=2, sticky='w', **ppad)
        self.look_var=tk.DoubleVar(value=8.0)
        ttk.Entry(pfrm, textvariable=self.look_var, width=8).grid(row=0, column=3, sticky='w', **ppad)

        ttk.Label(pfrm, text='LRS tolerance (± minutes):').grid(row=0, column=4, sticky='w', **ppad)
        self.tol_var=tk.IntVar(value=5)
        ttk.Entry(pfrm, textvariable=self.tol_var, width=8).grid(row=0, column=5, sticky='w', **ppad)

        # Buttons
        row+=1
        btnfrm = ttk.Frame(frm)
        btnfrm.grid(row=row, column=0, columnspan=3, sticky='we')
        ttk.Button(btnfrm, text='Verify/Install Dependencies', command=self._check_deps).pack(side='left', padx=8, pady=6)
        ttk.Button(btnfrm, text='Run Report', command=self._run).pack(side='left', padx=8, pady=6)
        ttk.Button(btnfrm, text='Open Output Folder', command=self._open_outdir).pack(side='left', padx=8, pady=6)

        # Progress + log
        row+=1
        self.prog = ttk.Progressbar(frm, mode='indeterminate')
        self.prog.grid(row=row, column=0, columnspan=3, sticky='we', padx=8)
        row+=1
        self.log = tk.Text(frm, height=18, wrap='word')
        self.log.grid(row=row, column=0, columnspan=3, sticky='nsew', padx=8, pady=6)
        frm.rowconfigure(row, weight=1)
        frm.columnconfigure(1, weight=1)

    def _pick_audit(self):
        p = filedialog.askopenfilename(title='Select auditfile.txt', filetypes=[('Text files','*.txt'), ('All files','*.*')])
        if p:
            self.audit_var.set(p)
            # Default output to same folder
            if not self.outdir_var.get():
                self.outdir_var.set(str(Path(p).parent))

    def _pick_lrs(self):
        p = filedialog.askopenfilename(title='Select LRS/SecurePrint CSV', filetypes=[('CSV files','*.csv'), ('All files','*.*')])
        if p:
            self.lrs_var.set(p)

    def _pick_outdir(self):
        p = filedialog.askdirectory(title='Select output folder')
        if p:
            self.outdir_var.set(p)

    def _open_outdir(self):
        outdir = self.outdir_var.get().strip()
        if not outdir:
            messagebox.showinfo('Open Output Folder', 'Please select an output folder first.')
            return
        try:
            os.startfile(outdir)  # Windows
        except Exception:
            try:
                import subprocess
                subprocess.Popen(['xdg-open', outdir])
            except Exception:
                messagebox.showwarning('Open Output Folder', f'Please open folder manually: {outdir}')

    def _append_log(self, msg: str):
        self.log.insert('end', msg + "\n")
        self.log.see('end')

    def _check_deps(self):
        self._append_log('Checking Python dependencies...')
        ok = ensure_dependencies(log_fn=lambda m: self.queue.put(('log', m)))
        if ok:
            messagebox.showinfo('Dependencies', 'All dependencies are installed.')
        else:
            messagebox.showerror('Dependencies', 'Some dependencies failed to install. See log for details.')

    def _validate_inputs(self):
        audit = self.audit_var.get().strip()
        if not audit:
            raise ValueError('Please select an audit TXT file.')
        if not Path(audit).exists():
            raise ValueError(f'Audit file not found: {audit}')
        outdir = self.outdir_var.get().strip() or str(Path(audit).parent)
        Path(outdir).mkdir(parents=True, exist_ok=True)
        # optional LRS
        lrs = self.lrs_var.get().strip()
        if lrs and not Path(lrs).exists():
            raise ValueError(f'LRS CSV not found: {lrs}')
        # params
        w = int(self.win_var.get())
        lb = float(self.look_var.get())
        tol = int(self.tol_var.get())
        if w <= 0: raise ValueError('Duplicate window must be > 0')
        if lb <= 0: raise ValueError('Look-back hours must be > 0')
        if tol < 0: raise ValueError('Tolerance minutes must be >= 0')
        return Path(audit), Path(outdir), (Path(lrs) if lrs else None), w, lb, tol

    def _run(self):
        if self._worker and self._worker.is_alive():
            messagebox.showinfo('In progress', 'A report is already running. Please wait...')
            return
        try:
            audit, outdir, lrs, w, lb, tol = self._validate_inputs()
        except Exception as e:
            messagebox.showerror('Validation error', str(e))
            return

        # Save settings
        save_settings({
            'audit': str(audit),
            'lrs': str(lrs) if lrs else '',
            'outdir': str(outdir),
            'window_seconds': int(w),
            'lookback_hours': float(lb),
            'lrs_tolerance': int(tol)
        })

        # Ensure deps before starting
        self._append_log('Ensuring dependencies...')
        if not ensure_dependencies(log_fn=lambda m: self.queue.put(('log', m))):
            messagebox.showerror('Dependencies', 'Failed to verify/install dependencies. See log for details.')
            return

        self._append_log('Starting report generation...')
        self._set_busy(True)
        def worker():
            try:
                xlsx = build_report(
                    audit_path=audit,
                    out_base=outdir/ 'report',
                    window_seconds=w,
                    login_lookback_hours=lb,
                    lrs_csv_path=lrs,
                    lrs_tolerance_minutes=tol,
                    log_fn=lambda m: self.queue.put(('log', m))
                )
                self.queue.put(('done', str(xlsx)))
            except Exception:
                self.queue.put(('err', traceback.format_exc()))
        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _set_busy(self, busy: bool):
        for child in self.winfo_children():
            try:
                child.configure(state=('disabled' if busy else 'normal'))
            except Exception:
                pass
        if busy:
            self.prog.start(10)
        else:
            self.prog.stop()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == 'log':
                    self._append_log(payload)
                elif kind == 'done':
                    self._set_busy(False)
                    self._append_log(f"SUCCESS: {payload}")
                    messagebox.showinfo('Done', f'Report generated:\n{payload}')
                elif kind == 'err':
                    self._set_busy(False)
                    self._append_log(payload)
                    messagebox.showerror('Error', 'An unexpected error occurred. See log for details.')
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _load_defaults(self):
        s = load_settings()
        if s:
            self.audit_var.set(s.get('audit',''))
            self.lrs_var.set(s.get('lrs',''))
            self.outdir_var.set(s.get('outdir',''))
            try:
                self.win_var.set(int(s.get('window_seconds',60)))
                self.look_var.set(float(s.get('lookback_hours',8.0)))
                self.tol_var.set(int(s.get('lrs_tolerance',5)))
            except Exception:
                pass


if __name__ == '__main__':
    app = App()
    app.mainloop()
