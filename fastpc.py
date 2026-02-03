#!/usr/bin/env python3
# FastPC Pro - Windows
# Profiles: safe/turbo/quick/deep/network/ui/all/custom
# GUI selection when double-clicked (no console) + scrollable UI
# Footer name: ABDUR RAHMAN

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

APP_DIR = Path.home() / ".fastpc"
LOG_FILE = APP_DIR / "fastpc.log"


# =========================
# Helpers (ONLY ONCE)
# =========================
def is_windows() -> bool:
    return os.name == "nt"


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def has_console() -> bool:
    """True when running in a real terminal (stdin exists)."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def gui_available() -> bool:
    try:
        import tkinter  # noqa
        return True
    except Exception:
        return False


def log(msg: str, enable_log: bool = True) -> None:
    line = f"[{now()}] {msg}"
    print(line)
    if enable_log:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def run_powershell(ps_script: str) -> tuple[int, str, str]:
    """Run a PowerShell command. Returns (returncode, stdout, stderr)."""
    ps_exe = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps_exe:
        return 127, "", "PowerShell not found."
    cmd = [ps_exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def is_admin() -> bool:
    rc, out, _ = run_powershell(
        r"[bool]([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent()))."
        r"IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    return rc == 0 and "true" in out.strip().lower()


def confirm(prompt: str) -> bool:
    """Console confirm; in windowed EXE (no console) auto-continues."""
    if not has_console():
        return True
    try:
        ans = input(f"{prompt} [y/N]: ").strip().lower()
        return ans in ("y", "yes")
    except Exception:
        return True


# =========================
# GUI (Scrollable Options Window)
# =========================
def gui_options(default_profile="safe"):
    import tkinter as tk
    from tkinter import ttk

    result = {
        "profile": default_profile,
        "dry_run": False,
        "log_enabled": True,
        "custom": {},
        "cancelled": True,
    }

    root = tk.Tk()
    root.title("FastPC - Options")
    root.geometry("560x640")
    root.minsize(560, 520)
    root.attributes("-topmost", True)

    # ---------- Layout: Scrollable content + fixed bottom bar ----------
    container = ttk.Frame(root)
    container.pack(fill="both", expand=True)

    # Scrollable area (Canvas + Scrollbar)
    canvas = tk.Canvas(container, highlightthickness=0)
    vscroll = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vscroll.set)

    vscroll.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    # This frame holds all scrollable widgets
    content = ttk.Frame(canvas, padding=(12, 12))
    content_id = canvas.create_window((0, 0), window=content, anchor="nw")

    # Bottom bar (fixed, not scrollable)
    bottom = ttk.Frame(root, padding=12)
    bottom.pack(fill="x", side="bottom")

    # Keep content width matching canvas width
    def on_canvas_configure(event):
        canvas.itemconfig(content_id, width=event.width)

    canvas.bind("<Configure>", on_canvas_configure)

    # Update scroll region when content changes size
    def on_content_configure(_event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))

    content.bind("<Configure>", on_content_configure)

    # ---------- Mouse wheel scroll (Windows/macOS/Linux) ----------
    def _on_mousewheel(event):
        # Windows: event.delta = ±120
        # macOS: delta values differ
        if event.delta:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_linux_scroll(event):
        # Linux uses Button-4/5
        if event.num == 4:
            canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            canvas.yview_scroll(1, "units")

    # Bind globally so wheel works over checkboxes/radiobuttons too
    root.bind_all("<MouseWheel>", _on_mousewheel)
    root.bind_all("<Button-4>", _on_linux_scroll)
    root.bind_all("<Button-5>", _on_linux_scroll)

    # ---------- Vars ----------
    profile_var = tk.StringVar(value=default_profile)
    dry_var = tk.BooleanVar(value=False)
    log_var = tk.BooleanVar(value=True)

    perf_power_var = tk.BooleanVar(value=True)
    perf_turbo_var = tk.BooleanVar(value=False)
    perf_game_var = tk.BooleanVar(value=True)

    clean_user_temp_var = tk.BooleanVar(value=True)
    clean_win_temp_var = tk.BooleanVar(value=False)
    clean_prefetch_var = tk.BooleanVar(value=False)
    clean_recycle_var = tk.BooleanVar(value=False)
    clean_thumbs_var = tk.BooleanVar(value=False)
    clean_do_var = tk.BooleanVar(value=False)
    clean_wu_var = tk.BooleanVar(value=False)

    # ---------- UI Widgets (go inside scrollable "content") ----------
    ttk.Label(content, text="Choose a profile:", font=("Segoe UI", 12, "bold")).pack(pady=(0, 10))

    prof_frame = ttk.Frame(content)
    prof_frame.pack(fill="x", padx=8)

    for p in ("safe", "turbo", "quick", "deep", "network", "ui", "all", "custom"):
        ttk.Radiobutton(prof_frame, text=p.upper(), value=p, variable=profile_var).pack(anchor="w")

    ttk.Separator(content).pack(fill="x", pady=10)

    toggles = ttk.Frame(content)
    toggles.pack(fill="x", padx=8)

    ttk.Checkbutton(toggles, text="Dry-run (preview only, no changes)", variable=dry_var).pack(anchor="w")
    ttk.Checkbutton(toggles, text="Enable logging to file", variable=log_var).pack(anchor="w")

    ttk.Separator(content).pack(fill="x", pady=14)

    custom_frame = ttk.LabelFrame(content, text="Customization (CUSTOM profile only)", padding=(12, 10))
    custom_frame.pack(fill="both", expand=True, padx=8, pady=(0, 10))

    ttk.Label(custom_frame, text="Performance", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
    ttk.Checkbutton(custom_frame, text="Enable High/Ultimate Performance power plan (temporary)", variable=perf_power_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Turbo CPU (min/max 100% + unpark cores) [more heat/battery]", variable=perf_turbo_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Enable Game Mode (temporary)", variable=perf_game_var).pack(anchor="w")

    ttk.Label(custom_frame, text="Cleanup", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(12, 6))
    ttk.Checkbutton(custom_frame, text="Clean user TEMP", variable=clean_user_temp_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Clean Windows TEMP (Admin)", variable=clean_win_temp_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Clean Prefetch (Admin)", variable=clean_prefetch_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Empty Recycle Bin", variable=clean_recycle_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Clear thumbnail cache", variable=clean_thumbs_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Clear Delivery Optimization cache", variable=clean_do_var).pack(anchor="w")
    ttk.Checkbutton(custom_frame, text="Clear Windows Update download cache (Admin)", variable=clean_wu_var).pack(anchor="w")

    def update_custom_state(*_):
        state = "normal" if profile_var.get() == "custom" else "disabled"
        for child in custom_frame.winfo_children():
            try:
                child.configure(state=state)
            except Exception:
                pass

    profile_var.trace_add("write", update_custom_state)
    update_custom_state()

    # ---------- Bottom bar (fixed) ----------
    def on_run():
        result["profile"] = profile_var.get()
        result["dry_run"] = dry_var.get()
        result["log_enabled"] = log_var.get()
        result["cancelled"] = False
        result["custom"] = {
            "perf_power": perf_power_var.get(),
            "perf_turbo": perf_turbo_var.get(),
            "perf_game": perf_game_var.get(),
            "clean_user_temp": clean_user_temp_var.get(),
            "clean_win_temp": clean_win_temp_var.get(),
            "clean_prefetch": clean_prefetch_var.get(),
            "clean_recycle": clean_recycle_var.get(),
            "clean_thumbs": clean_thumbs_var.get(),
            "clean_do": clean_do_var.get(),
            "clean_wu": clean_wu_var.get(),
        }
        root.destroy()

    ttk.Button(bottom, text="RUN", command=on_run).pack(side="left", padx=8)
    ttk.Label(bottom, text="ABDUR RAHMAN", font=("Segoe UI", 9)).pack(side="right")

    # Make sure scrollregion is correct on first render
    root.after(50, on_content_configure)

    root.mainloop()
    return result


# =========================
# Actions (PowerShell)
# =========================
def ps_clean_paths(label: str, ps_paths_expr: str, dry_run: bool, enable_log: bool) -> None:
    log(f"[*] {label}", enable_log)
    ps_script = rf"""
$Dry = {1 if dry_run else 0}
$Paths = {ps_paths_expr}
foreach($p in $Paths) {{
  if([string]::IsNullOrWhiteSpace($p)){{ continue }}
  if(!(Test-Path -LiteralPath $p)){{ Write-Host "[i] Missing: $p"; continue }}
  Write-Host "[*] Cleaning: $p"

  if($Dry -eq 1) {{
    Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue |
      Select-Object -First 40 FullName
    Write-Host "[dry-run] Showing up to 40 items. Nothing deleted."
    continue
  }}

  try {{
    Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue |
      Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "[+] Done: $p"
  }} catch {{
    Write-Host "[!] Some items could not be removed (in use/permissions): $p"
  }}
}}
"""
    rc, out, err = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)
    if rc != 0 and err.strip():
        log(f"[!] PowerShell error: {err.strip()}", enable_log)


def empty_recycle_bin(dry_run: bool, enable_log: bool) -> None:
    log("[*] Empty Recycle Bin", enable_log)
    ps_script = rf"""
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would empty Recycle Bin."
  return
}}
try {{
  Clear-RecycleBin -Force -ErrorAction SilentlyContinue
  Write-Host "[+] Recycle Bin emptied."
}} catch {{
  Write-Host "[!] Failed."
}}
"""
    rc, out, err = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def clear_thumbnail_cache(dry_run: bool, enable_log: bool) -> None:
    log("[*] Clear thumbnail cache (restarts Explorer)", enable_log)
    ps_script = rf"""
$Dry = {1 if dry_run else 0}
$thumb = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
if(!(Test-Path $thumb)) {{
  Write-Host "[i] Missing: $thumb"
  return
}}
if($Dry -eq 1) {{
  Write-Host "[dry-run] Would delete thumbcache_* in $thumb"
  Get-ChildItem -Path $thumb -Filter "thumbcache_*" -ErrorAction SilentlyContinue |
    Select-Object -First 40 FullName
  return
}}
try {{
  Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
  Get-ChildItem -Path $thumb -Filter "thumbcache_*" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
  Start-Process explorer.exe
  Write-Host "[+] Thumbnail cache cleared."
}} catch {{
  Write-Host "[!] Thumbnail clear failed partially."
  try {{ Start-Process explorer.exe }} catch {{}}
}}
"""
    rc, out, err = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def clear_delivery_optimization_cache(dry_run: bool, enable_log: bool) -> None:
    log("[*] Clear Delivery Optimization cache", enable_log)
    ps_script = rf"""
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would run Delete-DeliveryOptimizationCache -Force"
  return
}}
try {{
  Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue | Out-Null
  Write-Host "[+] DO cache cleared."
}} catch {{
  Write-Host "[!] Delivery Optimization cmd unavailable or failed."
}}
"""
    rc, out, err = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def clear_windows_update_cache(dry_run: bool, enable_log: bool) -> None:
    log("[*] Clear Windows Update download cache [Admin required]", enable_log)
    ps_script = rf"""
$isAdmin = [bool]([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).
  IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdmin) {{
  Write-Host "[!] Not admin. Skipping Windows Update cache."
  return
}}
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would stop wuauserv/bits, clear SoftwareDistribution\Download, restart services."
  return
}}
try {{
  Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
  Stop-Service bits -Force -ErrorAction SilentlyContinue
  $p = "C:\Windows\SoftwareDistribution\Download"
  if(Test-Path $p) {{
    Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue |
      Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
  }}
  Start-Service bits -ErrorAction SilentlyContinue
  Start-Service wuauserv -ErrorAction SilentlyContinue
  Write-Host "[+] Windows Update cache cleared."
}} catch {{
  Write-Host "[!] Failed clearing Windows Update cache."
}}
"""
    rc, out, err = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def restart_explorer(dry_run: bool, enable_log: bool) -> None:
    log("[*] Restart Explorer", enable_log)
    ps_script = rf"""
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would restart explorer.exe"
  return
}}
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe
Write-Host "[+] Explorer restarted."
"""
    rc, out, err = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def flush_dns(dry_run: bool, enable_log: bool) -> None:
    log("[*] Flush DNS", enable_log)
    ps_script = rf"""
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would run ipconfig /flushdns"
  return
}}
ipconfig /flushdns | Out-Null
Write-Host "[+] DNS flushed."
"""
    rc, out, _ = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def renew_ip(dry_run: bool, enable_log: bool) -> None:
    log("[*] Renew IP (release/renew)", enable_log)
    ps_script = rf"""
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would run ipconfig /release then /renew"
  return
}}
ipconfig /release | Out-Null
ipconfig /renew | Out-Null
Write-Host "[+] IP renewed."
"""
    rc, out, _ = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def clear_arp(dry_run: bool, enable_log: bool) -> None:
    log("[*] Clear ARP cache", enable_log)
    ps_script = rf"""
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would run arp -d *"
  return
}}
arp -d * | Out-Null
Write-Host "[+] ARP cleared."
"""
    rc, out, _ = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


def reset_winsock(dry_run: bool, enable_log: bool) -> None:
    log("[*] Reset Winsock [Admin required]", enable_log)
    ps_script = rf"""
$isAdmin = [bool]([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).
  IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdmin) {{
  Write-Host "[!] Not admin. Skipping winsock reset."
  return
}}
if({1 if dry_run else 0} -eq 1) {{
  Write-Host "[dry-run] Would run netsh winsock reset"
  return
}}
netsh winsock reset | Out-Null
Write-Host "[+] Winsock reset (reboot may be needed)."
"""
    rc, out, _ = run_powershell(ps_script)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)


# =========================
# SAFE/TURBO (Performance)
# =========================
def ps_set_reg(dry_run: bool, enable_log: bool, path: str, name: str, value: int) -> None:
    ps = rf"""
$Dry = {1 if dry_run else 0}
if($Dry -eq 1) {{ Write-Host "[dry-run] reg set {path} {name}={value}"; return }}
New-Item -Path "{path}" -Force | Out-Null
Set-ItemProperty -Path "{path}" -Name "{name}" -Type DWord -Value {value} -Force
Write-Host "[+] reg set {path} {name}={value}"
"""
    rc, out, err = run_powershell(ps)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)
    if rc != 0 and err.strip():
        log(f"[!] reg error: {err.strip()}", enable_log)


def game_mode_get() -> dict:
    ps = r"""
$path = "HKCU:\Software\Microsoft\GameBar"
$auto = 0
$allow = 0
try {
  $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
  if($p){ $auto = [int]($p.AutoGameModeEnabled); $allow = [int]($p.AllowAutoGameMode) }
} catch {}
@{ auto=$auto; allow=$allow } | ConvertTo-Json -Compress
"""
    rc, out, _ = run_powershell(ps)
    txt = out.strip().lower() if rc == 0 else ""
    return {
        "auto": 1 if '"auto":1' in txt else 0,
        "allow": 1 if '"allow":1' in txt else 0,
    }


def game_mode_set(on: bool, dry_run: bool, enable_log: bool) -> None:
    v = 1 if on else 0
    log(f"[*] Game Mode {'ON' if on else 'OFF'}", enable_log)
    ps_set_reg(dry_run, enable_log, r"HKCU:\Software\Microsoft\GameBar", "AutoGameModeEnabled", v)
    ps_set_reg(dry_run, enable_log, r"HKCU:\Software\Microsoft\GameBar", "AllowAutoGameMode", v)


def powerplan_get_active(enable_log: bool) -> str | None:
    rc, out, err = run_powershell(r"(powercfg /getactivescheme) 2>$null")
    if rc != 0 or not out.strip():
        log(f"[!] Could not read active power plan: {err.strip()}", enable_log)
        return None
    for token in out.split():
        if "-" in token and len(token) >= 32:
            return token.strip()
    return None


def powerplan_find_perf(enable_log: bool) -> str | None:
    ps = r"""
$plans = (powercfg /list) -join "`n"
$ultimate = $null
$high = $null
foreach($line in $plans -split "`n"){
  if($line -match '([0-9a-fA-F\-]{36}).*\((.+)\)'){
    $guid = $Matches[1]
    $name = $Matches[2]
    if($name -match 'Ultimate Performance'){ $ultimate = $guid }
    if($name -match 'High performance'){ $high = $guid }
  }
}
if($ultimate){ $ultimate } elseif($high){ $high } else { "" }
"""
    rc, out, err = run_powershell(ps)
    if rc != 0:
        log(f"[!] Failed to list power plans: {err.strip()}", enable_log)
        return None
    g = out.strip()
    return g or None


def powerplan_set(guid: str, dry_run: bool, enable_log: bool) -> None:
    if dry_run:
        log(f"[dry-run] Would set power plan: {guid}", enable_log)
        return
    rc, _, err = run_powershell(fr"powercfg /setactive {guid}")
    if rc != 0 and err.strip():
        log(f"[!] Failed to set power plan: {err.strip()}", enable_log)


def turbo_cpu_settings_on_scheme(scheme_guid: str, dry_run: bool, enable_log: bool) -> None:
    log("[*] TURBO: CPU min/max 100% + unpark cores (AC)", enable_log)
    ps = rf"""
$Dry = {1 if dry_run else 0}
$scheme = "{scheme_guid}"
$SUB_PROCESSOR = "SUB_PROCESSOR"
$PROCTHROTTLEMIN = "PROCTHROTTLEMIN"
$PROCTHROTTLEMAX = "PROCTHROTTLEMAX"
$CPMINCORES = "CPMINCORES"
$CPMAXCORES = "CPMAXCORES"

if($Dry -eq 1){{
  Write-Host "[dry-run] Would set CPU min/max 100 and core parking 100 on scheme $scheme"
  return
}}

powercfg /setacvalueindex $scheme $SUB_PROCESSOR $PROCTHROTTLEMIN 100 | Out-Null
powercfg /setacvalueindex $scheme $SUB_PROCESSOR $PROCTHROTTLEMAX 100 | Out-Null
powercfg /setacvalueindex $scheme $SUB_PROCESSOR $CPMINCORES 100 | Out-Null
powercfg /setacvalueindex $scheme $SUB_PROCESSOR $CPMAXCORES 100 | Out-Null
Write-Host "[+] TURBO CPU settings applied."
"""
    rc, out, err = run_powershell(ps)
    if out.strip():
        for line in out.splitlines():
            log(line.rstrip(), enable_log)
    if rc != 0 and err.strip():
        log(f"[!] TURBO powercfg error: {err.strip()}", enable_log)


def run_safe_profile(dry_run: bool, enable_log: bool) -> None:
    old_plan = powerplan_get_active(enable_log)
    perf_plan = powerplan_find_perf(enable_log)
    old_gm = game_mode_get()

    if perf_plan and old_plan and perf_plan.lower() != old_plan.lower():
        log(f"[*] Performance Mode: switching -> {perf_plan}", enable_log)
        powerplan_set(perf_plan, dry_run, enable_log)

    game_mode_set(True, dry_run, enable_log)
    restart_explorer(dry_run, enable_log)

    game_mode_set(bool(old_gm.get("auto", 0)), dry_run, enable_log)
    if old_plan and perf_plan and perf_plan.lower() != old_plan.lower():
        log(f"[*] Restoring power plan -> {old_plan}", enable_log)
        powerplan_set(old_plan, dry_run, enable_log)


def run_turbo_profile(dry_run: bool, enable_log: bool) -> None:
    old_plan = powerplan_get_active(enable_log)
    perf_plan = powerplan_find_perf(enable_log)
    old_gm = game_mode_get()

    if perf_plan:
        powerplan_set(perf_plan, dry_run, enable_log)
        turbo_cpu_settings_on_scheme(perf_plan, dry_run, enable_log)

    game_mode_set(True, dry_run, enable_log)
    restart_explorer(dry_run, enable_log)

    game_mode_set(bool(old_gm.get("auto", 0)), dry_run, enable_log)
    if old_plan and perf_plan and old_plan.lower() != perf_plan.lower():
        log(f"[*] Restoring power plan -> {old_plan}", enable_log)
        powerplan_set(old_plan, dry_run, enable_log)


# =========================
# Profile runner
# =========================
def run_custom_profile(custom: dict, dry_run: bool, enable_log: bool) -> None:
    old_plan = powerplan_get_active(enable_log)
    perf_plan = powerplan_find_perf(enable_log)
    old_gm = game_mode_get()

    if custom.get("perf_power") and perf_plan and old_plan and perf_plan.lower() != old_plan.lower():
        log(f"[*] Performance Mode (temporary) -> {perf_plan}", enable_log)
        powerplan_set(perf_plan, dry_run, enable_log)

    if custom.get("perf_turbo") and perf_plan:
        turbo_cpu_settings_on_scheme(perf_plan, dry_run, enable_log)

    if custom.get("perf_game"):
        game_mode_set(True, dry_run, enable_log)

    if custom.get("clean_user_temp"):
        ps_clean_paths("Clean user TEMP (%TEMP%/%TMP%)", r"@($env:TEMP,$env:TMP)", dry_run, enable_log)
    if custom.get("clean_win_temp"):
        ps_clean_paths("Clean Windows Temp (C:\\Windows\\Temp) [Admin recommended]", r'@("C:\Windows\Temp")', dry_run, enable_log)
    if custom.get("clean_prefetch"):
        ps_clean_paths("Clean Prefetch (C:\\Windows\\Prefetch) [Admin recommended]", r'@("C:\Windows\Prefetch")', dry_run, enable_log)
    if custom.get("clean_recycle"):
        empty_recycle_bin(dry_run, enable_log)
    if custom.get("clean_thumbs"):
        clear_thumbnail_cache(dry_run, enable_log)
    if custom.get("clean_do"):
        clear_delivery_optimization_cache(dry_run, enable_log)
    if custom.get("clean_wu"):
        clear_windows_update_cache(dry_run, enable_log)

    restart_explorer(dry_run, enable_log)

    if custom.get("perf_game"):
        game_mode_set(bool(old_gm.get("auto", 0)), dry_run, enable_log)
    if custom.get("perf_power") and old_plan and perf_plan and old_plan.lower() != perf_plan.lower():
        powerplan_set(old_plan, dry_run, enable_log)


def run_profile(profile: str, custom: dict, dry_run: bool, enable_log: bool) -> None:
    admin = is_admin()
    log(f"[i] Profile={profile} | Admin={1 if admin else 0} | DryRun={1 if dry_run else 0} | Log={LOG_FILE}", enable_log)

    if profile == "safe":
        run_safe_profile(dry_run, enable_log)
    elif profile == "turbo":
        run_turbo_profile(dry_run, enable_log)
    elif profile == "custom":
        run_custom_profile(custom, dry_run, enable_log)

    elif profile == "quick":
        ps_clean_paths("Clean user TEMP (%TEMP%/%TMP%)", r"@($env:TEMP,$env:TMP)", dry_run, enable_log)
        restart_explorer(dry_run, enable_log)

    elif profile == "deep":
        ps_clean_paths("Clean user TEMP (%TEMP%/%TMP%)", r"@($env:TEMP,$env:TMP)", dry_run, enable_log)
        ps_clean_paths("Clean Windows Temp (C:\\Windows\\Temp) [Admin recommended]", r'@("C:\Windows\Temp")', dry_run, enable_log)
        ps_clean_paths("Clean Prefetch (C:\\Windows\\Prefetch) [Admin recommended]", r'@("C:\Windows\Prefetch")', dry_run, enable_log)
        empty_recycle_bin(dry_run, enable_log)
        clear_thumbnail_cache(dry_run, enable_log)
        clear_delivery_optimization_cache(dry_run, enable_log)
        restart_explorer(dry_run, enable_log)

    elif profile == "network":
        flush_dns(dry_run, enable_log)
        renew_ip(dry_run, enable_log)
        clear_arp(dry_run, enable_log)
        reset_winsock(dry_run, enable_log)

    elif profile == "ui":
        clear_thumbnail_cache(dry_run, enable_log)
        restart_explorer(dry_run, enable_log)

    elif profile == "all":
        ps_clean_paths("Clean user TEMP (%TEMP%/%TMP%)", r"@($env:TEMP,$env:TMP)", dry_run, enable_log)
        ps_clean_paths("Clean Windows Temp (C:\\Windows\\Temp) [Admin recommended]", r'@("C:\Windows\Temp")', dry_run, enable_log)
        ps_clean_paths("Clean Prefetch (C:\\Windows\\Prefetch) [Admin recommended]", r'@("C:\Windows\Prefetch")', dry_run, enable_log)
        empty_recycle_bin(dry_run, enable_log)
        clear_thumbnail_cache(dry_run, enable_log)
        clear_delivery_optimization_cache(dry_run, enable_log)
        clear_windows_update_cache(dry_run, enable_log)

        flush_dns(dry_run, enable_log)
        renew_ip(dry_run, enable_log)
        clear_arp(dry_run, enable_log)
        reset_winsock(dry_run, enable_log)

        restart_explorer(dry_run, enable_log)
    else:
        raise ValueError(f"Unknown profile: {profile}")

    log("[✓] Finished.", enable_log)


# =========================
# main
# =========================
def main() -> int:
    parser = argparse.ArgumentParser(description="FastPC Pro (Windows)")
    parser.add_argument("--profile", default="safe",
                        choices=["safe", "turbo", "quick", "deep", "network", "ui", "all", "custom"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--no-log", action="store_true")
    args = parser.parse_args()

    if not is_windows():
        print("[-] Windows only.")
        return 2

    if not (shutil.which("powershell.exe") or shutil.which("pwsh.exe")):
        print("[-] PowerShell not found.")
        return 2

    custom = {}
    if not has_console() and gui_available():
        ui = gui_options(default_profile=args.profile)
        if ui.get("cancelled"):
            return 0
        args.profile = ui["profile"]
        args.dry_run = ui["dry_run"]
        args.no_log = not ui["log_enabled"]
        custom = ui.get("custom") or {}
        args.yes = True

    enable_log = not args.no_log

    if not args.yes:
        print()
        print(f"Will run: PROFILE={args.profile} | DRY_RUN={1 if args.dry_run else 0}")
        print(f"Log file: {LOG_FILE} (logging={'on' if enable_log else 'off'})")
        if not confirm("Continue?"):
            print("[i] Cancelled.")
            return 0

    run_profile(args.profile, custom, args.dry_run, enable_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
