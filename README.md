# FastPc
# FastPC Pro 🚀

**FastPC Pro** is a lightweight Windows optimization and cleanup tool built with **Python + PowerShell**.  
It provides safe performance tuning, deep system cleanup, network fixes, and a fully customizable GUI — all in one place.

> Designed for learning, personal use, and practical Windows optimization.

---

## ✨ Features

### 🔹 Performance Profiles
- **SAFE** – Temporary performance boost (power plan + Game Mode), then restores settings
- **TURBO** – Maximum performance (CPU 100%, unpark cores, Game Mode)
- **QUICK** – Fast user temp cleanup + Explorer restart
- **DEEP** – Deep system cleanup (Temp, Prefetch, Recycle Bin, caches)
- **NETWORK** – DNS flush, IP renew, ARP clear, Winsock reset
- **UI** – Explorer refresh & thumbnail cache cleanup
- **ALL** – Runs all cleanup + network actions
- **CUSTOM** – Choose exactly what you want to run (GUI)

---

## 🧠 CUSTOM Mode (GUI)
When **CUSTOM** is selected, you can individually enable:

### Performance
- High / Ultimate Performance power plan (temporary)
- Turbo CPU mode (min/max 100%, unpark cores)
- Windows Game Mode (temporary)

### Cleanup
- User TEMP
- Windows TEMP (Admin)
- Prefetch (Admin)
- Recycle Bin
- Thumbnail cache
- Delivery Optimization cache
- Windows Update download cache (Admin)

---

## 🖥 GUI Mode
- Automatically opens when the EXE is **double-clicked**
- Scrollable interface
- **RUN button**
- Dry-run toggle (preview only)
- Logging toggle
- Footer credit: **ABDUR RAHMAN**

---

## 🔍 Dry-Run Mode
Preview what will happen **without deleting or changing anything**.  
Perfect for safety and learning.

---

## 📝 Logging
- Logs are saved to:
- Can be disabled from GUI or CLI

---

## 🔐 Admin Awareness
- Detects administrator privileges automatically
- Admin-only actions are skipped safely if not elevated
- No forced elevation

---

## 🛠 Requirements
- Windows 10 / 11
- Python 3.10+ (for script)
- PowerShell (built-in on Windows)

Optional:
- **AutoHotkey v2** (only if GPU reset feature is later enabled)

---

## ▶ Usage

### Run as Python script
```bash
python fastpc.py
Command-line usage
python fastpc.py --profile turbo
python fastpc.py --profile custom --dry-run


Available profiles:

safe | turbo | quick | deep | network | ui | all | custom

📦 Build EXE (PyInstaller)
pyinstaller --onefile --noconsole --icon=icon.ico fastpc.py


Result:

dist/FastPC.exe


Double-click to launch GUI.

⚠ Disclaimer

This tool modifies temporary files, power plans, and network settings.

Use TURBO mode carefully (higher heat & battery usage)

Always prefer Dry-Run if unsure

Author is not responsible for misuse

👤 Author

ABDUR RAHMAN
