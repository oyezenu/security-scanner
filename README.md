# 🛡️ Security Scanner

An automated system health monitor built in Python. Runs continuously in the background, tracking memory usage and network I/O across all running processes — and fires real-time alerts when something looks off.

---

## ✨ Features

- 🔁 **Continuous monitoring** — scans every 30 seconds, automatically
- 🧠 **Top 5 memory consumers** — ranked by physical RAM (RSS) usage
- 🌐 **Network I/O snapshot** — cumulative bytes sent/received since boot
- 🖥️ **Desktop notifications** — Windows/macOS/Linux pop-up alerts via `plyer`
- 📧 **Email alerts** — sends a real email when memory thresholds are breached
- ⏱️ **Alert cooldown** — prevents notification spam for ongoing issues
- 📄 **Incident logging** — auto-generates a timestamped `.txt` report each session
- 🔒 **Secure config** — credentials stored in a local `.env` file, never committed to Git

---

## 📋 Requirements

- Python (Obviously)
- The following packages:

```bash
python -m pip install psutil python-dotenv plyer
python -m pip install tzdata   # Windows only
```

---

## ⚙️ Setup

### 1. Clone the repository

```bash
git clone https://github.com/oyezenu/security-scanner.git
cd security-scanner
```

### 2. Install dependencies

```bash
python -m pip install psutil python-dotenv plyer
```

### 3. Configure alerts

Copy the example config and fill in your details:

```bash
cp .env.example .env
```

Then open `.env` and set your values:

```env
ENABLE_DESKTOP_ALERTS=true
ENABLE_EMAIL_ALERTS=true

EMAIL_SENDER=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_RECIPIENT=your_email@gmail.com
```

> **Gmail users:** You must use an [App Password](https://myaccount.google.com/apppasswords), not your regular Gmail password.
> Go to: Google Account → Security → 2-Step Verification → App passwords

### 4. Run the scanner

```bash
python security.scan.py
```

Press `Ctrl+C` to stop.

---

## 🖥️ Sample Output

```
====================================================
  SECURITY SCANNER  |  Scan #1
====================================================
  Hostname: DESKTOP-XXXX

  Top 5 processes by memory use (RSS):
    1. chrome.exe     |  PID 4821  |  1,204.3 MB
    2. python.exe     |  PID 9103  |  312.7 MB
    3. explorer.exe   |  PID 1042  |  198.1 MB
    4. discord.exe    |  PID 3377  |  185.6 MB
    5. Code.exe       |  PID 7890  |  174.2 MB

  ⚠️  WARNING — HIGH MEMORY USAGE DETECTED
  [✓] Desktop notification sent.
  [✓] Email alert sent to your_email@gmail.com.

  Network I/O (cumulative since boot):
    Sent:      2,340.1 MB
    Received:  8,901.4 MB

  Next scan in 30s  —  Press Ctrl+C to stop.
```

---

## 📁 Project Structure

```
security-scanner/
├── security.scan.py     # Main scanner script
├── .env.example         # Config template
├── .gitignore           # Keeps secrets and logs out of Git
└── incident_reports/    # Locally auto-generated session logs
```


---

## 🛣️ Roadmap

- [ ] Web dashboard UI with live-updating charts
- [ ] AI-powered anomaly analysis via Gemini/OpenAI
- [ ] SQLite database for historical trend tracking
- [ ] Unit tests with `pytest`

---

*Built as a Python learning project — exploring system monitoring, automation, secure config management, and real-time alerting.*
