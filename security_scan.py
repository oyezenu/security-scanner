"""
security_scan.py — System Health Monitor
=========================================
Periodically captures a snapshot of system memory, network I/O, and running
processes. Fires desktop and/or email alerts when memory thresholds are breached.
Logs all incidents to a per-session report file.

Usage:
    python security_scan.py

Configuration:
    Copy .env.example → .env and fill in your credentials to enable alerts.

Dependencies:
    pip install psutil python-dotenv plyer
    pip install tzdata  # Windows only
"""

import os
import smtplib
import socket
import sys
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path



try:
    import tzdata  # noqa: F401 — IANA zones on Windows; pip install tzdata
except ImportError:
    pass


# python-dotenv reads the .env file and injects each KEY=VALUE pair into
# os.environ so that os.getenv() can retrieve them later in this script.
try:
    from dotenv import load_dotenv          
    load_dotenv()                           
except ImportError:
    pass                                    

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Time Zone
try:
    CENTRAL_TZ = ZoneInfo("America/Chicago")
except ZoneInfoNotFoundError:
    print(
        "Missing time zone data for Central Time.\n"
        "Install: python -m pip install tzdata",
        file=sys.stderr,
    )
    raise SystemExit(1) from None


def now_central() -> datetime:
    """Return the current time localized to US Central Time."""
    return datetime.now(CENTRAL_TZ)


# ── Core scan settings ────────────────────────────────────────────────────────

# MB threshold: if any of the top 5 processes exceeds this, trigger an alert.
MEMORY_WARNING_THRESHOLD_MB = 1000

# Each script run creates a new .txt log here.
INCIDENT_REPORTS_DIR = Path(__file__).resolve().parent / "incident_reports"

# How many seconds to wait between scans.
SCAN_INTERVAL_SECONDS = 30


# ── Alert settings (all loaded from your .env file) ──────────────────────────
# Email credentials — leave blank to disable email alerts entirely.
EMAIL_SENDER    = os.getenv("EMAIL_SENDER",    "")
EMAIL_PASSWORD  = os.getenv("EMAIL_PASSWORD",  "")  # Use a Gmail App Password, not your real password!
EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT", "")
SMTP_HOST       = os.getenv("SMTP_HOST",       "smtp.gmail.com")
try:
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
except ValueError:
    print(
        "[Config error] SMTP_PORT must be an integer. Defaulting to 587.",
        file=sys.stderr,
    )
    SMTP_PORT = 587

# Set ENABLE_EMAIL_ALERTS=true and/or ENABLE_DESKTOP_ALERTS=true in .env to toggle.
ENABLE_EMAIL_ALERTS   = os.getenv("ENABLE_EMAIL_ALERTS",   "false").lower() == "true"
ENABLE_DESKTOP_ALERTS = os.getenv("ENABLE_DESKTOP_ALERTS", "true").lower()  == "true"

# Minimum minutes to wait before repeating an alert — prevents notification spam.
ALERT_COOLDOWN_MINUTES = int(os.getenv("ALERT_COOLDOWN_MINUTES", "10"))

# Comma-separated process names that should never trigger an alert.
# Common safe Windows system processes are excluded by default.
# Override via EXCLUDED_PROCESSES=name1,name2 in your .env file.
EXCLUDED_PROCESSES: set[str] = {
    name.strip()
    for name in os.getenv(
        "EXCLUDED_PROCESSES", "MemCompression,Registry,System,Idle"
    ).split(",")
    if name.strip()
}

# Internal tracker: when was the last alert fired? (None = never)
_last_alert_time: datetime | None = None


# ── Screen / utility helpers ──────────────────────────────────────────────────

def clear_screen() -> None:
    """Clear the terminal (Windows: cls, macOS/Linux: clear)."""
    os.system("cls" if os.name == "nt" else "clear")


def network_totals_mb(psutil_module) -> tuple[float, float]:
    """
    Return cumulative bytes sent and received across all interfaces since boot.

    Args:
        psutil_module: The imported psutil module.

    Returns:
        A (sent_mb, recv_mb) tuple of floats.
    """
    try:
        counters = psutil_module.net_io_counters(pernic=False)
    except (RuntimeError, OSError):
        return 0.0, 0.0
    if counters is None:
        return 0.0, 0.0
    sent = counters.bytes_sent / (1024 * 1024)
    recv = counters.bytes_recv / (1024 * 1024)
    return sent, recv


# ── Incident log helpers ──────────────────────────────────────────────────────

def append_incident_report(
    log_path: Path,
    scan_count: int,
    rows: list[tuple[int, str, int]],
    threshold_bytes: int,
) -> None:
    """Append processes exceeding the memory threshold to the session log file."""
    offenders = [(rss, name, pid) for rss, name, pid in rows if rss > threshold_bytes]
    if not offenders:
        return

    offenders.sort(key=lambda x: x[0], reverse=True)
    timestamp = now_central().strftime("%Y-%m-%d %I:%M:%S %p %Z")

    with log_path.open("a", encoding="utf-8") as f:
        f.write(
            f"\n--- {timestamp} | scan #{scan_count} | "
            f"{len(offenders)} process(es) over {MEMORY_WARNING_THRESHOLD_MB} MB ---\n"
        )
        for rss, name, pid in offenders:
            mb = rss / (1024 * 1024)
            f.write(f"{name} | PID {pid} | {mb:,.1f} MB\n")


# ── Alert functions ───────────────────────────────────────────────────────────

def send_desktop_notification(title: str, message: str) -> None:
    """
    Fire a desktop pop-up notification via plyer.

    Args:
        title:   The notification title (bold heading).
        message: The body text shown in the notification pop-up.
    """
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="Security Scanner",
            timeout=10,
        )
        print("  [✓] Desktop notification sent.")
    except ImportError:
        print("  [Desktop alert skipped] Run: python -m pip install plyer")
    except Exception as exc:
        print(f"  [Desktop alert failed] {exc}")


def send_email_alert(subject: str, body: str) -> None:
    """
    Send an email alert via SMTP (defaults to Gmail).

    Credentials are read from environment variables set by the .env file.
    Gmail users must supply an App Password — not their account password.
    See: Google Account → Security → 2-Step Verification → App passwords
    """
    if not all([EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENT]):
        print(
            "  [Email alert skipped] Fill in EMAIL_SENDER, EMAIL_PASSWORD, "
            "and EMAIL_RECIPIENT in your .env file to enable email alerts."
        )
        return

    try:
        msg = MIMEMultipart()
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECIPIENT
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())

        print(f"  [✓] Email alert sent to {EMAIL_RECIPIENT}.")

    except smtplib.SMTPAuthenticationError:
        print(
            "  [Email alert failed] Authentication error — double-check "
            "EMAIL_SENDER and EMAIL_PASSWORD in your .env file.\n"
            "  Gmail users: make sure you're using an App Password, not your real password."
        )
    except Exception as exc:
        print(f"  [Email alert failed] {exc}")


def trigger_alerts(offenders: list[tuple[int, str, int]], scan_count: int) -> None:
    """
    Dispatch desktop and/or email alerts when a memory threshold breach is detected.

    Uses a cooldown window (ALERT_COOLDOWN_MINUTES) to suppress repeated
    notifications for the same ongoing issue.

    Uses `global _last_alert_time` to persist alert state across calls
    without requiring an external data structure.
    """
    global _last_alert_time

    # ── Cooldown Check ────────────────────────────────────────────────────────
    now = now_central()
    if _last_alert_time is not None:
        elapsed_minutes = (now - _last_alert_time).total_seconds() / 60
        if elapsed_minutes < ALERT_COOLDOWN_MINUTES:
            remaining = ALERT_COOLDOWN_MINUTES - elapsed_minutes
            print(f"  [Alert cooldown] Next alert eligible in {remaining:.1f} min.")
            return

    # Record this moment so the next call can check the cooldown.
    _last_alert_time = now

    # ── Alert Message ───────────────────────────────────────────────
    timestamp = now.strftime("%Y-%m-%d %I:%M:%S %p %Z")
    lines = [f"High memory detected at {timestamp} (scan #{scan_count}):"]
    for rss, name, pid in offenders:
        mb = rss / (1024 * 1024)
        lines.append(f"  • {name}  |  PID {pid}  |  {mb:,.1f} MB")

    subject   = f"[Security Scanner] High Memory Alert — {timestamp}"
    full_body = "\n".join(lines)
    short_msg = "\n".join(lines[:3])    

    # ── Dispatch ──────────────────────────────────────────────────────────────
    if ENABLE_DESKTOP_ALERTS:
        send_desktop_notification("⚠️ High Memory Detected!", short_msg)

    if ENABLE_EMAIL_ALERTS:
        send_email_alert(subject, full_body)


# ── Main scan loop ────────────────────────────────────────────────────────────

def run_scan(
    psutil_module,
    scan_count: int,
    session_log_path: Path,
    prev_net: tuple[float, float],
) -> tuple[float, float]:
    """
    Execute one full scan: banner, hostname, top 5 processes, health status, alerts.

    Args:
        psutil_module:    The imported psutil module.
        scan_count:       The current scan number (1-based).
        session_log_path: Path to the session's incident log file.
        prev_net:         (sent_mb, recv_mb) from the previous scan, used to
                          compute per-interval network deltas.

    Returns:
        The current (sent_mb, recv_mb) totals to be passed as prev_net next scan.
    """
    print("=" * 52)
    print(f"  SECURITY SCANNER  |  Scan #{scan_count:,}")
    print("=" * 52)
    if scan_count == 1:
        print(f"  Incident log: {session_log_path}")
    print()

    print("  Hostname:", socket.gethostname())
    print()

    # Collect memory info for every running process.
    rows: list[tuple[int, str, int]] = []
    for proc in psutil_module.process_iter(["pid", "name", "memory_info"]):
        try:
            info = proc.info
            name = info.get("name") or "(unknown)"
            pid  = int(info.get("pid") or 0)
            mem  = info.get("memory_info")
            rss  = mem.rss if mem else 0
            rows.append((rss, name, pid))
        except (psutil_module.NoSuchProcess, psutil_module.AccessDenied, psutil_module.ZombieProcess):
            continue

    rows.sort(key=lambda x: x[0], reverse=True)
    top = rows[:5]

    threshold_bytes = MEMORY_WARNING_THRESHOLD_MB * 1024 * 1024
    append_incident_report(session_log_path, scan_count, rows, threshold_bytes)

    print("  Top 5 processes by memory use (RSS):")
    for rank, (rss, name, pid) in enumerate(top, start=1):
        mb = rss / (1024 * 1024)
        print(f"{rank}. {name}  |  PID {pid}  |  {mb:,.1f} MB")

    print()

    # Check ALL processes (not just top 5) for threshold breaches, excluding known-safe processes.
    offenders = [
        (rss, name, pid)
        for rss, name, pid in rows
        if rss > threshold_bytes and name not in EXCLUDED_PROCESSES
    ]
    if offenders:
        print("  ⚠️  WARNING — HIGH MEMORY USAGE DETECTED")
        trigger_alerts(offenders, scan_count)
    else:
        print("  ✅  System health is within normal limits.")

    print()
    sent_mb, recv_mb = network_totals_mb(psutil_module)
    delta_sent = sent_mb - prev_net[0]
    delta_recv = recv_mb - prev_net[1]
    print("  Network I/O:")
    print(f"    Sent     (this interval):  {delta_sent:,.2f} MB")
    print(f"    Received (this interval):  {delta_recv:,.2f} MB")
    print(f"    Sent     (since boot):     {sent_mb:,.1f} MB")
    print(f"    Received (since boot):     {recv_mb:,.1f} MB")
    print()
    print(f"  Next scan in {SCAN_INTERVAL_SECONDS}s  —  Press Ctrl+C to stop.")
    return sent_mb, recv_mb


def main() -> None:
    try:
        import psutil
    except ImportError:
        print("Missing dependency: psutil")
        print("Install it by running:")
        print("  python -m pip install psutil")
        sys.exit(1)

    INCIDENT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    session_started = now_central()
    stamp            = session_started.strftime("%Y-%m-%d_%I-%M-%S-%p").replace(" ", "")
    session_log_path = INCIDENT_REPORTS_DIR / f"incident_{stamp}.txt"

    sent_mb, recv_mb = network_totals_mb(psutil)
    with session_log_path.open("w", encoding="utf-8") as f:
        started_line = session_started.strftime("%Y-%m-%d %I:%M:%S %p %Z")
        f.write(f"Incident report — session started {started_line}\n")
        f.write(f"Computer: {socket.gethostname()}\n")
        f.write("Network I/O (cumulative since boot) — snapshot at session start:\n")
        f.write(f"  Sent: {sent_mb:,.1f} MB  |  Received: {recv_mb:,.1f} MB\n")
        f.write(f"Below: processes over {MEMORY_WARNING_THRESHOLD_MB} MB (RSS), grouped by scan.\n")
        f.write("---\n")

    scan_count = 0
    prev_net = (sent_mb, recv_mb)   # baseline for first-scan delta
    while True:
        scan_count += 1
        clear_screen()
        prev_net = run_scan(psutil, scan_count, session_log_path, prev_net)
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSession terminated. Goodbye.")
        sys.exit(0)
