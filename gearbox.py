#!/usr/bin/env python3
# =============================================================================
# GearBox — Device Security Assessment Orchestration Tool
# =============================================================================
# Usage:
#   Standalone : python3 gearbox.py <project.yaml> [options]
#   Flask mode : launched automatically by app.py
# =============================================================================

from __future__ import annotations

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

import argparse         # stdlib — CLI argument parsing
import csv              # stdlib — risk-map CSV parsing and findings export
import ipaddress        # stdlib — CIDR / IP address validation
import json             # stdlib — findings JSONL, protocol tokens, NVD API responses
import logging          # stdlib — internal diagnostic logging
import os               # stdlib — environment variables, path helpers
import platform         # stdlib — OS detection for clients base directory
import re               # stdlib — banner / version string parsing, protocol token extraction
import shutil           # stdlib — tool PATH lookups, file operations
import signal           # stdlib — SIGINT/SIGTERM graceful shutdown handler
import socket           # stdlib — hostname recording in project_meta.json
import sqlite3          # stdlib — findings.db SQLite persistence
import subprocess       # stdlib — invokes nmap (Gordon Lyon @Fyodor — https://nmap.org), tcpdump, sslscan (rbsec — https://github.com/rbsec/sslscan), testssl.sh (Dirk Wetter @drwetter — https://github.com/drwetter/testssl.sh), nuclei (ProjectDiscovery @projectdiscovery — https://github.com/projectdiscovery/nuclei), gowitness (SensePost @sensepost — https://github.com/sensepost/gowitness), ssh-audit (Joe Testa @jtesta — https://github.com/jtesta/ssh-audit), responder (Laurent Gaffié @lgandx — https://github.com/lgandx/Responder), smbmap (ShawnDEvans — https://github.com/ShawnDEvans/smbmap), dnsmasq (Simon Kelley — https://www.thekelleys.org.uk/dnsmasq), cec-client (Pulse-Eight — https://github.com/Pulse-Eight/libcec), ddcutil (Sanford Rockowitz — https://www.ddcutil.com), candump/cansend (SocketCAN — https://github.com/linux-can/can-utils), proxmark3/pm3 (RfidResearchGroup — https://github.com/RfidResearchGroup/proxmark3)
import sys              # stdlib — exit codes, stdout protocol token output
import threading        # stdlib — background Nessus and Responder threads; concurrent service workers
import time             # stdlib — polling, timeouts, scan-wait loops
import uuid             # stdlib — finding unique identifiers
from concurrent.futures import ThreadPoolExecutor, as_completed, Future  # stdlib — Phase 2 concurrent service assessment workers
from contextlib import contextmanager   # stdlib — resource management helpers
from dataclasses import dataclass, field  # stdlib — ModuleContext and finding dataclasses
from datetime import datetime           # stdlib — timestamps in findings and logs
from pathlib import Path                # stdlib — cross-platform output directory management
from typing import Any, Optional        # stdlib — type hints

# §13b/§14j/§14k: run-dir audit logger (scan.log + scan.log.json + errors.log).
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_event_log as _el
except Exception:
    _el = None

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    from pr0t31n_pause import PauseManager, EXIT_PAUSED
except ImportError:
    PauseManager = None
    EXIT_PAUSED = 42

_pause: "PauseManager | None" = None


def _check_pause() -> None:
    if _pause and _pause.check_and_pause():
        console.log("Pause requested — saving checkpoint and exiting.", "INFO")
        sys.exit(EXIT_PAUSED)


def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """
    Build a structured project directory:
      <clients_base>/<client_short>/<year>/<tool_name>/<client_short>_<datetime>/
    """
    import re as _re
    slug = _re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now().strftime('%Y'))
    dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    try:
        (project_dir / "project_meta.json").write_text(
            json.dumps({
                "tool":         tool,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now().isoformat(),
                "hostname":     socket.gethostname(),
                "version":      version,
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def _u_dual_write_meta(project_dir, *, tool: str, version: str,
                       client_short: str = "", client_name: str = "",
                       engagement_name: str = "", target: str = "") -> bool:
    """Dual-write universal meta.json (schema 1.0). Graceful no-op when
    /opt/pr0t31n/shared/pr0t31n_schema.py is not installed."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return False
    try:
        meta = _us.make_meta(
            tool=tool, version=version,
            client_short=client_short or "unknown",
            client_name=client_name or client_short or "unknown",
            engagement_name=engagement_name or f"{tool} run",
            target=target or "",
        )
        _us.atomic_write_json(Path(project_dir) / "meta.json", meta)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Python Package Registry  (checked / installed before anything else runs)
# ---------------------------------------------------------------------------
# Each entry:
#   import_name  – name passed to importlib.import_module / __import__
#   pip_name     – pip install argument (may differ, e.g. "pyyaml" vs "yaml")
#   apt_name     – apt-get install argument (Debian/Ubuntu/Kali)
#   brew_name    – brew install argument (macOS)
#   required     – bool; False = optional (degraded-mode if absent)
#   description  – human-readable purpose shown in install prompt
# ---------------------------------------------------------------------------
REQUIRED_PACKAGES: list[dict] = [
    {
        "import_name": "yaml",
        "pip_name":    "pyyaml",
        "apt_name":    "python3-yaml",
        "brew_name":   None,
        "required":    True,
        "description": "YAML configuration parsing",
    },
    {
        "import_name": "requests",
        "pip_name":    "requests",
        "apt_name":    "python3-requests",
        "brew_name":   None,
        "required":    False,
        "description": "Nessus API and NVD vulnerability lookups",
    },
    {
        "import_name": "qrcode",
        "pip_name":    "qrcode[pil]",
        "apt_name":    "python3-qrcode",
        "brew_name":   None,
        "required":    False,
        "description": "QR code generation for photo upload prompts",
    },
    {
        "import_name": "PIL",
        "pip_name":    "pillow",
        "apt_name":    "python3-pil",
        "brew_name":   None,
        "required":    False,
        "description": "Image processing (required by qrcode[pil])",
    },
    {
        "import_name": "serial",
        "pip_name":    "pyserial",
        "apt_name":    "python3-serial",
        "brew_name":   None,
        "required":    False,
        "description": "DB9 serial port auto-detection and sniffing (RS-232/RS-422/RS-485)",
    },
]

# ---------------------------------------------------------------------------
# System Tool Registry
# ---------------------------------------------------------------------------
# os_support: list of sys.platform prefixes this tool supports.
#   ["linux", "darwin"] = both  |  ["linux"] = Debian/Linux only
# kali_apt_name: override apt package name specifically on Kali Linux.
#   None = not available via apt on Kali; use go/git/pip fallback instead.
# bin_aliases: alternative binary names that confirm the tool is installed
#   (e.g. 'pm3' wrapper proves proxmark3 is present).
# extra_paths: absolute paths (~ expanded) to check beyond PATH.
# ---------------------------------------------------------------------------
REQUIRED_TOOLS: list[dict] = [
    {"bin":"nmap",       "apt_name":"nmap",            "brew_name":"nmap",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":True,  "needs_sudo":False,
     "kali_apt_name":"nmap",
     "extra_paths":["/usr/bin/nmap","/usr/local/bin/nmap","/opt/homebrew/bin/nmap"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"tcpdump",    "apt_name":"tcpdump",          "brew_name":"tcpdump",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":True,  "needs_sudo":False,
     "kali_apt_name":"tcpdump",
     "extra_paths":["/usr/bin/tcpdump","/usr/sbin/tcpdump",
                    "/usr/local/sbin/tcpdump","/opt/homebrew/sbin/tcpdump"],
     "interfaces":["Ethernet","Ethernet_tap"], "os_support":["linux","darwin"]},
    {"bin":"ethtool",    "apt_name":"ethtool",          "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/sigma-1/ethtool.git",
     "git_subdir":"",
     "install_note":"On macOS: built from sigma-1/ethtool via git clone",
     "required":True,    "needs_sudo":False,
     "kali_apt_name":"ethtool",
     "extra_paths":["/sbin/ethtool","/usr/sbin/ethtool","/usr/bin/ethtool",
                    "/usr/local/sbin/ethtool","/usr/local/bin/ethtool",
                    "~/ethtool/ethtool"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"dhclient",   "apt_name":"isc-dhcp-client",  "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"On macOS use: ipconfig set <iface> DHCP",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"isc-dhcp-client",
     "extra_paths":["/sbin/dhclient","/usr/sbin/dhclient","/usr/local/sbin/dhclient"],
     "interfaces":["Ethernet"], "os_support":["linux"]},
    {"bin":"netplan",    "apt_name":"netplan.io",        "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Debian/Ubuntu only",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":None,
     "extra_paths":["/usr/sbin/netplan","/usr/bin/netplan","/usr/local/sbin/netplan"],
     "interfaces":["Ethernet"], "os_support":["linux"]},
    {"bin":"ip",         "apt_name":"iproute2",          "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only (iproute2)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"iproute2",
     "extra_paths":["/sbin/ip","/usr/sbin/ip","/bin/ip","/usr/bin/ip"],
     "interfaces":["Ethernet"], "os_support":["linux"]},
    {"bin":"ping",       "apt_name":"iputils-ping",      "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"iputils-ping",
     "extra_paths":["/bin/ping","/usr/bin/ping","/sbin/ping","/usr/local/bin/ping"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"curl",       "apt_name":"curl",              "brew_name":"curl",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"curl",
     "extra_paths":["/usr/bin/curl","/usr/local/bin/curl","/opt/homebrew/bin/curl"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"openssl",    "apt_name":"openssl",           "brew_name":"openssl",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"openssl",
     "extra_paths":["/usr/bin/openssl","/usr/local/bin/openssl",
                    "/opt/homebrew/bin/openssl",
                    "/opt/homebrew/opt/openssl/bin/openssl"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"sslscan",    "apt_name":"sslscan",           "brew_name":"sslscan",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"sslscan",
     "extra_paths":["/usr/bin/sslscan","/usr/local/bin/sslscan",
                    "/opt/homebrew/bin/sslscan"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"testssl.sh", "apt_name":None,                "brew_name":"testssl",
     "pip_name":None,
     "git_repo":"https://github.com/drwetter/testssl.sh.git",
     "git_subdir":"",
     "install_note":"Clone to ~/testssl.sh and add to PATH",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"testssl.sh",
     "extra_paths":["~/testssl.sh/testssl.sh","~/testssl.sh/testssl",
                    "/usr/local/bin/testssl.sh","/opt/homebrew/bin/testssl",
                    "/usr/bin/testssl.sh"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"nuclei",     "apt_name":None,                "brew_name":"nuclei",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "go_pkg":"github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
     "install_note":"Install via: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"nuclei",
     "extra_paths":["~/go/bin/nuclei","/usr/local/bin/nuclei",
                    "/opt/homebrew/bin/nuclei","/usr/bin/nuclei"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"gowitness",  "apt_name":"gowitness",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "go_pkg":"github.com/sensepost/gowitness/v3/cmd/gowitness@latest",
     "go_pkg_fallbacks":["github.com/sensepost/gowitness@latest"],
     "install_note":"Linux: apt install gowitness  |  macOS: go install github.com/sensepost/gowitness/v3/cmd/gowitness@latest",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"gowitness",
     "extra_paths":["~/go/bin/gowitness","/usr/local/bin/gowitness",
                    "/opt/homebrew/bin/gowitness","/usr/bin/gowitness",
                    "/root/go/bin/gowitness"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"sshscan",    "apt_name":None,                "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/evict/SSHScan.git",
     "git_subdir":"",
     "install_note":"Clone to ~/SSHScan; run: pip install -r requirements.txt",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":None,
     "extra_paths":["~/SSHScan/sshscan","~/.local/bin/sshscan",
                    "/usr/local/bin/sshscan"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    # responder: bin may appear as 'responder' or 'Responder'
    {"bin":"responder",  "apt_name":"responder",         "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/lgandx/Responder.git",
     "git_subdir":"",
     "install_note":"May be installed as 'Responder' (capital R) via git clone",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"responder",
     "extra_paths":["~/Responder/Responder.py","~/Responder/responder",
                    "/usr/bin/responder","/usr/local/bin/responder",
                    "/usr/bin/Responder","/usr/local/bin/Responder"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"lsusb",      "apt_name":"usbutils",          "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only (usbutils)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"usbutils",
     "extra_paths":["/usr/bin/lsusb","/usr/local/bin/lsusb","/sbin/lsusb"],
     "interfaces":["USB"], "os_support":["linux"]},
    {"bin":"minicom",    "apt_name":"minicom",           "brew_name":"minicom",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"minicom",
     "extra_paths":["/usr/bin/minicom","/usr/local/bin/minicom",
                    "/opt/homebrew/bin/minicom"],
     "interfaces":["DB9"], "os_support":["linux","darwin"]},
    {"bin":"candump",    "apt_name":"can-utils",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only (can-utils)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"can-utils",
     "extra_paths":["/usr/bin/candump","/usr/local/bin/candump","/sbin/candump"],
     "interfaces":["DB9"], "os_support":["linux"]},
    {"bin":"canplayer",  "apt_name":"can-utils",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only (can-utils)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"can-utils",
     "extra_paths":["/usr/bin/canplayer","/usr/local/bin/canplayer"],
     "interfaces":["DB9"], "os_support":["linux"]},
    {"bin":"cansend",    "apt_name":"can-utils",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only (can-utils)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"can-utils",
     "extra_paths":["/usr/bin/cansend","/usr/local/bin/cansend"],
     "interfaces":["DB9"], "os_support":["linux"]},
    {"bin":"dnsmasq",    "apt_name":"dnsmasq",           "brew_name":"dnsmasq",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"DHCP server used during Ethernet assessment",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"dnsmasq",
     "extra_paths":["/usr/sbin/dnsmasq","/usr/local/sbin/dnsmasq","/usr/bin/dnsmasq"],
     "interfaces":["Ethernet"], "os_support":["linux"]},
    {"bin":"cec-client", "apt_name":"cec-utils",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only (cec-utils)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"cec-utils",
     "extra_paths":["/usr/bin/cec-client","/usr/local/bin/cec-client"],
     "interfaces":["HDMI","Dvi","sdi","Dp"], "os_support":["linux"]},
    {"bin":"get-edid",   "apt_name":"read-edid",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Linux only; on macOS EDID is read from IORegistry via system_profiler",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"read-edid",
     "extra_paths":["/usr/sbin/get-edid","/usr/bin/get-edid"],
     "interfaces":["HDMI","Dvi","Dp"], "os_support":["linux"]},
    {"bin":"edid-decode", "apt_name":"edid-decode",      "brew_name":"edid-decode",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"edid-decode",
     "extra_paths":["/usr/bin/edid-decode","/usr/local/bin/edid-decode",
                    "/opt/homebrew/bin/edid-decode"],
     "interfaces":["HDMI","Dvi","Dp"], "os_support":["linux","darwin"]},
    {"bin":"ddcutil",    "apt_name":"ddcutil",           "brew_name":"ddcutil",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"",  "required":False, "needs_sudo":False,
     "kali_apt_name":"ddcutil",
     "extra_paths":["/usr/bin/ddcutil","/usr/local/bin/ddcutil",
                    "/opt/homebrew/bin/ddcutil"],
     "interfaces":["HDMI","Dvi","Dp"], "os_support":["linux","darwin"]},
    {"bin":"pm3",        "apt_name":None,                "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/RfidResearchGroup/proxmark3.git",
     "git_subdir":"client",
     "install_note":"Built from source via cmake — see https://github.com/RfidResearchGroup/proxmark3",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"proxmark3",
     "extra_paths":[
         "/usr/local/bin/pm3",
         "~/proxmark3/client/pm3",
         "/usr/local/bin/proxmark3",
         "~/proxmark3/client/proxmark3",
         "/usr/bin/pm3",
         "/usr/bin/proxmark3",
         "/opt/homebrew/bin/pm3",
         "/opt/homebrew/bin/proxmark3",
     ],
     "bin_aliases":["proxmark3"],
     "interfaces":["RFID"], "os_support":["linux","darwin"]},
    {"bin":"git",        "apt_name":"git",               "brew_name":"git",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Required for git-based tool installs",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"git",
     "extra_paths":["/usr/bin/git","/usr/local/bin/git","/opt/homebrew/bin/git"],
     "interfaces":[], "os_support":["linux","darwin"]},
    {"bin":"ssh-audit",   "apt_name":"ssh-audit",         "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Install via: apt install ssh-audit",
     "required":False, "needs_sudo":False,
     "kali_apt_name":"ssh-audit",
     "extra_paths":["/usr/bin/ssh-audit","/usr/local/bin/ssh-audit",
                    "/usr/lib/ssh-audit/ssh-audit"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    {"bin":"shcheck.py", "apt_name":None,                "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/santoru/shcheck.git",
     "git_subdir":"",
     "install_note":"Clone to ~/shcheck and run: pip install requests",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":None,
     "extra_paths":["~/shcheck/shcheck.py","/usr/local/bin/shcheck.py",
                    "~/.local/bin/shcheck.py","/usr/bin/shcheck.py"],
     "interfaces":["Ethernet"], "os_support":["linux","darwin"]},
    # ── Bluetooth / BLE toolchain (see install.py Phase 4b) ──────────────────
    {"bin":"bluetoothctl", "apt_name":"bluez",              "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Core BlueZ stack — also provides hcitool/sdptool/l2ping/btmgmt/btmon",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"bluez",
     "extra_paths":["/usr/bin/bluetoothctl","/usr/local/bin/bluetoothctl"],
     "interfaces":["Bluetooth"], "os_support":["linux"]},
    {"bin":"btmgmt",     "apt_name":"bluez",                "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"BlueZ management CLI (pairing / sc / io-cap control)",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"bluez",
     "extra_paths":["/usr/bin/btmgmt","/usr/local/bin/btmgmt"],
     "interfaces":["Bluetooth"], "os_support":["linux"]},
    {"bin":"btmon",      "apt_name":"bluez",                "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"BlueZ HCI/SMP monitor — decoded pairing transcripts",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"bluez",
     "extra_paths":["/usr/bin/btmon","/usr/local/bin/btmon"],
     "interfaces":["Bluetooth"], "os_support":["linux"]},
    {"bin":"gatttool",   "apt_name":"bluez",                "brew_name":None,
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Deprecated GATT client (still shipped on Kali) — GATT read/write",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"bluez",
     "extra_paths":["/usr/bin/gatttool","/usr/local/bin/gatttool"],
     "interfaces":["Bluetooth"], "os_support":["linux"]},
    {"bin":"bettercap",  "apt_name":"bettercap",            "brew_name":"bettercap",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"BLE recon/enum/write (ble.* modules)",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"bettercap",
     "extra_paths":["/usr/bin/bettercap","/usr/local/bin/bettercap"],
     "interfaces":["Bluetooth"], "os_support":["linux","darwin"]},
    {"bin":"crackle",    "apt_name":"crackle",              "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/mikeryan/crackle.git",
     "git_subdir":"",
     "install_note":"BLE legacy-pairing TK/LTK cracker — built from source (make)",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":"crackle",
     "extra_paths":["/opt/crackle/crackle","/usr/local/bin/crackle","/usr/bin/crackle"],
     "interfaces":["Bluetooth"], "os_support":["linux"]},
    {"bin":"sniff_receiver.py", "apt_name":None,            "brew_name":None,
     "pip_name":None,
     "git_repo":"https://github.com/nccgroup/Sniffle.git",
     "git_subdir":"python_cli",
     "install_note":"Sniffle host CLI (TI CC1352/CC26x2) — crackle-ready LE capture",
     "required":False,   "needs_sudo":False,
     "kali_apt_name":None,
     "extra_paths":["/opt/Sniffle/python_cli/sniff_receiver.py",
                    "~/Sniffle/python_cli/sniff_receiver.py"],
     "interfaces":["Bluetooth"], "os_support":["linux","darwin"]},
    {"bin":"ubertooth-btle", "apt_name":"ubertooth",        "brew_name":"ubertooth",
     "pip_name":None,    "git_repo":None,  "git_subdir":"",
     "install_note":"Ubertooth One BLE sniffer (crackle-native pcap)",
     "required":False,   "needs_sudo":True,
     "kali_apt_name":"ubertooth",
     "extra_paths":["/usr/bin/ubertooth-btle","/usr/local/bin/ubertooth-btle"],
     "interfaces":["Bluetooth"], "os_support":["linux"]},
]

# ---------------------------------------------------------------------------
# Interface → Module mapping
# ---------------------------------------------------------------------------
INTERFACE_MODULES: dict[str, list[str]] = {
    "Ethernet":     ["Photo", "EthernetIface", "Ethtool", "ConfigDiscovery",
                     "TrafficCollector", "DhcpServer", "NmapLive", "Nessus", "Responder",
                     "NmapPort", "BannerGrab", "Web", "Nuclei", "SSL", "SSH", "FTP", "SMB", "NFS",
                     "EthernetCleanup"],
    "USB":          ["Photo", "UsbPower", "Keyboard", "KeyCombos", "Mouse", "BashBunny",
                     "UsbMassStorage", "UsbEthernetAdapter"],
    "Ethernet_tap": ["Photo", "Tcpdump_running", "Tcpdump_boot", "Tcpdump_shutdown"],
    "HDMI":         ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC", "HdmiHDCP", "HdmiCEC"],
    "Dvi":          ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC"],
    "sdi":          ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC", "HdmiHDCP", "HdmiCEC"],
    "Dp":           ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC", "HdmiHDCP", "HdmiCEC"],
    "Rca":          ["Photo", "Input", "Output"],
    "Aux":          ["Photo", "Input", "Output"],
    "Zigbee":       ["Photo", "Sniff", "Flood"],
    "Bluetooth":    ["Photo", "Bluetooth"],
    "DB9":          ["Photo", "SerialDetect", "CanAssess"],
    "WiFi":         ["Photo", "WiFi"],
    "SubGHz":       ["Photo", "SubGHz"],
    "UWB":          ["Photo", "UWB"],
    "SmartCard":    ["Photo", "SmartCard"],
    "ZWave":        ["Photo", "ZWave"],
    "LoRa":         ["Photo", "LoRa"],
    "RFID":         ["Photo", "RFIDSniff", "RFIDReplay"],
}

# Gearbox stdout prefixes (consumed by Flask app.py reader)
GB_PROMPT_PREFIX  = "__GB_PROMPT__:"

# ---------------------------------------------------------------------------
# EOL / CVE helpers
# ---------------------------------------------------------------------------

# End-of-life dates for common software.  Key = lowercase "product version_prefix".
# Add entries as needed; these are checked with startswith() after normalisation.
_EOL_SOFTWARE: dict[str, str] = {
    # OpenSSH — no EOL for individual releases, skip
    # Apache HTTP Server
    "apache 2.2":   "2017-12-31", "apache 2.0": "2013-07-10",
    "httpd 2.2":    "2017-12-31",
    # nginx
    "nginx 1.14":   "2019-04-16", "nginx 1.12": "2018-06-05",
    "nginx 1.10":   "2017-04-25",
    # PHP
    "php 5":        "2018-12-31", "php 7.0": "2019-01-10",
    "php 7.1":      "2019-12-01", "php 7.2": "2020-11-30",
    "php 7.3":      "2021-12-06", "php 7.4": "2022-11-28",
    # OpenSSL
    "openssl 1.0":  "2020-01-01", "openssl 1.1.0": "2019-09-11",
    # Python
    "python 2":     "2020-01-01", "python 3.6": "2021-12-23",
    "python 3.7":   "2023-06-27", "python 3.8": "2024-10-07",
    # Node.js
    "node 12":      "2022-04-30", "node 14": "2023-04-30",
    "node 16":      "2023-09-11",
    # Java / JDK
    "jdk 8":        "2030-12-31",   # LTS — still supported but flag for review
    "jdk 11":       "2026-09-30",
    # IIS
    "iis 6":        "2015-07-14", "iis 7": "2015-07-14",
    # Tomcat
    "tomcat 6":     "2016-12-31", "tomcat 7": "2021-03-31",
    "tomcat 8.0":   "2018-06-30",
    # MySQL
    "mysql 5.5":    "2018-12-31", "mysql 5.6": "2021-02-28",
    # PostgreSQL
    "postgresql 9":  "2020-11-12", "postgresql 10": "2022-11-10",
    "postgresql 11": "2023-11-09",
    # Samba
    "samba 4.6":    "2018-03-13", "samba 4.7": "2018-09-12",
    # ProFTPD
    "proftpd 1.2":  "2009-11-01", "proftpd 1.3.0": "2010-01-01",
    # vsftpd
    "vsftpd 2":     "2012-06-30",
    # Postfix
    "postfix 2":    "2019-01-01",
    # Exim
    "exim 4.8":     "2017-04-21",
    # BIND
    "bind 9.10":    "2019-12-31", "bind 9.11": "2021-12-31",
    # Redis
    "redis 3":      "2019-12-31", "redis 4": "2020-12-31",
    # MongoDB
    "mongodb 3":    "2020-01-07", "mongodb 4.0": "2022-04-30",
    # Memcached
    "memcached 1.4": "2019-10-30",
    # VsFTPd  
    "dropbear 2015": "2019-01-01", "dropbear 2016": "2019-01-01",
}

_EOL_OS: dict[str, str] = {
    # Ubuntu
    "ubuntu 14":    "2019-04-30", "ubuntu 16": "2021-04-30",
    "ubuntu 18":    "2023-04-30", "ubuntu 20": "2025-04-30",
    "ubuntu 21.10": "2022-07-14", "ubuntu 22.10": "2023-07-20",
    # Debian
    "debian 7":     "2018-06-17", "debian 8": "2020-06-30",
    "debian 9":     "2022-06-30", "debian 10": "2024-06-30",
    # CentOS
    "centos 5":     "2017-03-31", "centos 6": "2020-11-30",
    "centos 7":     "2024-06-30", "centos 8": "2021-12-31",
    # RHEL
    "rhel 5":       "2020-11-30", "rhel 6": "2024-06-30",
    "red hat 5":    "2020-11-30", "red hat 6": "2024-06-30",
    # Windows Server
    "windows server 2003": "2015-07-14",
    "windows server 2008": "2020-01-14",
    "windows server 2012": "2023-10-10",
    # Windows Desktop
    "windows xp":   "2014-04-08", "windows vista": "2017-04-11",
    "windows 7":    "2020-01-14", "windows 8": "2016-01-12",
    "windows 8.1":  "2023-01-10",
    # macOS
    "macos 10.14":  "2021-10-25", "macos 10.15": "2022-10-24",
    "mac os x 10.8": "2015-08-01",
    # FreeBSD
    "freebsd 10":   "2018-10-31", "freebsd 11": "2021-09-30",
    # OpenBSD
    "openbsd 6.4":  "2019-10-17", "openbsd 6.5": "2020-05-19",
    # Android
    "android 4":    "2019-01-01", "android 5": "2019-01-01",
    "android 6":    "2020-01-01", "android 7": "2021-01-01",
}


def _check_eol_software(name: str, version: str) -> tuple[bool, str]:
    """Return (is_eol, eol_date) for a software name+version."""
    key = f"{name.lower()} {version.lower()}"
    for prefix, date in _EOL_SOFTWARE.items():
        if key.startswith(prefix):
            return True, date
    return False, ""


def _check_eol_os(os_name: str, os_version: str) -> tuple[bool, str]:
    """Return (is_eol, eol_date) for an OS name+version."""
    key = f"{os_name.lower()} {os_version.lower()}"
    for prefix, date in _EOL_OS.items():
        if key.startswith(prefix):
            return True, date
    return False, ""


def _lookup_cves(product: str, version: str, max_results: int = 5) -> list[dict]:
    """
    Query osv.dev for known CVEs/vulnerabilities for a product+version.
    Returns a list of {id, summary, severity, url} dicts.
    Falls back to NVD if osv.dev returns nothing.
    Non-blocking: returns [] on any network error.
    """
    if not requests:
        return []
    results: list[dict] = []
    # ── OSV.dev (no API key, good coverage) ──────────────────────────────
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"version": version, "package": {"name": product,
                                                    "ecosystem": ""}},
            timeout=10, verify=False)
        if resp.ok:
            for vuln in resp.json().get("vulns", [])[:max_results]:
                vid = vuln.get("id", "")
                summary = (vuln.get("summary") or
                           vuln.get("details", "")[:120])
                severity = ""
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        try:
                            score = float(sev.get("score", "0").split("/")[0].split("S:")[-1] or "0")
                            if score >= 9.0:   severity = "Critical"
                            elif score >= 7.0: severity = "High"
                            elif score >= 4.0: severity = "Medium"
                            else:              severity = "Low"
                        except Exception:
                            pass
                        break
                cve_url = f"https://osv.dev/vulnerability/{vid}"
                if vid.startswith("CVE-"):
                    cve_url = f"https://nvd.nist.gov/vuln/detail/{vid}"
                results.append({
                    "id": vid, "summary": summary,
                    "severity": severity or "Medium", "url": cve_url,
                })
    except Exception:
        pass
    # ── NVD fallback — only if osv returned nothing and product looks meaningful ──
    if not results and len(product) > 3:
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": f"{product} {version}",
                        "resultsPerPage": max_results},
                timeout=12, verify=False)
            if resp.ok:
                for item in resp.json().get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    vid = cve.get("id", "")
                    descs = cve.get("descriptions", [])
                    summary = next((d["value"] for d in descs
                                    if d.get("lang") == "en"), "")[:120]
                    metrics = cve.get("metrics", {})
                    severity = ""
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        mlist = metrics.get(key, [])
                        if mlist:
                            severity = mlist[0].get("cvssData", {}).get(
                                "baseSeverity", "").title()
                            break
                    results.append({
                        "id": vid, "summary": summary,
                        "severity": severity or "Medium",
                        "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
                    })
        except Exception:
            pass
    return results


def _parse_ssh_banner(banner_str: str) -> tuple[str, str, str, str]:
    """
    Parse an SSH version banner like 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5'.
    Returns (ssh_software, ssh_version, os_name, os_version).
    Examples:
      'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5'
        → ('OpenSSH', '8.2p1', 'Ubuntu', '4ubuntu0.5')
      'SSH-2.0-dropbear_2020.81'
        → ('Dropbear SSH', '2020.81', '', '')
      'OpenSSH 8.9p1'
        → ('OpenSSH', '8.9p1', '', '')
    """
    # Strip the SSH protocol prefix if present
    s = re.sub(r'^SSH-\d+\.\d+-', '', banner_str.strip(), flags=re.I)

    ssh_software = ""
    ssh_version  = ""
    os_name      = ""
    os_version   = ""

    # OpenSSH: OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    m = re.match(r'OpenSSH[_\s](\S+?)(?:\s+(.+))?$', s, re.I)
    if m:
        ssh_software = "OpenSSH"
        ssh_version  = m.group(1).lstrip('_')
        os_part      = (m.group(2) or "").strip()
    else:
        # Dropbear: dropbear_2020.81
        m2 = re.match(r'dropbear[_\s](\S+)', s, re.I)
        if m2:
            ssh_software = "Dropbear SSH"
            ssh_version  = m2.group(1).lstrip('_')
            os_part      = ""
        else:
            # Generic: SoftwareName_or_Name version
            m3 = re.match(r'([A-Za-z]\w+)[_\s](\d[\d.p\-]+\w*)(.*)?', s)
            if m3:
                ssh_software = m3.group(1)
                ssh_version  = m3.group(2)
                os_part      = (m3.group(3) or "").strip()
            else:
                return "", "", "", ""

    # Parse OS part: "Ubuntu-4ubuntu0.5", "Debian-9+deb9u7", "FreeBSD-amd64"
    if os_part:
        os_map = {
            r'ubuntu':   "Ubuntu",
            r'debian':   "Debian",
            r'raspbian': "Raspbian",
            r'centos':   "CentOS",
            r'rhel|red\s*hat': "Red Hat Enterprise Linux",
            r'fedora':   "Fedora",
            r'freebsd':  "FreeBSD",
            r'openbsd':  "OpenBSD",
            r'netbsd':   "NetBSD",
            r'gentoo':   "Gentoo",
            r'arch':     "Arch Linux",
            r'alpine':   "Alpine Linux",
            r'suse|opensuse': "openSUSE",
            r'windows':  "Windows",
            r'macos|darwin': "macOS",
        }
        # Strip leading/trailing dashes
        os_clean = os_part.lstrip('- ').rstrip()
        for pattern, name in os_map.items():
            if re.search(pattern, os_clean, re.I):
                os_name = name
                # Extract version number after the os name or dash
                vm = re.search(r'[-_\s](\d[\d.+~]+)', os_clean)
                if vm:
                    os_version = vm.group(1)
                    # Simplify: "4ubuntu0.5" → just the leading version number
                    simple = re.match(r'(\d+[\.\d]*)', os_version)
                    if simple:
                        os_version = simple.group(1)
                break
        # If no OS matched, the part may be architecture or distro-specific data — skip it
    return ssh_software, ssh_version, os_name, os_version



# ---------------------------------------------------------------------------
# NessusConfig — encrypted credential storage in config.yaml
# ---------------------------------------------------------------------------

class NessusConfig:
    """
    Manages Nessus credentials in a per-user config.yaml file.

    Location:   ~/.config/gearbox/config.yaml
    Key file:   ~/.config/gearbox/.nessus_key  (auto-generated on first run)

    The password is encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
    If the `cryptography` package is not available, a base64 obfuscation
    fallback is used with a prominent warning.

    Public API:
        load()            -> (user: str, pwd: str) | (None, None)
        save(user, pwd)   -> None
        clear()           -> None  (remove stored credentials)
    """

    _CONFIG_DIR  = Path.home() / ".config" / "gearbox"
    _CONFIG_FILE = _CONFIG_DIR / "config.yaml"
    _KEY_FILE    = _CONFIG_DIR / ".nessus_key"

    # ── Encryption helpers ────────────────────────────────────────────────

    @classmethod
    def _get_or_create_key(cls) -> bytes:
        cls._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if cls._KEY_FILE.exists():
            return cls._KEY_FILE.read_bytes().strip()
        try:
            from cryptography.fernet import Fernet  # cryptography — PyCA team (https://cryptography.io)
            key = Fernet.generate_key()
        except ImportError:
            # Fallback: derive a pseudo-key from machine identifiers
            import hashlib, platform
            seed = platform.node() + str(Path.home()) + "gearbox_nessus"
            raw  = hashlib.sha256(seed.encode()).digest()
            import base64
            key  = base64.urlsafe_b64encode(raw)
        cls._KEY_FILE.write_bytes(key)
        cls._KEY_FILE.chmod(0o600)
        return key

    @classmethod
    def _encrypt(cls, plaintext: str) -> str:
        try:
            from cryptography.fernet import Fernet
            f = Fernet(cls._get_or_create_key())
            return f.encrypt(plaintext.encode()).decode()
        except ImportError:
            import base64
            # Obfuscation-only fallback (not true encryption)
            return "b64:" + base64.b64encode(plaintext.encode()).decode()

    @classmethod
    def _decrypt(cls, ciphertext: str) -> str:
        if ciphertext.startswith("b64:"):
            import base64
            return base64.b64decode(ciphertext[4:]).decode()
        try:
            from cryptography.fernet import Fernet
            f = Fernet(cls._get_or_create_key())
            return f.decrypt(ciphertext.encode()).decode()
        except Exception:
            return ""

    # ── Public API ────────────────────────────────────────────────────────

    @classmethod
    def load(cls) -> tuple:
        """Return (username, password) from config.yaml, or (None, None)."""
        if not cls._CONFIG_FILE.exists():
            return None, None
        try:
            if yaml is None:
                return None, None
            with open(cls._CONFIG_FILE, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            nessus = cfg.get("nessus", {})
            user   = nessus.get("username", "").strip()
            enc    = nessus.get("password_enc", "").strip()
            if not user or not enc:
                return None, None
            pwd = cls._decrypt(enc)
            return (user, pwd) if pwd else (None, None)
        except Exception as e:
            console.log(f"Could not read Nessus config: {e}", "WARNING")
            return None, None

    @classmethod
    def save(cls, username: str, password: str) -> None:
        """Encrypt password and write credentials to config.yaml."""
        cls._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Preserve any existing non-nessus config keys
        existing: dict = {}
        if cls._CONFIG_FILE.exists():
            try:
                if yaml is not None:
                    with open(cls._CONFIG_FILE, encoding="utf-8") as f:
                        existing = yaml.safe_load(f) or {}
            except Exception:
                pass
        existing["nessus"] = {
            "username":     username,
            "password_enc": cls._encrypt(password),
        }
        if yaml is not None:
            with open(cls._CONFIG_FILE, "w", encoding="utf-8") as f:
                yaml.dump(existing, f, default_flow_style=False)
            cls._CONFIG_FILE.chmod(0o600)
            console.log(
                f"Nessus credentials saved to {cls._CONFIG_FILE}", "INFO")
        else:
            console.log("PyYAML not available — cannot save config.yaml", "WARNING")

    @classmethod
    def clear(cls) -> None:
        """Remove stored Nessus credentials."""
        if not cls._CONFIG_FILE.exists():
            return
        try:
            if yaml is not None:
                with open(cls._CONFIG_FILE, encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                cfg.pop("nessus", None)
                with open(cls._CONFIG_FILE, "w", encoding="utf-8") as f:
                    yaml.dump(cfg, f, default_flow_style=False)
        except Exception as e:
            console.log(f"Could not clear Nessus config: {e}", "WARNING")

GB_STATUS_PREFIX  = "__GB_STATUS__:"
GB_FINDING_PREFIX = "__GB_FINDING__:"

# ---------------------------------------------------------------------------
# Finding title acronym normalisation
# ---------------------------------------------------------------------------

# Acronyms that must appear in ALL CAPS in finding titles.
# Add entries here to expand coverage across all modules.
_TITLE_ACRONYMS: tuple[str, ...] = (
    "HTTP", "HTTPS", "SSL", "TLS", "FTP", "FTPS", "SFTP", "SSH",
    "SMB", "NFS", "RDP", "VPN", "DNS", "DHCP", "SNMP", "LDAP", "LDAPS",
    "API", "RPC", "RCE", "SQL", "XSS", "SSRF", "LFI", "RFI", "XXE",
    "IDOR", "CSRF", "JWT", "CORS", "PHP", "ASP", "JSP",
    "CVE", "CWE", "CVSS", "NVD",
    "OT", "ICS", "SCADA", "PLC", "HMI",
    "TCP", "UDP", "IP", "MAC", "ARP", "ICMP", "OSPF", "BGP",
    "MFA", "SSO", "SAML", "OAUTH",
    "RC4", "DES", "AES", "RSA", "MD5", "SHA",
    "NTLM", "HSTS", "CSP", "SAN", "CN", "CA",
    "IIS", "CMS", "CRS",
    "URL", "URI", "UUID", "HTML", "XML", "JSON", "YAML",
    "OS", "CPU", "AWS", "GCP", "OTP",
)

# Build a word-boundary pattern once
_ACRONYM_RE = re.compile(
    r'\b(' + '|'.join(re.escape(a) for a in _TITLE_ACRONYMS) + r')\b',
    re.IGNORECASE,
)


def _fix_acronyms(text: str) -> str:
    """
    Uppercase any known acronym that appears as a whole word in *text*.
    Call this on any finding title after title-casing or other transforms.

    Examples:
        "Weak Tls Configuration"  → "Weak TLS Configuration"
        "Http Response Splitting" → "HTTP Response Splitting"
        "ssl/tls — Rc4 Cipher"   → "SSL/TLS — RC4 Cipher"
    """
    return _ACRONYM_RE.sub(lambda m: m.group(0).upper(), text)

GB_LOG_PREFIX     = "__GB_LOG__:"
GB_OBS_PREFIX     = "__GB_OBSERVATION__:"

# Concurrency limits
# Concurrency limits tuned for Raspberry Pi 5 (4× Cortex-A76, 16 GB RAM).
# 16 GB doubles the memory headroom, allowing more parallel tool instances.
# CPU is still 4 cores, so CPU-bound tasks stay conservatively limited.
_PHASE_SEMAPHORE_COUNT = 8   # max concurrent phase-2 module threads per instance

# ── Global subprocess gate ───────────────────────────────────────────────────
# Hard ceiling on total live child processes across ALL threads.
# Nessus (HTTP only), Responder (Popen), and every run_tool() call count.
# Threads block waiting for a slot rather than forking unbounded processes.
_MAX_SUBPROCS = 15
_subproc_sem  = threading.Semaphore(_MAX_SUBPROCS)

# ── Per-subprocess memory limit ──────────────────────────────────────────────
_SUBPROCESS_MEM_LIMIT_BYTES = int(2 * 1024 ** 3)  # 2 GB per child process

def _mem_limit_preexec():
    """preexec_fn: cap each child's virtual address space to prevent OOM."""
    if sys.platform == "win32":
        return
    try:
        import resource as _rlim
        _rlim.setrlimit(_rlim.RLIMIT_AS,
                        (_SUBPROCESS_MEM_LIMIT_BYTES, _SUBPROCESS_MEM_LIMIT_BYTES))
    except (AttributeError, ValueError, OSError):
        pass

# ── OOM watchdog ─────────────────────────────────────────────────────────────
_tracked_procs: list = []
_tracked_procs_lock = threading.Lock()

def _track_proc(proc):
    with _tracked_procs_lock:
        _tracked_procs.append(proc)

def _start_oom_watchdog(threshold_pct=90, interval=15):
    """Kill the largest tracked subprocess when system memory exceeds threshold."""
    try:
        import psutil as _psw
    except ImportError:
        return None

    def _watchdog():
        while True:
            try:
                time.sleep(interval)
                mem = _psw.virtual_memory()
                if mem.percent < threshold_pct:
                    continue
                with _tracked_procs_lock:
                    _tracked_procs[:] = [p for p in _tracked_procs if p.poll() is None]
                    live = list(_tracked_procs)
                if not live:
                    continue
                biggest, biggest_rss = None, 0
                for p in live:
                    try:
                        pi = _psw.Process(p.pid)
                        rss = pi.memory_info().rss
                        if rss > biggest_rss:
                            biggest, biggest_rss = p, rss
                    except (_psw.NoSuchProcess, _psw.AccessDenied, OSError):
                        pass
                if biggest and biggest_rss > 100 * 1024 * 1024:
                    try:
                        biggest.kill()
                    except OSError:
                        pass
            except Exception:
                pass

    _t = threading.Thread(target=_watchdog, daemon=True, name="gb-oom-watchdog")
    _t.start()
    return _t

# Per-subsystem concurrency caps (RPi 5, 4 cores, 16 GB RAM)
# Adjust these if running on more capable hardware.
_MAX_NMAP_PORT_WORKERS     = 3    # parallel nmap port scans  (I/O + CPU heavy)
_MAX_PER_HOST_WORKERS      = 6    # hosts assessed in parallel after port scan
_MAX_BANNER_GRAB_WORKERS   = 20   # simultaneous TCP socket banner grabs (I/O-bound)
_MAX_WEB_WORKERS           = 6    # parallel URL assessments (nuclei/gowitness)
_MAX_SSH_WORKERS           = 5    # parallel SSH tests
_MAX_SMB_WORKERS           = 4    # parallel SMB tests
_MAX_NFS_WORKERS           = 4    # parallel NFS tests
_MAX_TRAFFIC_WORKERS       = 2    # tcpdump + tshark (2 tools, always concurrent)


# Module-level optional imports (populated by _load_optional_imports)
yaml     = None
requests = None
qrcode   = None

# ---------------------------------------------------------------------------
# OS / Distro Detection
# ---------------------------------------------------------------------------

def _is_kali_linux() -> bool:
    """Return True if running on Kali Linux."""
    try:
        with open('/etc/os-release') as f:
            return 'kali' in f.read().lower()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Sudo password cache + helpers
# ---------------------------------------------------------------------------

_sudo_password: str = ""


def _get_sudo_password() -> str:
    """
    Return a cached sudo password, trying the Nessus config.yaml password first.
    Only prompts the user if the stored password fails validation.
    """
    global _sudo_password
    if _sudo_password:
        return _sudo_password

    # Try the Nessus password from config.yaml — users often use the same password
    _, nessus_pass = NessusConfig.load()
    if nessus_pass:
        try:
            result = subprocess.run(
                ["sudo", "-S", "-v"],
                input=nessus_pass + "\n",
                capture_output=True, text=True, timeout=15,
            )
            combined = (result.stdout + result.stderr).lower()
            if result.returncode == 0 or "timestamp updated" in combined:
                _sudo_password = nessus_pass
                console.log("Sudo authenticated using Nessus credentials.", "INFO")
                return _sudo_password
        except Exception:
            pass

    for attempt in range(3):
        suffix = f" (attempt {attempt + 1}/3)" if attempt else ""
        pwd = console.prompt(
            f"Elevated privileges (sudo) are required for this operation.{suffix}\n"
            "  Enter your sudo password:",
            prompt_type="password",
        ).strip()

        if not pwd:
            continue

        # Validate immediately with sudo -S -v
        try:
            result = subprocess.run(
                ["sudo", "-S", "-v"],
                input=pwd + "\n",
                capture_output=True,
                text=True,
                timeout=15,
            )
            combined = (result.stdout + result.stderr).lower()
            if result.returncode == 0 or "timestamp updated" in combined:
                _sudo_password = pwd
                console.log("Sudo authentication successful.", "INFO")
                return _sudo_password
            if ("incorrect password" in combined or "sorry" in combined
                    or "authentication failure" in combined):
                console.log("Sudo password incorrect — please try again.", "ERROR")
                continue
            # Non-password failure — accept and let real command surface the error
            _sudo_password = pwd
            return _sudo_password
        except Exception:
            _sudo_password = pwd
            return _sudo_password

    console.log("Sudo authentication failed after 3 attempts.", "ERROR")
    return ""


def _sudo_run(cmd: list[str], timeout: int = 300,
              cwd: Optional[str] = None) -> tuple[bool, str]:
    """Run a command with sudo, injecting the cached password via stdin."""
    pwd      = _get_sudo_password()
    full_cmd = ["sudo", "-S"] + cmd
    _subproc_sem.acquire()
    try:
        result = subprocess.run(
            full_cmd, input=pwd + "\n",
            capture_output=True, text=True, timeout=timeout,
            cwd=cwd,
        )
        output = (result.stdout + result.stderr).strip()
        combined_lower = output.lower()
        if result.returncode != 0 and (
            "incorrect password" in combined_lower
            or "sorry, try again" in combined_lower
            or "authentication failure" in combined_lower
        ):
            global _sudo_password
            _sudo_password = ""
            console.log(
                "Sudo authentication failed. Password cleared — "
                "will re-prompt on next attempt.", "ERROR")
        return result.returncode == 0, output
    except FileNotFoundError:
        return False, "sudo not found"
    except Exception as e:
        return False, str(e)
    finally:
        _subproc_sem.release()


# ---------------------------------------------------------------------------
# Git-clone install  (cmake detected FIRST)
# ---------------------------------------------------------------------------

def _git_clone_install(tool: dict) -> bool:
    """
    Clone a git repository to ~/repo_name and build/install it.

    Build strategy — tried in the order that makes sense for each project type:
      0. cmake project (CMakeLists.txt present) — detected FIRST
         Runs: cmake configure → cmake build → sudo cmake install
         Covers proxmark3 and any other cmake-based C project.
      1. Binary already present after clone (pre-built / script)
      2. setup.py install --user  (Python projects)
      3. autogen.sh → ./configure → make → sudo make install  (autotools)
      4. make → sudo make install  (plain Makefile)

    After any successful install every known install directory is added to
    os.environ["PATH"] so the binary is reachable for the rest of the session.
    """
    repo_url  = tool["git_repo"]
    bin_name  = tool["bin"]
    subdir    = tool.get("git_subdir", "")
    home      = Path.home()
    repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
    clone_dir = home / repo_name

    def _add_to_path(directory: str) -> None:
        cur = os.environ.get("PATH", "")
        if directory not in cur.split(os.pathsep):
            os.environ["PATH"] = directory + os.pathsep + cur

    def _enrich_paths_after_install() -> None:
        for d in [
            "/usr/local/bin", "/usr/local/sbin", "/usr/bin",
            str(clone_dir / subdir) if subdir else str(clone_dir),
            str(clone_dir),
        ]:
            _add_to_path(d)

    # ── Clone ─────────────────────────────────────────────────────────────
    console.log(f"Cloning {repo_url} to {clone_dir}...", "INFO")
    if not clone_dir.exists():
        ok, out = _run_install_cmd(
            ["git", "clone", "--depth=1", repo_url, str(clone_dir)])
        if not ok:
            console.log(f"git clone failed: {out[:200]}", "WARNING")
            return False

    bin_dir = str(clone_dir / subdir) if subdir else str(clone_dir)
    _add_to_path(bin_dir)
    _add_to_path(str(clone_dir))

    # ── 0. cmake project — detected FIRST ─────────────────────────────────
    cmake_lists = clone_dir / "CMakeLists.txt"
    if cmake_lists.exists():
        if not shutil.which("cmake"):
            console.log(
                f"'{repo_name}' requires cmake which is not installed. "
                "Install cmake (apt-get install cmake / brew install cmake) "
                "and re-run.", "WARNING")
            return False

        build_dir = clone_dir / "_build"
        build_dir.mkdir(exist_ok=True)

        console.log(f"Configuring {repo_name} with cmake...", "INFO")
        ok, out = _run_install_cmd(
            ["cmake", "-DCMAKE_INSTALL_PREFIX=/usr/local", ".."],
            cwd=str(build_dir))
        if not ok:
            console.log(f"cmake configure failed: {out[:300]}", "WARNING")
            return False

        cpus = str(os.cpu_count() or 2)
        console.log(f"Building {repo_name} (--parallel {cpus})...", "INFO")
        ok, out = _run_install_cmd(
            ["cmake", "--build", ".", "--parallel", cpus],
            cwd=str(build_dir))
        if not ok:
            console.log(f"cmake build failed: {out[:300]}", "WARNING")
            return False

        console.log(f"Installing {repo_name} (sudo cmake --install)...", "INFO")
        ok2, out2 = _sudo_run(["cmake", "--install", "."], cwd=str(build_dir))
        _enrich_paths_after_install()

        if ok2:
            if tool_available(bin_name):
                found = shutil.which(bin_name) or f"/usr/local/bin/{bin_name}"
                console.log(f"'{bin_name}' installed via cmake → {found}", "INFO")
                return True
            console.log(
                f"cmake install succeeded but '{bin_name}' not found — "
                f"checking in-tree at {bin_dir}", "WARNING")
        else:
            console.log(f"cmake --install failed: {out2[:300]}", "WARNING")

        if tool_available(bin_name):
            console.log(f"'{bin_name}' available in build tree at {bin_dir}.", "INFO")
            return True
        return False

    # ── 1. Already available ───────────────────────────────────────────────
    if shutil.which(bin_name):
        console.log(f"Tool '{bin_name}' available at {bin_dir}", "INFO")
        return True

    # ── 2. Python project — setup.py ──────────────────────────────────────
    setup_py = clone_dir / "setup.py"
    if setup_py.exists():
        console.log(f"Running setup.py for {repo_name}...", "INFO")
        ok, _ = _run_install_cmd(
            [sys.executable, str(setup_py), "install", "--user"])
        _add_to_path(str(home / ".local" / "bin"))
        if ok and shutil.which(bin_name):
            return True

    # ── 3. Autotools C project ─────────────────────────────────────────────
    autogen   = clone_dir / "autogen.sh"
    configure = clone_dir / "configure"

    if autogen.exists():
        if sys.platform == "darwin" and not shutil.which("automake"):
            console.log("automake required — installing via Homebrew...", "INFO")
            if shutil.which("brew"):
                ok, out = _run_install_cmd(["brew", "install", "automake"])
                if ok:
                    console.log("automake installed.", "INFO")
                else:
                    console.log(f"brew install automake failed: {out[:200]}", "WARNING")
            else:
                console.log("Homebrew not found. Install automake manually.", "WARNING")
        console.log(f"Running autogen.sh for {repo_name}...", "INFO")
        ok, out = _run_install_cmd(["bash", "autogen.sh"], cwd=str(clone_dir))
        if not ok:
            console.log(f"autogen.sh failed: {out[:200]}", "WARNING")

    if configure.exists() and not (clone_dir / "Makefile").exists():
        console.log(f"Running ./configure for {repo_name}...", "INFO")
        ok, out = _run_install_cmd(["./configure"], cwd=str(clone_dir))
        if not ok:
            console.log(f"./configure failed: {out[:200]}", "WARNING")

    # ── 4. make → sudo make install ───────────────────────────────────────
    if (clone_dir / "Makefile").exists():
        console.log(f"Running make for {repo_name}...", "INFO")
        ok, out = _run_install_cmd(["make"], cwd=str(clone_dir))
        if ok:
            console.log(f"Running sudo make install for {repo_name}...", "INFO")
            ok2, out2 = _sudo_run(["make", "install"], cwd=str(clone_dir))
            _enrich_paths_after_install()
            if ok2 and shutil.which(bin_name):
                console.log(f"Tool '{bin_name}' installed via make.", "INFO")
                return True
            if not ok2:
                console.log(f"make install failed: {out2[:200]}", "WARNING")
                if shutil.which(bin_name):
                    return True
        else:
            console.log(f"make failed: {out[:200]}", "WARNING")

    if tool_available(bin_name):
        return True

    console.log(
        f"'{bin_name}' not found after clone/build. "
        f"Manual setup may be needed: {tool.get('install_note', '')}",
        "WARNING")
    return False


# ---------------------------------------------------------------------------
# Go toolchain helper + go install
# ---------------------------------------------------------------------------

def _ensure_go() -> tuple[bool, str]:
    """
    Ensure the Go toolchain is available.

    Search order:
      1. 'go' already in PATH
      2. Common install locations (/usr/local/go/bin, ~/go/bin, brew/snap paths)
      3. Offer to install:
           Linux  → apt-get install golang-go  (fallback: snap install go --classic)
           macOS  → brew install go             (fallback: prompt for manual install)

    Returns (available: bool, go_binary_path: str).
    """
    _go_dirs = [
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        str(Path.home() / "go" / "bin"),
        "/snap/bin",
        "/usr/local/go/bin",  # official tarball install
    ]

    def _add_to_path(d: str) -> None:
        if d not in os.environ.get("PATH", "").split(os.pathsep):
            os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")

    def _refresh_go_bin() -> Optional[str]:
        """Re-scan for 'go' after an install attempt."""
        for d in _go_dirs:
            candidate = os.path.join(d, "go")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                _add_to_path(d)
                # Also ensure GOPATH/bin is in PATH so installed binaries work
                gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
                _add_to_path(os.path.join(gopath, "bin"))
                return candidate
        return shutil.which("go")

    # 1. Already in PATH
    go_bin = shutil.which("go")
    if go_bin:
        gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
        _add_to_path(os.path.join(gopath, "bin"))
        return True, go_bin

    # 2. Common install locations
    found = _refresh_go_bin()
    if found:
        console.log(f"Found Go at {found} — added to PATH.", "INFO")
        return True, found

    # 3. Offer to install
    console.log("Go (golang) is not installed — needed for nuclei, gowitness, etc.",
                "WARNING")

    if sys.platform.startswith("linux"):
        choice = console.prompt(
            "Go is not installed.\n"
            "  Install it now?",
            options=["Yes — apt-get install golang-go",
                     "Yes — snap install go --classic",
                     "No — skip Go tools"],
            prompt_type="choice",
        )

        if choice in ("1",) or "apt" in choice.lower():
            ok, out = _sudo_run(["apt-get", "install", "-y", "golang-go"])
            if ok:
                _add_to_path("/usr/bin")
                found = _refresh_go_bin()
                if found:
                    console.log("Go installed via apt successfully.", "INFO")
                    return True, found
            console.log(f"apt install of golang-go failed: {out[:200]}", "WARNING")

        elif choice in ("2",) or "snap" in choice.lower():
            ok, out = _sudo_run(["snap", "install", "go", "--classic"])
            if ok:
                _add_to_path("/snap/bin")
                found = _refresh_go_bin()
                if found:
                    console.log("Go installed via snap successfully.", "INFO")
                    return True, found
            console.log(f"snap install go failed: {out[:200]}", "WARNING")

    elif sys.platform == "darwin":
        if shutil.which("brew"):
            choice = console.prompt(
                "Go is not installed.\n  Install via Homebrew?",
                options=["Yes — brew install go", "No — skip"],
                prompt_type="choice",
            )
            if choice.startswith("Yes") or choice == "1":
                ok, out = _sudo_run(["brew", "install", "go"])
                if ok:
                    _add_to_path("/opt/homebrew/bin")
                    found = _refresh_go_bin()
                    if found:
                        console.log("Go installed via Homebrew successfully.", "INFO")
                        return True, found
                console.log(f"brew install go failed: {out[:200]}", "WARNING")
        else:
            console.log(
                "On macOS install Go from https://go.dev/dl/ or install Homebrew first.",
                "WARNING")

    return False, ""


def _go_install(tool: dict) -> bool:
    """
    Install a tool via `go install <pkg>`.

    Tries the primary go_pkg first. If it fails with a pseudo-version error,
    each entry in go_pkg_fallbacks is attempted in order.
    """
    bin_name  = tool["bin"]
    go_pkg    = tool.get("go_pkg", "")
    fallbacks = tool.get("go_pkg_fallbacks", [])

    if not go_pkg and not fallbacks:
        console.log(
            f"No go_pkg defined for '{bin_name}'. Cannot install via Go.", "WARNING")
        return False

    go_avail, go_bin = _ensure_go()
    if not go_avail:
        console.log(
            f"Go toolchain not available. Cannot install '{bin_name}' via go install.",
            "WARNING")
        return False

    gopath     = os.environ.get("GOPATH") or str(Path.home() / "go")
    go_bin_dir = os.path.join(gopath, "bin")
    if go_bin_dir not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = go_bin_dir + os.pathsep + os.environ.get("PATH", "")

    def _try_pkg(pkg: str) -> bool:
        console.log(f"Running: sudo go install {pkg}", "INFO")
        ok, out = _sudo_run([go_bin or "go", "install", pkg])
        if not ok:
            if "v0.0.0-" in out or "no Go files" in out:
                console.log(
                    f"  '{pkg}' resolved to a pseudo-version or has no main "
                    f"package — trying next candidate.", "WARNING")
            else:
                console.log(
                    f"  go install failed for '{bin_name}' [{pkg}]: "
                    f"{out[:200]}", "WARNING")
            return False
        if tool_available(bin_name):
            found = shutil.which(bin_name) or os.path.join(go_bin_dir, bin_name)
            console.log(
                f"'{bin_name}' installed via go install [{pkg}] → {found}", "INFO")
            return True
        direct = os.path.join(go_bin_dir, bin_name)
        if os.path.isfile(direct) and os.access(direct, os.X_OK):
            console.log(f"'{bin_name}' built to {direct} via [{pkg}].", "INFO")
            return True
        console.log(
            f"  go install [{pkg}] exited cleanly but '{bin_name}' not found "
            f"in {go_bin_dir} — likely a module root with no cmd package.",
            "WARNING")
        return False

    if go_pkg and _try_pkg(go_pkg):
        return True
    for pkg in fallbacks:
        if _try_pkg(pkg):
            return True

    console.log(
        f"All go install attempts failed for '{bin_name}'. "
        f"Tried: {', '.join([go_pkg] + fallbacks)}", "WARNING")
    return False


# ---------------------------------------------------------------------------
# _install_tool  (dispatch to correct method)
# ---------------------------------------------------------------------------

def _install_tool(tool: dict, method: str) -> bool:
    """Install a system tool via the given method."""
    bin_name = tool["bin"]
    console.log(f"Installing '{bin_name}' via {method}...", "INFO")

    if method == "apt":
        # Resolve the correct apt package name (kali_apt_name takes priority on Kali)
        is_kali = _is_kali_linux()
        apt_pkg = (tool.get("kali_apt_name") or tool["apt_name"]) if is_kali else tool["apt_name"]
        ok, out = _sudo_run(["apt-get", "install", "-y", apt_pkg])
        if not ok:
            console.log(f"apt-get install failed: {out[:200]}", "WARNING")
            return False
    elif method == "brew":
        ok, out = _run_install_cmd(["brew", "install", tool["brew_name"]])
        if not ok:
            console.log(f"brew install failed: {out[:200]}", "WARNING")
            return False
    elif method == "go":
        return _go_install(tool)
    elif method == "pip":
        pip_pkg = tool.get("pip_name")
        if not pip_pkg:
            return False
        ok, out = _run_install_cmd(
            [sys.executable, "-m", "pip", "install",
             pip_pkg, "--break-system-packages", "--quiet"])
        if not ok:
            ok, out = _run_install_cmd(
                [sys.executable, "-m", "pip", "install", pip_pkg, "--quiet"])
        if not ok:
            console.log(f"pip install failed: {out[:200]}", "WARNING")
            return False
    elif method == "git":
        return _git_clone_install(tool)
    else:
        return False

    return tool_available(bin_name)


# ---------------------------------------------------------------------------
# _auto_install_video_tool  (silent install for video/HDMI modules)
# ---------------------------------------------------------------------------

def _auto_install_video_tool(bin_name: str) -> bool:
    """
    Silently install a video/HDMI testing tool if it is not already present.
    Resolves the tool definition from REQUIRED_TOOLS and selects apt (Linux)
    or brew (macOS) automatically.  Returns True if the tool is available
    after the attempt.
    """
    if tool_available(bin_name):
        return True
    tool_def = next((t for t in REQUIRED_TOOLS if t["bin"] == bin_name), None)
    if not tool_def:
        return False
    is_mac   = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")
    if is_linux and tool_def.get("apt_name"):
        _install_tool(tool_def, "apt")
    elif is_mac and tool_def.get("brew_name") and shutil.which("brew"):
        _install_tool(tool_def, "brew")
    return tool_available(bin_name)


# ---------------------------------------------------------------------------
# _ensure_i2c_dev  (load kernel module + install i2c-tools if needed)
# ---------------------------------------------------------------------------

def _ensure_i2c_dev() -> bool:
    """
    Ensure the i2c-dev kernel module is loaded so that ddcutil can access
    /dev/i2c-* buses.  Called on Linux only before any DDC operation.

    Steps:
      1. If /dev/i2c-* devices already exist, return True immediately.
      2. Try 'modprobe i2c-dev' via sudo to load the kernel module.
      3. If modprobe fails or /dev/i2c-* still absent, install i2c-tools
         via apt (which includes udev rules that auto-load i2c-dev).
      4. Return True if /dev/i2c-* devices are visible afterwards.
    """
    if sys.platform != "linux" and not sys.platform.startswith("linux"):
        return True  # macOS uses IORegistry — no i2c-dev needed

    import glob as _glob

    def _i2c_present() -> bool:
        return bool(_glob.glob("/dev/i2c-*"))

    if _i2c_present():
        return True

    console.log("i2c-dev: no /dev/i2c-* devices found — loading kernel module…", "INFO")
    ok, out = _sudo_run(["modprobe", "i2c-dev"], timeout=15)
    if ok and _i2c_present():
        console.log("i2c-dev kernel module loaded successfully.", "INFO")
        return True

    if not ok:
        console.log(f"modprobe i2c-dev failed: {out[:120]}", "WARNING")

    # Fallback: install i2c-tools (brings in udev rules that load i2c-dev)
    console.log("Attempting to install i2c-tools via apt…", "INFO")
    ok2, out2 = _sudo_run(["apt-get", "install", "-y", "i2c-tools"], timeout=120)
    if not ok2:
        console.log(f"i2c-tools install failed: {out2[:120]}", "WARNING")

    # One more attempt after potential install
    ok3, _ = _sudo_run(["modprobe", "i2c-dev"], timeout=15)
    if _i2c_present():
        console.log("i2c-dev available after i2c-tools install.", "INFO")
        return True

    console.log("i2c-dev could not be loaded — DDC/CI test requires /dev/i2c-* devices.", "WARNING")
    return False


# ---------------------------------------------------------------------------
# check_and_install_tools  (Kali-aware priority)
# ---------------------------------------------------------------------------

def check_and_install_tools(interfaces_in_scope: list[str]) -> bool:
    """
    Check all system tools needed for the interfaces being tested.
    Tools not supported on the current OS are silently skipped.

    Install method priority:
      Kali Linux  : apt (Kali repos carry most security tools) → go → git → pip
      Other Linux : apt → go → git → pip
      macOS       : brew → go → git → pip

    Returns False only if a required tool could not be installed.
    """
    is_mac   = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")
    platform = "darwin" if is_mac else ("linux" if is_linux else "")
    is_kali  = _is_kali_linux()

    if is_kali:
        console.log("Kali Linux detected — apt repos take priority for tool installation.", "INFO")

    scope_set = set(interfaces_in_scope)

    tools_to_check = [
        t for t in REQUIRED_TOOLS
        if (not t["interfaces"] or bool(set(t["interfaces"]) & scope_set))
        and (not t.get("os_support") or
             any(platform.startswith(p) for p in t["os_support"]))
    ]

    missing = [t for t in tools_to_check if not tool_available(t["bin"])]

    if not missing:
        console.log("All required system tools are present.", "INFO")
        return True

    console.log(
        f"System tool check: {len(missing)} tool(s) not found in PATH.", "WARNING")
    for t in missing:
        tag    = "[REQUIRED]" if t["required"] else "[optional]"
        ifaces = ", ".join(t["interfaces"]) or "all"
        console.log(f"  {t['bin']:<20} {tag}  interfaces: {ifaces}", "WARNING")

    skip_all = False

    for tool in missing:
        if skip_all:
            break

        bin_name = tool["bin"]
        required = tool["required"]
        tag      = "REQUIRED" if required else "optional"
        note     = f"\n  Note: {tool['install_note']}" if tool["install_note"] else ""
        ifaces   = ", ".join(tool["interfaces"]) or "general testing"

        # Resolve apt package name — prefer kali_apt_name on Kali
        apt_pkg = (tool.get("kali_apt_name") or tool["apt_name"]) if is_kali else tool["apt_name"]

        choice = console.prompt(
            f"Tool '{bin_name}' is not installed. ({tag})\n"
            f"  Needed for: {ifaces}{note}\n"
            f"  Install it now?",
            options=["Yes -- install now",
                     "No -- skip this tool",
                     "Skip all remaining tools"],
            prompt_type="choice",
        )

        if "skip all" in choice.lower() or choice == "3":
            skip_all = True
            if required:
                console.log(f"FATAL: '{bin_name}' is required. Cannot continue.", "ERROR")
                return False
            break

        if choice.lower().startswith("no") or choice == "2":
            if required:
                console.log(f"FATAL: '{bin_name}' is required. Cannot continue.", "ERROR")
                return False
            continue

        # Build install method priority list
        methods: list[str] = []
        if is_linux and apt_pkg:
            methods.append("apt")
        if is_mac and tool["brew_name"] and shutil.which("brew"):
            methods.append("brew")
        if tool.get("go_pkg"):
            # On Kali: only add go if no apt package available
            if not is_kali or not apt_pkg:
                methods.append("go")
        if tool["git_repo"] and shutil.which("git"):
            methods.append("git")
        if tool["pip_name"]:
            methods.append("pip")

        if not methods:
            console.log(
                f"No automatic install method for '{bin_name}'. "
                f"{tool['install_note']}", "WARNING")
            if required:
                return False
            continue

        installed = False
        for i, method in enumerate(methods):
            if _install_tool(tool, method):
                installed = True
                break
            if i < len(methods) - 1:
                next_m = methods[i + 1]
                fb = console.prompt(
                    f"'{method}' install of '{bin_name}' failed.\n"
                    f"  Try via {next_m}?",
                    options=[f"Yes -- try {next_m}", "No -- skip"],
                    prompt_type="choice",
                )
                if fb.lower().startswith("no") or fb == "2":
                    break

        if not installed and required:
            console.log(
                f"FATAL: Could not install required tool '{bin_name}'.", "ERROR")
            return False
        if not installed:
            console.log(
                f"Optional tool '{bin_name}' unavailable -- "
                f"related tests will be skipped.", "WARNING")

    return True


# ---------------------------------------------------------------------------
# _run_install_cmd  (with permission-error detection + sudo escalation)
# ---------------------------------------------------------------------------

def _run_install_cmd(cmd: list[str], cwd: Optional[str] = None) -> tuple[bool, str]:
    """
    Run an installation command; return (success, output).

    If the command fails with a permission / EACCES error, the user is prompted
    to retry with sudo.
    """
    _PERMISSION_MARKERS = (
        "permission denied", "eacces", "operation not permitted",
        "cannot create", "cannot write", "read-only file system",
        "access denied", "insufficient permissions",
    )

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=cwd)
        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return True, output

        output_lower = output.lower()
        needs_elevation = any(m in output_lower for m in _PERMISSION_MARKERS)

        if needs_elevation:
            console.log(
                f"Command '{cmd[0]}' failed with a permission error.\n"
                f"  Snippet: {output[:180]}",
                "WARNING",
            )
            choice = console.prompt(
                f"Install of '{cmd[0]}' requires elevated permissions.\n"
                f"  Retry with sudo?",
                options=["Yes -- retry with sudo", "No -- skip"],
                prompt_type="choice",
            )
            if choice.startswith("Yes") or choice == "1":
                ok, sudo_out = _sudo_run(cmd, cwd=cwd)
                return ok, sudo_out

        return False, output

    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Python package installation helpers
# ---------------------------------------------------------------------------

def _try_import(name: str) -> bool:
    """Return True if the named module can be imported."""
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _install_package(pkg: dict, method: str) -> bool:
    """
    Install a single Python package using the given method ('brew', 'apt', 'pip').
    Returns True if installation succeeded and the import now works.
    """
    import_name = pkg["import_name"]
    pip_name    = pkg["pip_name"]
    apt_name    = pkg["apt_name"]
    brew_name   = pkg.get("brew_name")

    console.log(f"Installing {pip_name} via {method}...", "INFO")

    if method == "brew":
        if not brew_name:
            return False
        ok, out = _run_install_cmd(["brew", "install", brew_name])
        if not ok:
            console.log(f"brew install failed: {out[:200]}", "WARNING")
            return False
    elif method == "apt":
        if not apt_name:
            return False
        ok, out = _sudo_run(["apt-get", "install", "-y", apt_name])
        if not ok:
            console.log(f"apt-get install failed: {out[:200]}", "WARNING")
            return False
    elif method == "pip":
        ok, out = _run_install_cmd(
            [sys.executable, "-m", "pip", "install",
             pip_name, "--break-system-packages", "--quiet"])
        if not ok:
            ok, out = _run_install_cmd(
                [sys.executable, "-m", "pip", "install", pip_name, "--quiet"])
        if not ok:
            console.log(f"pip install failed: {out[:200]}", "WARNING")
            return False
    else:
        return False

    return _try_import(import_name)


def check_and_install_packages() -> bool:
    """
    Run at startup (before the console banner). For each missing package,
    prompt the user via console.prompt() so the Flask app displays a popup,
    or falls back to a TTY prompt when run standalone.

    Installation order:
      Kali Linux : apt-get first (avoids PEP 668 pip conflicts), then pip
      Other Linux: apt-get first, then pip --break-system-packages
      macOS      : Homebrew first, then pip --break-system-packages

    Returns False only if a *required* package could not be installed.
    """
    is_mac   = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")
    is_kali  = _is_kali_linux()

    if is_kali:
        console.log("Kali Linux — using apt for Python packages to avoid PEP 668 conflicts.", "INFO")

    missing = [p for p in REQUIRED_PACKAGES if not _try_import(p["import_name"])]
    if not missing:
        return True

    console.log(
        f"Dependency check: {len(missing)} package(s) not installed.", "WARNING")
    for p in missing:
        tag = "REQUIRED" if p["required"] else "optional"
        console.log(
            f"  {p['pip_name']:<24} [{tag}] -- {p['description']}", "WARNING")

    skip_all = False

    for pkg in missing:
        if skip_all:
            break

        pip_name = pkg["pip_name"]
        required = pkg["required"]
        tag      = "REQUIRED" if required else "optional"

        choice = console.prompt(
            f"Package '{pip_name}' is not installed.\n"
            f"  Purpose : {pkg['description']} ({tag})\n"
            f"  Install it now?",
            options=[
                "Yes -- install now",
                "No -- skip this package",
                "Skip all remaining packages",
            ],
            prompt_type="choice",
        )

        choice_lower = choice.lower()

        if "skip all" in choice_lower or choice == "3":
            console.log("Skipping all remaining package installations.", "WARNING")
            skip_all = True
            if required:
                console.log(
                    f"FATAL: '{pip_name}' is required and cannot be skipped.", "ERROR")
                return False
            break

        if choice_lower.startswith("no") or choice == "2":
            if required:
                console.log(f"FATAL: '{pip_name}' is required. Cannot continue.", "ERROR")
                return False
            console.log(f"Skipping optional package '{pip_name}'.", "WARNING")
            continue

        installed = False

        if is_mac:
            methods = []
            if shutil.which("brew") and pkg.get("brew_name"):
                methods.append("brew")
            methods.append("pip")
        elif is_linux:
            methods = []
            if shutil.which("apt-get") and pkg.get("apt_name"):
                methods.append("apt")
            methods.append("pip")
        else:
            methods = ["pip"]

        for i, method in enumerate(methods):
            if _install_package(pkg, method):
                installed = True
                break
            if i < len(methods) - 1:
                next_m = methods[i + 1]
                fb = console.prompt(
                    f"'{method}' installation of '{pip_name}' failed.\n"
                    f"  Try via {next_m} instead?",
                    options=[f"Yes -- try {next_m}", "No -- skip"],
                    prompt_type="choice",
                )
                if fb.lower().startswith("no") or fb == "2":
                    break

        if not installed and required:
            console.log(
                f"FATAL: Could not install required package '{pip_name}'.", "ERROR")
            return False
        if not installed:
            console.log(
                f"Optional package '{pip_name}' could not be installed -- "
                f"related features will be disabled.", "WARNING")

    return True

def get_all_interfaces() -> list:
    """
    Return a list of dicts [{name, ip}] for every non-loopback IPv4 interface.
    Used to generate per-interface join URLs for photo prompts.
    """
    def _is_usable(ip: str) -> bool:
        return not ip.startswith('127.') and not ip.startswith('169.254.')

    results = []
    try:
        import netifaces as _ni
        for iface in _ni.interfaces():
            for addr in _ni.ifaddresses(iface).get(_ni.AF_INET, []):
                ip = addr.get('addr', '')
                if ip and _is_usable(ip):
                    results.append({'name': iface, 'ip': ip})
        if results:
            return results
    except Exception:
        pass

    try:
        out = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=4)
        iface_name = ''
        for line in out.splitlines():
            m = re.match(r'^\d+:\s+(\S+):', line)
            if m:
                iface_name = m.group(1).rstrip(':')
            m2 = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if m2 and iface_name:
                ip = m2.group(1)
                if _is_usable(ip):
                    results.append({'name': iface_name, 'ip': ip})
        if results:
            return results
    except Exception:
        pass

    ip = get_local_ip()
    if ip and _is_usable(ip):
        results.append({'name': 'eth0', 'ip': ip})
    return results or [{'name': 'lo', 'ip': '127.0.0.1'}]




def _load_optional_imports() -> None:
    """
    Re-import soft-dependency modules after the package check has run.
    Sets module-level globals used throughout the script.
    """
    global yaml, requests, qrcode
    try:
        import yaml as _yaml  # PyYAML — Kirill Simonov & PyYAML team (https://pyyaml.org) — YAML project config parsing
        yaml = _yaml
    except ImportError:
        pass
    try:
        import requests as _req  # requests — Python Requests (https://docs.python-requests.org) — Nessus REST API calls and NVD/OSV CVE enrichment
        requests = _req
    except ImportError:
        pass
    try:
        import qrcode as _qr  # qrcode — Lincoln Loop (https://github.com/lincolnloop/python-qrcode) — QR code generation for photo upload prompts
        qrcode = _qr
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# get_local_ip
# ---------------------------------------------------------------------------

def _get_server_ips() -> set:
    """
    Return a set of ALL IPv4 addresses assigned to any of this machine's
    network interfaces (excluding loopback).  Used to update gearbox's own
    host from the scan scope so it is never treated as a target.

    Resolution order (all sources merged):
      1. `ip -4 addr show`  — most reliable on modern Linux/Kali
      2. netifaces library  — if installed
      3. socket.getaddrinfo fallback
    """
    ips: set = set()

    # ── 1. `ip addr` parsing ─────────────────────────────────────────────
    try:
        import subprocess as _sp, re as _re
        r = _sp.run(["ip", "-4", "addr", "show"],
                    capture_output=True, text=True, timeout=5)
        for m in _re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout):
            addr = m.group(1)
            if not addr.startswith("127."):
                ips.add(addr)
    except Exception:
        pass

    # ── 2. netifaces ─────────────────────────────────────────────────────
    try:
        import netifaces as _ni
        for iface in _ni.interfaces():
            for addr in _ni.ifaddresses(iface).get(_ni.AF_INET, []):
                ip = addr.get("addr", "")
                if ip and not ip.startswith("127."):
                    ips.add(ip)
    except ImportError:
        pass
    except Exception:
        pass

    # ── 3. hostname fallback ──────────────────────────────────────────────
    try:
        import socket as _sock
        hostname = _sock.gethostname()
        for info in _sock.getaddrinfo(hostname, None, _sock.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    return ips


def _pcap_has_external_traffic(pcap_path, server_ips: set) -> bool:
    """
    Return True if *pcap_path* contains at least one IP packet whose source
    or destination is NOT in *server_ips*.

    Uses tshark to extract ip.src / ip.dst fields.  If tshark is unavailable
    the function returns True (conservative — assume external traffic exists).

    Multicast (224.0.0.0/4), limited broadcast (255.255.255.255), and
    link-local (169.254.0.0/16) addresses are ignored; they are not indicative
    of a real external device.
    """
    if not shutil.which("tshark"):
        return True   # can't check — assume external traffic

    _IGNORED = re.compile(
        r'^(22[4-9]|2[3-5]\d)\.'        # multicast  224-255.x.x.x
        r'|^255\.255\.255\.255$'         # broadcast
        r'|^169\.254\.'                  # link-local APIPA
        r'|^127\.'                       # loopback
    )

    try:
        import subprocess as _sp
        r = _sp.run(
            ["tshark", "-r", str(pcap_path),
             "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-q"],
            capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            for ip in line.split():
                ip = ip.strip()
                if not ip or _IGNORED.match(ip):
                    continue
                if ip not in server_ips:
                    return True
    except Exception:
        return True   # conservative on error

    return False


def _get_interface_ips(iface: str) -> set:
    """
    Return a set of IPv4 addresses assigned specifically to *iface*.
    Used so that only the designated test interface's own IP is excluded
    from nmap scope — not IPs from other adapters or VPNs.
    """
    ips: set = set()
    try:
        import subprocess as _sp, re as _re
        r = _sp.run(["ip", "-4", "addr", "show", iface],
                    capture_output=True, text=True, timeout=5)
        for m in _re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout):
            addr = m.group(1)
            if not addr.startswith("127."):
                ips.add(addr)
    except Exception:
        pass
    return ips


# ---------------------------------------------------------------------------
# Ethernet shutdown cleanup registry
# ---------------------------------------------------------------------------
# _active_ethernet_ctxs holds ModuleContext objects for every Ethernet
# instance currently being assessed.  _run_ethernet_modules registers a ctx
# on entry and removes it on exit (via try/finally).
#
# _ethernet_shutdown_cleanup() is called by the SIGINT/SIGTERM handler and by
# the "Cancel" option so that any in-flight Responder process is killed and
# any running Nessus scan is told to stop before the process exits.
# ---------------------------------------------------------------------------

_active_ethernet_ctxs: list = []


def _ethernet_shutdown_cleanup() -> None:
    """
    Called on SIGINT, SIGTERM, or user Cancel during Ethernet assessment.
    For every active Ethernet context:
      1. Reverts the test interface if DhcpServer reconfigured it
         (kills dnsmasq, flushes static IP, requests a new DHCP lease).
      2. Kills any running Responder subprocess.
      3. Tells Nessus to stop any scan that was started by gearbox.
    """
    for ctx in list(_active_ethernet_ctxs):
        # ── Revert interface if DhcpServer ran ───────────────────────────
        if ctx.config.get("_dhcp_server_ran"):
            iface = ctx.config.get(
                "_dhcp_server_iface",
                ctx.config.get("test_interface", "eth0"))

            # Kill dnsmasq
            pid = ctx.config.get("_dhcp_proc_pid")
            if pid:
                try:
                    os.kill(pid, 15)   # SIGTERM
                    time.sleep(1)
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass
                except Exception:
                    pass

            # Flush the static IP assigned for DHCP serving
            try:
                subprocess.run(
                    ["ip", "addr", "flush", "dev", iface],
                    capture_output=True, timeout=10)
            except Exception:
                pass

            # Request a new lease to restore normal connectivity
            if shutil.which("dhclient"):
                try:
                    subprocess.run(
                        ["dhclient", iface],
                        capture_output=True, timeout=30)
                except Exception:
                    pass
            elif shutil.which("dhcpcd"):
                try:
                    subprocess.run(
                        ["dhcpcd", iface],
                        capture_output=True, timeout=30)
                except Exception:
                    pass

            ctx.config.pop("_dhcp_server_ran",   None)
            ctx.config.pop("_dhcp_server_iface", None)
            ctx.config.pop("_dhcp_proc_pid",     None)

        # ── Kill Responder ────────────────────────────────────────────────
        stop_event = getattr(ctx, '_responder_stop_event', None)
        if stop_event:
            try:
                stop_event.set()
            except Exception:
                pass
        responder_proc = getattr(ctx, '_responder_proc', None)
        if responder_proc:
            try:
                responder_proc.terminate()
            except Exception:
                pass
            try:
                responder_proc.kill()
            except Exception:
                pass

        # ── Stop Nessus scan via API ──────────────────────────────────────
        scan_id   = getattr(ctx, '_nessus_scan_id',   None)
        token     = getattr(ctx, '_nessus_token',     None)
        api_token = getattr(ctx, '_nessus_api_token', None)
        if scan_id and token and api_token:
            try:
                import requests as _nreq
                _nreq.post(
                    f"https://127.0.0.1:8834/scans/{scan_id}/stop",
                    headers={
                        "X-Cookie":    f"token={token}",
                        "X-API-Token": api_token,
                        "Connection":  "close",
                        "Content-Type": "application/json",
                    },
                    verify=False, timeout=10)
            except Exception:
                pass


def _interface_has_dhcp_server_ip(iface: str) -> bool:
    """Return True if *iface* currently holds the DhcpServer gateway address."""
    try:
        r = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5)
        return "192.168.4." in r.stdout
    except Exception:
        return False


def _revert_test_iface(iface: str, pid: int | None = None, logger=None) -> None:
    """
    Revert *iface* from DHCP-server mode back to a normal DHCP-client state:
      1. Terminate dnsmasq (by tracked pid, then pkill as fallback).
      2. Flush all addresses from the interface.
      3. Request a fresh DHCP lease via dhclient / dhcpcd (best-effort).
    Safe to call even if the interface was never reconfigured.
    """
    def _log(msg):
        if logger:
            logger.info(msg, tool="ip")

    # Kill tracked dnsmasq pid
    if pid:
        try:
            os.kill(pid, 15)
            time.sleep(1)
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            _log(f"dnsmasq (pid={pid}) terminated")
        except ProcessLookupError:
            pass
        except Exception as e:
            _log(f"Could not kill dnsmasq pid={pid}: {e}")

    # Fallback: pkill any stray dnsmasq bound to this interface
    try:
        subprocess.run(["pkill", "-f", f"dnsmasq.*{iface}"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    # Flush all static addresses
    try:
        subprocess.run(
            ["ip", "addr", "flush", "dev", iface],
            capture_output=True, timeout=10)
        _log(f"Flushed addresses from {iface}")
    except Exception as e:
        _log(f"ip addr flush failed: {e}")

    # Re-request DHCP lease
    if shutil.which("dhclient"):
        try:
            subprocess.run(["dhclient", iface], capture_output=True, timeout=30)
            _log(f"dhclient requested new lease on {iface}")
        except Exception as e:
            _log(f"dhclient failed: {e}")
    elif shutil.which("dhcpcd"):
        try:
            subprocess.run(["dhcpcd", iface], capture_output=True, timeout=30)
            _log(f"dhcpcd requested new lease on {iface}")
        except Exception as e:
            _log(f"dhcpcd failed: {e}")


def get_local_ip() -> str:
    """
    Return the machine's primary LAN IP address (not loopback, not external).

    Strategy:
    1. Enumerate all network interfaces via netifaces if available.
    2. UDP connect trick to private broadcast addresses (no packet sent).
    3. Parse /proc/net/fib_trie on Linux.
    4. gethostbyname fallback.
    """
    import socket as _socket
    try:
        # UDP connect trick — no packet is actually sent
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        return _socket.gethostbyname(_socket.gethostname())
    except Exception:
        return "127.0.0.1"


def _list_ethernet_interfaces() -> list:
    """
    Return a sorted list of physical/ethernet-like interface names on the host.
    Excludes loopback, common virtual, tunnel, and wireless prefixes.
    Uses 'ip link show' on Linux; 'ifconfig -l' on macOS/BSD as fallback.
    """
    import re as _re

    candidates: list = []

    # ── Linux: ip link show ───────────────────────────────────────────────
    try:
        r = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            m = _re.match(r'^\d+:\s+(\S+?)[@:]', line)
            if not m:
                continue
            name = m.group(1)
            # Skip loopback and well-known virtual / wireless prefixes
            skip_prefixes = (
                "lo", "veth", "docker", "br-", "virbr", "dummy",
                "tun", "tap", "wlan", "wlp", "wl", "ppp",
            )
            if name == "lo" or any(name.startswith(p) for p in skip_prefixes):
                continue
            candidates.append(name)
    except Exception:
        pass

    # ── macOS / BSD: ifconfig -l ──────────────────────────────────────────
    if not candidates:
        try:
            r = subprocess.run(
                ["ifconfig", "-l"],
                capture_output=True, text=True, timeout=5,
            )
            skip_prefixes = (
                "lo", "utun", "gif", "stf", "XHC", "ap", "bridge",
                "p2p", "awdl", "llw", "ppp",
            )
            for name in r.stdout.split():
                if any(name.startswith(p) for p in skip_prefixes):
                    continue
                candidates.append(name)
        except Exception:
            pass

    return sorted(set(candidates))


# ---------------------------------------------------------------------------
# Console  (module-level singleton for structured output)
# ---------------------------------------------------------------------------

class Console:
    """
    Unified output channel for gearbox.

    In subprocess mode (stdout is not a TTY — i.e. launched by app.py):
      all messages are prefixed with protocol tokens (__GB_LOG__:, etc.)
      so the Flask reader can parse and route them to the correct buffers.

    In TTY mode (direct terminal execution):
      messages are printed as human-readable coloured text.
    """

    def __init__(self) -> None:
        self._tty  = sys.stdout.isatty()
        self._lock = threading.Lock()
        self._runlog = None   # §13b/§14j: run-dir EventLogger, attached in main()

    def attach_run_dir(self, run_dir) -> None:
        """§13b/§14j/§14k: bring up the on-disk audit log for this run and record
        the tool's own version as a startup EVENT. Console.log()/status_update()
        forward here so every message + phase transition is persisted with a
        timestamp (the __GB_* token stream is ephemeral / live-UI only)."""
        if _el is None:
            return
        try:
            self._runlog = _el.EventLogger(Path(run_dir) / "scan.log",
                                            errors_path=Path(run_dir) / "errors.log")
            self._runlog.event(f"GearBox v{VERSION} started")
        except Exception:
            self._runlog = None

    def start(self) -> None:
        """Initialise the display. Call once at script start."""
        if not self._tty:
            console.log(f"GearBox v{VERSION} — starting in subprocess mode", "INFO")
            return
        self._render_banner()

    def log(self, message: str, level: str = "INFO") -> None:
        # §13b: persist every message to the run-dir audit log with a timestamp.
        if self._runlog is not None:
            try:
                lv = (level or "INFO").upper()
                if lv == "ERROR":     self._runlog.error(message)
                elif lv == "WARNING": self._runlog.warn(message)
                else:                 self._runlog.info(message)
            except Exception:
                pass
        with self._lock:
            if not self._tty:
                sys.stdout.write(GB_LOG_PREFIX + f"[{level}] {message}\n")
                sys.stdout.flush()
            else:
                colours = {
                    "INFO":    "\033[0m",
                    "WARNING": "\033[33m",
                    "ERROR":   "\033[31m",
                    "SUCCESS": "\033[32m",
                    "DEBUG":   "\033[36m",
                }
                c   = colours.get(level, "\033[0m")
                rst = "\033[0m"
                print(f"{c}[{level}]{rst} {message}")

    def prompt(
        self,
        question:        str,
        options:         list[str] = None,
        prompt_type:     str = "text",   # text | choice | file | confirm | password
        skippable:       bool = False,
        prompt_id:       Optional[str] = None,
        join_url:        str = "",
        join_interfaces: list = None,
    ) -> str:
        """
        Prompt the user for input.
        In Flask mode: emit __GB_PROMPT__ JSON and block reading stdin.
        In TTY mode: use input() / getpass() with option display.
        For file prompts, join_url is included in the payload and a QR code
        is printed to the terminal if qrcode is available.
        For password prompts, input is masked in TTY (getpass) and the Flask
        modal renders a password-type input field.
        """
        options = list(options) if options else []
        if skippable and options:
            options = options + ["Skip"]
        elif skippable:
            options = ["Skip"]

        pid = prompt_id or str(uuid.uuid4())
        payload = {
            "id":              pid,
            "question":        question,
            "type":            prompt_type,
            "options":         options,
            "required":        not skippable,
            "skippable":       skippable,
            "join_url":        join_url,
            "join_interfaces": join_interfaces or [],
        }

        with self._lock:
            if not self._tty:
                sys.stdout.write(GB_PROMPT_PREFIX + json.dumps(payload) + "\n")
                sys.stdout.flush()
            else:
                print()
                print(f"  ┌─ PROMPT {'─' * 60}")
                print(f"  │  {question}")
                if options:
                    for i, opt in enumerate(options, 1):
                        print(f"  │  [{i}] {opt}")
                if prompt_type == "file" and join_url:
                    print(f"  │")
                    print(f"  │  📱 Mobile join URL: {join_url}")
                    if qrcode:
                        try:
                            _qr = qrcode.QRCode(border=1)
                            _qr.add_data(join_url)
                            _qr.make(fit=True)
                            import io as _io
                            buf = _io.StringIO()
                            _qr.print_ascii(out=buf, invert=True)
                            for qr_line in buf.getvalue().splitlines():
                                print(f"  │  {qr_line}")
                        except Exception:
                            pass
                    else:
                        print(f"  │  (install 'qrcode[pil]' to display QR code)")
                print(f"  └{'─' * 68}")

        try:
            if prompt_type == "password" and self._tty:
                # TTY: getpass masks the input at the terminal level
                import getpass as _getpass
                raw = _getpass.getpass("  Password (hidden): ").strip()
            elif prompt_type == "password" and not self._tty:
                # Flask mode: __GB_PROMPT__ JSON was already written to stdout.
                # Use readline() NOT input() — input() echoes characters back to
                # stdout, exposing the password in the console stream.
                raw = sys.stdin.readline().rstrip("\n").strip()
            else:
                raw = input().strip()
        except (EOFError, KeyboardInterrupt):
            raw = ""

        if options and raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                raw = options[idx]

        return raw

    def status_update(
        self,
        subdevice: str,
        interface: str,
        instance:  str,
        module:    str,
        status:    str,
        detail:    str = "",
    ) -> None:
        """Emit a module status update (consumed by Flask or printed to TTY)."""
        payload = {
            "subdevice": subdevice,
            "interface": interface,
            "instance":  instance,
            "module":    module,
            "status":    status,
            "detail":    detail,
            "timestamp": datetime.now().isoformat(),
        }
        # §14j: persist the phase/module transition to the audit log with a
        # timestamp (the __GB_STATUS__ token below is ephemeral / live-UI only).
        if self._runlog is not None:
            try:
                self._runlog.event(
                    f"phase {interface}/{instance}/{module}: {status}"
                    + (f" — {detail}" if detail else ""))
            except Exception:
                pass
        if not self._tty:
            sys.stdout.write(GB_STATUS_PREFIX + json.dumps(payload) + "\n")
            sys.stdout.flush()
        else:
            sym = {"complete": "✓", "error": "✗", "running": "→",
                   "skipped": "~", "na": "—"}.get(status, "·")
            print(f"  {sym} [{interface}/{instance}] {module}: {status.upper()}"
                  + (f" — {detail}" if detail else ""))

    def emit_observation(
        self,
        title:       str,
        description: str,
        tool:        str  = "",
        tool_version:str  = "",
        output_file: str  = "",
        output_text: str  = "",
        risk:        str  = "",
    ) -> None:
        """
        Emit a structured observation (tool output finding of note).
        In Flask mode: written as __GB_OBSERVATION__: JSON so the reader
        stores it in the observations buffer and emits it to all clients.
        In TTY mode: printed to the terminal.
        """
        payload = {
            "title":    title,
            "desc":     description,
            "tool":     tool,
            "version":  tool_version,
            "file":     output_file,
            "output":   output_text[:2000],
            "risk":     risk,
            "type":     "observation",
        }
        if not self._tty:
            sys.stdout.write(GB_OBS_PREFIX + json.dumps(payload) + "\n")
            sys.stdout.flush()
        else:
            sym = "🔍"
            print(f"\n  {sym} OBSERVATION [{tool}]: {title}")
            if description:
                print(f"     {description[:120]}")

    def emit_finding(self, finding_dict: dict) -> None:
        """Emit a finding (consumed by Flask or printed to TTY)."""
        if not self._tty:
            sys.stdout.write(GB_FINDING_PREFIX + json.dumps(finding_dict) + "\n")
            sys.stdout.flush()
        else:
            risk  = finding_dict.get("risk", "Unknown")
            title = finding_dict.get("title", "")
            print(f"\n  ⚠ FINDING [{risk}]: {title}")

    def _emit_text(self, text: str) -> None:
        if not self._tty:
            sys.stdout.write(GB_LOG_PREFIX + text + "\n")
            sys.stdout.flush()
        else:
            print(text)

    def _render_banner(self) -> None:
        lines = [
            "╔══════════════════════════════════════════════════╗",
            f"║      GearBox v{VERSION}  — Gauntlet Platform        ║",
            "║      Device Security Assessment Orchestrator      ║",
            "╚══════════════════════════════════════════════════╝",
        ]
        for line in lines:
            print(line)
        print()


# Module-level console singleton (used by all helpers above)
console = Console()


# ---------------------------------------------------------------------------
# GearboxLogger
# ---------------------------------------------------------------------------

class GearboxLogger:
    """Per-instance structured logger — wraps console output with context."""

    def __init__(self, ctx: "ModuleContext") -> None:
        self.ctx = ctx

    def info(self, message: str, tool: str = "") -> None:
        console.log(self._fmt(message, tool), "INFO")

    def warn(self, message: str, tool: str = "") -> None:
        console.log(self._fmt(message, tool), "WARNING")

    def error(self, message: str, exc: Optional[Exception] = None,
              tool: str = "") -> None:
        msg = self._fmt(message, tool)
        if exc:
            msg += f" [{type(exc).__name__}: {exc}]"
        console.log(msg, "ERROR")

    def record_observation(self, title: str, description: str,
                           tool: str = "", tool_version: str = "",
                           output_file: str = "", output_text: str = "",
                           risk: str = "") -> None:
        console.emit_observation(
            title=title, description=description,
            tool=tool, tool_version=tool_version,
            output_file=output_file, output_text=output_text,
            risk=risk,
        )

    def record_finding(self, title: str, description: str, tool: str = "",
                       risk: str = "Unknown", raw_output: str = "") -> None:
        ctx = self.ctx
        ctx.findings.create(
            ctx=ctx,
            title=title,
            description=description,
            tool=tool,
            raw_output=raw_output,
            source_type="primary",
            force_risk=risk,
        )

    def cmd(self, cmd_list: list[str], tool: str = "") -> None:
        console.log(f"$ {' '.join(cmd_list)}", "DEBUG")

    def _fmt(self, message: str, tool: str = "") -> str:
        ctx = self.ctx
        prefix = f"[{ctx.interface}/{ctx.instance_key}]"
        if tool:
            prefix += f"[{tool}]"
        return f"{prefix} {message}"

# ---------------------------------------------------------------------------
# Source + Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Source:
    source_type: str = "primary"   # primary | secondary
    tool:        str = ""
    evidence:    str = ""
    timestamp:   str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Finding:
    title:             str   = ""
    description:       str   = ""
    risk:              str   = "Unknown"
    classification:    str   = "Unconfirmed"
    subdevice:         str   = ""
    interface:         str   = ""
    instance:          str   = ""
    ip:                str   = ""
    port:              str   = ""
    output_file:       str   = ""    # primary / first output file (legacy compat)
    output_files:      list  = field(default_factory=list)  # all contributing files
    cvss_score:        float = 0.0
    cve_ids:           list  = field(default_factory=list)
    affected_component:str   = ""
    affected_version:  str   = ""
    remediation:       str   = ""
    tools_used:        list  = field(default_factory=list)
    commands_used:     list  = field(default_factory=list)
    sources:           list  = field(default_factory=list)
    id:                str   = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:         str   = field(default_factory=lambda: datetime.now().isoformat())
    affected:          list  = field(default_factory=list)  # affected locations/paths/headers

    def add_output_file(self, path: str) -> None:
        """Add a contributing output file, deduplicating."""
        if path and path not in self.output_files:
            self.output_files.append(path)
        # Keep output_file in sync with the first entry
        if self.output_files and not self.output_file:
            self.output_file = self.output_files[0]

    def add_source(self, source: Source) -> None:
        self.sources.append(source)
        self._update_classification()
        self._update_classification()

    def _update_classification(self) -> None:
        primaries   = [s for s in self.sources if s.source_type == "primary"]
        secondaries = [s for s in self.sources if s.source_type == "secondary"]
        if len(primaries) >= 1 and len(secondaries) >= 1:
            self.classification = "Validated"
        elif len(primaries) >= 1:
            self.classification = "Confirmed"
        else:
            self.classification = "Unconfirmed"

    def set_rce_classification(self) -> None:
        self.classification = "Validated"

    def set_dos_classification(self) -> None:
        self.classification = "Confirmed"

    def to_dict(self) -> dict:
        # Ensure output_files includes output_file for backward compat
        all_files = list(self.output_files)
        if self.output_file and self.output_file not in all_files:
            all_files.insert(0, self.output_file)
        return {
            "title":              self.title,
            "description":        self.description,
            "risk":               self.risk,
            "classification":     self.classification,
            "subdevice":          self.subdevice,
            "interface":          self.interface,
            "instance":           self.instance,
            "ip":                 self.ip,
            "port":               self.port,
            "output_file":        all_files[0] if all_files else "",
            "output_files":       all_files,
            "cve_ids":            self.cve_ids,
            "cvss_score":         self.cvss_score,
            "affected_component": self.affected_component,
            "affected_version":   self.affected_version,
            "remediation":        self.remediation,
            "tools_used":         self.tools_used,
            "commands_used":      self.commands_used,
            "id":                 self.id,
            "timestamp":          self.timestamp,
            "affected":           self.affected,
        }


# ---------------------------------------------------------------------------
# ModuleContext
# ---------------------------------------------------------------------------

@dataclass
class ModuleContext:
    """Shared context passed to every module instance."""
    # Project identity
    config:          dict
    subdevice_key:   str
    subdevice_name:  str
    interface:       str
    instance_key:    str
    instance_loc:    str
    instance_dir:    Path
    file_prefix:     str
    # Shared services
    db:              Any
    findings:        Any   # FindingManager
    progress:        Any   # ProgressManager
    logger:          Any   # GearboxLogger
    ip_tracker:      Any   # IpTracker
    net:             Any   # NetworkUtils
    # State flags
    skip_nessus:     bool = False


# ---------------------------------------------------------------------------
# DatabaseManager  (SQLite)
# ---------------------------------------------------------------------------

class DatabaseManager:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        with self._conn() as conn:
            self._init_schema(conn)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self, conn) -> None:
        conn.executescript('''
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    description TEXT,
                    risk TEXT,
                    classification TEXT,
                    subdevice TEXT,
                    interface TEXT,
                    instance TEXT,
                    ip TEXT DEFAULT '',
                    port TEXT DEFAULT '',
                    cve_ids TEXT,
                    cvss_score REAL,
                    tools_used TEXT,
                    commands_used TEXT,
                    affected_component TEXT,
                    affected_version TEXT,
                    remediation TEXT,
                    timestamp TEXT
                );

                CREATE TABLE IF NOT EXISTS discovered_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    subdevice TEXT,
                    interface TEXT,
                    instance TEXT,
                    timestamp TEXT,
                    mac_address TEXT,
                    hostname TEXT,
                    os_name TEXT,
                    UNIQUE(ip, subdevice, interface, instance)
                );

                CREATE TABLE IF NOT EXISTS open_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    version TEXT,
                    subdevice TEXT,
                    interface TEXT,
                    instance TEXT,
                    timestamp TEXT,
                    UNIQUE(ip, port, protocol, subdevice, interface, instance)
                );

                CREATE TABLE IF NOT EXISTS software_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    port INTEGER,
                    software_name TEXT,
                    software_version TEXT,
                    discovery_tool TEXT,
                    subdevice TEXT,
                    interface TEXT,
                    instance TEXT,
                    eol INTEGER DEFAULT 0,
                    outdated INTEGER DEFAULT 0,
                    timestamp TEXT
                );

                CREATE TABLE IF NOT EXISTS network_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdevice TEXT,
                    interface TEXT,
                    instance TEXT,
                    ip_address TEXT,
                    gateway TEXT,
                    subnet TEXT,
                    dns TEXT,
                    netplan_path TEXT,
                    timestamp TEXT
                );
            ''')
        self._migrate_schema(conn)

    def _migrate_schema(self, conn) -> None:
        """Add columns to existing DBs that pre-date them."""
        cursor = conn.execute("PRAGMA table_info(discovered_hosts)")
        existing = {row[1] for row in cursor.fetchall()}
        for col, coldef in [
            ("mac_address", "TEXT"),
            ("hostname",    "TEXT"),
            ("os_name",     "TEXT"),
        ]:
            if col not in existing:
                conn.execute(
                    f"ALTER TABLE discovered_hosts ADD COLUMN {col} {coldef}")

    def upsert_host(self, ip: str, ctx: ModuleContext,
                    mac_address: str = "", hostname: str = "",
                    os_name: str = "") -> None:
        # Never record a server IP as a discovered target.
        if ip in _get_server_ips():
            return
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO discovered_hosts "
                "(ip, subdevice, interface, instance, timestamp, "
                "mac_address, hostname, os_name) VALUES (?,?,?,?,?,?,?,?)",
                (ip, ctx.subdevice_key, ctx.interface, ctx.instance_key,
                 datetime.now().isoformat(),
                 mac_address or None, hostname or None, os_name or None))
            # Update enrichment fields if we now have better data
            if mac_address or hostname or os_name:
                conn.execute(
                    "UPDATE discovered_hosts SET "
                    "mac_address = COALESCE(NULLIF(mac_address,''), ?), "
                    "hostname    = COALESCE(NULLIF(hostname,''), ?), "
                    "os_name     = COALESCE(NULLIF(os_name,''), ?) "
                    "WHERE ip=? AND subdevice=? AND interface=? AND instance=?",
                    (mac_address or None, hostname or None, os_name or None,
                     ip, ctx.subdevice_key, ctx.interface, ctx.instance_key))

    def upsert_port(self, ip: str, port: int, protocol: str,
                    service: str, version: str, ctx: ModuleContext) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO open_ports "
                "(ip, port, protocol, service, version, subdevice, interface, instance, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ip, port, protocol, service, version,
                 ctx.subdevice_key, ctx.interface, ctx.instance_key,
                 datetime.now().isoformat()))

    def upsert_software(self, ip: str, port: int, name: str, version: str,
                        tool: str, ctx: ModuleContext) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO software_inventory "
                "(ip, port, software_name, software_version, discovery_tool, "
                "subdevice, interface, instance, timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
                (ip, port, name, version, tool,
                 ctx.subdevice_key, ctx.interface, ctx.instance_key,
                 datetime.now().isoformat()))

    def get_hosts(self, ctx: ModuleContext) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ip FROM discovered_hosts WHERE subdevice=? AND interface=? AND instance=?",
                (ctx.subdevice_key, ctx.interface, ctx.instance_key)).fetchall()
        return [r["ip"] for r in rows]

    def get_ports_for_host(self, ip: str, ctx: ModuleContext) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT port, protocol, service, version FROM open_ports "
                "WHERE ip=? AND subdevice=? AND interface=? AND instance=? ORDER BY port",
                (ip, ctx.subdevice_key, ctx.interface, ctx.instance_key)).fetchall()
        return [dict(r) for r in rows]

    def store_network_config(self, ip: str, gateway: str, subnet: str,
                             dns: str, netplan_path: str, ctx: ModuleContext) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO network_configs "
                "(subdevice, interface, instance, ip_address, gateway, subnet, dns, netplan_path, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ctx.subdevice_key, ctx.interface, ctx.instance_key,
                 ip, gateway, subnet, dns, netplan_path, datetime.now().isoformat()))

    def save_finding(self, finding: Finding) -> None:
        d = finding.to_dict()
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO findings "
                "(id, title, description, risk, classification, subdevice, interface, instance, "
                "ip, port, "
                "cve_ids, cvss_score, tools_used, commands_used, affected_component, "
                "affected_version, remediation, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (d["id"], d["title"], d["description"], d["risk"], d["classification"],
                 d["subdevice"], d["interface"], d["instance"],
                 d.get("ip",""), d.get("port",""),
                 json.dumps(d["cve_ids"]), d["cvss_score"],
                 json.dumps(d["tools_used"]), json.dumps(d["commands_used"]),
                 d["affected_component"], d["affected_version"],
                 d["remediation"], d["timestamp"]))


# ---------------------------------------------------------------------------
# FindingManager
# ---------------------------------------------------------------------------

# Risk mapping loaded from optional YAML file (populated by load_risk_map)
_RISK_MAP: dict[str, str] = {}

_HARDCODED_RISKS: dict[str, str] = {
    "telnet":            "Critical",
    "unencrypted":       "High",
    "default credential":"Critical",
    "anonymous ftp":     "High",
    "snmp v1":           "High",
    "snmp v2":           "Medium",
    "weak ssl":          "High",
    "sslv2":             "Critical",
    "sslv3":             "High",
    "null cipher":       "High",
    "self-signed":       "Low",
    "expired cert":      "Medium",
    "open redirect":     "Medium",
    "xss":               "Medium",
    "sqli":              "Critical",
    "rce":               "Critical",
    "command injection": "Critical",
    "path traversal":    "High",
    "directory listing": "Medium",
    "smb signing":       "Medium",
    "ntlm":              "High",
    "pass-the-hash":     "High",
    "nfs export":        "High",
    "world-writable":    "High",
}

# ---------------------------------------------------------------------------
# Nessus plugin title → pr0t31n standard title normalisation map
# Applied when ingesting Nessus XML/CSV to align overlapping finding names
# with the cross-tool standard defined in the finding overlap analysis.
# ---------------------------------------------------------------------------
_NESSUS_TITLE_NORM: dict[str, str] = {
    "Default Credentials Accepted":         "Weak or Default Credentials Accepted",
    "Default Credentials":                   "Weak or Default Credentials Accepted",
    "SNMP Default Community String":         "SNMP Default Community String Accepted",
    "SNMP Agent Default Community Name (public)": "SNMP Default Community String Accepted",
    "Web Server Version Disclosure":         "Information Disclosure: Server Header",
    "Web — Server Version Disclosure":       "Information Disclosure: Server Header",
    "Web — Directory Listing Enabled":       "Directory Listing Enabled",
    "Open TCP/UDP Port Identified":          "Open Port Discovered",
    "Live Host Discovered":                  "Live Host Discovered",
    "SSL/TLS — Expired Certificate":         "SSL/TLS Certificate: Expired",
    "SSL/TLS — Self-Signed Certificate":     "SSL/TLS Certificate: Self-Signed",
    "SSL/TLS — Missing HSTS Header":         "Missing Security Header: Strict-Transport-Security",
    "SSL/TLS — Certificate Hostname Mismatch": "SSL/TLS Certificate: Hostname Mismatch",
    "SSL/TLS — Weak Certificate Signature Algorithm": "SSL/TLS Certificate: Weak Signature Algorithm",
    "SMB — World-Readable Share Discovered": "SMB Share Accessible Without Authentication",
    "SMB — Null Session Permitted":          "SMB Share Accessible Without Authentication",
    "SMB — Signing Disabled or Not Required": "SMB Signing Disabled or Not Required",
    "SSH — Weak Cipher or MAC Algorithm":    "SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)",
    "SSH — Protocol Version 1 Supported":   "SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)",
    "SSH — Root Login Permitted":            "SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)",
    "SSH — Password Authentication Enabled": "SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)",
    "FTP Anonymous Login Permitted":         "FTP Anonymous Login Permitted",
    "NFS World-Readable Export":             "NFS World-Readable Export",
    "LLMNR Query Observed":                  "LLMNR/NBT-NS Broadcast Poisoning Possible",
    "NBT-NS Query Observed":                 "LLMNR/NBT-NS Broadcast Poisoning Possible",
}

# ---------------------------------------------------------------------------
# CVE rename map — well-known CVEs given descriptive titles
# ---------------------------------------------------------------------------
_CVE_RENAME_MAP: dict[str, str] = {
    "CVE-2017-0143": "EternalBlue — Remote Code Execution — SMBv1 — Windows 7 SP1",
    "CVE-2017-0144": "EternalBlue — Remote Code Execution — SMBv1 — Windows 7 SP1",
    "CVE-2010-4231": "Directory Traversal Vulnerability",
    "CVE-2014-0160": "Heartbleed — OpenSSL TLS Heartbeat Information Disclosure",
    "CVE-2014-3566": "POODLE — SSL 3.0 Protocol Downgrade",
    "CVE-2014-0224": "OpenSSL CCS Injection",
    "CVE-2012-4929": "CRIME — TLS/SPDY Compression Information Disclosure",
    "CVE-2016-0800": "DROWN — SSLv2 Cross-Protocol Attack",
    "CVE-2016-9244": "Ticketbleed — TLS Session Ticket Vulnerability",
    "CVE-2013-0169": "LUCKY13 — CBC Padding Oracle Attack on TLS",
    "CVE-2015-0204": "FREAK — RSA Export Key Attack",
    "CVE-2015-4000": "Logjam — Weak Diffie-Hellman Export Parameters",
    "CVE-2009-3555": "TLS Renegotiation Vulnerability",
    "CVE-2011-3389": "BEAST — Browser Exploit Against SSL/TLS",
    "CVE-2013-3587": "BREACH — HTTP Compression Side-Channel Attack",
    "CVE-2017-13099": "ROBOT — Return Of Bleichenbacher's Oracle Threat",
    "CVE-2019-0708": "BlueKeep — Remote Code Execution — RDP — Windows 7/2008",
    "CVE-2020-0796": "SMBGhost — Remote Code Execution — SMBv3 — Windows 10",
    "CVE-2021-44228": "Log4Shell — Remote Code Execution — Log4j",
    "CVE-2021-22986": "F5 BIG-IP iControl REST Remote Code Execution",
    "CVE-2018-13379": "Fortinet FortiGate SSL VPN Path Traversal",
    "CVE-2020-1472": "Zerologon — Privilege Escalation — Netlogon",
    "CVE-2021-26084": "Atlassian Confluence OGNL Injection Remote Code Execution",
    "CVE-2022-22965": "Spring4Shell — Remote Code Execution — Spring Framework",
    "CVE-2021-34527": "PrintNightmare — Remote Code Execution — Windows Print Spooler",
    "CVE-2020-14882": "Oracle WebLogic Server Remote Code Execution",
    "CVE-2021-27065": "Microsoft Exchange Server Remote Code Execution (ProxyLogon)",
    "CVE-2021-26855": "Microsoft Exchange Server SSRF (ProxyLogon)",
    "CVE-2014-6271": "Shellshock — Remote Code Execution — Bash CGI",
    "CVE-2021-21985": "VMware vCenter Server Remote Code Execution",
}

# Nmap CVE false positives — these findings should never be created
_NMAP_FP_SKIP: set[str] = {
    "CVE-2012-3541",  # false positive in nmap smb-vuln-* scripts
}

# ---------------------------------------------------------------------------
# summary.json helper — records curl commands and screenshots per instance
# ---------------------------------------------------------------------------

def _summary_append(yaml_path: str, sd_key: str, interface: str,
                    inst_key: str, entry: dict) -> None:
    """
    Append one entry to summary.json in the project directory.
    entry must contain 'type' ('curl' or 'screenshot') plus type-specific keys.
    """
    import json as _json
    summary_path = Path(yaml_path).resolve().parent / "summary.json"
    try:
        if summary_path.exists():
            data = _json.loads(summary_path.read_text(encoding="utf-8"))
        else:
            data = {}
        inst_id = f"{sd_key}.{interface}.{inst_key}"
        if inst_id not in data:
            data[inst_id] = {"curl": [], "screenshots": []}
        bucket = "screenshots" if entry.get("type") == "screenshot" else "curl"
        data[inst_id][bucket].append(entry)
        summary_path.write_text(
            _json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def _cve_title(cve_id: str, fallback: str = "") -> str:
    """Return a descriptive title for a CVE ID, or fallback if not known."""
    return _CVE_RENAME_MAP.get(cve_id.upper(), fallback or cve_id.upper())

# Matches trailing location suffixes that should not appear in finding titles.
_LOCATION_SUFFIX_RE = re.compile(
    r'(?:'
    r'(?:\s*\u2014\s*\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?$)'
    r'|(?:\s*\(https?://[^)]+\)\s*$)'
    r'|(?:\s*\(\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\)\s*$)'
    r'|(?:\s+\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\s*$)'
    r')',
)


def _strip_location(title: str) -> str:
    """Remove trailing IP, IP:port, or URL suffixes from a finding title."""
    prev = None
    while prev != title:
        prev  = title
        title = _LOCATION_SUFFIX_RE.sub('', title).strip().rstrip('-').rstrip('\u2014').strip()
    return title



class FindingManager:
    def __init__(self, db: DatabaseManager, yaml_path: str) -> None:
        self._db        = db
        self._yaml_path = yaml_path
        self._seen: dict[str, Finding] = {}
        self._lock      = threading.Lock()
        # findings.jsonl lives alongside the YAML — same dir gauntlet reads from
        self._jsonl_path = str(
            Path(yaml_path).resolve().parent / "findings.jsonl")
        # Track the last-written JSON string per finding id so we can skip
        # identical writes (prevents exact duplicates accumulating on disk).
        self._written: dict[str, str] = {}

    def _append_jsonl(self, finding: Finding) -> None:
        """Append finding to findings.jsonl, skipping if content is unchanged."""
        try:
            line = json.dumps(finding.to_dict())
            fid  = finding.id
            # Only write if this is a new finding or the content actually changed.
            if fid and self._written.get(fid) == line:
                return
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            if fid:
                self._written[fid] = line
        except Exception as e:
            console.log(f"Could not write findings.jsonl: {e}", "WARNING")

    def resolve_risk(self, title: str, tool_risk: str = "Unknown",
                     cve_ids: list[str] = None) -> str:
        """
        Resolve risk using priority chain:
        1. Hardcoded assignments
        2. Risk mapping file
        3. Tool-provided risk
        4. NVD/CVE public lookup
        5. Unknown
        """
        title_lower = title.lower()
        for pattern, risk in _HARDCODED_RISKS.items():
            if pattern in title_lower:
                return risk
        if _RISK_MAP:
            for pattern, risk in _RISK_MAP.items():
                if pattern.lower() in title_lower:
                    return risk
        if tool_risk and tool_risk != "Unknown":
            return tool_risk
        if cve_ids:
            for cve_id in cve_ids:
                nvd_risk = self._lookup_nvd(cve_id)
                if nvd_risk and nvd_risk != "Unknown":
                    return nvd_risk
        return "Unknown"

    def _lookup_nvd(self, cve_id: str) -> str:
        if not requests:
            return "Unknown"
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        score = metrics[key][0]["cvssData"]["baseScore"]
                        return self._cvss_to_risk(float(score))
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def _cvss_to_risk(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 5.0:
            return "Medium"
        if score >= 1.0:
            return "Medium"
        return "Informational"

    def create(
        self,
        ctx:                 ModuleContext,
        title:               str,
        description:         str,
        tool:                str = "",
        command:             str = "",
        raw_output:          str = "",
        source_type:         str = "primary",
        tool_risk:           str = "Unknown",
        cve_ids:             list[str] = None,
        affected_component:  str = "",
        affected_version:    str = "",
        remediation:         str = "",
        force_risk:          str = "",
        force_classification:str = "",
        ip:                  str = "",
        port:                str = "",
        output_file:         str = "",
        output_files:        list = None,
    ) -> Finding:
        """
        Create a new finding (or return existing duplicate within same instance).
        Dedup key is: instance + title + ip + port  so the same finding on
        different IPs/ports always creates separate entries.

        When the same finding is reported by multiple tools (e.g. sslscan AND
        testssl both flag TLS 1.0), the second call merges the new output_file
        into the existing finding's output_files list rather than creating a
        duplicate.
        """
        cve_ids = cve_ids or []
        output_files = output_files or []

        # Strip trailing IP/port/URL location suffixes from the title.
        # Location context is stored in the ip/port fields.
        title = _strip_location(title)

        # Normalise: include output_file in output_files
        all_files = list(output_files)
        if output_file and output_file not in all_files:
            all_files.insert(0, output_file)
        # §13c: store evidence paths relative to the run directory root.
        try:
            _gb_root = Path(self._jsonl_path).resolve().parent
            all_files = [_gb_rel(_f, _gb_root) for _f in all_files if _f]
        except Exception:
            pass

        instance_key = f"{ctx.subdevice_key}.{ctx.interface}.{ctx.instance_key}"
        dedup_key = f"{instance_key}::{title.lower()}::{ip}::{port}"

        # Cross-title merge key: same IP + port → same physical service.
        # If a finding with an identical normalised title (ignoring trailing
        # parenthetical like " (1.2.3.4:443)") already exists for this IP:port,
        # merge files and tools rather than creating a separate entry.
        _title_base = re.sub(r'\s*\([^)]*\)\s*$', '', title.lower()).strip()
        ip_port_title_key = f"{instance_key}::{_title_base}::{ip}::{port}"

        with self._lock:
            # ── Exact dedup (same title + ip + port) ─────────────────────────
            if dedup_key in self._seen:
                f = self._seen[dedup_key]
                for fp in all_files:
                    f.add_output_file(fp)
                if tool and tool not in f.tools_used:
                    f.tools_used.append(tool)
                if cve_ids:
                    for c in cve_ids:
                        if c not in f.cve_ids:
                            f.cve_ids.append(c)
                f.add_source(Source(source_type=source_type, tool=tool,
                                    evidence=raw_output[:500]))
                self._apply_title_rules(f)
                self._persist(f)
                return f

            # ── Cross-title merge (same base title + ip + port, different tool) ──
            # Register both key variants pointing to the same finding object.
            if ip_port_title_key != dedup_key and ip_port_title_key in self._seen:
                f = self._seen[ip_port_title_key]
                for fp in all_files:
                    f.add_output_file(fp)
                if tool and tool not in f.tools_used:
                    f.tools_used.append(tool)
                if cve_ids:
                    for c in cve_ids:
                        if c not in f.cve_ids:
                            f.cve_ids.append(c)
                f.add_source(Source(source_type=source_type, tool=tool,
                                    evidence=raw_output[:500]))
                # Also register the exact key so future exact matches are caught
                self._seen[dedup_key] = f
                self._apply_title_rules(f)
                self._persist(f)
                return f

            risk = force_risk or self.resolve_risk(title, tool_risk, cve_ids)

            finding = Finding(
                title=title,
                description=description,
                risk=risk,
                subdevice=ctx.subdevice_key,
                interface=ctx.interface,
                instance=ctx.instance_key,
                ip=ip,
                port=str(port) if port else "",
                output_file=all_files[0] if all_files else "",
                output_files=all_files,
                cve_ids=cve_ids,
                affected_component=affected_component,
                affected_version=affected_version,
                remediation=remediation,
                tools_used=[tool] if tool else [],
                commands_used=[command] if command else [],
            )
            if force_classification:
                finding.classification = force_classification
            finding.add_source(Source(source_type=source_type, tool=tool,
                                      evidence=raw_output[:500]))
            self._seen[dedup_key] = finding
            if ip_port_title_key != dedup_key:
                self._seen[ip_port_title_key] = finding
            # ── Post-create transforms ────────────────────────────────────
            self._apply_title_rules(finding)
            self._persist(finding)
            return finding

    @staticmethod
    def _extract_ip_port_from_url(url: str) -> tuple:
        """
        Extract (ip, port) from a URL string.
        Handles: https://IP:PORT, http://IP:PORT, http://IP (port 80),
                 https://IP (port 443), bare IP:PORT strings.
        Returns ("", "") when nothing can be extracted.
        """
        if not url:
            return "", ""
        url = url.strip()
        # Full URL with optional port
        m = re.match(
            r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?",
            url)
        if m:
            ip   = m.group(1)
            port = m.group(2) or ("443" if url.startswith("https") else "80")
            return ip, port
        # Bare IP:port
        m = re.match(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$", url)
        if m:
            return m.group(1), m.group(2)
        # Bare IP
        m = re.match(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", url)
        if m:
            return m.group(1), ""
        return "", ""

    def _apply_title_rules(self, finding: "Finding") -> None:
        """
        Apply post-creation title/risk normalisation rules in-place.
        Called after every create() so rules fire whether a finding is new or merged.
        """
        t = finding.title

        # ── CVE-only titles → descriptive names ──────────────────────────
        cve_only_m = re.match(
            r'^(CVE-\d{4}-\d+)\s*(?:[—\-].*)?$', t, re.I)
        if cve_only_m:
            cve_id = cve_only_m.group(1).upper()
            if cve_id in _NMAP_FP_SKIP:
                # Mark for removal — set to a sentinel the loader filters out
                finding.title = "__FP_SKIP__"
                return
            known = _CVE_RENAME_MAP.get(cve_id, "")
            if known:
                loc = f" ({finding.ip}:{finding.port})" if finding.ip else ""
                finding.title = _fix_acronyms(known + loc)

        # ── SSL/TLS title normalisation ───────────────────────────────────
        t = finding.title
        if re.search(r'ssl.tls.*failed.*chain.*incomplete|chain.*incomplete',
                     t, re.I):
            finding.title = re.sub(
                r'SSL/TLS[^\w]*(failed.*chain.*incomplete|chain.*incomplete)[^\w]*',
                'SSL/TLS - Chain of Trust Incomplete', t, flags=re.I).strip()
        elif re.search(r'ssl.tls.*\d+\s*days', t, re.I):
            # "SSL/TLS — 395 days" → "SSL/TLS - Overly Long Certificate Expiry"
            finding.title = "SSL/TLS - Overly Long Certificate Expiry"
            finding.risk  = "Low"
        elif re.search(r'Certificate Hostname Mismatch', t, re.I):
            finding.risk = "Informational"
        elif re.search(r'No Certificate Revocation Information', t, re.I):
            finding.risk = "Informational"
        elif re.search(r'No SAN.*browsers.*complaining|browsers.*complaining.*SAN', t, re.I):
            finding.risk = "Informational"

        # ── LFI / Path Traversal rename ───────────────────────────────────
        t = finding.title
        lfi_m = re.match(
            r'^(.+?)\s+(?:Local\s+File\s+Inclusion|LFI|Path\s+Traversal)',
            t, re.I)
        if lfi_m and not t.lower().startswith("local file inclusion"):
            software = lfi_m.group(1).strip()
            finding.title = f"Local File Inclusion - {software}"
        elif re.search(r'Local\s+File\s+Inclusion|LFI|Path\s+Traversal', t, re.I):
            # Already starts with LFI — ensure standard prefix
            body = re.sub(
                r'^(?:Local\s+File\s+Inclusion|LFI|Path\s+Traversal)\s*[-—:]\s*',
                '', t, flags=re.I).strip()
            if body and not t.lower().startswith("local file inclusion - "):
                finding.title = f"Local File Inclusion - {body}"

        # ── SMB Anonymous Access rename ───────────────────────────────────
        # (renamed in _run_smbmap; here we just ensure no bare "Anonymous Access")

        # ── Unauth MQTT → Service Version Identified ──────────────────────
        t = finding.title
        if re.search(r'Unauth\s+Mqtt\s+Broker', t, re.I):
            ver_m = re.search(r'[:\s]+([\d\.]+)', t)
            ver   = ver_m.group(1) if ver_m else ''
            ip_m  = re.search(r'\(([^)]+)\)', t)
            loc   = ip_m.group(0) if ip_m else ''
            finding.title = _fix_acronyms(
                f"Service Version Identified — MQTT{(' ' + ver) if ver else ''} {loc}".strip())
            finding.risk = "Informational"

        # ── Map Unauth Exposure → Low risk ────────────────────────────────
        if re.search(r'Map\s+Unauth\s+Exposure', t, re.I):
            finding.risk = "Low"

        # ── LFI/Path Traversal — test URL and remove false positives ─────
        if re.search(r'Local File Inclusion|LFI|Path Traversal', finding.title, re.I):
            self._test_lfi_finding(finding)

    def _test_lfi_finding(self, finding: "Finding") -> None:
        """
        Test an LFI/Path Traversal finding by fetching the claimed vulnerable URL
        and comparing it to the parent URL response.  Marks the finding as
        __FP_SKIP__ (suppressed) if the responses match or the target is unreachable.
        """
        try:
            url = ""
            # Extract URL from output_files or output_file
            for of in finding.output_files:
                if re.match(r'https?://', of):
                    url = of
                    break
            # Also check description for a URL
            if not url:
                url_m = re.search(r'https?://\S+', finding.description or "")
                if url_m:
                    url = url_m.group(0).rstrip(".,)")
            if not url and finding.ip:
                scheme = "https" if (finding.port or "80") in ("443", "8443") else "http"
                url = f"{scheme}://{finding.ip}:{finding.port}" if finding.port else (
                    f"{scheme}://{finding.ip}")
            if not url:
                return

            # Derive parent URL (strip path)
            parent_m = re.match(r'(https?://[^/:]+(?::\d+)?)', url)
            parent_url = parent_m.group(1) if parent_m else url

            if url == parent_url:
                return  # nothing to compare

            def _fetch(u: str) -> tuple:
                """Return (status_code, body_snippet) or (-1, "") on failure."""
                try:
                    result = subprocess.run(
                        ["curl", "-k", "-s", "--max-time", "10",
                         "-w", "\n__HTTPCODE__%{http_code}",
                         "-L", "--max-redirs", "3", u],
                        capture_output=True, text=True, timeout=15)
                    out = result.stdout or ""
                    code_m = re.search(r'__HTTPCODE__(\d+)', out)
                    code = int(code_m.group(1)) if code_m else -1
                    body = re.sub(r'__HTTPCODE__\d+', '', out).strip()[:2000]
                    return code, body
                except Exception:
                    return -1, ""

            vuln_code, vuln_body = _fetch(url)
            # Unusable response → remove finding
            if vuln_code in (-1, 0) or vuln_code >= 500 or vuln_code == 0:
                finding.title = "__FP_SKIP__"
                return
            # Connection refused / timeout
            if vuln_code < 0:
                finding.title = "__FP_SKIP__"
                return

            parent_code, parent_body = _fetch(parent_url)

            # If response matches parent closely → likely false positive
            if vuln_code == parent_code and vuln_body and parent_body:
                similarity = (
                    len(set(vuln_body.split()) & set(parent_body.split()))
                    / max(len(set(parent_body.split())), 1)
                )
                if similarity > 0.85:
                    finding.title = "__FP_SKIP__"
        except Exception:
            pass  # never crash the main flow

    def _persist(self, finding: "Finding") -> None:
        try:
            self._db.save_finding(finding)
        except Exception:
            pass
        # Don't write false-positive sentinels to disk
        if finding.title == "__FP_SKIP__":
            return
        self._append_jsonl(finding)
        console.emit_finding(finding.to_dict())


# ---------------------------------------------------------------------------
# ProgressManager
# ---------------------------------------------------------------------------

class ProgressManager:
    """Thread-safe JSON progress file manager."""

    def __init__(self, progress_file: str) -> None:
        self._file  = progress_file
        self._lock  = threading.Lock()
        self._state = self._load()

    def _load(self) -> dict:
        if os.path.exists(self._file):
            try:
                with open(self._file, encoding="utf-8") as f:
                    data = json.load(f)
                    data.setdefault("version", 1)
                    data.setdefault("started", datetime.now().isoformat())
                    data.setdefault("completed_instances", [])
                    data.setdefault("module_status", {})
                    return data
            except Exception:
                pass
        return {
            "version":             1,
            "started":             datetime.now().isoformat(),
            "completed_instances": [],
            "module_status":       {},
        }

    def _save(self) -> None:
        """Write progress atomically — write to a temp file then rename so
        a concurrent _load() never sees a half-written or truncated file."""
        try:
            import tempfile, os as _os
            dir_name = _os.path.dirname(self._file) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            try:
                with _os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self._state, f, indent=2)
                _os.replace(tmp_path, self._file)
            except Exception:
                try:
                    _os.unlink(tmp_path)
                except Exception:
                    pass
                raise
        except Exception as e:
            console.log(f"WARNING: Could not save progress file: {e}", "WARNING")

    def is_instance_complete(self, sd: str, iface: str, inst: str) -> bool:
        return f"{sd}.{iface}.{inst}" in self._state.get("completed_instances", [])

    def mark_instance_complete(self, sd: str, iface: str, inst: str) -> None:
        """
        Mark an instance complete only if every module is in a terminal state
        AND the Photo module was actually captured (not skipped).
        Modules with status 'na' (port dead) are excluded from the check.
        """
        modules       = INTERFACE_MODULES.get(iface, [])
        module_status = self._state.get("module_status", {})
        prefix        = f"{sd}.{iface}.{inst}"

        for mod in modules:
            key    = f"{prefix}.{mod}"
            status = module_status.get(key, {}).get("status", "pending")

            if status == "na":
                continue

            if mod == "Photo" and status != "complete":
                console.log(
                    f"Instance {prefix} not marked complete: "
                    f"Photo module is '{status}' — a photo must be captured.",
                    "WARNING")
                return

            if status not in ("complete", "skipped"):
                console.log(
                    f"Instance {prefix} not marked complete: "
                    f"module '{mod}' is still '{status}'.",
                    "WARNING")
                return

        with self._lock:
            lst = self._state.setdefault("completed_instances", [])
            if prefix not in lst:
                lst.append(prefix)
            self._save()
        console.log(f"Instance {prefix} marked complete.", "INFO")

    def _reload_from_disk(self) -> None:
        """Re-read progress.json so gauntlet Clear operations are respected."""
        try:
            fresh = self._load()
            with self._lock:
                on_disk = fresh.get("module_status", {})
                in_mem  = self._state.setdefault("module_status", {})
                for key, val in on_disk.items():
                    in_mem[key] = val
                for key in list(in_mem.keys()):
                    if key not in on_disk:
                        del in_mem[key]
                self._state["completed_instances"] = fresh.get("completed_instances", [])
        except Exception:
            pass

    def is_module_complete(self, sd: str, iface: str, inst: str,
                           module: str) -> bool:
        """
        Return True when the module has a terminal status (complete or skipped).
        Re-reads from disk first so gauntlet Clear operations are respected
        without requiring a gearbox restart.

        Evidence file validation is intentionally NOT done here — that is
        gauntlet's job via verify_module_files() at page load time.
        """
        self._reload_from_disk()
        key    = f"{sd}.{iface}.{inst}.{module}"
        status = self._state.get("module_status", {}).get(key, {}).get("status")
        return status in ("complete", "skipped", "na")

    def set_module_status(self, sd: str, iface: str, inst: str,
                          module: str, status: str, detail: str = "") -> None:
        with self._lock:
            key = f"{sd}.{iface}.{inst}.{module}"
            self._state.setdefault("module_status", {})[key] = {
                "status":    status,
                "detail":    detail,
                "timestamp": datetime.now().isoformat(),
            }
            self._save()

    def get_module_status(self, sd: str, iface: str, inst: str,
                          module: str) -> str:
        key = f"{sd}.{iface}.{inst}.{module}"
        return self._state.get("module_status", {}).get(key, {}).get("status", "pending")

# ---------------------------------------------------------------------------
# IpTracker
# ---------------------------------------------------------------------------

class IpTracker:
    """
    Tracks all observed internal IPs across all interfaces.
    Maintains observed_ranges.txt (/24 or larger) and observed_ips.csv.
    """

    _PRIVATE = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    def __init__(self, project_dir: Path) -> None:
        self._dir    = project_dir
        self._ranges: set[str] = set()
        self._ips:    list[dict] = []
        self._lock   = threading.Lock()

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._PRIVATE)
        except ValueError:
            return False

    def observe(self, ip: str, ports: list[dict] = None,
                subdevice: str = "", instance: str = "") -> None:
        if not self._is_private(ip):
            return
        try:
            addr   = ipaddress.ip_address(ip)
            net24  = ipaddress.ip_network(f"{ip}/24", strict=False)
            net_str = str(net24)
        except ValueError:
            return
        with self._lock:
            self._ips.append({
                "ip":       ip,
                "ports":    ports or [],
                "subdevice":subdevice,
                "instance": instance,
            })
            self._ranges.add(net_str)
        self._flush()

    def _flush(self) -> None:
        ranges_file = self._dir / "observed_ranges.txt"
        ips_file    = self._dir / "observed_ips.csv"
        try:
            with open(ranges_file, "w", encoding="utf-8") as f:
                for r in sorted(self._ranges):
                    f.write(r + "\n")
        except Exception:
            pass
        try:
            import csv as _csv
            seen: set[str] = set()
            with open(ips_file, "w", encoding="utf-8", newline="") as f:
                writer = _csv.DictWriter(
                    f, fieldnames=["ip", "ports", "subdevice", "instance"])
                writer.writeheader()
                for entry in self._ips:
                    key = f"{entry['ip']}:{entry['subdevice']}:{entry['instance']}"
                    if key not in seen:
                        seen.add(key)
                        writer.writerow({
                            "ip":       entry["ip"],
                            "ports":    ";".join(str(p.get("port","")) for p in entry["ports"]),
                            "subdevice":entry["subdevice"],
                            "instance": entry["instance"],
                        })
        except Exception:
            pass


# ---------------------------------------------------------------------------
# NetworkUtils
# ---------------------------------------------------------------------------

class NetworkUtils:
    """Network configuration helpers (ethtool, dhclient, netplan, ip route)."""

    NETPLAN_DIR           = Path("/etc/netplan")
    NETPLAN_BACKUP_SUFFIX = ".gb_backup"
    _PRIVILEGED_CMDS      = {"dhclient", "ip", "tcpdump", "netplan", "ethtool"}

    def __init__(self, logger: GearboxLogger) -> None:
        self._logger = logger

    def _run(self, cmd: list[str], tool: str = "",
             timeout: int = 30, needs_root: bool = False) -> tuple[bool, str]:
        if needs_root:
            ok, output = _sudo_run(cmd, timeout=timeout)
        else:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout + result.stderr).strip()
            ok     = result.returncode == 0
        return ok, output

    def get_link_status(self, interface: str) -> Optional[str]:
        """Use ethtool to check if interface has carrier signal."""
        try:
            ok, output = self._run(
                ["ethtool", interface], tool="ethtool", timeout=10)
            if "Link detected: yes" in output:
                return "yes"
            if "Link detected: no" in output:
                return "no"
        except Exception as e:
            self._logger.warn(f"ethtool failed on {interface}: {e}", tool="ethtool")
        return None

    def attempt_dhcp(self, interface: str, timeout: int = 30) -> Optional[str]:
        """
        Attempt DHCP on interface. Returns assigned IP or None.
        APIPA addresses (169.254.x.x) are treated as failure — they indicate
        the host fell back to link-local self-assignment, not a real DHCP lease.
        """
        def _is_routable(ip: str) -> bool:
            return not ip.startswith("169.254.")

        try:
            ok, output = self._run(
                ["dhclient", "-v", interface, "-timeout", str(timeout)],
                tool="dhclient", timeout=timeout + 10, needs_root=True)
            m = re.search(r'bound to (\d+\.\d+\.\d+\.\d+)', output)
            if m and _is_routable(m.group(1)):
                return m.group(1)
            # Try ip addr show as fallback
            _, out2 = self._run(["ip", "addr", "show", interface], tool="ip")
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', out2)
            if m and _is_routable(m.group(1)):
                return m.group(1)
        except Exception:
            pass
        return None

    def _detect_net_manager(self) -> str:
        """
        Detect the host network manager.  Returns one of:
          'netplan'    — /etc/netplan dir exists AND netplan binary is present
          'interfaces' — /etc/network/interfaces file exists (Debian/Kali/Ubuntu pre-netplan)
          'ip'         — fall back to raw ip commands (works everywhere)
        """
        if self.NETPLAN_DIR.is_dir() and shutil.which("netplan"):
            return "netplan"
        if Path("/etc/network/interfaces").exists():
            return "interfaces"
        return "ip"

    def set_static_ip(self, interface: str, ip: str, prefix: int,
                      gateway: str, ctx: ModuleContext) -> bool:
        """
        Configure a static IP on *interface*.

        Automatically detects the host network manager and applies the config
        using the appropriate method:
          netplan     — writes /etc/netplan/99-gearbox-<iface>.yaml + netplan apply
          interfaces  — ip commands directly (no config file written; safe for testing)
          ip          — ip commands directly (same as interfaces fallback)
        """
        net_mgr = self._detect_net_manager()
        self._logger.info(
            f"set_static_ip: network manager detected as '{net_mgr}'", tool="ip")
        if net_mgr == "netplan":
            return self._set_static_ip_netplan(interface, ip, prefix, gateway, ctx)
        return self._set_static_ip_ipcmd(interface, ip, prefix, gateway, ctx)

    def _set_static_ip_netplan(self, interface: str, ip: str, prefix: int,
                                gateway: str, ctx: ModuleContext) -> bool:
        """Apply static IP via netplan (Ubuntu 18.04+ / Debian with netplan)."""
        config_file = self.NETPLAN_DIR / f"99-gearbox-{interface}.yaml"
        try:
            for existing in self.NETPLAN_DIR.glob("*.yaml"):
                backup = existing.with_suffix(self.NETPLAN_BACKUP_SUFFIX)
                if not backup.exists():
                    try:
                        shutil.copy2(str(existing), str(backup))
                    except Exception:
                        pass
        except Exception as e:
            self._logger.warn(f"Could not backup netplan configs: {e}")

        netplan_config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {
                    interface: {
                        "addresses": [f"{ip}/{prefix}"],
                        "routes": [{"to": "default", "via": gateway}] if gateway else [],
                    }
                }
            }
        }
        try:
            if yaml:
                with open(str(config_file), "w") as f:
                    yaml.dump(netplan_config, f, default_flow_style=False)
            else:
                with open(str(config_file), "w") as f:
                    f.write(f"network:\n  version: 2\n  renderer: networkd\n"
                            f"  ethernets:\n    {interface}:\n"
                            f"      addresses:\n        - {ip}/{prefix}\n")
            ok, _ = self._run(["netplan", "apply"], tool="netplan", needs_root=True)
            if ok:
                ctx.db.store_network_config(
                    ip, gateway, f"{ip}/{prefix}", "", str(config_file), ctx)
                self._logger.info(
                    f"Static IP {ip}/{prefix} configured via netplan", tool="netplan")
                return True
        except Exception as e:
            self._logger.error(f"set_static_ip (netplan) failed: {e}")
        return False

    def _set_static_ip_ipcmd(self, interface: str, ip: str, prefix: int,
                              gateway: str, ctx: ModuleContext) -> bool:
        """
        Apply a static IP using raw ip commands — works on any Linux regardless
        of network manager (/etc/network/interfaces, NetworkManager, systemd-networkd).
        Not persistent across reboots; suitable for the duration of a test session.
        """
        try:
            self._run(["ip", "addr", "flush", "dev", interface],
                      tool="ip", needs_root=True)
            ok, out = self._run(
                ["ip", "addr", "add", f"{ip}/{prefix}", "dev", interface],
                tool="ip", needs_root=True)
            if not ok:
                self._logger.warn(f"ip addr add {ip}/{prefix} failed: {out}", tool="ip")
            self._run(["ip", "link", "set", interface, "up"],
                      tool="ip", needs_root=True)
            if gateway:
                # Remove any existing default route before adding ours
                self._run(["ip", "route", "del", "default"],
                          tool="ip", needs_root=True)
                ok2, out2 = self._run(
                    ["ip", "route", "add", "default", "via", gateway],
                    tool="ip", needs_root=True)
                if not ok2:
                    self._logger.warn(
                        f"ip route add default via {gateway} failed: {out2}", tool="ip")
            ctx.db.store_network_config(
                ip, gateway, f"{ip}/{prefix}", "", "ip-cmd", ctx)
            self._logger.info(
                f"Static IP {ip}/{prefix} configured via ip command (gw: {gateway})",
                tool="ip")
            return True
        except Exception as e:
            self._logger.error(f"set_static_ip (ip-cmd) failed: {e}")
        return False

    def revert_netplan(self, interface: str) -> None:
        """Restore netplan configuration from backup (netplan systems only)."""
        if self._detect_net_manager() != "netplan":
            return
        config_file = self.NETPLAN_DIR / f"99-gearbox-{interface}.yaml"
        try:
            if config_file.exists():
                config_file.unlink()
            for backup in self.NETPLAN_DIR.glob("*.gb_backup"):
                orig = backup.with_suffix("")
                shutil.move(str(backup), str(orig))
            self._run(["netplan", "apply"], tool="netplan", needs_root=True)
            self._logger.info(f"Netplan configuration reverted for {interface}")
        except Exception as e:
            self._logger.warn(f"Failed to revert netplan for {interface}: {e}")

    def add_route(self, subnet: str, gateway: str) -> None:
        """Add a route for an observed subnet."""
        try:
            self._run(["ip", "route", "add", subnet, "via", gateway],
                      tool="ip", needs_root=True)
            self._logger.info(f"Route added: {subnet} via {gateway}")
        except Exception as e:
            self._logger.warn(f"Failed to add route {subnet} via {gateway}: {e}")


# ---------------------------------------------------------------------------
# run_tool  (subprocess runner with logging)
# ---------------------------------------------------------------------------

def _u_write_tool_log(*, cmd, started, ended, exit_code, stdout, stderr,
                      tool_name, tool_path, output_file, extra_header=None,
                      errors_log=None) -> None:
    """Best-effort universal .log emission via /opt/pr0t31n/shared/pr0t31n_tool_runner.

    Silent no-op if the shared module is not installed — never breaks the scan.
    Per CLAUDE.md Section 14, every third-party tool invocation emits a
    sibling .log + tool-output errors are auto-detected and appended to the
    *errors_log* path when provided (CLAUDE.md Section 14).
    """
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_tool_runner as _ur
        _ur.write_tool_log(
            cmd=cmd, started=started, ended=ended, exit_code=exit_code,
            stdout=stdout, stderr=stderr,
            tool_name=tool_name, tool_path=tool_path,
            output_file=output_file,
            extra_header=extra_header,
            errors_log=errors_log,
        )
    except Exception:
        pass


def _gb_rel(p, root) -> str:
    """§13c: return path relative to the run root, or the original on failure."""
    try:
        return str(Path(p).resolve().relative_to(Path(root).resolve()))
    except Exception:
        return str(p)


def _hw_run(cmd, ctx=None, tool_name: str = "", output_file=None,
            timeout: int = 60, text: bool = True, **kw):
    """§14: drop-in subprocess.run for hardware tools (get-edid / edid-decode /
    cec-client) that don't go through run_tool — ALSO emits a .log sibling via
    pr0t31n_tool_runner. Returns the CompletedProcess unchanged."""
    import subprocess as _sp
    from datetime import datetime as _dt, timezone as _tz
    started = _dt.now(_tz.utc)
    proc = None
    rc, out, err = -1, "", ""
    try:
        proc = _sp.run(cmd, capture_output=True, text=text, timeout=timeout, **kw)
        rc = proc.returncode
        out = proc.stdout if isinstance(proc.stdout, str) else ""   # binary → empty (noted)
        err = proc.stderr if isinstance(proc.stderr, str) else (
            (proc.stderr or b"").decode("utf-8", "replace") if proc.stderr else "")
    except _sp.TimeoutExpired:
        err, rc = "(timeout)", -1
        proc = _sp.CompletedProcess(cmd, rc, b"" if not text else "", b"" if not text else "")
    ended = _dt.now(_tz.utc)
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_tool_runner as _ur
        _logdir = None
        if output_file is None and ctx is not None:
            _logdir = getattr(ctx, "instance_dir", None)
        _ur.write_tool_log(
            cmd=cmd, started=started, ended=ended, exit_code=rc,
            stdout=out, stderr=err,
            tool_name=tool_name or (cmd[0] if cmd else "tool"),
            output_file=str(output_file) if output_file else None,
            log_dir=str(_logdir) if _logdir else None,
            extra_header=(None if text else {"Note": "binary output — see primary artifact"}),
        )
    except Exception:
        pass
    return proc


def run_tool(
    cmd:         list[str],
    ctx:         ModuleContext,
    tool_name:   str = "",
    output_file: Optional[Path] = None,
    timeout:     int = 300,
    env:         Optional[dict] = None,
) -> tuple[int, str, str]:
    """
    Run an external tool as a subprocess.
    Logs the command, streams output, and writes to output_file if provided.
    Returns (returncode, stdout, stderr).

    Also emits a sibling .log file (output_file + '.log', or
    <tool>_<ts>.log when no output_file is given) containing a bash-prompted
    transcript, start/end timestamps, exit code, and tool version — per
    CLAUDE.md Section 15.
    """
    from datetime import datetime as _dt
    cmd_str  = " ".join(cmd)
    ctx.logger.cmd(cmd, tool=tool_name)
    # Log tool version on first use (cached after first call)
    if tool_name:
        _tv = get_tool_version(tool_name)
        if _tv:
            ctx.logger.info(f"{tool_name} version: {_tv}", tool=tool_name)

    proc_env = {**os.environ, **(env or {})}
    _tool_path = cmd[0] if cmd else (tool_name or "")
    _started = _dt.now().astimezone()
    _log_dir = output_file.parent if output_file else (ctx.instance_dir if hasattr(ctx, "instance_dir") else None)
    # errors.log path: per-instance, so tool-output errors detected by the
    # shared runner land in the same errors.log the rest of Gearbox uses.
    _errors_log = (ctx.instance_dir / "errors.log") if hasattr(ctx, "instance_dir") else None
    _check_pause()
    _subproc_sem.acquire()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=proc_env,
            preexec_fn=_mem_limit_preexec if sys.platform != "win32" else None,
        )
        _pause_key = None
        if _pause:
            _pause_key = _pause.register(
                proc, tool_name or cmd_str,
                [str(output_file)] if output_file else [])
        _track_proc(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            if _pause_key is not None:
                _pause.unregister(_pause_key)
            ctx.logger.warn(f"{tool_name} timed out after {timeout}s", tool=tool_name)
            _u_write_tool_log(
                cmd=cmd, started=_started, ended=_dt.now().astimezone(),
                exit_code=None,
                stdout=(stdout or ""), stderr=(stderr or ""),
                tool_name=(tool_name or Path(_tool_path).name),
                tool_path=_tool_path,
                output_file=output_file if output_file else None,
                extra_header={"Note": f"TIMEOUT after {timeout}s"},
                errors_log=_errors_log,
            )
            _check_pause()
            return -1, "", f"{tool_name} timed out"
        finally:
            if _pause_key is not None:
                _pause.unregister(_pause_key)

        stdout = stdout or ""
        stderr = stderr or ""

        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(str(output_file), "w", encoding="utf-8") as f:
                f.write(stdout)
                if stderr:
                    f.write("\n--- STDERR ---\n")
                    f.write(stderr)

        _u_write_tool_log(
            cmd=cmd, started=_started, ended=_dt.now().astimezone(),
            exit_code=proc.returncode, stdout=stdout, stderr=stderr,
            tool_name=(tool_name or Path(_tool_path).name),
            tool_path=_tool_path,
            output_file=output_file if output_file else None,
            errors_log=_errors_log,
        )
        _check_pause()
        return proc.returncode, stdout, stderr

    except FileNotFoundError:
        _u_write_tool_log(
            cmd=cmd, started=_started, ended=_dt.now().astimezone(),
            exit_code=None, stdout="", stderr=f"{tool_name} not found",
            tool_name=(tool_name or Path(_tool_path).name),
            tool_path=_tool_path,
            output_file=output_file if output_file else None,
            extra_header={"Note": "FileNotFoundError — binary not on PATH"},
            errors_log=_errors_log,
        )
        return -1, "", f"{tool_name} not found"
    except Exception as e:
        ctx.logger.error(f"{tool_name} execution failed: {e}", exc=e, tool=tool_name)
        _u_write_tool_log(
            cmd=cmd, started=_started, ended=_dt.now().astimezone(),
            exit_code=None, stdout="", stderr=str(e),
            tool_name=(tool_name or Path(_tool_path).name),
            tool_path=_tool_path,
            output_file=output_file if output_file else None,
            extra_header={"Note": f"EXCEPTION: {type(e).__name__}"},
            errors_log=_errors_log,
        )
        return -1, "", str(e)
    finally:
        _subproc_sem.release()


# ---------------------------------------------------------------------------
# get_tool_version  (cached version detection)
# ---------------------------------------------------------------------------

_tool_version_cache: dict[str, str] = {}

_TOOL_VERSION_CMDS: dict[str, list[str]] = {
    "nmap":       ["nmap", "--version"],
    "nessus":     [],  # version via API
    "ssh-audit":  ["ssh-audit", "--version"],
    "sslscan":    ["sslscan", "--version"],
    "testssl":    ["testssl", "--version"],
    "nuclei":     ["nuclei", "--version"],
    "nikto":      ["nikto", "-Version"],
    "hydra":      ["hydra", "--version"],
    "john":       ["john", "--version"],
    "hashcat":    ["hashcat", "--version"],
    "sqlmap":     ["sqlmap", "--version"],
    "metasploit": ["msfconsole", "--version"],
    "responder":  ["Responder.py", "--version"],
    "tcpdump":    ["tcpdump", "--version"],
    "tshark":     ["tshark", "--version"],
    "curl":       ["curl", "--version"],
    "wget":       ["wget", "--version"],
    "openssl":    ["openssl", "version"],
    "python3":    ["python3", "--version"],
    "python":     ["python", "--version"],
    "pip":        ["pip", "--version"],
    "gobuster":   ["gobuster", "version"],
    "ffuf":       ["ffuf", "--version"],
    "wfuzz":      ["wfuzz", "--version"],
    "dirb":       ["dirb", "--version"],
    "masscan":    ["masscan", "--version"],
    "enum4linux":  ["enum4linux", "--version"],
    "crackmapexec": ["crackmapexec", "--version"],
    "impacket":   ["impacket-wmiexec", "--version"],
    # Bluetooth / BLE toolchain
    "bluetoothctl": ["bluetoothctl", "--version"],
    "btmgmt":      [],                       # no version flag
    "btmon":       ["btmon", "--version"],
    "hcitool":     [],                       # deprecated; no version flag
    "gatttool":    [],                       # deprecated; no version flag
    "sdptool":     [],                       # no version flag
    "l2ping":      [],                       # no version flag
    "hciconfig":   [],                       # no version flag
    "bettercap":   ["bettercap", "-version"],
    "crackle":     [],                       # prints usage/version on run
    "ubertooth-btle": ["ubertooth-util", "-v"],
    "spooftooph":  [],
    "sniff_receiver.py": [],                 # Sniffle host CLI
}


def get_tool_version(tool_name: str) -> str:
    """
    Return the version string for a tool, e.g. "Nmap 7.94SVN".
    Results are cached for the lifetime of the process.
    Returns empty string if version cannot be determined.
    """
    key = tool_name.lower()
    if key in _tool_version_cache:
        return _tool_version_cache[key]

    cmd = _TOOL_VERSION_CMDS.get(key, [tool_name, "--version"])
    if not cmd:
        _tool_version_cache[key] = ""
        return ""

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout or result.stderr or "").strip()
        # Grab the first non-empty line that looks like a version
        for line in output.splitlines():
            line = line.strip()
            if line:
                _tool_version_cache[key] = line
                return line
    except Exception:
        pass

    _tool_version_cache[key] = ""
    return ""


# ---------------------------------------------------------------------------
# tool_available  (comprehensive multi-location search + PATH enrichment)
# ---------------------------------------------------------------------------

def tool_available(name: str) -> bool:
    """
    Return True if a tool binary exists anywhere gearbox would install it to,
    not just in the current $PATH.

    When a binary is found outside PATH, its parent directory is prepended to
    os.environ["PATH"] so the tool stays accessible for the rest of the session.

    Search order:
      1. shutil.which() — current $PATH (fastest, catches apt/brew installs)
      2. Common system directories that may not be in PATH
      3. Homebrew cellar paths (macOS, both Intel and Apple Silicon)
      4. pip --user / go install / ~/bin user directories
      5. git-clone build locations derived from REQUIRED_TOOLS git_repo
      6. Extra paths declared in the tool's REQUIRED_TOOLS entry
      7. bin_aliases — alternative binary names that confirm the tool is installed
      8. Case-variant aliases (responder ↔ Responder, testssl ↔ testssl.sh)
    """
    home = Path.home()

    _SYSTEM_DIRS = [
        "/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin",
        "/usr/local/sbin", "/snap/bin", "/opt/bin", "/opt/local/bin",
    ]
    _BREW_DIRS = [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]
    _USER_DIRS = [
        str(home / ".local" / "bin"),
        str(home / "go" / "bin"),
        str(home / "bin"),
    ]

    def _exists(path: str) -> bool:
        p = Path(os.path.expanduser(path))
        return p.is_file() and os.access(p, os.X_OK)

    def _enrich_path(found_path: str) -> None:
        parent = str(Path(os.path.expanduser(found_path)).parent)
        cur = os.environ.get("PATH", "")
        if parent not in cur.split(os.pathsep):
            os.environ["PATH"] = parent + os.pathsep + cur

    # 1. $PATH lookup
    if shutil.which(name):
        return True

    # 2-4. Common install directories
    for d in _SYSTEM_DIRS + _BREW_DIRS + _USER_DIRS:
        candidate = os.path.join(d, name)
        if _exists(candidate):
            _enrich_path(candidate)
            return True

    # Look up tool entry once for steps 5-8
    tool_entry = next((t for t in REQUIRED_TOOLS if t["bin"] == name), None)

    # 5. Git-clone build locations derived from REQUIRED_TOOLS git_repo
    if tool_entry and tool_entry.get("git_repo"):
        repo_url  = tool_entry["git_repo"]
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
        subdir    = tool_entry.get("git_subdir", "")
        clone_dir = home / repo_name
        search_dir = clone_dir / subdir if subdir else clone_dir
        for candidate in [
            str(search_dir / name),
            str(search_dir / (name + ".py")),
        ]:
            if _exists(candidate):
                _enrich_path(candidate)
                return True
        if clone_dir.is_dir():
            for child in clone_dir.iterdir():
                if child.is_dir():
                    candidate = str(child / name)
                    if _exists(candidate):
                        _enrich_path(candidate)
                        return True

    # 6. Extra paths declared in tool entry
    if tool_entry:
        for extra in tool_entry.get("extra_paths", []):
            if _exists(extra):
                _enrich_path(extra)
                return True

    # 7. bin_aliases — alternative binary names proving the tool is installed
    if tool_entry:
        for alias in tool_entry.get("bin_aliases", []):
            if shutil.which(alias):
                return True
            for d in _SYSTEM_DIRS + _BREW_DIRS + _USER_DIRS:
                candidate = os.path.join(d, alias)
                if _exists(candidate):
                    _enrich_path(candidate)
                    return True
            for extra in tool_entry.get("extra_paths", []):
                alias_path = extra.replace(name, alias)
                if alias_path != extra and _exists(alias_path):
                    _enrich_path(alias_path)
                    return True

    # 8. Case-variant aliases
    _case_aliases: dict[str, list[str]] = {
        "responder": ["Responder"],
        "Responder": ["responder"],
        "testssl.sh": ["testssl"],
        "testssl":    ["testssl.sh"],
    }
    for alt in _case_aliases.get(name, []):
        if shutil.which(alt):
            return True

    return False

# Attach a non-recursive wrapper for alias resolution
tool_available.__wrapped__ = lambda name: bool(shutil.which(name))  # type: ignore

# ---------------------------------------------------------------------------
# BaseModule
# ---------------------------------------------------------------------------

class BaseModule:
    """Base class for all assessment modules."""
    name:           str  = ""
    description:    str  = ""
    concurrent_safe:bool = False

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx

    def run(self) -> None:
        """Execute this module. Override in subclasses."""
        raise NotImplementedError

    def _mark_running(self) -> None:
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "running",
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "running",
        )
        self.ctx.logger.info(f"→ Starting module: {self.name}", tool=self.name)

    def _mark_complete(self, detail: str = "") -> None:
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "complete", detail,
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "complete", detail,
        )
        self.ctx.logger.info(f"✓ Module complete: {self.name}", tool=self.name)

    def _mark_error(self, detail: str = "") -> None:
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "error", detail,
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "error", detail,
        )
        self.ctx.logger.error(f"✗ Module error: {self.name} — {detail}", tool=self.name)

    def _mark_skipped(self, reason: str = "") -> None:
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "skipped", reason,
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "skipped", reason,
        )

    def _mark_waiting(self, reason: str = "") -> None:
        """
        Mark this module as 'waiting' — not yet actively running, but blocked
        on a source module (e.g. NmapPort) that is still in progress and may
        yet discover more targets.
        """
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "waiting", reason,
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "waiting", reason,
        )
        self.ctx.logger.info(
            f"⏳ Module waiting: {self.name} — {reason}", tool=self.name)

    def _source_module_done(self, source_name: str) -> bool:
        """
        Return True when a source module (e.g. 'NmapPort') has reached a
        terminal state (complete, skipped, error, na).
        Polls progress in-memory — no filesystem access.
        """
        status = self.ctx.progress.get_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, source_name,
        )
        return status in ("complete", "skipped", "error", "na")

    def _mark_na(self, reason: str = "") -> None:
        """Mark this module N/A — port is dead or prerequisite not met; excluded from module counts."""
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "na", reason,
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "na", reason,
        )
        self.ctx.logger.info(
            f"— Module N/A: {self.name}" + (f" — {reason}" if reason else ""),
            tool=self.name)

    def _record_tool_run(self, tool: str, command: str,
                          output_file: str = "", purpose: str = "") -> None:
        """Record a tool invocation to summary.json for export correlation."""
        try:
            _summary_append(
                str(self.ctx.findings._yaml_path),
                self.ctx.subdevice_key,
                self.ctx.interface,
                self.ctx.instance_key,
                {
                    "type":        "curl",
                    "title":       tool,
                    "tool":        tool,
                    "command":     command,
                    "output_file": output_file,
                    "purpose":     purpose,
                },
            )
        except Exception:
            pass

    def _mark_na_complete(self, port_type: str) -> None:
        """
        Mark as complete with an NA-target detail when no applicable ports
        were found.  Shows 'complete' status badge plus detail text
        'N/A No <port_type> Ports' so it is clear the module ran but had
        nothing to act on — without polluting the skipped-by-user concept.
        """
        detail = f"N/A No {port_type} Ports"
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "complete", detail,
        )
        console.status_update(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, self.name, "complete", detail,
        )
        self.ctx.logger.info(
            f"Module {self.name} complete — {detail}", tool=self.name)

    def _target_hosts(self) -> list[str]:
        """
        Return the list of hosts this module should assess.
        When _single_host_ip is set (per-host dispatch from NmapPort),
        returns only that one IP.  Otherwise returns all known hosts.
        """
        single = getattr(self, "_single_host_ip", None)
        if single:
            return [single]
        return self.ctx.db.get_hosts(self.ctx)

    def _out_file(self, suffix: str, subdir: str = "") -> Path:
        """Return a path within the instance directory for tool output."""
        base = self.ctx.instance_dir
        if subdir:
            base = base / subdir
            base.mkdir(parents=True, exist_ok=True)
        return base / f"{self.ctx.file_prefix}_{suffix}"

    def _observe(self, title: str, description: str,
                 tool: str = "", output_file: str = "",
                 output_text: str = "", risk: str = "") -> None:
        """Emit a structured observation from parsed tool output."""
        self.ctx.logger.record_observation(
            title=title, description=description,
            tool=tool, output_file=output_file,
            output_text=output_text, risk=risk,
        )

    def _record_curl(self, cmd: list, purpose: str,
                     response_code: int, output_file: str) -> None:
        """Record a curl command execution to summary.json."""
        try:
            _summary_append(
                str(self.ctx.findings._yaml_path),
                self.ctx.subdevice_key,
                self.ctx.interface,
                self.ctx.instance_key,
                {
                    "type":          "curl",
                    "command":       " ".join(str(c) for c in cmd),
                    "purpose":       purpose,
                    "response_code": response_code,
                    "output_file":   output_file,
                },
            )
        except Exception:
            pass

    def _emit_version_findings(
        self,
        software: str,
        version: str,
        ip: str,
        port: str,
        tool: str,
        output_file: str,
        is_os: bool = False,
    ) -> None:
        """
        Emit standardised findings for a discovered software or OS version:
          1. "Service Version Identified" or "Operating System Identified" (Informational)
          2. "End-of-Life Software/OS Detected" if version is EOL (Medium / High)
          3. Per-CVE findings for known vulnerabilities (High or per-severity)

        Skips creation when software is blank, 'unknown', or not meaningful.
        """
        if not software or not version:
            return
        # Skip generic / unknown tokens and HTTP protocol version strings
        skip_terms = {"unknown", "generic", "service", "other", "n/a", "none"}
        if software.lower() in skip_terms or version.lower() in skip_terms:
            return
        # Skip bare HTTP protocol version identifiers (not meaningful software names)
        if re.match(r'^https?$', software, re.I) or re.match(r'^http/1\.[01]$', software, re.I):
            return
        if software.upper() in ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"):
            return

        loc = f"({ip}:{port})" if ip and port else (f"({ip})" if ip else "")
        sw_label = _fix_acronyms(f"{software} {version}")

        # ── 1. Version / OS identified ────────────────────────────────────
        if is_os:
            title = _fix_acronyms(
                f"Operating System Identified — {sw_label} {loc}").strip()
            desc  = (f"The operating system on {ip} was identified as "
                     f"{software} {version} via {tool}.")
        else:
            title = _fix_acronyms(
                f"Service Version Identified — {sw_label} {loc}").strip()
            desc  = (f"Version information was disclosed: {software} {version} "
                     f"on {ip}:{port}. Exact version data enables targeted exploitation.")
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=desc,
            tool=tool, source_type="primary", force_risk="Informational",
            affected_component=software, affected_version=version,
            ip=ip, port=str(port), output_file=output_file,
        )

        # ── 2. EOL check ──────────────────────────────────────────────────
        if is_os:
            is_eol, eol_date = _check_eol_os(software, version)
            eol_risk  = "High"
            eol_prefix = "End-of-Life Operating System Detected"
        else:
            is_eol, eol_date = _check_eol_software(software, version)
            eol_risk  = "Medium"
            eol_prefix = "End-of-Life Software Detected"

        if is_eol:
            eol_title = _fix_acronyms(f"{eol_prefix} — {sw_label}")
            eol_desc  = (
                f"{software} {version} reached end-of-life on {eol_date}. "
                f"No further security patches will be issued. "
                f"Upgrade to a supported version immediately.")
            self.ctx.findings.create(
                ctx=self.ctx, title=eol_title, description=eol_desc,
                tool=tool, source_type="primary", force_risk=eol_risk,
                affected_component=software, affected_version=version,
                ip=ip, port=str(port), output_file=output_file,
            )

        # ── 3. CVE lookup ─────────────────────────────────────────────────
        cves = _lookup_cves(software, version)
        for cve in cves:
            cve_id   = cve["id"]
            cve_risk = cve.get("severity", "Medium")
            cve_url  = cve.get("url", "")
            summary  = cve.get("summary", "")
            cve_title = _fix_acronyms(
                f"{cve_id} — {software} {version} {loc}").strip()
            # Dedup key includes CVE ID so the same CVE across tools merges
            self.ctx.findings.create(
                ctx=self.ctx,
                title=cve_title,
                description=(f"{cve_id}: {summary}\n\nReference: {cve_url}"
                             if cve_url else f"{cve_id}: {summary}"),
                tool=tool,
                raw_output=summary[:500],
                source_type="primary",
                force_risk=cve_risk,
                cve_ids=[cve_id] if cve_id.startswith("CVE-") else [],
                affected_component=software,
                affected_version=version,
                ip=ip, port=str(port),
                output_file=output_file,
            )


    def _prompt(self, question: str, options: list[str] = None,
                prompt_type: str = "text", skippable: bool = False,
                join_url: str = "", join_interfaces: list = None) -> str:
        return console.prompt(
            question, options=options or [], prompt_type=prompt_type,
            skippable=skippable, join_url=join_url,
            join_interfaces=join_interfaces or [],
        )

    def _prompt_connected_photo(self, connection_description: str = "") -> None:
        """Prompt for a photo of the testing tool connected to this instance.
        Tracks as '{ModuleName}ConnectedPhoto' in progress."""
        prog_key = f"{self.name}ConnectedPhoto"
        if self.ctx.progress.is_module_complete(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, prog_key):
            return

        join_interfaces = self.ctx.config.get("join_interfaces") or []
        join_url        = join_interfaces[0]["url"] if join_interfaces else ""

        if not connection_description:
            connection_description = f"testing tool connected to [{self.ctx.instance_loc}]"

        if join_url:
            iface_lines = "\n" + "\n".join(
                f"  [{i['name']}]  {i['url']}" for i in join_interfaces)
            msg = (
                f"Upload a photo showing the {connection_description}."
                f"\n  Scan a QR code or visit a URL on your mobile device:{iface_lines}"
                f"\n  OR type 'skip' to continue."
            )
        else:
            msg = (
                f"Upload a photo showing the {connection_description}."
                f"\n  Visit the Gauntlet web interface on a mobile device to upload,"
                f" OR type 'skip' to continue."
            )

        answer = self._prompt(
            msg,
            prompt_type="file",
            skippable=True,
            join_url=join_url,
            join_interfaces=join_interfaces,
        )

        name_slug = self.name.lower().replace(" ", "_")
        photo_dir = self.ctx.instance_dir / f"{self.name}ConnectedPhoto"
        photo_dir.mkdir(parents=True, exist_ok=True)
        dest = photo_dir / f"{self.ctx.file_prefix}_{name_slug}_connected_photo.jpg"

        if answer and answer.lower() not in ("skip", "") and os.path.exists(answer):
            shutil.copy2(answer, str(dest))
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, prog_key, "complete", "Connected photo captured")
        else:
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, prog_key, "skipped", "Skipped by user")

    def _mark_connected_photo_na(self, reason: str = "") -> None:
        """Mark the connected-photo entry N/A — parent was skipped or not applicable."""
        prog_key = f"{self.name}ConnectedPhoto"
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, prog_key, "na",
            reason or "Parent module skipped or N/A")


# ---------------------------------------------------------------------------
# Photo Module
# ---------------------------------------------------------------------------

class PhotoModule(BaseModule):
    name            = "Photo"
    description     = "Capture photo of target interface via mobile device"
    concurrent_safe = True

    def run(self) -> None:
        self._mark_running()
        try:
            join_interfaces = []
            try:
                # Prefer the interfaces list injected by app.py via --join-interfaces
                join_interfaces = self.ctx.config.get("join_interfaces") or []
                if not join_interfaces:
                    flask_port = 5700
                    project_id = self.ctx.config.get("project_id", "")
                    join_interfaces = [
                        {"name": iface["name"], "ip": iface["ip"],
                         "url": f"https://{iface['ip']}:{flask_port}/join/{project_id}"}
                        for iface in get_all_interfaces()
                    ]
            except Exception:
                pass

            # Use first URL as the primary join_url for the prompt payload
            join_url = join_interfaces[0]["url"] if join_interfaces else ""

            # Build human-readable interface list for the prompt message
            iface_lines = ""
            if join_interfaces:
                iface_lines = "\n" + "\n".join(
                    f"  [{i['name']}]  {i['url']}"
                    for i in join_interfaces
                )

            if join_url:
                msg = (
                    f"Photo required for [{self.ctx.interface}] at location: "
                    f"{self.ctx.instance_loc}.\n"
                    f"  Scan a QR code or visit a URL on your mobile device to upload "
                    f"a photo of this interface port:{iface_lines}\n"
                    f"  OR type 'skip' to continue."
                )
            else:
                msg = (
                    f"Photo required for [{self.ctx.interface}] at location: "
                    f"{self.ctx.instance_loc}.\n"
                    f"  Visit the Gauntlet web interface "
                    f"on a mobile device and upload a photo of this interface port, "
                    f"OR type 'skip' to continue."
                )

            # In TTY mode, print a QR code block for every interface
            if console._tty and qrcode and join_interfaces:
                for iface in join_interfaces:
                    try:
                        _qr = qrcode.QRCode(border=1)
                        _qr.add_data(iface["url"])
                        _qr.make(fit=True)
                        import io as _io
                        buf = _io.StringIO()
                        _qr.print_ascii(out=buf, invert=True)
                        print(f"\n  [{iface['name']}]  {iface['url']}")
                        for line in buf.getvalue().splitlines():
                            print(f"  {line}")
                    except Exception:
                        pass

            # The prompt payload carries join_interfaces as JSON so the Flask
            # modal can render the dropdown picker
            answer = self._prompt(
                msg,
                prompt_type="file",
                skippable=True,
                join_url=join_url,
                join_interfaces=join_interfaces,
            )

            if answer.lower() in ("skip", ""):
                self._mark_skipped("Photo not captured — skipped by user")
                return

            # Answer should be the file path returned by upload_photo
            out_file = self.ctx.instance_dir / f"{self.ctx.file_prefix}_photo.jpg"
            if os.path.exists(answer):
                shutil.copy2(answer, str(out_file))
            self._mark_complete("Photo captured")
        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Ethernet Interface Selection Module
# ---------------------------------------------------------------------------

class EthernetIfaceModule(BaseModule):
    """
    Resolves the physical test interface before any Ethernet assessment
    modules run.  Sets ctx.config['test_interface'] which every subsequent
    Ethernet module reads.

    Logic:
      1. If an interface named 'test_direct' exists on the host → use it
         automatically (no prompt required).
      2. Otherwise → enumerate all available ethernet interfaces and present
         a numbered menu; the user's selection is forced for all modules.
    """
    name        = "EthernetIface"
    description = "Select test interface (test_direct auto-detect or user choice)"

    _TEST_DIRECT = "test_direct"

    def run(self) -> None:
        self._mark_running()
        try:
            ifaces = _list_ethernet_interfaces()

            # ── 1. Auto-select test_direct if present ─────────────────────
            if self._TEST_DIRECT in ifaces:
                self.ctx.config["test_interface"] = self._TEST_DIRECT
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_test_interface", self._TEST_DIRECT)
                self.ctx.logger.info(
                    f"Interface '{self._TEST_DIRECT}' detected — "
                    f"forcing it for all Ethernet modules.",
                    tool=self.name)
                self._mark_complete(f"Auto-selected: {self._TEST_DIRECT}")
                return

            # ── 2. Prompt user to choose from available interfaces ─────────
            self.ctx.logger.info(
                f"'{self._TEST_DIRECT}' not found.  "
                f"Available interfaces: {ifaces or ['(none detected)']}",
                tool=self.name)

            if not ifaces:
                # Nothing detected — fall back to whatever is already configured
                current = self.ctx.config.get("test_interface", "eth0")
                self.ctx.logger.warn(
                    f"No ethernet interfaces detected — "
                    f"keeping configured value: {current}",
                    tool=self.name)
                self._mark_complete(f"No interfaces found — using {current}")
                return

            answer = self._prompt(
                f"Interface '{self._TEST_DIRECT}' was not found on this host.\n"
                f"Select the Ethernet interface to use for testing "
                f"[{self.ctx.instance_loc}]:",
                options=ifaces,
                prompt_type="choice",
            )

            # Map numeric choice or literal name back to interface name
            selected = None
            try:
                idx = int(answer) - 1
                if 0 <= idx < len(ifaces):
                    selected = ifaces[idx]
            except (ValueError, TypeError):
                pass
            if selected is None:
                selected = answer if answer in ifaces else ifaces[0]

            self.ctx.config["test_interface"] = selected
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_test_interface", selected)
            self.ctx.logger.info(
                f"Test interface set to: {selected}", tool=self.name)
            self._mark_complete(f"Selected: {selected}")

        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Ethtool Module
# ---------------------------------------------------------------------------

class EthtoolModule(BaseModule):
    name        = "Ethtool"
    description = "Check Ethernet link status via ethtool"

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")

            answer = self._prompt(
                f"Connect one end of the Ethernet cable to testing port "
                f"{TEST_INTERFACE}, the other end to the target port: "
                f"[{self.ctx.instance_loc}].\n  Set the Ethernet testing port "
                f"knob to 'DIRECT'. Press Enter when ready.",
                options=["Ready", "Skip"],
                prompt_type="choice",
            )
            if "skip" in answer.lower() or answer == "2":
                self._mark_skipped("User skipped Ethtool")
                self._mark_connected_photo_na("Ethtool skipped")
                return

            self._prompt_connected_photo(
                f"Ethernet cable connected between {TEST_INTERFACE} and "
                f"[{self.ctx.instance_loc}]")

            if not tool_available("ethtool"):
                self._mark_skipped("ethtool not available")
                return

            rc, stdout, stderr = run_tool(
                ["ethtool", TEST_INTERFACE],
                self.ctx, tool_name="ethtool", timeout=10)

            output = stdout + stderr

            # Save ethtool output to file so evidence checking can verify it
            ethtool_file = self.ctx.instance_dir / f"{self.ctx.file_prefix}_ethtool.txt"
            try:
                ethtool_file.write_text(output, encoding="utf-8")
            except Exception:
                pass

            if "Link detected: yes" in output:
                self.ctx.logger.info(
                    f"Link detected on {TEST_INTERFACE}", tool="ethtool")
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_link_alive", "yes",
                )
                self._observe(
                    title=f"Ethernet Link Detected — {self.ctx.instance_key}",
                    description=f"ethtool confirmed carrier signal on {TEST_INTERFACE} "
                                f"for port [{self.ctx.instance_loc}].",
                    tool="ethtool",
                    output_text=output[:500],
                    risk="Informational",
                )
                self._mark_complete("Link detected")
            else:
                self.ctx.logger.info(
                    f"No link detected on {TEST_INTERFACE} — port disabled",
                    tool="ethtool")
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_link_alive", "no",
                )
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"Ethernet Port Disabled — {self.ctx.instance_key}",
                    description=(
                        f"The Ethernet port at {self.ctx.instance_loc} "
                        f"does not produce a link signal when connected directly."
                    ),
                    tool="ethtool",
                    raw_output=output,
                    source_type="primary",
                    force_risk="Informational",
                    ip="",
                    output_file="",
                )
                self._mark_complete("Port disabled / no link")
        except Exception as e:
            self.ctx.logger.error(f"Ethtool module failed: {e}", exc=e, tool="ethtool")
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# ConfigDiscovery Module
# ---------------------------------------------------------------------------

class ConfigDiscoveryModule(BaseModule):
    name        = "ConfigDiscovery"
    description = "Discover network configuration via DHCP, traffic analysis, or brute force"

    def run(self) -> None:
        self._mark_running()
        try:
            link_alive = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_link_alive")
            if link_alive == "no":
                self.ctx.logger.info(
                    "ConfigDiscovery N/A — port is dead", tool=self.name)
                self._mark_na("Port is dead — no link detected")
                return

            # ── Set up log file for this run ─────────────────────────────
            out_dir = self.ctx.instance_dir / "ConfigDiscovery"
            out_dir.mkdir(parents=True, exist_ok=True)
            log_file = out_dir / "config_discovery_log.txt"
            attempts: list[str] = []

            def _log(msg: str) -> None:
                attempts.append(msg)
                self.ctx.logger.info(msg, tool=self.name)

            def _flush_log(outcome: str) -> None:
                """Write everything attempted + final outcome to the log file."""
                try:
                    with open(str(log_file), "w", encoding="utf-8") as _lf:
                        _lf.write(f"ConfigDiscovery — {self.ctx.instance_key}\n")
                        _lf.write("=" * 60 + "\n")
                        for line in attempts:
                            _lf.write(line + "\n")
                        _lf.write("\nOutcome: " + outcome + "\n")
                except Exception:
                    pass

            net_utils = NetworkUtils(self.ctx.logger)
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")

            # ── Step 1: Try DHCP ─────────────────────────────────────────
            _log(f"Step 1: Attempting DHCP on {TEST_INTERFACE} (timeout 30s)…")
            ip = net_utils.attempt_dhcp(TEST_INTERFACE, timeout=30)

            if ip:
                _log(f"  DHCP succeeded → {ip}")
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_network_configured", ip)
                self._observe(
                    title=f"Network Configuration via DHCP — {self.ctx.instance_key}",
                    description=f"DHCP lease obtained: IP {ip} on interface "
                                f"[{self.ctx.instance_loc}].",
                    tool="dhclient",
                    output_text=f"IP: {ip}",
                    output_file=str(log_file),
                    risk="Informational",
                )
                _flush_log(f"DHCP: {ip}")
                self._mark_complete(f"DHCP: {ip}")
                return

            _log("  DHCP failed — no lease obtained.")

            # ── Step 2: Passive traffic capture ──────────────────────────
            if tool_available("tcpdump"):
                _log("Step 2: Capturing traffic for 30s to infer config (tcpdump)…")
                tcpdump_out = out_dir / "config_discovery_tcpdump.pcap"
                run_tool(
                    ["tcpdump", "-i", TEST_INTERFACE, "-w", str(tcpdump_out),
                     "-G", "30", "-W", "1"],
                    self.ctx, tool_name="tcpdump", timeout=40)
                _log(f"  Capture saved → {tcpdump_out.name}")

                # Trawler post-capture pass (CLAUDE.md Section 16) ───────
                if tcpdump_out.exists() and tcpdump_out.stat().st_size > 0:
                    try:
                        import sys as _s
                        if "/opt/pr0t31n/shared" not in _s.path:
                            _s.path.insert(0, "/opt/pr0t31n/shared")
                        import pr0t31n_trawler as _pt
                        _pt.run_trawler_on_pcap(
                            tcpdump_out, out_dir,
                            targets=None, scope="int",
                            findings_path=(self.ctx.instance_dir / "findings.json"
                                            if hasattr(self.ctx, "instance_dir") else None),
                            errors_log=(self.ctx.instance_dir / "errors.log"
                                         if hasattr(self.ctx, "instance_dir") else None),
                        )
                    except Exception as _tw_exc:
                        self.ctx.logger.warn(
                            f"Trawler integration error (non-fatal): {_tw_exc}",
                            tool="trawler")

                configs = self._infer_configs(net_utils)
                if configs:
                    ip, gw, prefix = configs[0]
                    _log(f"  Inferred config: {ip}/{prefix} gw {gw}")
                    if net_utils.set_static_ip(TEST_INTERFACE, ip, prefix, gw, self.ctx):
                        self.ctx.progress.set_module_status(
                            self.ctx.subdevice_key, self.ctx.interface,
                            self.ctx.instance_key, "_network_configured", ip)
                        _flush_log(f"Static from traffic: {ip}/{prefix} gw {gw}")
                        self._mark_complete(f"Static: {ip}/{prefix} gw {gw}")
                        return
                    _log("  Could not apply inferred config.")
                else:
                    _log("  No config inferred from captured traffic.")
            else:
                _log("Step 2: tcpdump not available — skipping passive capture.")

            # ── Step 3: Try common IP ranges ─────────────────────────────
            _log("Step 3: Trying common IP ranges as last resort…")
            result = self._try_common_ranges_logged(net_utils, _log)
            _flush_log(result)

        except Exception as e:
            self.ctx.logger.error(
                f"ConfigDiscovery failed: {e}", exc=e, tool=self.name)
            self._mark_error(str(e))

    def _infer_configs(self, net_utils: NetworkUtils) -> list[tuple]:
        """Infer (test_ip, gateway, prefix_len) from observed IPs."""
        observed_ips = self.ctx.db.get_hosts(self.ctx)
        server_ips   = _get_server_ips()
        configs = []
        for ip_str in observed_ips:
            # Skip IPs that belong to the server — they prove nothing about peers
            if ip_str in server_ips:
                continue
            try:
                ip   = ipaddress.ip_address(ip_str)
                net  = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                hosts = list(net.hosts())
                gateway = str(hosts[-2]) if len(hosts) > 1 else str(hosts[0])
                test_ip = str(hosts[0])
                # Skip if the candidate gateway is itself a server IP
                if gateway in server_ips:
                    continue
                if self._test_connectivity(gateway):
                    configs.append((test_ip, gateway, 24))
            except Exception:
                pass
        return configs

    def _test_connectivity(self, target: str) -> bool:
        """Ping test."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", target],
                capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def _try_common_ranges(self, net_utils: "NetworkUtils") -> None:
        """Kept for backward compatibility — delegates to logged version."""
        self._try_common_ranges_logged(net_utils, lambda msg: None)

    def _try_common_ranges_logged(self, net_utils: "NetworkUtils",
                                   _log) -> str:
        """
        Try common private IP ranges. Calls _log(msg) for each attempt.
        Returns a summary string for the log file.
        """
        TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
        common = [
            ("192.168.1.100",  "192.168.1.1",   24),
            ("192.168.0.100",  "192.168.0.1",   24),
            ("10.0.0.100",     "10.0.0.1",      24),
            ("172.16.0.100",   "172.16.0.1",    24),
        ]
        server_ips = _get_server_ips()
        for candidate_ip, gw, prefix in common:
            # Do not try a range where the gateway address belongs to the server
            # itself — pinging our own interface would be false proof of a peer.
            server_ips.add(candidate_ip)  # always exclude the just-assigned IP
            _log(f"  Trying {candidate_ip}/{prefix} gw {gw}…")
            if net_utils.set_static_ip(TEST_INTERFACE, candidate_ip, prefix, gw, self.ctx):
                time.sleep(2)
                # Gateway ping only counts if the gateway is NOT one of the
                # server's own IPs (avoids false-positive on multi-homed hosts).
                if gw in server_ips:
                    _log(f"    Gateway {gw} is a local server IP — not valid proof of peer.")
                    subprocess.run(["ip", "addr", "flush", "dev", TEST_INTERFACE],
                                   capture_output=True, timeout=5)
                    continue
                if self._test_connectivity(gw):
                    _log(f"  Success: {candidate_ip}/{prefix} gw {gw}")
                    self.ctx.progress.set_module_status(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, "_network_configured", candidate_ip)
                    self._observe(
                        title=f"Network Configuration Established — {self.ctx.instance_key}",
                        description=f"Static IP {candidate_ip}/{prefix} via gateway "
                                    f"{gw} configured on [{self.ctx.instance_loc}].",
                        tool="ip",
                        output_text=f"IP: {candidate_ip}/{prefix}, GW: {gw}",
                        risk="Informational",
                    )
                    self._mark_complete(f"Static: {candidate_ip}/{prefix} gw {gw}")
                    return f"Static: {candidate_ip}/{prefix} gw {gw}"
                else:
                    _log(f"    Applied but no gateway ping response.")
                    subprocess.run(["ip", "addr", "flush", "dev", TEST_INTERFACE],
                                   capture_output=True, timeout=5)
        _log("  No common range succeeded.")
        self.ctx.logger.warn(
            "Could not establish network connectivity on any tried range")
        self._mark_complete("No network config found — all methods exhausted")
        return "No network configuration established"


# ---------------------------------------------------------------------------
# TrafficCollector Module
# ---------------------------------------------------------------------------

class TrafficCollectorModule(BaseModule):
    name            = "TrafficCollector"
    description     = "Capture 60 seconds of live traffic via tcpdump and tshark"
    concurrent_safe = False
    CAPTURE_SECONDS = 60

    def run(self) -> None:
        self._mark_running()
        try:
            link_alive = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_link_alive")
            if link_alive == "no":
                self._mark_na("Port is dead — no link detected")
                return

            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
            out_dir = self.ctx.instance_dir / "TrafficCollector"
            out_dir.mkdir(parents=True, exist_ok=True)
            prefix  = f"{self.ctx.file_prefix}_traffic"

            # Files named after the tool that produces them — both in TrafficCollector/
            tcpdump_pcap  = out_dir / f"{prefix}_tcpdump.pcap"
            tshark_pcap   = out_dir / f"{prefix}_tshark.pcap"
            summary_file  = out_dir / f"{prefix}_tshark_summary.txt"

            self.ctx.logger.info(
                f"Capturing traffic on {TEST_INTERFACE} for {self.CAPTURE_SECONDS}s "
                f"(tcpdump + tshark concurrently)…",
                tool="tcpdump")

            # ── Run tcpdump and tshark concurrently ───────────────────────────
            # tcpdump: raw packet capture → tool-named .pcap
            # tshark:  simultaneous live capture + protocol statistics
            def _run_tcpdump() -> None:
                if not tool_available("tcpdump"):
                    self.ctx.logger.warn("tcpdump not available — skipping raw capture",
                                          tool="tcpdump")
                    return
                run_tool(
                    ["tcpdump", "-i", TEST_INTERFACE,
                     "-w", str(tcpdump_pcap),
                     "-G", str(self.CAPTURE_SECONDS), "-W", "1",
                     "--immediate-mode"],
                    self.ctx, tool_name="tcpdump",
                    timeout=self.CAPTURE_SECONDS + 15)
                if tcpdump_pcap.exists() and tcpdump_pcap.stat().st_size > 0:
                    self.ctx.logger.info(
                        f"tcpdump: captured {tcpdump_pcap.stat().st_size:,} bytes",
                        tool="tcpdump")
                else:
                    self.ctx.logger.warn("tcpdump produced empty pcap", tool="tcpdump")
                    # Record tcpdump command for export
                    self._record_tool_run(
                        "tcpdump",
                        f"tcpdump -i {TEST_INTERFACE} -w {tcpdump_pcap}",
                        output_file=str(tcpdump_pcap),
                        purpose="Passive traffic capture")

            def _run_tshark_capture() -> None:
                if not tool_available("tshark"):
                    self.ctx.logger.warn("tshark not available — skipping live capture",
                                          tool="tshark")
                    return
                run_tool(
                    ["tshark", "-i", TEST_INTERFACE,
                     "-a", f"duration:{self.CAPTURE_SECONDS}",
                     "-w", str(tshark_pcap)],
                    self.ctx, tool_name="tshark",
                    timeout=self.CAPTURE_SECONDS + 15)
                if tshark_pcap.exists() and tshark_pcap.stat().st_size > 0:
                    self.ctx.logger.info(
                        f"tshark: captured {tshark_pcap.stat().st_size:,} bytes",
                        tool="tshark")
                else:
                    self.ctx.logger.warn("tshark produced empty pcap", tool="tshark")

            with ThreadPoolExecutor(max_workers=_MAX_TRAFFIC_WORKERS,
                         thread_name_prefix="traffic") as _tp:
                _td_fut = _tp.submit(_run_tcpdump)
                _ts_fut = _tp.submit(_run_tshark_capture)
                # Hard ceiling: capture duration + 60s grace
                _cap_timeout = self.CAPTURE_SECONDS + 60
                try:
                    _td_fut.result(timeout=_cap_timeout)
                except TimeoutError:
                    self.ctx.logger.warn(
                        "tcpdump capture exceeded time limit", tool="tcpdump")
                try:
                    _ts_fut.result(timeout=_cap_timeout)
                except TimeoutError:
                    self.ctx.logger.warn(
                        "tshark capture exceeded time limit", tool="tshark")

            # Use whichever pcap is available for protocol analysis (prefer tshark)
            analysis_pcap = (tshark_pcap if tshark_pcap.exists() and tshark_pcap.stat().st_size > 0
                             else tcpdump_pcap if tcpdump_pcap.exists() and tcpdump_pcap.stat().st_size > 0
                             else None)

            # ── tshark summary analysis ───────────────────────────────────────
            if analysis_pcap and tool_available("tshark"):
                pcap_file = analysis_pcap  # alias for the analysis block below
                rc, out, _ = run_tool(
                    ["tshark", "-r", str(analysis_pcap),
                     "-q",
                     "-z", "conv,ip",              # IP conversation statistics
                     "-z", "io,phs",               # protocol hierarchy
                     "-z", "endpoints,ip"],        # active endpoints
                    self.ctx, tool_name="tshark",
                    output_file=summary_file, timeout=60)

                # Parse interesting protocols from protocol hierarchy
                interesting = []
                for proto in ("smb2", "smb", "kerberos", "ldap", "ntlmssp",
                               "rdp", "telnet", "ftp", "snmp", "mqtt",
                               "modbus", "dnp3", "bacnet", "profinet"):
                    if proto in out.lower():
                        interesting.append(proto.upper())

                if interesting:
                    self._observe(
                        title=f"Interesting Protocols Detected — {self.ctx.instance_key}",
                        description=(
                            f"tshark identified the following protocols in captured "
                            f"traffic on [{self.ctx.instance_loc}]: "
                            f"{', '.join(interesting)}."
                        ),
                        tool="tshark",
                        output_file=str(summary_file),
                        output_text=out[:1000],
                        risk="Informational",
                    )

                    # Industrial / OT protocols are higher risk
                    ot_protos = [p for p in interesting
                                 if p in ("MODBUS", "DNP3", "BACNET", "PROFINET")]
                    if ot_protos:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title=f"Industrial/OT Protocol Exposure — {', '.join(ot_protos)}",
                            description=(
                                f"OT/ICS protocols ({', '.join(ot_protos)}) observed in "
                                f"traffic captured on [{self.ctx.instance_loc}]. "
                                f"These protocols typically lack authentication and encryption."
                            ),
                            tool="tshark",
                            raw_output=out[:500],
                            tool_risk="High",
                            source_type="primary",
                            output_file=str(summary_file),
                            ip="",    # passive capture — no specific IP
                            port="",  # passive capture — no specific port
                        )
            elif analysis_pcap:
                self.ctx.logger.info(
                    "tshark not available — pcap saved, no protocol summary generated",
                    tool="tshark")

            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                # ── Trawler post-capture pass (CLAUDE.md Section 16) ──────────
                # Every pcap-producing tool MUST hand the capture to Trawler so
                # protocol-level findings (cleartext creds, unencrypted mgmt
                # protocols, etc.) are surfaced in the originating tool's
                # findings.json.  Best-effort: failures don't block the scan.
                try:
                    import sys as _s
                    if "/opt/pr0t31n/shared" not in _s.path:
                        _s.path.insert(0, "/opt/pr0t31n/shared")
                    import pr0t31n_trawler as _pt
                    _tw_findings_path = (self.ctx.instance_dir / "findings.json"
                                          if hasattr(self.ctx, "instance_dir") else None)
                    _tw_errors_log    = (self.ctx.instance_dir / "errors.log"
                                          if hasattr(self.ctx, "instance_dir") else None)
                    _tw_res = _pt.run_trawler_on_pcap(
                        pcap_file, out_dir,
                        targets=None,    # auto-extract top talkers from pcap
                        scope="int",
                        findings_path=_tw_findings_path,
                        errors_log=_tw_errors_log,
                    )
                    if _tw_res.get("ran"):
                        _n = len(_tw_res.get("findings", []))
                        self.ctx.logger.info(
                            f"Trawler analysed {pcap_file.name}: {_n} finding(s)",
                            tool="trawler")
                    elif _tw_res.get("skipped_reason"):
                        self.ctx.logger.warn(
                            f"Trawler skipped: {_tw_res['skipped_reason']}",
                            tool="trawler")
                except Exception as _tw_exc:
                    self.ctx.logger.warn(
                        f"Trawler integration error (non-fatal): {_tw_exc}",
                        tool="trawler")

                # ── Filter: treat server-only traffic as empty ────────────────
                # If every IP in the capture belongs to a server interface, the
                # pcap is self-traffic (e.g. ARP from the server itself).
                # Flag it so DhcpServer and other downstream modules don't skip.
                server_ips   = _get_server_ips()
                has_external = _pcap_has_external_traffic(pcap_file, server_ips)

                if not has_external:
                    self.ctx.logger.info(
                        "TrafficCollector: all captured IPs belong to server "
                        "interfaces — treating capture as server-only traffic "
                        "(external device not yet seen).",
                        tool="tshark")
                    self.ctx.progress.set_module_status(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, "_traffic_server_only", "yes")
                    self._mark_complete(
                        f"Captured {pcap_file.stat().st_size:,} bytes "
                        f"(server-only traffic — no external device seen)")
                else:
                    self.ctx.progress.set_module_status(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, "_traffic_server_only", "no")
                    self._mark_complete(
                        f"Captured {pcap_file.stat().st_size:,} bytes"
                        + (f"; protocols: {', '.join(interesting)}" if
                           'interesting' in dir() and interesting else ""))
            else:
                self._mark_skipped("No traffic captured (tcpdump unavailable or empty)")

        except Exception as e:
            self.ctx.logger.error(f"TrafficCollector failed: {e}", exc=e,
                                   tool="tcpdump")
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# DhcpServer Module
# ---------------------------------------------------------------------------

class DhcpServerModule(BaseModule):
    """
    Runs after TrafficCollector when the port is alive but no traffic was
    captured.  Reconfigures the test interface as a DHCP server
    (192.168.4.0/24, gateway 192.168.4.1) using dnsmasq, waits for leases,
    then nmap-pings 192.168.4.2-254 to discover any newly-addressed devices.

    Sets ctx.config["_dhcp_server_ran"] = True so EthernetCleanupModule knows
    the interface was reconfigured and needs to be reverted.
    """
    name            = "DhcpServer"
    description     = "Configure test interface as DHCP server and discover devices"
    concurrent_safe = False

    _DHCP_SUBNET    = "192.168.4"
    _GW_IP          = "192.168.4.1"
    _DHCP_RANGE     = "192.168.4.2,192.168.4.254,1h"
    _LEASE_WAIT_S   = 45    # seconds to wait for at least one lease
    _POLL_INTERVAL  = 5

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")

            # Only run if link is alive
            link = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_link_alive")
            if link != "yes":
                self._mark_na("Port is dead — no link detected")
                return

            if not tool_available("dnsmasq"):
                self._mark_skipped("dnsmasq not available — install can-utils package")
                return

            self.ctx.logger.info(
                f"No traffic on {TEST_INTERFACE} — configuring DHCP server "
                f"({self._GW_IP}/24, range {self._DHCP_RANGE})", tool="dnsmasq")

            # ── Configure IP on test interface ────────────────────────────────
            subprocess.run(
                ["ip", "addr", "flush", "dev", TEST_INTERFACE],
                capture_output=True, timeout=10)
            subprocess.run(
                ["ip", "addr", "add", f"{self._GW_IP}/24", "dev", TEST_INTERFACE],
                capture_output=True, timeout=10)
            subprocess.run(
                ["ip", "link", "set", TEST_INTERFACE, "up"],
                capture_output=True, timeout=10)

            # Mark that we reconfigured this interface so cleanup knows
            self.ctx.config["_dhcp_server_ran"] = True
            self.ctx.config["_dhcp_server_iface"] = TEST_INTERFACE

            # ── Write dnsmasq config ──────────────────────────────────────────
            conf_dir  = self.ctx.instance_dir / "DhcpServer"
            conf_dir.mkdir(parents=True, exist_ok=True)
            conf_file  = conf_dir / "dnsmasq.conf"
            lease_file = conf_dir / "dnsmasq.leases"
            pid_file   = conf_dir / "dnsmasq.pid"
            log_file   = conf_dir / "dnsmasq.log"

            conf_file.write_text(
                f"interface={TEST_INTERFACE}\n"
                f"bind-interfaces\n"
                f"dhcp-range={self._DHCP_RANGE}\n"
                f"dhcp-option=3,{self._GW_IP}\n"
                f"dhcp-option=6,{self._GW_IP}\n"
                f"dhcp-leasefile={lease_file}\n"
                f"pid-file={pid_file}\n"
                f"log-facility={log_file}\n"
                f"no-resolv\n"
                f"no-hosts\n"
            )

            # ── Launch dnsmasq ────────────────────────────────────────────────
            proc = subprocess.Popen(
                ["dnsmasq", "--no-daemon", f"--conf-file={conf_file}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=_mem_limit_preexec if sys.platform != "win32" else None,
            )
            _track_proc(proc)
            if _pause:
                _pause.register(proc, "dnsmasq")
            self.ctx.config["_dhcp_proc_pid"] = proc.pid

            self.ctx.logger.info(
                f"dnsmasq started (pid={proc.pid}); waiting up to "
                f"{self._LEASE_WAIT_S}s for DHCP leases…", tool="dnsmasq")

            # ── Wait for lease(s) ─────────────────────────────────────────────
            waited    = 0
            leased_ips: list = []
            while waited < self._LEASE_WAIT_S:
                _check_pause()
                time.sleep(self._POLL_INTERVAL)
                waited += self._POLL_INTERVAL
                if lease_file.exists():
                    lines = [l.strip() for l in lease_file.read_text().splitlines()
                             if l.strip()]
                    leased_ips = []
                    for ln in lines:
                        parts = ln.split()
                        # dnsmasq lease format: epoch mac ip hostname client-id
                        if len(parts) >= 3:
                            leased_ips.append(parts[2])
                    if leased_ips:
                        self.ctx.logger.info(
                            f"DHCP leases issued to: {leased_ips}", tool="dnsmasq")
                        break

            if leased_ips:
                self._observe(
                    title=f"DHCP Leases Issued — {self.ctx.instance_key}",
                    description=(
                        f"dnsmasq issued DHCP leases on [{self.ctx.instance_loc}] "
                        f"(interface {TEST_INTERFACE}) to: {', '.join(leased_ips)}."
                    ),
                    tool="dnsmasq",
                    output_file=str(lease_file),
                    output_text=lease_file.read_text()[:500] if lease_file.exists() else "",
                    risk="Informational",
                )

            # Persist gateway IP as network config for subsequent nmap modules
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_network_configured", self._GW_IP)

            # ── nmap ping sweep of DHCP range ────────────────────────────────
            nmap_target  = f"{self._DHCP_SUBNET}.2-254"
            nmap_xml     = conf_dir / "nmap_dhcp_live.xml"
            nmap_txt     = conf_dir / "nmap_dhcp_live.txt"
            exclude_self = self._GW_IP

            cmd = ["nmap", "-sn",
                   "--exclude", exclude_self,
                   "--host-timeout", "30s",
                   "-oX", str(nmap_xml), "-oN", str(nmap_txt),
                   nmap_target]
            self.ctx.logger.info(
                f"nmap ping sweep: {nmap_target}", tool="nmap")
            run_tool(cmd, self.ctx, tool_name="nmap",
                     output_file=nmap_txt, timeout=180)

            live_ips: list = []
            if nmap_xml.exists():
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(str(nmap_xml))
                    for host in tree.findall(".//host"):
                        status = host.find("status")
                        if status is not None and status.get("state") == "up":
                            addr = host.find("address[@addrtype='ipv4']")
                            if addr is not None:
                                live_ips.append(addr.get("addr"))
                except Exception:
                    pass

            if live_ips:
                # Upsert each discovered host into the DB so NmapPort and Phase 2
                # modules can target them even if NmapLive's sweep misses them.
                for ip in live_ips:
                    self.ctx.db.upsert_host(ip, self.ctx)
                    self.ctx.ip_tracker.observe(
                        ip,
                        subdevice=self.ctx.subdevice_key,
                        instance=self.ctx.instance_key)

                # Store on ctx directly so NmapPort reads them without touching
                # the progress/reload system (mirrors what NmapLive does).
                existing = list(getattr(self.ctx, '_live_ips', None) or [])
                merged = existing + [ip for ip in live_ips if ip not in existing]
                self.ctx._live_ips = merged

                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_live_ips", json.dumps(merged))
                self._observe(
                    title=f"Devices Discovered via DHCP — {self.ctx.instance_key}",
                    description=(
                        f"After acting as DHCP server on [{self.ctx.instance_loc}], "
                        f"nmap discovered {len(live_ips)} live host(s): "
                        f"{', '.join(live_ips)}."
                    ),
                    tool="nmap",
                    output_file=str(nmap_txt),
                    risk="Informational",
                )
                self._mark_complete(
                    f"DHCP server active; {len(live_ips)} host(s) discovered: "
                    f"{', '.join(live_ips)}")
            elif leased_ips:
                self._mark_complete(
                    f"DHCP leases issued to {len(leased_ips)} host(s); "
                    f"nmap found no responding hosts")
            else:
                self._mark_complete(
                    "DHCP server ran for "
                    f"{self._LEASE_WAIT_S}s; no leases issued")

        except Exception as e:
            self.ctx.logger.error(f"DhcpServer failed: {e}", exc=e, tool="dnsmasq")
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# NmapLive Module
# ---------------------------------------------------------------------------

class NmapLiveModule(BaseModule):
    name            = "NmapLive"
    description     = "Discover live hosts on the network segment"
    concurrent_safe = True

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
            net_cfg = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_network_configured")

            if net_cfg in ("pending", "skipped", ""):
                # _network_configured not set — ConfigDiscovery may have run in a
                # prior session without writing this key, or may have skipped.
                # Try to fall back by reading the current IP from the test interface.
                try:
                    import subprocess as _sp
                    r = _sp.run(["ip", "-4", "addr", "show", TEST_INTERFACE],
                                capture_output=True, text=True, timeout=5)
                    import re as _re
                    m = _re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                    if m:
                        net_cfg = m.group(1)
                        self.ctx.logger.info(
                            f"_network_configured not set — inferred IP "
                            f"{net_cfg} from {TEST_INTERFACE}", tool="nmap")
                        # Persist so later modules (NmapPort, Web, etc.) can use it
                        self.ctx.progress.set_module_status(
                            self.ctx.subdevice_key, self.ctx.interface,
                            self.ctx.instance_key, "_network_configured", net_cfg)
                except Exception:
                    pass

            if net_cfg in ("pending", "skipped", ""):
                self._mark_skipped("No network configuration established")
                return

            try:
                net = ipaddress.ip_network(f"{net_cfg}/24", strict=False)
                target = str(net)
            except Exception:
                target = net_cfg

            out_file = self._out_file("nmap_live.xml", subdir="NmapLive")
            txt_file = self._out_file("nmap_live.txt", subdir="NmapLive")

            # Build exclude list: only IPs on the designated test interface.
            # Using only the test interface prevents IPs from VPNs, management
            # adapters, or other NICs from leaking into scope.
            server_ips  = _get_interface_ips(TEST_INTERFACE)
            server_ips.add(net_cfg)          # always include the configured IP
            exclude_arg = ",".join(sorted(server_ips))

            # -sn = ping sweep only (no port scan, no OS detection)
            # -O requires root AND an open/closed port — incompatible with -sn,
            # causes nmap to exit with an error and write no output files.
            cmd = ["nmap", "-sn",
                   "--exclude", exclude_arg,
                   "--host-timeout", "30s",
                   "-oX", str(out_file), "-oN", str(txt_file), target]
            rc, stdout, stderr = run_tool(
                cmd, self.ctx, tool_name="nmap", output_file=txt_file, timeout=180)

            if not out_file.exists():
                self.ctx.logger.warn(
                    f"nmap did not write XML output (rc={rc}). "
                    f"stderr: {stderr[:200]}", tool="nmap")
                self._mark_skipped(f"nmap failed (rc={rc}) — no live hosts found")
                return

            host_records = self._parse_nmap_live_xml(out_file)
            # Remove every server IP — nmap --exclude is best-effort;
            # this is the definitive post-scan update.
            host_records = [h for h in host_records if h["ip"] not in server_ips]
            live_ips = [h["ip"] for h in host_records]
            self.ctx.logger.info(
                f"Live hosts (server IPs removed): {live_ips}", tool="nmap")

            for h in host_records:
                self.ctx.db.upsert_host(
                    h["ip"], self.ctx,
                    mac_address=h.get("mac_address", ""),
                    hostname=h.get("hostname", ""))
                self.ctx.ip_tracker.observe(h["ip"], subdevice=self.ctx.subdevice_key,
                                             instance=self.ctx.instance_key)

            # Merge with any IPs already seeded by DhcpServer so hosts that
            # received a lease but went quiet before this sweep are not lost.
            existing = list(getattr(self.ctx, '_live_ips', None) or [])
            merged = existing + [ip for ip in live_ips if ip not in existing]
            self.ctx._live_ips = merged

            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_live_ips",
                json.dumps(merged))

            if live_ips:
                self._observe(
                    title="Live Host Discovered",
                    description=f"A host was confirmed active on the network by responding to one or more probe types (ICMP, TCP SYN, ARP, or UDP), expanding the known attack surface. "
                                f"Nmap ping sweep found {len(live_ips)} live host(s): "
                                f"{', '.join(live_ips)}",
                    remediation="Reconcile all discovered hosts against the authorised asset inventory and investigate any unexpected or unregistered hosts.",
                    tool="nmap",
                    output_file=str(txt_file),
                    output_text=", ".join(live_ips),
                    risk="Informational",
                )

            self._mark_complete(f"{len(merged)} live host(s) total"
                                + (f" ({len(live_ips)} from sweep, "
                                   f"{len(merged) - len(live_ips)} from DHCP)"
                                   if len(merged) > len(live_ips) else ""))
        except Exception as e:
            self.ctx.logger.error(f"NmapLive failed: {e}", exc=e, tool="nmap")
            self._mark_error(str(e))

    def _parse_nmap_live_xml(self, xml_file: Path) -> list[dict]:
        """Return list of dicts with ip, mac_address, hostname for each live host."""
        hosts = []
        try:
            if not xml_file.exists() or xml_file.stat().st_size == 0:
                self.ctx.logger.info("nmap XML is empty — no hosts up", tool="nmap")
                return []
            content = xml_file.read_text(encoding="utf-8", errors="replace").strip()
            if not content or "<nmaprun" not in content:
                self.ctx.logger.info("nmap XML has no nmaprun element — no hosts up",
                                     tool="nmap")
                return []
            # Ensure closing tag (XML may be truncated on timeout)
            if "</nmaprun>" not in content:
                content += "</nmaprun>"
            import xml.etree.ElementTree as ET
            tree = ET.fromstring(content)
            for host in tree.findall(".//host"):
                state = host.find(".//status")
                if state is not None and state.get("state") == "up":
                    addr = host.find(".//address[@addrtype='ipv4']")
                    if addr is None:
                        continue
                    ip = addr.get("addr", "")
                    if not ip:
                        continue
                    # Extract MAC address
                    mac_el = host.find(".//address[@addrtype='mac']")
                    mac = mac_el.get("addr", "") if mac_el is not None else ""
                    # Extract hostname (prefer user type, fall back to PTR)
                    hostname = ""
                    for hn in host.findall(".//hostname"):
                        h = hn.get("name", "")
                        if h:
                            hostname = h
                            if hn.get("type") == "user":
                                break
                    hosts.append({"ip": ip, "mac_address": mac, "hostname": hostname})
        except ET.ParseError as e:
            self.ctx.logger.info(
                f"nmap live XML parse note (likely zero hosts): {e}", tool="nmap")
        except Exception as e:
            self.ctx.logger.warn(f"Could not parse nmap live XML: {e}", tool="nmap")
        return hosts


# ---------------------------------------------------------------------------
# Nessus Module
# ---------------------------------------------------------------------------

class NessusModule(BaseModule):
    name            = "Nessus"
    description     = "Run Nessus vulnerability scan against discovered hosts"
    concurrent_safe = True
    NESSUS_URL      = "https://127.0.0.1:8834"
    _MAX_RETRIES    = 3
    _RETRY_BACKOFF  = 3   # seconds between retries

    def _req(self, method: str, path: str, token: str = "",
             api_token: str = "", retries: int = None, **kwargs) -> "requests.Response":
        """
        Make a single Nessus API call using a brand-new connection each time.
        No Session, no connection pooling — avoids ConnectionReset on keep-alive.

        Nessus 10.x requires BOTH:
          X-Cookie: token=<session_token>   — from POST /session
          X-API-Token: <uuid>               — fetched from the UI JS bundle
        """
        url     = f"{self.NESSUS_URL}{path}"
        retries = retries if retries is not None else self._MAX_RETRIES

        headers = {"Connection": "close", "Content-Type": "application/json"}
        if token:
            headers["X-Cookie"] = f"token={token}"
        if api_token:
            headers["X-API-Token"] = api_token

        last_exc = None
        for attempt in range(retries + 1):
            try:
                resp = requests.request(
                    method, url,
                    headers=headers,
                    verify=False,
                    **kwargs,
                )
                return resp
            except Exception as exc:
                last_exc = exc
                err_str  = str(exc).lower()
                retryable = any(k in err_str for k in (
                    "connection reset", "connectionreset",
                    "chunkedencodingerror", "broken pipe",
                    "remote end closed", "econnreset", "104",
                    "connection aborted", "connection refused",
                ))
                if retryable and attempt < retries:
                    wait = self._RETRY_BACKOFF * (attempt + 1)
                    self.ctx.logger.warn(
                        f"Nessus {method} {path} failed "
                        f"(attempt {attempt+1}/{retries+1}): {exc} "
                        f"— retrying in {wait}s", tool="nessus")
                    time.sleep(wait)
                    continue
                raise
        raise last_exc  # type: ignore

    def _get_scan_template_uuid(self, token: str, api_token: str) -> str:
        """
        Fetch the scan template UUID from Nessus dynamically.
        Prefers (in order): Advanced Scan, Basic Network Scan, Discovery.
        Falls back to the first available template if none of the above exist.
        This avoids the 'Invalid uuid' error caused by using a hardcoded UUID
        that does not match the installed Nessus version.
        """
        PREFERRED = [
            "advanced scan",
            "basic network scan",
            "discovery",
            "host discovery",
        ]
        # Fallback UUID that works on many Nessus installations as a last resort
        FALLBACK_UUID = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

        try:
            resp = self._req(
                "GET", "/editor/scan/templates",
                token=token, api_token=api_token, timeout=15)
            templates = resp.json().get("templates", [])
            if not templates:
                return FALLBACK_UUID

            # Build a lookup by normalised title
            by_title = {t.get("title", "").lower().strip(): t.get("uuid", "")
                        for t in templates}
            by_name  = {t.get("name",  "").lower().strip(): t.get("uuid", "")
                        for t in templates}

            for pref in PREFERRED:
                if pref in by_title and by_title[pref]:
                    return by_title[pref]
                if pref in by_name and by_name[pref]:
                    return by_name[pref]

            # Return the first non-empty UUID
            for t in templates:
                uid = t.get("uuid", "")
                if uid:
                    self.ctx.logger.info(
                        f"Using first available Nessus template: "
                        f"{t.get('title','')} ({uid[:8]}…)", tool="nessus")
                    return uid

        except Exception as e:
            self.ctx.logger.warn(
                f"Could not fetch Nessus scan templates: {e} — using fallback UUID",
                tool="nessus")

        return FALLBACK_UUID

    def _get_api_token(self) -> str:
        """
        Fetch the Nessus X-API-Token from the UI JS bundle.
        Nessus 10.x embeds a UUID in /nessus6.js — falls back to a static value.
        """
        import re as _re
        try:
            resp = requests.get(
                f"{self.NESSUS_URL}/nessus6.js",
                verify=False, timeout=10,
                headers={"Connection": "close"})
            # UUID pattern: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            uuid_re = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            m = _re.search(uuid_re, resp.text, _re.I)
            if m:
                return m.group(0)
        except Exception:
            pass
        return "4f9b6a3e-5c2d-4e1a-9f7b-3a8c6d2e1f05"

    def run(self) -> None:
        self._mark_running()
        try:
            if self.ctx.skip_nessus:
                self._mark_skipped("--skip-nessus flag set")
                return
            if not requests:
                self._mark_skipped("requests library not installed")
                return

            # Use the IP injected by InstanceOrchestrator (snapshot before any reload)
            # Fall back to progress read only if the ctx attribute isn't set
            net_cfg = getattr(self.ctx, '_nessus_net_cfg', None) or \
                      self.ctx.progress.get_module_status(
                          self.ctx.subdevice_key, self.ctx.interface,
                          self.ctx.instance_key, "_network_configured")
            if not net_cfg or net_cfg in ("pending", "skipped", ""):
                self._mark_skipped("No network configuration established")
                return

            # Require at least one discovered live target — never scan a /24 blind
            live_ips: list = list(getattr(self.ctx, '_live_ips', None) or [])
            if not live_ips:
                raw = self.ctx.progress.get_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_live_ips")
                if raw:
                    try:
                        live_ips = json.loads(raw)
                    except Exception:
                        live_ips = []
            if not live_ips:
                self._mark_skipped("No live targets discovered — skipping Nessus scan")
                return

            # ── Credentials: load from config.yaml, fall back to env, then prompt ──
            nessus_user, nessus_pass = NessusConfig.load()

            # Fall back to environment (set by check_environment or --nessus-user arg)
            if not nessus_user:
                nessus_user = (os.environ.get("nessus_user", "")
                               or os.environ.get("NESSUS_USER", "")).strip()
            if not nessus_pass:
                nessus_pass = (os.environ.get("nessus_pass", "")
                               or os.environ.get("NESSUS_PASS", "")).strip()

            if nessus_user and nessus_pass:
                self.ctx.logger.info(
                    "Nessus credentials loaded.", tool="nessus")
            if not nessus_user:
                nessus_user = self._prompt(
                    "Nessus username (or type 'skip' to disable Nessus for this run):",
                    prompt_type="text", skippable=True).strip()
                if not nessus_user or nessus_user.lower() == "skip":
                    self._mark_skipped("Nessus credentials not provided")
                    return
            if not nessus_pass:
                nessus_pass = self._prompt(
                    "Nessus password:",
                    prompt_type="password").strip()
                if not nessus_pass:
                    self._mark_skipped("Nessus password not provided")
                    return
                # Persist newly-entered credentials for future runs
                NessusConfig.save(nessus_user, nessus_pass)
                os.environ["nessus_user"] = nessus_user
                os.environ["nessus_pass"] = nessus_pass

            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

            # ── Fetch X-API-Token for Nessus 10.x ────────────────────────────
            api_token = self._get_api_token()
            self.ctx.logger.info(f"Nessus API token: {api_token[:8]}…", tool="nessus")

            # ── Authenticate ─────────────────────────────────────────────────
            try:
                auth_resp = self._req(
                    "POST", "/session",
                    api_token=api_token,
                    json={"username": nessus_user, "password": nessus_pass},
                    timeout=20)
                token = auth_resp.json().get("token", "")
                if not token:
                    self._mark_skipped(
                        f"Nessus authentication failed (HTTP {auth_resp.status_code}): "
                        f"{auth_resp.text[:200]}")
                    return
            except Exception as e:
                self._mark_skipped(f"Nessus unreachable at {self.NESSUS_URL}: {e}")
                return

            # Exclude ALL scanner IPs — every interface, not just the test one.
            # _get_server_ips() enumerates every network adapter on the machine.
            server_ips = _get_server_ips()
            server_ips.add(net_cfg)    # belt-and-suspenders: always include configured IP

            # ── Derive active subnets from live_ips, then subtract server IPs ──
            # Collect the unique /24 subnets that contain our discovered hosts,
            # then enumerate every host address in those subnets minus the
            # server's own IPs.  This lets Nessus find additional hosts on
            # active subnets while guaranteeing the scanner is never a target.
            active_subnets: list[ipaddress.IPv4Network] = []
            seen_nets: set[str] = set()
            for lip in live_ips:
                try:
                    net24 = ipaddress.ip_network(f"{lip}/24", strict=False)
                    key = str(net24)
                    if key not in seen_nets:
                        seen_nets.add(key)
                        active_subnets.append(net24)
                except Exception:
                    pass

            if not active_subnets:
                self._mark_skipped(
                    "Could not derive any valid subnet from live IPs — skipping Nessus.")
                return

            scan_hosts = [
                str(h)
                for net in active_subnets
                for h in net.hosts()
                if str(h) not in server_ips
            ]
            if not scan_hosts:
                self._mark_skipped(
                    "All hosts in active subnets belong to the scanner — nothing to scan.")
                return
            targets = "\n".join(scan_hosts)

            self.ctx.logger.info(
                f"Nessus targets: {len(scan_hosts)} host(s) across "
                f"{len(active_subnets)} subnet(s) "
                f"(live IPs: {live_ips}, excluded server IPs: {sorted(server_ips)})",
                tool="nessus")

            out_dir = self.ctx.instance_dir / "Nessus"
            out_dir.mkdir(parents=True, exist_ok=True)

            # ── Discover scan template UUID dynamically ───────────────────────
            # The UUID differs between Nessus versions and installations.
            # Fetch /editor/scan/templates and pick the "Advanced Scan" or
            # "Basic Network Scan" template rather than using a hardcoded value.
            scan_uuid = self._get_scan_template_uuid(token, api_token)
            self.ctx.logger.info(
                f"Using scan template UUID: {scan_uuid}", tool="nessus")

            # ── Create scan ───────────────────────────────────────────────────
            try:
                scan_resp = self._req(
                    "POST", "/scans", token=token, api_token=api_token,
                    json={
                        "uuid": scan_uuid,
                        "settings": {
                            "name": (
                                f"GearBox-{self.ctx.instance_key}-"
                                f"{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                            ),
                            "text_targets": targets,
                            "exclude_targets": ",".join(excluded_hosts),
                        },
                    },
                    timeout=20)
                scan_id = scan_resp.json().get("scan", {}).get("id")
            except Exception as e:
                self._mark_error(f"Could not create Nessus scan: {e}")
                return

            if not scan_id:
                self._mark_skipped(
                    f"Could not create Nessus scan: {scan_resp.text[:200]}")
                return

            # ── Launch ────────────────────────────────────────────────────────
            try:
                self._req("POST", f"/scans/{scan_id}/launch",
                          token=token, api_token=api_token, timeout=20)
            except Exception as e:
                self._mark_error(f"Could not launch Nessus scan: {e}")
                return

            # Expose scan identity on ctx so _ethernet_shutdown_cleanup() can
            # call POST /scans/{scan_id}/stop if a shutdown occurs mid-scan.
            self.ctx._nessus_scan_id   = scan_id
            self.ctx._nessus_token     = token
            self.ctx._nessus_api_token = api_token

            findings_count, poll_status = self._poll_nessus(
                token, api_token, scan_id, out_dir)

            # Clear scan identity — scan is no longer active.
            self.ctx._nessus_scan_id   = None
            self.ctx._nessus_token     = None
            self.ctx._nessus_api_token = None

            if poll_status == "ok":
                self._mark_complete(
                    f"Nessus scan complete — {findings_count} finding(s)")
            elif poll_status in ("canceled", "timeout"):
                # Scan was canceled/aborted or timed out — not an error on our side
                self._mark_skipped(
                    f"Nessus scan did not complete (status: {poll_status}). "
                    f"No results available.")
            else:
                # Scan completed on Nessus but export/download failed.
                self._mark_error(
                    "Nessus scan completed on Nessus server but results could not be "
                    "downloaded. Check Nessus connectivity and permissions, then re-run.")

        except Exception as e:
            self.ctx.logger.error(f"Nessus failed: {e}", exc=e, tool="nessus")
            self._mark_error(str(e))

    def _reauth_nessus(self, api_token: str) -> str:
        """Re-authenticate and return a fresh session token."""
        # Load from config.yaml first, then fall back to environment
        nessus_user, nessus_pass = NessusConfig.load()
        if not nessus_user:
            nessus_user = (os.environ.get("nessus_user", "")
                           or os.environ.get("NESSUS_USER", "")).strip()
        if not nessus_pass:
            nessus_pass = (os.environ.get("nessus_pass", "")
                           or os.environ.get("NESSUS_PASS", "")).strip()
        if not nessus_user or not nessus_pass:
            self.ctx.logger.warn(
                "Cannot re-authenticate — Nessus credentials not found",
                tool="nessus")
            return ""
        try:
            resp = self._req(
                "POST", "/session",
                api_token=api_token,
                json={"username": nessus_user, "password": nessus_pass},
                timeout=20)
            new_token = resp.json().get("token", "")
            if new_token:
                self.ctx.logger.info("Nessus session refreshed.", tool="nessus")
            else:
                self.ctx.logger.warn(
                    f"Nessus re-auth failed: {resp.text[:200]}", tool="nessus")
            return new_token
        except Exception as e:
            self.ctx.logger.warn(f"Nessus re-auth error: {e}", tool="nessus")
            return ""

    def _reauth_with_retry(self, api_token: str, current_token: str) -> str:
        """
        Re-authenticate with up to 3 attempts; wait 2 minutes between failures.
        Returns new token on success, current_token if all attempts fail.
        """
        MAX_REAUTH_ATTEMPTS = 3
        REAUTH_WAIT_SECONDS = 120
        for attempt in range(MAX_REAUTH_ATTEMPTS):
            if attempt > 0:
                self.ctx.logger.warn(
                    f"Nessus re-auth attempt {attempt+1}/{MAX_REAUTH_ATTEMPTS}"
                    f" — waiting {REAUTH_WAIT_SECONDS}s…", tool="nessus")
                time.sleep(REAUTH_WAIT_SECONDS)
            fresh = self._reauth_nessus(api_token)
            if fresh:
                self.ctx.logger.info(
                    f"Nessus re-auth succeeded on attempt {attempt+1}.", tool="nessus")
                return fresh
            self.ctx.logger.warn(
                f"Nessus re-auth attempt {attempt+1} failed.", tool="nessus")
        self.ctx.logger.error(
            "All Nessus re-auth attempts exhausted — continuing with stale token.",
            tool="nessus")
        return current_token

    def _poll_nessus(self, token: str, api_token: str,
                     scan_id: int, out_dir: Path) -> int:
        """Poll until scan completes, then export and download both .nessus and .csv."""
        self.ctx.logger.info(f"Polling Nessus scan {scan_id}…", tool="nessus")

        # Use a mutable list so the token can be refreshed and stay in scope
        # for the export phase that follows the poll loop.
        _tok = [token]   # _tok[0] is always the current live token

        # Proactively refresh session every 50 polls (~25 min) to stay ahead
        # of the default 30-minute Nessus session expiry.
        _PROACTIVE_REFRESH_INTERVAL = 50

        # Poll until complete — max 240 polls × 30 s = 120 minutes.
        last_status = "running"
        for attempt in range(240):
            time.sleep(30)
            # Proactive re-auth before session can expire
            if attempt > 0 and attempt % _PROACTIVE_REFRESH_INTERVAL == 0:
                self.ctx.logger.info(
                    f"Poll {attempt+1}: proactive session refresh…", tool="nessus")
                fresh = self._reauth_nessus(api_token)
                if fresh:
                    _tok[0] = fresh
                    self.ctx.logger.info("Proactive refresh succeeded.", tool="nessus")
                else:
                    self.ctx.logger.warn(
                        "Proactive refresh failed — continuing with existing token.",
                        tool="nessus")
            try:
                resp = self._req("GET", f"/scans/{scan_id}",
                                 token=_tok[0], api_token=api_token, timeout=20)
                # Token expired — re-authenticate immediately
                if resp.status_code in (401, 403):
                    self.ctx.logger.warn(
                        f"Poll {attempt+1}: session expired (HTTP {resp.status_code})"
                        " — re-authenticating…", tool="nessus")
                    _tok[0] = self._reauth_with_retry(api_token, _tok[0])
                    continue
                last_status = resp.json().get("info", {}).get("status", last_status)
                self.ctx.logger.info(
                    f"  Scan {scan_id} status: {last_status} (poll {attempt+1})"
                    f" [token_prefix={_tok[0][:6] if _tok[0] else 'none'}]",
                    tool="nessus")
                if last_status == "completed":
                    break
                if last_status in ("canceled", "aborted"):
                    self.ctx.logger.warn(
                        f"Nessus scan {last_status} — attempting export anyway.",
                        tool="nessus")
                    break  # fall through to export phase
            except Exception as e:
                self.ctx.logger.warn(f"Poll {attempt+1} error: {e}", tool="nessus")

        # Guard: only export if the scan actually completed.
        if last_status not in ("completed", "canceled", "aborted"):
            # Poll loop exhausted — re-auth and do one final status check before giving up.
            self.ctx.logger.warn(
                f"Poll loop exhausted (scan {scan_id} still {last_status!r}) — "
                "re-authenticating and retrying final status check…", tool="nessus")
            fresh = self._reauth_nessus(api_token)
            if fresh:
                _tok[0] = fresh
                try:
                    resp = self._req("GET", f"/scans/{scan_id}",
                                     token=_tok[0], api_token=api_token, timeout=20)
                    if resp.status_code == 200:
                        last_status = resp.json().get("info", {}).get("status", last_status)
                        self.ctx.logger.info(
                            f"Post-reauth status check: {last_status}", tool="nessus")
                except Exception as e:
                    self.ctx.logger.warn(
                        f"Post-reauth status check failed: {e}", tool="nessus")
            else:
                self.ctx.logger.warn(
                    "Re-auth failed — cannot perform final status check.", tool="nessus")

        if last_status not in ("completed", "canceled", "aborted"):
            self.ctx.logger.warn(
                f"Nessus scan {scan_id} did not reach a terminal state "
                f"(last status: {last_status!r}). Skipping export.",
                tool="nessus")
            return 0, "timeout"

        total_findings = 0
        any_downloaded = False

        # Re-authenticate before export — use the latest token from _tok[0]
        token = _tok[0]
        self.ctx.logger.info(
            "Refreshing session token before export…", tool="nessus")
        fresh = self._reauth_nessus(api_token)
        if fresh:
            token = fresh
        else:
            self.ctx.logger.warn(
                "Could not refresh token before export — "
                "attempting with existing token", tool="nessus")

        # Export and download both formats (.nessus XML first, then CSV)
        for fmt, ext in [("nessus", ".nessus"), ("csv", ".csv")]:
            self.ctx.logger.info(f"Requesting Nessus {fmt} export…", tool="nessus")
            try:
                exp_resp = self._req(
                    "POST", f"/scans/{scan_id}/export",
                    token=token, api_token=api_token,
                    json={"format": fmt}, timeout=30)
                resp_json = exp_resp.json()
                file_id = resp_json.get("file") or resp_json.get("token")
            except Exception as e:
                self.ctx.logger.warn(f"Export request ({fmt}) failed: {e}", tool="nessus")
                continue

            if not file_id:
                self.ctx.logger.warn(
                    f"No file_id in Nessus {fmt} export response: {exp_resp.text[:200]}",
                    tool="nessus")
                continue

            self.ctx.logger.info(f"Waiting for {fmt} export (file_id={file_id})…",
                                  tool="nessus")
            # Wait up to 10 minutes for export to be ready (large scans take time)
            ready = False
            for attempt in range(120):
                time.sleep(5)
                try:
                    st = self._req("GET",
                                   f"/scans/{scan_id}/export/{file_id}/status",
                                   token=token, api_token=api_token, timeout=15)
                    st_val = st.json().get("status", "")
                    self.ctx.logger.info(
                        f"  {fmt} export status: {st_val} (attempt {attempt+1})",
                        tool="nessus")
                    if st_val == "ready":
                        ready = True
                        break
                    if st_val in ("error", "aborted"):
                        self.ctx.logger.warn(
                            f"  {fmt} export {st_val}", tool="nessus")
                        break
                except Exception as e:
                    self.ctx.logger.warn(f"  Export status check failed: {e}", tool="nessus")

            if not ready:
                self.ctx.logger.warn(f"Nessus {fmt} export never became ready", tool="nessus")
                continue

            # Download
            out_path = out_dir / f"nessus_results{ext}"
            downloaded = False
            for stream in (True, False):
                try:
                    self.ctx.logger.info(
                        f"Downloading {fmt} ({'streaming' if stream else 'direct'})…",
                        tool="nessus")
                    dl = self._req("GET",
                                   f"/scans/{scan_id}/export/{file_id}/download",
                                   token=token, api_token=api_token,
                                   timeout=600, stream=stream)
                    if stream:
                        with open(str(out_path), "wb") as f:
                            for chunk in dl.iter_content(chunk_size=65536):
                                if chunk:
                                    f.write(chunk)
                    else:
                        out_path.write_bytes(dl.content)

                    size = out_path.stat().st_size if out_path.exists() else 0
                    if size > 0:
                        downloaded = True
                        self.ctx.logger.info(
                            f"Downloaded Nessus {ext} → {out_path} ({size:,} bytes)",
                            tool="nessus")
                        break
                    else:
                        self.ctx.logger.warn(
                            f"{ext} downloaded but file is empty — retrying",
                            tool="nessus")
                except Exception as e:
                    self.ctx.logger.warn(
                        f"{ext} download ({'stream' if stream else 'direct'}) failed: {e}",
                        tool="nessus")

            if not downloaded:
                self.ctx.logger.warn(f"Could not download Nessus {ext}", tool="nessus")
            else:
                any_downloaded = True

        # Parse .nessus XML for findings (richer than CSV)
        nessus_file = out_dir / "nessus_results.nessus"
        csv_file    = out_dir / "nessus_results.csv"

        if nessus_file.exists() and nessus_file.stat().st_size > 0:
            total_findings = self._parse_nessus_xml(nessus_file)
        elif csv_file.exists() and csv_file.stat().st_size > 0:
            self.ctx.logger.info("Falling back to CSV parsing", tool="nessus")
            total_findings = self._parse_nessus_csv(csv_file)
        else:
            self.ctx.logger.warn("No Nessus output files found to parse", tool="nessus")

        return total_findings, ("ok" if any_downloaded else "download_failed")

    def _parse_nessus_xml(self, nessus_file: Path) -> int:
        """
        Parse a .nessus XML file and create findings.
        The .nessus format is a Nessus XML v2 file with ReportItem elements.
        """
        count = 0
        RISK_MAP = {
            "4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Informational"
        }
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(str(nessus_file))
            root = tree.getroot()

            for report_host in root.findall(".//ReportHost"):
                host_ip = report_host.get("name", "")

                for item in report_host.findall("ReportItem"):
                    severity   = item.get("severity", "0")
                    risk       = RISK_MAP.get(severity, "Informational")
                    if severity == "0":
                        continue   # skip informational noise

                    plugin_id   = item.get("pluginID", "")
                    plugin_name = item.get("pluginName", "")
                    port_str    = item.get("port", "")
                    protocol    = item.get("protocol", "tcp")
                    svc_name    = item.get("svc_name", "")

                    description = (item.findtext("description") or "").strip()
                    solution    = (item.findtext("solution") or "").strip()
                    plugin_out  = (item.findtext("plugin_output") or "").strip()
                    synopsis    = (item.findtext("synopsis") or "").strip()
                    cve_list    = [c.text.strip() for c in item.findall("cve") if c.text]
                    cvss        = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score") or "0"

                    # Build a clean, professional title
                    title = plugin_name or f"Nessus Plugin {plugin_id}"
                    # Normalise overlapping Nessus plugin titles to pr0t31n standard
                    title = _NESSUS_TITLE_NORM.get(title, title)

                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title=title,
                        description=synopsis or description,
                        tool="nessus",
                        raw_output=plugin_out[:500],
                        tool_risk=risk,
                        force_risk=risk,
                        cve_ids=cve_list,
                        affected_component=f"{svc_name} on {host_ip}:{port_str}/{protocol}" if port_str else host_ip,
                        remediation=solution,
                        source_type="primary",
                        ip=host_ip,
                        port=port_str,
                        output_file=str(nessus_file),
                    )
                    count += 1

        except Exception as e:
            self.ctx.logger.warn(f"Could not parse Nessus XML: {e}", tool="nessus")
        return count

    def _parse_nessus_csv(self, csv_path: Path) -> int:
        """Parse Nessus CSV and create findings."""
        count = 0
        try:
            with open(str(csv_path), encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    risk = row.get("Risk", "None")
                    if risk in ("None", ""):
                        continue
                    _csv_ip   = (row.get("Host") or row.get("IP Address") or "").strip()
                    _csv_port = (row.get("Port") or "").strip()
                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title=_NESSUS_TITLE_NORM.get(row.get("Name", ""), row.get("Name", "Nessus Finding")),
                        description=row.get("Description", ""),
                        tool="nessus",
                        tool_risk=risk,
                        cve_ids=[c.strip() for c in row.get("CVE", "").split(",") if c.strip()],
                        affected_component=row.get("Plugin Output", "")[:200],
                        remediation=row.get("Solution", ""),
                        source_type="primary",
                        ip=_csv_ip, port=_csv_port,
                        output_file=str(csv_path),
                    )
                    count += 1
        except Exception as e:
            self.ctx.logger.warn(f"Could not parse Nessus CSV: {e}")
        return count


# ---------------------------------------------------------------------------
# Responder Module
# ---------------------------------------------------------------------------

class ResponderModule(BaseModule):
    """
    Launch Responder in poisoning mode (-FP flags) in the background.
    Continuously tail Responder log files to extract hashes and plaintext
    credentials and create findings in real time.  The subprocess is kept
    alive until the ethernet pipeline signals completion via a threading.Event
    injected on ctx._responder_stop_event.  All captured credentials are also
    appended to per-hash-type files in the project output directory.
    """
    name            = "Responder"
    description     = "LLMNR/NBT-NS/MDNS poisoner — captures hashes and credentials"
    concurrent_safe = True

    # Regex patterns for each credential type in Responder logs
    _HASH_PATTERNS = {
        "NTLMv2": re.compile(
            r'\[[\+\*]\]\s+(?P<type>NTLMv2(?:-SSP)?)\s+Hash\s+:\s+'
            r'(?P<user>[^\\\s]+\\[^\s:]+)::(?P<hash>\S+:\S+:\S+:\S+:\S+)',
            re.I),
        "NTLMv1": re.compile(
            r'\[[\+\*]\]\s+(?P<type>NTLMv1(?:-SSP)?)\s+Hash\s+:\s+'
            r'(?P<user>[^\\\s]+\\[^\s:]+)::(?P<hash>\S+:\S+:\S+)',
            re.I),
        "NetNTLMv2": re.compile(
            r'(?P<user>[^\\\s]+\\[^\s:]+)::(?P<domain>[^:]+):'
            r'(?P<hash>[0-9a-fA-F]{16}:[0-9a-fA-F]+:[0-9a-fA-F]+)',
            re.I),
        "Cleartext": re.compile(
            r'\[[\+\*]\]\s+(?:Cleartext|Password)\s+:\s+(?P<password>\S+).*?'
            r'(?:User|Username)\s*:\s*(?P<user>\S+)',
            re.I | re.S),
        "BasicAuth": re.compile(
            r'\[[\+\*]\]\s+(?:HTTP|FTP|SMTP|POP3|IMAP)\s+'
            r'(?:Basic|AUTH|Cleartext).*?'
            r'User\s*:\s*(?P<user>\S+).*?'
            r'Password\s*:\s*(?P<password>\S+)',
            re.I | re.S),
    }

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")

            if not tool_available("responder") and not tool_available("Responder"):
                self._mark_skipped("Responder not installed")
                return

            responder_bin = (shutil.which("responder")
                             or shutil.which("Responder")
                             or "responder")

            out_dir = self.ctx.instance_dir / "Responder"
            out_dir.mkdir(parents=True, exist_ok=True)

            # ── Locate Responder's default log directory ──────────────────────
            # Responder does not support a -l flag for log redirection.
            # It always writes to its installation directory's logs/ subfolder.
            responder_log_dirs = [
                Path("/usr/share/responder/logs"),
                Path("/opt/responder/logs"),
                Path.home() / ".local/share/responder/logs",
                Path(responder_bin).parent / "logs" if responder_bin != "responder" else Path(""),
            ]
            log_dir = None
            for candidate in responder_log_dirs:
                if candidate and candidate.exists():
                    log_dir = candidate
                    break
            if log_dir is None:
                # Create a likely path — Responder will create it if needed
                log_dir = Path("/usr/share/responder/logs")
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                except Exception:
                    log_dir = out_dir / "logs"
                    log_dir.mkdir(parents=True, exist_ok=True)

            self.ctx.logger.info(
                f"Responder log dir: {log_dir}", tool="responder")

            # Responder requires root to bind to privileged ports.
            # Gearbox runs under sudo so os.geteuid() should be 0.
            # Still prepend sudo -E as a safety net on some distros.
            sudo_prefix = [] if os.geteuid() == 0 else ["sudo", "-E"]
            cmd = sudo_prefix + [responder_bin, "-I", TEST_INTERFACE, "-F", "-P"]

            self.ctx.logger.info(
                f"Starting Responder on {TEST_INTERFACE} with flags -FP…",
                tool="responder")

            responder_log_file = out_dir / "responder_stdout.log"
            try:
                log_fh = open(str(responder_log_file), "w")
                # Acquire a subprocess slot for the Responder process lifetime.
                _subproc_sem.acquire()
                self.ctx._responder_sem_acquired = True
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    preexec_fn=_mem_limit_preexec if sys.platform != "win32" else None,
                )
                _track_proc(proc)
                if _pause:
                    _pause.register(proc, "responder")
                # keep filehandle so we can close it on exit
                self.ctx._responder_log_fh = log_fh
            except Exception as e:
                self._mark_skipped(f"Could not start Responder: {e}")
                return

            # Store process on ctx so orchestrator can kill it later
            self.ctx._responder_proc = proc
            stop_event = getattr(self.ctx, '_responder_stop_event', None)
            if stop_event is None:
                stop_event = threading.Event()
                self.ctx._responder_stop_event = stop_event

            seen_hashes: set[str] = set()
            file_positions: dict[str, int] = {}

            def _scan_file(path: Path) -> None:
                key = str(path)
                try:
                    pos  = file_positions.get(key, 0)
                    size = path.stat().st_size
                    if size <= pos:
                        return
                    with open(str(path), encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        new_text = fh.read()
                        file_positions[key] = fh.tell()
                    for cred_type, pattern in self._HASH_PATTERNS.items():
                        for m in pattern.finditer(new_text):
                            self._handle_credential(
                                cred_type, m, path, out_dir, seen_hashes)
                except Exception:
                    pass

            while not stop_event.is_set():
                for log_file in log_dir.glob("*.log"):
                    _scan_file(log_file)
                if responder_log_file.exists():
                    _scan_file(responder_log_file)
                stop_event.wait(timeout=5)

            # Terminate Responder
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            finally:
                fh_attr = getattr(self.ctx, '_responder_log_fh', None)
                if fh_attr:
                    try:
                        fh_attr.close()
                    except Exception:
                        pass
                if getattr(self.ctx, '_responder_sem_acquired', False):
                    _subproc_sem.release()
                    self.ctx._responder_sem_acquired = False

            # Copy Responder logs to evidence directory
            try:
                for lf in log_dir.glob("*.log"):
                    dest = out_dir / lf.name
                    if not dest.exists():
                        import shutil as _sh
                        _sh.copy2(str(lf), str(dest))
            except Exception:
                pass

            self.ctx.logger.info(
                f"Responder stopped. Total credentials harvested: {len(seen_hashes)}",
                tool="responder")
            self._mark_complete(f"{len(seen_hashes)} credential(s) captured")

        except Exception as e:
            self.ctx.logger.error(f"Responder module failed: {e}", exc=e,
                                   tool="responder")
            self._mark_error(str(e))

    def _handle_credential(self, cred_type: str, match: re.Match,
                            log_file, out_dir: Path,
                            seen_hashes: set) -> None:
        """Process a matched credential: deduplicate, create finding, append to file."""
        try:
            if cred_type in ("NTLMv2", "NTLMv1", "NetNTLMv2"):
                user  = match.group("user")
                hsh   = match.group("hash")
                dedup = f"{cred_type}::{user}::{hsh[:32]}"
                if dedup in seen_hashes:
                    return
                seen_hashes.add(dedup)

                title       = f"{cred_type} Hash Captured — {user}"
                description = (f"Responder captured a {cred_type} challenge-response "
                                f"hash for user {user} via LLMNR/NBT-NS/MDNS poisoning.")
                raw         = f"{user}::{hsh}"
                risk        = "Critical"

                # Append to per-type hash file in project root for cracking
                hash_file = out_dir / f"{cred_type.lower().replace('-','_')}_hashes.txt"
                with open(str(hash_file), "a", encoding="utf-8") as hf:
                    hf.write(raw + "\n")

                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=title,
                    description=description,
                    tool="responder",
                    raw_output=raw[:500],
                    force_risk=risk,
                    source_type="primary",
                    output_file=str(hash_file),
                    ip="",
                    port="",
                )

            elif cred_type in ("Cleartext", "BasicAuth"):
                user     = match.group("user")
                password = match.group("password")
                dedup    = f"Cleartext::{user}::{password[:16]}"
                if dedup in seen_hashes:
                    return
                seen_hashes.add(dedup)

                title       = f"Cleartext Credential Captured — {user}"
                description = (f"Responder captured plaintext credentials for "
                                f"user {user} via protocol poisoning.")
                risk        = "Critical"

                creds_file = out_dir / "cleartext_credentials.txt"
                with open(str(creds_file), "a", encoding="utf-8") as cf:
                    cf.write(f"{user}:{password}\n")

                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=title,
                    description=description,
                    tool="responder",
                    raw_output=f"User: {user}",
                    force_risk=risk,
                    source_type="primary",
                    output_file=str(creds_file),
                    ip="",
                    port="",
                )

                self.ctx.logger.info(
                    f"Cleartext credential harvested for {user}", tool="responder")

        except Exception as e:
            self.ctx.logger.warn(f"Credential parse error ({cred_type}): {e}",
                                  tool="responder")


class NmapPortModule(BaseModule):
    name        = "NmapPort"
    description = "Full TCP/UDP port scan of all discovered live hosts"

    def run(self) -> None:
        self._mark_running()
        try:
            # Pre-mark all port-dependent modules as "waiting" so the Evidence tab
            # shows a live status from the moment NmapPort begins scanning.
            _WAITING_MODULES = [
                "BannerGrab","SSH","Web","Nuclei","SSL","FTP","SMB","NFS"]
            for _wmod in _WAITING_MODULES:
                try:
                    self.ctx.progress.set_module_status(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, _wmod, "waiting",
                        "Waiting for NmapPort…")
                    console.status_update(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, _wmod, "waiting",
                        "Waiting for NmapPort…")
                except Exception:
                    pass

            # ── Resolve live IPs ──────────────────────────────────────────────
            # Priority 1: direct ctx attribute set by NmapLive in this process run
            #             (avoids the progress/reload system entirely).
            # Priority 2: progress file entry (for resumed runs).
            # Priority 3: database discovered_hosts (last resort).
            live_ips: list[str] = []

            ctx_ips = getattr(self.ctx, '_live_ips', None)
            if ctx_ips:
                live_ips = ctx_ips
                self.ctx.logger.info(
                    f"NmapPort: using {len(live_ips)} live IPs from NmapLive ctx",
                    tool="nmap")
            else:
                live_ips_json = self.ctx.progress.get_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_live_ips")
                if live_ips_json not in ("pending", "skipped", ""):
                    try:
                        live_ips = json.loads(live_ips_json)
                    except Exception:
                        live_ips = [live_ips_json] if live_ips_json else []

            # Final fallback: DB hosts already upserted by NmapLive
            if not live_ips:
                live_ips = self.ctx.db.get_hosts(self.ctx)
                if live_ips:
                    self.ctx.logger.info(
                        f"NmapPort: using {len(live_ips)} IPs from DB (progress fallback)",
                        tool="nmap")

            if not live_ips:
                self._mark_skipped("No live hosts to port scan")
                return

            out_dir = self.ctx.instance_dir / "NmapPort"
            out_dir.mkdir(parents=True, exist_ok=True)

            def scan_host(ip: str) -> None:
                safe    = ip.replace(".", "_")
                xml_out = out_dir / f"{safe}_ports.xml"
                txt_out = out_dir / f"{safe}_ports.txt"
                # -O (OS detection) requires root; add it only when we can
                os_flags = ["-O", "--osscan-guess"] if os.geteuid() == 0 else []
                cmd = [
                    "nmap", "-sV", "-sC", "--open", "-p-",
                    "--version-intensity", "7",
                    *os_flags,
                    # "vuln" scripts removed — they can run for hours per host
                    # and are the primary cause of pipeline lock-up. Nuclei
                    # handles vuln detection with proper timeout controls.
                    "--script", "default,auth",
                    "--script-timeout", "20s",
                    "--host-timeout", "10m",   # hard per-host ceiling
                    "--max-retries", "1",
                    "--min-rtt-timeout", "100ms",
                    "--max-rtt-timeout", "500ms",
                    "-oX", str(xml_out),
                    "-oN", str(txt_out),
                    ip,
                ]
                run_tool(cmd, self.ctx, tool_name="nmap",
                         output_file=txt_out, timeout=660)
                self._record_tool_run(
                    "nmap", " ".join(str(x) for x in cmd),
                    output_file=str(txt_out),
                    purpose="Port and service scan")
                self._parse_port_results(ip, xml_out)

            # Per-host module dispatch — runs immediately after each host's
            # port scan + parse completes. Each module receives a fresh ctx
            # scoped to this instance; it reads the just-written DB rows for
            # this IP and runs its specific service checks.
            #
            # Module → port/service filter (checked before dispatch to avoid
            # spawning threads that would instantly skip):
            #   BannerGrab  — all open ports
            #   Web         — http/https service or common web ports
            #   Nuclei      — same as Web
            #   SSL         — https/ssl/tls service or ports 443/8443 etc.
            #   SSH         — ssh service or port 22 (no conflicting service)
            #   SMB         — microsoft-ds/netbios-ssn/smb or ports 139/445
            #   NFS         — rpcbind/nfs/mountd or ports 111/2049

            _HTTP_SVCS   = {"http","http-alt","http-proxy","www","webcache","openssl"}
            _HTTPS_SVCS  = {"https","https-alt","ssl","tls"}
            _HTTP_PORTS  = {80,8080,8000,8008,8081,8082,8880,3000,5000,9080}
            _HTTPS_PORTS = {443,8443,4443,9443,10443}

            def _should_run(mod_name: str, ports: list[dict]) -> bool:
                """Return True if ip has at least one port relevant to mod_name."""
                if mod_name == "BannerGrab":
                    return len(ports) > 0
                if mod_name in ("Web", "Nuclei"):
                    return any(
                        (p.get("service","").lower() in _HTTP_SVCS | _HTTPS_SVCS)
                        or p["port"] in _HTTP_PORTS | _HTTPS_PORTS
                        for p in ports)
                if mod_name == "SSL":
                    # SSL only against confirmed HTTPS/SSL/TLS ports
                    return any(
                        (p.get("service") or "").lower() in
                        {"https","https-alt","ssl","tls"}
                        or "https" in (p.get("version") or "").lower()
                        or "ssl"   in (p.get("version") or "").lower()
                        or p["port"] in {443,8443,4443,9443,10443}
                        for p in ports)
                if mod_name == "SSH":
                    return any(
                        "ssh" in (p.get("service") or "").lower()
                        or (p["port"] == 22 and
                            (p.get("service") or "").lower() in ("","ssh","unknown"))
                        for p in ports)
                if mod_name == "SMB":
                    return any(
                        (p.get("service") or "").lower() in
                        ("microsoft-ds", "netbios-ssn", "smb")
                        or p["port"] in (139, 445)
                        for p in ports)
                if mod_name == "FTP":
                    return any(p["port"] in (20, 21) for p in ports)
                if mod_name == "NFS":
                    return any(
                        (p.get("service") or "").lower() in ("rpcbind","nfs","mountd")
                        or p["port"] in (111, 2049)
                        for p in ports)
                return False

            _PER_HOST_MODULES = [
                "BannerGrab", "Web", "Nuclei", "SSL", "SSH", "FTP", "SMB", "NFS"]

            _MOD_TIMEOUTS = {
                "BannerGrab": 180,
                "Web":        900,
                "Nuclei":     900,
                "SSL":        600,
                "SSH":        180,
                "FTP":        120,
                "SMB":        180,
                "NFS":        120,
            }

            _assessment_executor = ThreadPoolExecutor(
                max_workers=_MAX_PER_HOST_WORKERS,
                thread_name_prefix="per-host-assess")
            _assessment_futures: list = []
            _completed_hosts: set = set()
            _completed_lock = threading.Lock()

            def _assess_host_post_scan(ip: str) -> None:
                """Run per-host assessment modules for a single IP."""
                ports = self.ctx.db.get_ports_for_host(ip, self.ctx)
                self.ctx.logger.info(
                    f"NmapPort: dispatching assessment for {ip} "
                    f"({len(ports)} open port(s))", tool="nmap")
                for mod_name in _PER_HOST_MODULES:
                    if not _should_run(mod_name, ports):
                        self.ctx.logger.info(
                            f"NmapPort: skipping {mod_name} for {ip} "
                            f"— no relevant ports", tool="nmap")
                        continue
                    cls = _MODULE_REGISTRY.get(mod_name)
                    if cls is None:
                        continue
                    try:
                        mod                  = cls(self.ctx)
                        mod._single_host_ip  = ip   # scope to this IP only
                        budget = _MOD_TIMEOUTS.get(mod_name, 300)
                        self.ctx.logger.info(
                            f"NmapPort: running {mod_name} for {ip} "
                            f"(budget {budget}s)", tool="nmap")
                        with ThreadPoolExecutor(
                                max_workers=1,
                                thread_name_prefix=f"ph-{mod_name[:4]}") as _ph:
                            _f = _ph.submit(mod.run)
                            try:
                                _f.result(timeout=budget)
                            except TimeoutError:
                                self.ctx.logger.warn(
                                    f"Per-host {mod_name} for {ip} exceeded "
                                    f"{budget}s — moving on", tool=mod_name)
                        # After this IP is processed, reset to "waiting" so the
                        # Evidence tab doesn't show "complete" while more hosts
                        # may still be scanned by the ongoing NmapPort run.
                        _cur = self.ctx.progress.get_module_status(
                            self.ctx.subdevice_key, self.ctx.interface,
                            self.ctx.instance_key, mod_name)
                        if _cur in ("complete", "skipped"):
                            self.ctx.progress.set_module_status(
                                self.ctx.subdevice_key, self.ctx.interface,
                                self.ctx.instance_key, mod_name, "waiting",
                                f"Waiting for more hosts… ({ip} done)")
                            console.status_update(
                                self.ctx.subdevice_key, self.ctx.interface,
                                self.ctx.instance_key, mod_name, "waiting",
                                f"Waiting for more hosts… ({ip} done)")
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"Per-host {mod_name} for {ip} error: {e}",
                            tool=mod_name)

            with ThreadPoolExecutor(max_workers=_MAX_NMAP_PORT_WORKERS,
                                thread_name_prefix="nmap-port") as pool:
                futures = {pool.submit(scan_host, ip): ip for ip in live_ips}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        fut.result()
                        # Immediately dispatch per-host assessment in background
                        with _completed_lock:
                            if ip not in _completed_hosts:
                                _completed_hosts.add(ip)
                                af = _assessment_executor.submit(
                                    _assess_host_post_scan, ip)
                                _assessment_futures.append(af)
                    except Exception as e:
                        self.ctx.logger.error(f"Port scan of {ip} failed: {e}", exc=e)

            # Wait for all per-host assessments to complete (2-hour ceiling)
            self.ctx.logger.info(
                "NmapPort: waiting for per-host assessments to complete…",
                tool="nmap")
            try:
                for af in as_completed(_assessment_futures, timeout=7200):
                    try:
                        af.result(timeout=60)
                    except TimeoutError:
                        self.ctx.logger.warn(
                            "Per-host assessment future timed out", tool="nmap")
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"Per-host assessment error: {e}", tool="nmap")
            except TimeoutError:
                self.ctx.logger.warn(
                    "Overall per-host assessment deadline (2h) exceeded — "
                    "continuing with results gathered so far.",
                    tool="nmap")
            finally:
                _assessment_executor.shutdown(wait=False)

            # ── Final status sweep ────────────────────────────────────────────
            # Any phase2 module still in "waiting" state was never dispatched
            # because no relevant ports existed on any discovered host.
            # Mark it complete with an N/A detail so Evidence shows clean status.
            _MODULE_PORT_LABELS = {
                "BannerGrab": "Open",
                "Web":        "HTTP/HTTPS",
                "Nuclei":     "HTTP/HTTPS",
                "SSL":        "HTTPS/SSL",
                "SSH":        "SSH",
                "FTP":        "FTP",
                "SMB":        "SMB",
                "NFS":        "NFS/RPC",
            }
            for _sweep_mod, _port_label in _MODULE_PORT_LABELS.items():
                _cur_status = self.ctx.progress.get_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, _sweep_mod)
                if _cur_status in ("waiting", "pending", ""):
                    self.ctx.logger.info(
                        f"NmapPort sweep: {_sweep_mod} never called — "
                        f"no {_port_label} ports found. Marking N/A.",
                        tool="nmap")
                    self.ctx.progress.set_module_status(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, _sweep_mod, "complete",
                        f"N/A No {_port_label} Ports")
                    console.status_update(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, _sweep_mod, "complete",
                        f"N/A No {_port_label} Ports")

            self._mark_complete(f"Port scan and assessment complete for {len(live_ips)} host(s)")
        except Exception as e:
            self.ctx.logger.error(f"NmapPort failed: {e}", exc=e, tool="nmap")
            self._mark_error(str(e))

    def _parse_port_results(self, ip: str, xml_file: Path) -> None:
        """Parse nmap XML and populate DB with open ports."""
        if not xml_file.exists() or xml_file.stat().st_size == 0:
            self.ctx.logger.info(f"No port XML for {ip} — likely no open ports", tool="nmap")
            return
        open_ports = []
        try:
            import xml.etree.ElementTree as ET
            content = xml_file.read_text(encoding="utf-8", errors="replace").strip()
            if not content or "<nmaprun" not in content:
                self.ctx.logger.info(f"Empty nmap port XML for {ip}", tool="nmap")
                return
            if "</nmaprun>" not in content:
                content += "</nmaprun>"
            try:
                tree = ET.fromstring(content)
            except ET.ParseError as e:
                self.ctx.logger.info(
                    f"nmap port XML parse note for {ip} (likely no open ports): {e}",
                    tool="nmap")
                return
            for host in tree.findall(".//host"):
                addr_el = host.find(".//address[@addrtype='ipv4']")
                if addr_el is None:
                    continue
                host_ip = addr_el.get("addr", ip)
                # Extract MAC, hostname, OS for this host
                _mac_el = host.find(".//address[@addrtype='mac']")
                _mac    = _mac_el.get("addr", "") if _mac_el is not None else ""
                _hostname = ""
                for _hn in host.findall(".//hostname"):
                    _h = _hn.get("name", "")
                    if _h:
                        _hostname = _h
                        if _hn.get("type") == "user":
                            break
                _os_name = ""
                _os_el = host.find(".//osmatch")
                if _os_el is not None:
                    _os_name = _os_el.get("name", "")
                if _mac or _hostname or _os_name:
                    self.ctx.db.upsert_host(
                        host_ip, self.ctx,
                        mac_address=_mac,
                        hostname=_hostname,
                        os_name=_os_name)
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portid   = int(port_el.get("portid", 0))
                    protocol = port_el.get("protocol", "tcp")
                    svc_el   = port_el.find("service")
                    service  = svc_el.get("name", "") if svc_el is not None else ""
                    version  = svc_el.get("version", "") if svc_el is not None else ""
                    self.ctx.db.upsert_port(host_ip, portid, protocol,
                                             service, version, self.ctx)
                    open_ports.append(f"{portid}/{protocol} {service} {version}".strip())
                    # Emit version/EOL/CVE findings via shared helper
                    if version and len(version.strip()) > 2:
                        ver_clean = version.strip()
                        # SSH — separate software from OS in version string
                        if service and "ssh" in service.lower():
                            sw, sv, os_n, os_v = _parse_ssh_banner(ver_clean)
                            if sw and sv:
                                self._emit_version_findings(
                                    sw, sv, host_ip, str(portid), "nmap",
                                    str(xml_file), is_os=False)
                            if os_n and os_v:
                                self._emit_version_findings(
                                    os_n, os_v, host_ip, str(portid), "nmap",
                                    str(xml_file), is_os=True)
                        else:
                            parts    = ver_clean.split(None, 1)
                            software = parts[0] if len(parts) > 1 else (service or "Service")
                            ver_str  = parts[1] if len(parts) > 1 else ver_clean
                            self._emit_version_findings(
                                software, ver_str, host_ip, str(portid),
                                "nmap", str(xml_file), is_os=False)
        except Exception as e:
            self.ctx.logger.warn(f"Could not parse nmap port XML for {ip}: {e}")
            return

        if open_ports:
            self._observe(
                title="Open Port Discovered",
                description=f"A TCP or UDP port was confirmed open on the target host, indicating an exposed service that contributes to the overall network attack surface. "
                            f"{len(open_ports)} open port(s) found on {ip}: "
                            + ", ".join(open_ports[:20])
                            + (" …" if len(open_ports) > 20 else ""),
                tool="nmap",
                output_file=str(xml_file),
                output_text="\n".join(open_ports),
                risk="Informational",
            )

        # ── Unencrypted protocol findings ─────────────────────────────────
        # Raise Medium findings for cleartext protocols detected by nmap.
        UNENCRYPTED = {
            20:  "FTP-data",
            21:  "FTP",
            23:  "Telnet",
            25:  "SMTP",
            80:  "HTTP",
            110: "POP3",
            143: "IMAP",
        }
        try:
            import xml.etree.ElementTree as _ET
            _content = xml_file.read_text(encoding="utf-8", errors="replace").strip()
            if _content and "<nmaprun" in _content:
                if "</nmaprun>" not in _content:
                    _content += "</nmaprun>"
                _tree = _ET.fromstring(_content)
                for _host in _tree.findall(".//host"):
                    _addr = _host.find(".//address[@addrtype='ipv4']")
                    if _addr is None:
                        continue
                    _hip = _addr.get("addr", ip)
                    for _port_el in _host.findall(".//port"):
                        _state = _port_el.find("state")
                        if _state is None or _state.get("state") != "open":
                            continue
                        _portid = int(_port_el.get("portid", 0))
                        if _portid in UNENCRYPTED:
                            _proto_name = UNENCRYPTED[_portid]
                            if _portid == 23:
                                self.ctx.findings.create(
                                    ctx=self.ctx,
                                    title="Unencrypted Service: Telnet",
                                    description="A Telnet service is accessible on the network, transmitting all data including authentication credentials in cleartext, enabling passive interception or active MITM attacks.",
                                    remediation="Disable the Telnet daemon and replace it with SSH for all remote administration; block port 23 at the network perimeter.",
                                    tool="nmap",
                                    raw_output=f"port {_portid}/{_proto_name} open",
                                    source_type="primary",
                                    force_risk="High",
                                    ip=_hip,
                                    port=str(_portid),
                                    output_file=str(xml_file),
                                )
                            else:
                                self.ctx.findings.create(
                                    ctx=self.ctx,
                                    title=f"Unencrypted Protocol Detected: {_proto_name} — {_hip}:{_portid}",
                                    description=(
                                        f"The {_proto_name} service on {_hip}:{_portid} transmits "
                                        f"data in cleartext. Credentials, session data, and "
                                        f"sensitive information are vulnerable to interception "
                                        f"by an attacker with network access."),
                                    tool="nmap",
                                    raw_output=f"port {_portid}/{_proto_name} open",
                                    source_type="primary",
                                    force_risk="Medium",
                                    ip=_hip,
                                    port=str(_portid),
                                    output_file=str(xml_file),
                                )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# BannerGrab Module
# ---------------------------------------------------------------------------

class BannerGrabModule(BaseModule):
    name            = "BannerGrab"
    description     = "Grab service banners from all open ports (concurrent)"
    concurrent_safe = True

    # Version extraction patterns — ordered from most specific to least
    _VERSION_PATTERNS = [
        # HTTP Server header: Apache/2.4.41, nginx/1.18.0, Microsoft-IIS/10.0
        (re.compile(r'^Server:\s*(.+)', re.I | re.M),
         lambda m: m.group(1).strip()),
        # SSH banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        (re.compile(r'SSH-\d+\.\d+-(\S+)', re.I),
         lambda m: m.group(1).strip()),
        # X-Powered-By: PHP/7.4.3, ASP.NET
        (re.compile(r'^X-Powered-By:\s*(.+)', re.I | re.M),
         lambda m: m.group(1).strip()),
        # Generic: "word/version" format (OpenSSL/1.1.1, mod_ssl/2.4.41)
        (re.compile(r'([A-Za-z][\w\-]+)/(\d[\d\.]+[\w\-]*)', re.I),
         lambda m: f"{m.group(1)} {m.group(2)}"),
    ]

    def run(self) -> None:
        self._mark_running()
        try:
            hosts = self._target_hosts()
            if not hosts:
                self._mark_na_complete("Live")
                return

            out_dir = self.ctx.instance_dir / "BannerGrab"
            out_dir.mkdir(parents=True, exist_ok=True)

            work = []
            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    work.append((ip, p["port"],
                                 p.get("service", ""), p.get("version", "")))

            if not work:
                self._mark_na_complete("Open")
                return

            with ThreadPoolExecutor(max_workers=_MAX_BANNER_GRAB_WORKERS) as pool:
                futures = {
                    pool.submit(self._grab, ip, port, svc, ver, out_dir): (ip, port)
                    for ip, port, svc, ver in work
                }
                for fut in as_completed(futures):
                    ip, port = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"Banner grab failed {ip}:{port}: {e}")

            self._mark_complete(f"Banner grab complete — {len(work)} port(s)")
        except Exception as e:
            self.ctx.logger.error(f"BannerGrab failed: {e}", exc=e)
            self._mark_error(str(e))
    def _grab(self, ip: str, port: int, svc: str, ver: str,
              out_dir: Path) -> None:
        import socket as _s
        banner = ""
        try:
            with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                # HTTP probe first; fall back to passive read for other services
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " +
                              ip.encode() + b"\r\n\r\n")
                except Exception:
                    pass
                try:
                    data = s.recv(4096)
                    banner = data.decode("utf-8", errors="replace")
                except Exception:
                    pass
        except Exception:
            pass

        if not banner and not ver:
            return  # nothing to report

        safe = ip.replace(".", "_")
        out  = out_dir / f"{safe}_{port}_banner.txt"
        with open(str(out), "w", encoding="utf-8") as f:
            f.write(f"# {ip}:{port} ({svc} {ver})\n")
            if banner:
                f.write(banner)

        # Emit observation for every captured banner
        if banner:
            self._observe(
                title=f"Service Banner — {ip}:{port} ({svc})",
                description=(f"Banner captured from {ip}:{port}"
                             + (f" — {ver}" if ver else "")
                             + f":\n{banner[:300]}"),
                tool="banner_grab",
                output_file=str(out),
                output_text=banner[:1000],
                risk="Informational",
            )

        # ── Version extraction ────────────────────────────────────────────────
        # Each entry: (software, version, is_os)
        detected: list[tuple[str, str, bool]] = []
        os_found: tuple[str, str] = ("", "")   # track OS separately

        # 1. SSH banners get special handling — separate software from OS
        ssh_raw = ""
        if svc and "ssh" in svc.lower():
            if ver:
                ssh_raw = ver.strip()
            elif banner:
                m_ssh = re.search(r'SSH-\d+\.\d+-(\S+)', banner)
                if m_ssh:
                    ssh_raw = m_ssh.group(1)
        if ssh_raw:
            sw, sv, os_n, os_v = _parse_ssh_banner(ssh_raw)
            if sw and sv:
                detected.append((sw, sv, False))
            if os_n and os_v:
                os_found = (os_n, os_v)
                detected.append((os_n, os_v, True))
            # Already handled ssh — skip normal nmap ver processing below
            ver = ""

        # 2. Use nmap-reported version from DB for non-SSH services
        if ver and len(ver.strip()) > 2:
            ver_clean = ver.strip()
            if svc and re.match(r'^\d', ver_clean):
                detected.append((svc.upper(), ver_clean, False))
            else:
                parts = ver_clean.split(None, 1)
                if len(parts) == 2:
                    detected.append((parts[0], parts[1], False))
                else:
                    detected.append((svc.upper() if svc else "Service", ver_clean, False))

        # 3. Extract additional versions from banner text (non-SSH)
        if banner and not ssh_raw:
            for pattern, extractor in self._VERSION_PATTERNS:
                for m in pattern.finditer(banner):
                    raw_str = extractor(m)
                    slash_m = re.match(r'^([A-Za-z][\w\-\.]+)/(\d[\d\.]+[\w\-]*)', raw_str)
                    space_m = re.match(r'^([A-Za-z][\w\-\.]+)\s+(\d[\d\.]+[\w\-]*)', raw_str)
                    if slash_m:
                        sw, sv = slash_m.group(1), slash_m.group(2)
                    elif space_m:
                        sw, sv = space_m.group(1), space_m.group(2)
                    else:
                        continue
                    if (sw, sv, False) not in detected and len(sv) >= 3:
                        detected.append((sw, sv, False))

        # ── Emit findings via shared helper (version + EOL + CVE) ─────────────
        for software, version, is_os in detected:
            self._emit_version_findings(
                software=software,
                version=version,
                ip=ip,
                port=str(port),
                tool="banner_grab",
                output_file=str(out),
                is_os=is_os,
            )


# ---------------------------------------------------------------------------
# Web Module
# ---------------------------------------------------------------------------

class WebModule(BaseModule):
    name            = "Web"
    description     = ("Web service assessment: HTTP port detection, TLS certificate grab, "
                        "gowitness screenshots, wget spidering, default page detection, "
                        "service version identification, nuclei vulnerability scanning.")
    concurrent_safe = True

    # Default page signatures — title / body patterns that indicate a default install
    _DEFAULT_PAGE_SIGS = [
        (r'Apache2?\s+(?:Default|Test|Ubuntu|Debian)\s+Page', "Apache default page"),
        (r'Welcome to nginx',                                   "nginx default page"),
        (r'IIS Windows Server',                                 "IIS default page"),
        (r'Microsoft-IIS.*test\s+page',                         "IIS test page"),
        (r'It works!',                                          "Apache 'It works!' page"),
        (r'Apache HTTP Server Test Page',                       "Apache test page"),
        (r'Test Page for the Nginx',                            "nginx test page"),
        (r'Lighttpd\s+placeholder',                             "Lighttpd placeholder"),
        (r'index of /',                                         "Directory listing exposed"),
        (r'<title>Directory listing',                           "Directory listing exposed"),
        (r'phpinfo\(\)',                                         "PHP info page exposed"),
        (r'PHP Version',                                         "PHP info page exposed"),
        (r'Tomcat.*default\s+home',                             "Tomcat default page"),
        (r'Welcome to Tomcat',                                  "Tomcat default page"),
        (r'Welcome to JBoss',                                   "JBoss default page"),
        (r'Congratulations.*WordPress',                         "WordPress default install"),
        (r'WordPress › Installation',                           "WordPress install page"),
        (r'Drupal.*installation\s+complete',                    "Drupal default install"),
    ]

    # shcheck security header names expected in findings
    _SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
    ]

    def run(self) -> None:
        self._mark_running()
        try:
            hosts = self._target_hosts()
            if not hosts:
                self._mark_na_complete("Live")
                return

            out_dir = self.ctx.instance_dir / "Web"
            out_dir.mkdir(parents=True, exist_ok=True)

            web_targets = self._detect_web_ports(hosts, out_dir)

            if not web_targets:
                self._mark_na_complete("HTTP/HTTPS")
                return

            with open(str(out_dir / "targets.txt"), "w") as f:
                f.write("\n".join(url for url, _, _ in web_targets) + "\n")

            self.ctx.logger.info(
                f"Web targets: {[url for url,_,_ in web_targets]}", tool="web")

            with ThreadPoolExecutor(
                    max_workers=min(_MAX_WEB_WORKERS,
                                    len(web_targets))) as pool:
                futures = {
                    pool.submit(
                        self._assess_target, url, ip, port, out_dir): url
                    for url, ip, port in web_targets
                }
                for fut in as_completed(futures):
                    url = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"Web assessment of {url} failed: {e}")

            self._mark_complete(
                f"Web testing complete — {len(web_targets)} target(s)")
        except Exception as e:
            self.ctx.logger.error(f"Web module failed: {e}", exc=e)
            self._mark_error(str(e))
    def _detect_web_ports(self, hosts: list, out_dir: Path) -> list:
        """
        Check every open port for HTTP/HTTPS by:
          a) service name from nmap scan
          b) port-number heuristics for common web ports
          c) active HTTP probe (curl HEAD) for unlabelled ports
        Returns list of (url, ip, port) tuples.
        """
        # Service names that indicate HTTP/HTTPS
        HTTP_SVCS  = {"http", "http-alt", "http-proxy", "www", "webcache",
                      "8080", "8443", "8888", "tornado", "openssl"}
        HTTPS_SVCS = {"https", "https-alt", "ssl", "tls"}
        # Port numbers that are almost always web
        HTTP_PORTS  = {80, 8080, 8000, 8008, 8081, 8082, 8880, 3000, 5000, 9080}
        HTTPS_PORTS = {443, 8443, 4443, 9443, 10443}

        targets = []
        probed  = set()

        for ip in hosts:
            ports = self.ctx.db.get_ports_for_host(ip, self.ctx)
            for p in ports:
                port = p["port"]
                svc  = (p.get("service") or "").lower()

                if svc in HTTPS_SVCS or port in HTTPS_PORTS:
                    url = f"https://{ip}:{port}"
                elif svc in HTTP_SVCS or port in HTTP_PORTS:
                    url = f"http://{ip}:{port}"
                else:
                    # Probe unknown ports with curl
                    if (ip, port) not in probed:
                        probed.add((ip, port))
                        url = self._probe_port(ip, port)
                    else:
                        url = None

                if url:
                    entry = (url, ip, port)
                    if entry not in targets:
                        targets.append(entry)

        return targets

    _TLS_PORTS_WEB = {443, 8443, 4443, 9443, 10443}

    def _probe_port(self, ip: str, port: int) -> Optional[str]:
        """Quick HTTP probe — returns URL if port responds to HTTP or HTTPS.

        On a canonical TLS port (443/8443/etc.) only HTTPS is attempted.  If
        the TLS handshake fails but the server still answers plain HTTP with
        any code, we must NOT mis-classify the port as scheme=http — that
        would feed shcheck a URL like http://host:443/ and produce false-
        positive "missing header" findings for every header.
        """
        schemes = ("https",) if port in self._TLS_PORTS_WEB else ("https", "http")
        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}"
            try:
                rc, stdout, _ = run_tool(
                    ["curl", "-k", "-s", "--max-time", "5",
                     "-o", "/dev/null", "-w", "%{http_code}", url],
                    self.ctx, tool_name="curl", timeout=8)
                code = stdout.strip()
                if code.isdigit() and int(code) > 0:
                    self.ctx.logger.info(
                        f"Probe found web service at {url} (HTTP {code})", tool="curl")
                    return url
            except Exception:
                pass
        return None

    # ── 2. Per-target assessment ──────────────────────────────────────────────

    def _assess_target(self, url: str, ip: str, port: int, out_dir: Path) -> None:
        safe = re.sub(r'[^\w\-]', '_', url)
        is_https = url.startswith("https://")
        all_output_files: list[str] = []   # all files this target produces

        # a) Grab TLS certificate
        if is_https:
            self._grab_certificate(url, ip, port, out_dir, safe)
            # Collect cert files
            certs_dir = out_dir / "certificates"
            for f in certs_dir.glob(f"{safe}_cert*") if certs_dir.exists() else []:
                all_output_files.append(str(f))

        # b) Download page content — write response headers to headers/ dir
        #    so all header-related files live in the same folder as shcheck output
        headers_dir  = out_dir / "headers"
        headers_dir.mkdir(parents=True, exist_ok=True)
        headers_file = headers_dir / f"{safe}_headers.txt"
        html_file    = out_dir / f"{safe}_index.html"
        _fetch_cmd = ["curl", "-k", "-s", "-L", "--max-time", "15",
                      "-D", str(headers_file), "-o", str(html_file), url]
        _fetch_rc, _, _ = run_tool(_fetch_cmd, self.ctx, tool_name="curl", timeout=20)
        self._record_curl(_fetch_cmd,
                          f"Fetch web content and response headers from {url}",
                          _fetch_rc, str(html_file))
        if html_file.exists():    all_output_files.append(str(html_file))
        if headers_file.exists(): all_output_files.append(str(headers_file))

        # Parse Server: header for software version finding
        if headers_file.exists():
            try:
                hdr_content = headers_file.read_text(encoding="utf-8", errors="replace")
                server_m = re.search(r'^Server:\s*(.+)', hdr_content, re.I | re.M)
                if server_m:
                    server_val = server_m.group(1).strip()
                    # Extract software name and version from "Apache/2.4.51 (Ubuntu)"
                    ver_m = re.match(r'([A-Za-z][\w\-\.]+)/(\S+)', server_val)
                    if ver_m:
                        sw_name = ver_m.group(1)
                        sw_ver  = ver_m.group(2).split('(')[0].strip().rstrip('/')
                    else:
                        sw_name = server_val.split()[0] if server_val.split() else server_val
                        sw_ver  = ""
                    if sw_ver:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="Information Disclosure: Server Header",
                            description="The HTTP Server response header reveals the web server software name and version, reducing the attacker's reconnaissance effort needed to identify version-specific vulnerabilities.",
                            remediation="Remove or genericise the Server response header in the web server configuration (e.g., ServerTokens Prod in Apache; server_tokens off in nginx).",
                            tool="curl",
                            raw_output=f"Server: {server_val}",
                            source_type="primary",
                            force_risk="Low",
                            affected_component=f"HTTP Server on {ip}:{port}",
                            affected_version=sw_ver,
                            ip=ip,
                            port=str(port),
                            output_file=str(headers_file),
                        )
            except Exception:
                pass

        # Check cookie attributes from curl response headers
        if headers_file.exists():
            try:
                _hdr_text = headers_file.read_text(encoding="utf-8", errors="replace")
                _sc_lines = [
                    ln.split(":", 1)[1].strip()
                    for ln in _hdr_text.splitlines()
                    if re.match(r'set-cookie\s*:', ln, re.I)
                ]
                for _sc in _sc_lines:
                    _sc_lo  = _sc.lower()
                    _cname  = (_sc.split("=")[0].strip() if "=" in _sc
                               else _sc.split(";")[0].strip())
                    _sc_out = f"Set-Cookie: {_sc[:300]}"
                    if "httponly" not in _sc_lo:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="Missing Secure Cookie Attribute: HttpOnly",
                            description=(
                                f"Cookie '{_cname}' does not have the HttpOnly attribute. "
                                "Without HttpOnly, the cookie is accessible to JavaScript, "
                                "exposing it to XSS-based theft."),
                            tool="curl", raw_output=_sc_out,
                            source_type="primary", force_risk="Low",
                            ip=ip, port=str(port), output_file=str(headers_file),
                        )
                    if is_https and "secure" not in _sc_lo:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="Missing Secure Cookie Attribute: Secure",
                            description=(
                                f"Cookie '{_cname}' does not have the Secure attribute on an "
                                "HTTPS site. Without Secure, the cookie can be transmitted "
                                "over unencrypted HTTP connections."),
                            tool="curl", raw_output=_sc_out,
                            source_type="primary", force_risk="Low",
                            ip=ip, port=str(port), output_file=str(headers_file),
                        )
                    _ss_m = re.search(r'samesite\s*=\s*([^\s;,]+)', _sc_lo)
                    if not _ss_m:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="Missing Secure Cookie Attribute: SameSite",
                            description=(
                                f"Cookie '{_cname}' does not have the SameSite attribute. "
                                "Without SameSite, the cookie is sent with cross-site requests, "
                                "increasing CSRF risk."),
                            tool="curl", raw_output=_sc_out,
                            source_type="primary", force_risk="Low",
                            ip=ip, port=str(port), output_file=str(headers_file),
                        )
                    else:
                        _ss_val = _ss_m.group(1).strip()
                        if _ss_val not in ("strict", "lax", "none"):
                            self.ctx.findings.create(
                                ctx=self.ctx,
                                title="Misconfigured Secure Cookie Attribute: SameSite",
                                description=(
                                    f"Cookie '{_cname}' has SameSite set to an unrecognised "
                                    f"value '{_ss_val}'. Browsers treat it as SameSite=None."),
                                tool="curl", raw_output=_sc_out,
                                source_type="primary", force_risk="Low",
                                ip=ip, port=str(port), output_file=str(headers_file),
                            )
                        elif _ss_val == "none" and "secure" not in _sc_lo:
                            self.ctx.findings.create(
                                ctx=self.ctx,
                                title="Misconfigured Secure Cookie Attribute: SameSite",
                                description=(
                                    f"Cookie '{_cname}' has SameSite=None without the Secure "
                                    "attribute. Browsers reject or block such cookies."),
                                tool="curl", raw_output=_sc_out,
                                source_type="primary", force_risk="Low",
                                ip=ip, port=str(port), output_file=str(headers_file),
                            )
            except Exception:
                pass

        # c) Screenshot
        self._screenshot(url, out_dir, safe)
        ss_dir = out_dir / "screenshots"
        for f in (list(ss_dir.glob("*.png")) + list(ss_dir.glob("*.jpg"))) if ss_dir.exists() else []:
            all_output_files.append(str(f))

        # d) Spider up to 5 levels
        self._spider(url, out_dir, safe)
        # Collect spider sitemap
        spider_map = out_dir / "spider" / safe / "sitemap.txt"
        if spider_map.exists():
            all_output_files.append(str(spider_map))

        # e) Detect default/test pages
        if html_file.exists():
            self._detect_default_page(url, html_file, safe, out_dir)

        # f) Security headers — handled by SSLModule

        # g) Emit summary observation  (Nuclei runs in NucleiModule) linking all collected output files
        if all_output_files:
            self._observe(
                title=f"Web Assessment — {url}",
                description=(f"Web assessment of {url}: certificate grab, "
                             f"screenshot, spider, nuclei. "
                             f"{len(all_output_files)} output file(s)."),
                tool="web",
                output_file=all_output_files[0],
                output_text="",
                risk="Informational",
            )

        # i) Analyse collected output
        if html_file.exists():
            self._analyze_web_output(url, out_dir, safe)

    # ── 3. Certificate grabber ────────────────────────────────────────────────

    def _grab_certificate(self, url: str, ip: str, port: int,
                           out_dir: Path, safe: str) -> None:
        """Grab and store the TLS certificate chain using openssl s_client."""
        certs_dir = out_dir / "certificates"
        certs_dir.mkdir(parents=True, exist_ok=True)
        cert_file = certs_dir / f"{safe}_cert.pem"
        info_file  = certs_dir / f"{safe}_cert_info.txt"

        # Feed empty stdin so s_client closes immediately after receiving the cert
        # Run openssl directly (not via shell) and use a proper stdin pipe
        try:
            result = subprocess.run(
                ["openssl", "s_client",
                 "-connect", f"{ip}:{port}",
                 "-showcerts",
                 "-servername", ip,
                 "-timeout", "10"],
                input=b"",          # empty stdin → s_client reads EOF and exits
                capture_output=True,
                timeout=20,
            )
            output = result.stdout.decode("utf-8", errors="replace") \
                   + result.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            self.ctx.logger.warn(
                f"openssl s_client timed out for {ip}:{port} — skipping cert grab",
                tool="openssl")
            return
        except Exception as e:
            self.ctx.logger.warn(f"openssl s_client failed for {ip}:{port}: {e}",
                                  tool="openssl")
            return
        # Extract PEM blocks
        pem_blocks = re.findall(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            output, re.DOTALL)
        if pem_blocks:
            cert_file.write_text("\n".join(pem_blocks))
        else:
            cert_file.write_text(output[:4000])

        # Parse cert details with openssl x509
        if pem_blocks and tool_available("openssl"):
            rc2, info, _ = run_tool(
                ["openssl", "x509", "-noout", "-text",
                 "-in", str(cert_file)],
                self.ctx, tool_name="openssl", timeout=10)
            info_file.write_text(info)

            # Check expiry
            rc3, dates, _ = run_tool(
                ["openssl", "x509", "-noout", "-dates",
                 "-in", str(cert_file)],
                self.ctx, tool_name="openssl", timeout=10)
            exp_m = re.search(r'notAfter=(.*)', dates)
            if exp_m:
                exp_str = exp_m.group(1).strip()
                self._observe(
                    title=f"TLS Certificate — {url}",
                    description=f"Certificate expires: {exp_str}",
                    tool="openssl",
                    output_file=str(info_file),
                    output_text=dates,
                    risk="Informational",
                )
                # Check for self-signed
                sub_m    = re.search(r'Subject:\s*(.+)', info)
                issuer_m = re.search(r'Issuer:\s*(.+)',  info)
                # Check expiry (warn if within 30 days or already expired)
                try:
                    from datetime import datetime as _dt
                    exp_dt = _dt.strptime(exp_str.strip(), "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_dt - _dt.utcnow()).days
                    if days_left < 0:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="SSL/TLS Certificate: Expired",
                            description="The server's TLS certificate has passed its expiry date, causing browser trust errors and indicating a breakdown in certificate lifecycle management.",
                            remediation="Renew the certificate immediately and implement automated renewal (e.g., ACME/Let's Encrypt) to prevent future expiry.",
                            tool="openssl", raw_output=dates,
                            # G4 (2026-06-11 review): risk lowered HIGH→MEDIUM.
                            # Expired cert is trust/availability harm, not direct
                            # C/I impact. On embedded targets this is the factory
                            # default for many devices.
                            source_type="primary", force_risk="Medium",
                            ip=ip, port=str(port),
                            output_file=str(info_file),
                        )
                    elif days_left < 30:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="SSL/TLS Certificate: Expiring Soon",
                            description=(f"The TLS certificate at {url} expires in "
                                         f"{days_left} day(s) ({exp_str})."),
                            tool="openssl", raw_output=dates,
                            source_type="primary", force_risk="Medium",
                            ip=ip, port=str(port),
                            output_file=str(info_file),
                        )
                except Exception:
                    pass

                if sub_m and issuer_m and sub_m.group(1).strip() == issuer_m.group(1).strip():
                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title="SSL/TLS Certificate: Self-Signed",
                        description="The server presented a self-signed TLS certificate that is not anchored to a publicly trusted CA, preventing clients from verifying the server's identity and enabling trivial MITM attacks.",
                        remediation="Replace self-signed certificates with certificates issued by a trusted CA; use ACME/Let's Encrypt for cost-free automation.",
                        tool="openssl", raw_output=dates,
                        # G4 (2026-06-11 review): risk lowered MEDIUM→LOW.
                        # Self-signed is the factory default on most embedded
                        # devices; LOW is the calibrated risk.
                        source_type="primary", force_risk="Low",
                        ip=ip, port=str(port),
                        output_file=str(info_file),
                    )

    # ── 4. Screenshot ─────────────────────────────────────────────────────────

    def _screenshot_url(self, url: str, out_dir: Path, safe_tag: str) -> None:
        """Screenshot a specific URL, using safe_tag for the output filename."""
        ss_dir = out_dir / "screenshots"
        ss_dir.mkdir(parents=True, exist_ok=True)
        if not tool_available("gowitness"):
            return
        gw_bin = shutil.which("gowitness") or "gowitness"
        # Pass safe_tag as screenshot prefix if gowitness supports it;
        # otherwise gowitness will auto-name — we rename after.
        rc, stdout, stderr = run_tool(
            [gw_bin, "scan", "single",
             "--url", url,
             "--screenshot-path", str(ss_dir),
             "--timeout", "20"],
            self.ctx, tool_name="gowitness", timeout=35)
        if rc != 0 and ("unknown" in (stderr+stdout).lower()):
            run_tool(
                [gw_bin, "single", url,
                 "--destination", str(ss_dir), "--timeout", "20"],
                self.ctx, tool_name="gowitness", timeout=35)
        # Log to summary.json
        screenshots = list(ss_dir.glob("*.png")) + list(ss_dir.glob("*.jpg"))
        for ss in screenshots:
            _summary_append(
                str(self.ctx.findings._yaml_path),
                self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
                {"type": "screenshot", "title": f"screenshot_{safe_tag}",
                 "tool": "gowitness", "url": url, "output_file": str(ss)})

    def _screenshot(self, url: str, out_dir: Path, safe: str) -> None:
        """Screenshot the URL using gowitness. Handles v2 and v3 CLI syntax."""
        ss_dir = out_dir / "screenshots"
        ss_dir.mkdir(parents=True, exist_ok=True)

        if not tool_available("gowitness"):
            # Offer to install gowitness
            choice = self._prompt(
                "gowitness is not installed. Install it now?",
                options=["Yes — install gowitness", "No — skip screenshots"],
                prompt_type="choice",
                skippable=True,
            )
            if choice.startswith("Yes") or choice == "1":
                _install_tool(
                    next(t for t in REQUIRED_TOOLS if t["bin"] == "gowitness"),
                    "apt" if sys.platform.startswith("linux") else "go")
                if not tool_available("gowitness"):
                    _install_tool(
                        next(t for t in REQUIRED_TOOLS if t["bin"] == "gowitness"),
                        "go")
            if not tool_available("gowitness"):
                self.ctx.logger.warn(
                    "gowitness unavailable after install attempt — skipping screenshot",
                    tool="gowitness")
                return

        gw_bin = shutil.which("gowitness") or "gowitness"

        # Detect version by trying v3 `scan single` first, fall back to v2 `single`
        rc, stdout, stderr = run_tool(
            [gw_bin, "scan", "single",
             "--url", url,
             "--screenshot-path", str(ss_dir),
             "--timeout", "20"],
            self.ctx, tool_name="gowitness", timeout=35)

        # v3 exits 0 on success; if it says "unknown command" fall back to v2
        if rc != 0 and ("unknown" in stderr.lower() or "unknown" in stdout.lower()):
            run_tool(
                [gw_bin, "single", url,
                 "--destination", str(ss_dir),
                 "--timeout", "20"],
                self.ctx, tool_name="gowitness", timeout=35)

        # Emit observation for any screenshot files created
        screenshots = list(ss_dir.glob("*.png")) + list(ss_dir.glob("*.jpg"))
        if screenshots:
            self.ctx.logger.info(
                f"Screenshot(s) saved: {[s.name for s in screenshots]}", tool="gowitness")
            self._observe(
                title=f"Screenshot Captured — {url}",
                description=f"gowitness captured {len(screenshots)} screenshot(s) of {url}.",
                tool="gowitness",
                output_file=str(screenshots[0]),
                risk="Informational",
            )
            # Record each screenshot in summary.json
            _yaml_path = str(self.ctx.findings._yaml_path)
            for ss in screenshots:
                _summary_append(
                    _yaml_path,
                    self.ctx.subdevice_key,
                    self.ctx.interface,
                    self.ctx.instance_key,
                    {
                        "type":        "screenshot",
                        "title":       "screenshot",
                        "tool":        "gowitness",
                        "url":         url,
                        "output_file": str(ss),
                    },
                )

    # ── 5. Spider ─────────────────────────────────────────────────────────────

    def _spider(self, url: str, out_dir: Path, safe: str) -> None:
        """
        Spider the web service up to 5 levels deep using wget --mirror.
        Stores full site structure under Web/spider/<safe_url>/.
        Also records discovered URLs as a sitemap.txt observation.
        """
        spider_base = out_dir / "spider" / safe
        spider_base.mkdir(parents=True, exist_ok=True)

        if not tool_available("wget"):
            # Fallback: curl-based shallow spider (links only)
            self._spider_curl_fallback(url, spider_base, safe, out_dir)
            return

        rc, stdout, stderr = run_tool(
            ["wget",
             "--mirror",
             "--no-check-certificate",
             "--no-parent",
             "--convert-links",
             "--level=10",
             "--timeout=10",
             "--tries=1",
             "--wait=0.5",
             "--quiet",
             "--directory-prefix", str(spider_base),
             url],
            self.ctx, tool_name="wget", timeout=300)

        # Count discovered files
        discovered = list(spider_base.rglob("*"))
        files      = [f for f in discovered if f.is_file()]
        dirs       = [d for d in discovered if d.is_dir()]

        sitemap = spider_base / "sitemap.txt"
        sitemap.write_text(
            "\n".join(str(f.relative_to(spider_base)) for f in files))

        # Record wget command and output location to summary.json
        _summary_append(
            str(self.ctx.findings._yaml_path),
            self.ctx.subdevice_key,
            self.ctx.interface,
            self.ctx.instance_key,
            {
                "type":          "curl",        # reuse curl bucket for all commands
                "command":       (
                    f"wget --mirror --no-check-certificate --no-parent "
                    f"--convert-links --level=10 --timeout=10 --tries=1 "
                    f"--wait=0.5 --quiet --directory-prefix "
                    f"{spider_base} {url}"
                ),
                "purpose":       f"Spider {url} up to 5 levels deep to map site structure",
                "response_code": rc,
                "output_file":   str(sitemap.relative_to(
                    Path(str(self.ctx.findings._yaml_path)).parent)
                    if sitemap.exists() else str(sitemap)),
            },
        )

        if files:
            self._observe(
                title=f"Web Spider Results — {url}",
                description=(f"Spider crawled {len(files)} file(s) across "
                             f"{len(dirs)} director(y/ies) up to 5 levels deep."),
                tool="wget",
                output_file=str(sitemap),
                output_text="\n".join(
                    str(f.relative_to(spider_base)) for f in files[:50]),
                risk="Informational",
            )
            # Screenshot every HTML file found during spidering
            html_files_found = [f for f in files if f.suffix.lower() in ('.html','.htm')]
            if tool_available("gowitness") and html_files_found:
                # Derive the URL path for each spidered HTML file
                # wget mirrors to spider_base/<hostname>/<path>
                from urllib.parse import urlparse as _urlparse
                _parsed = _urlparse(url)
                _host_dir = spider_base / _parsed.netloc
                for html_f in html_files_found[:50]:   # cap at 50 screenshots
                    try:
                        rel = html_f.relative_to(_host_dir)
                        page_url = f"{_parsed.scheme}://{_parsed.netloc}/{rel}"
                    except ValueError:
                        page_url = url
                    # safe tag for screenshot filename
                    _safe_page = re.sub(r'[^A-Za-z0-9_\-]', '_',
                                        str(html_f.relative_to(spider_base)))[:80]
                    self._screenshot_url(page_url, out_dir, _safe_page)

    def _spider_curl_fallback(self, url: str, spider_base: Path,
                               safe: str, out_dir: Path) -> None:
        """Shallow link extraction when wget is unavailable."""
        html_file = out_dir / f"{safe}_index.html"
        if not html_file.exists():
            return
        try:
            content = html_file.read_text(encoding="utf-8", errors="replace")
            links = set(re.findall(r'href=["\']([^"\'#?]+)', content, re.I))
            sitemap = spider_base / "sitemap_links.txt"
            sitemap.write_text("\n".join(sorted(links)))
            self._observe(
                title=f"Web Links Extracted — {url}",
                description=f"Extracted {len(links)} unique link(s) from page source.",
                tool="curl",
                output_file=str(sitemap),
                output_text="\n".join(sorted(links)[:50]),
                risk="Informational",
            )
        except Exception:
            pass

    # ── 6. Default page detection ─────────────────────────────────────────────

    def _detect_default_page(self, url: str, html_file: Path,
                               safe: str, out_dir: Path) -> None:
        """Check for default/test pages that indicate unconfigured servers."""
        try:
            content = html_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        _dp_ip, _dp_port = self.ctx.findings._extract_ip_port_from_url(url)
        for pattern, label in self._DEFAULT_PAGE_SIGS:
            if re.search(pattern, content, re.IGNORECASE):
                if "directory listing" in label.lower():
                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title="Directory Listing Enabled",
                        description="The web server is configured to display a browsable directory index, exposing file structure and potentially sensitive files to unauthenticated users.",
                        remediation="Disable directory indexing (e.g., Options -Indexes in Apache; autoindex off in nginx) and ensure every directory contains an explicit index document.",
                        tool="curl",
                        raw_output=content[:500],
                        source_type="primary",
                        force_risk="Medium",
                        ip=_dp_ip,
                        port=_dp_port,
                        output_file=str(html_file),
                    )
                else:
                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title=f"Default/Test Page Exposed — {label} at {url}",
                        description=(
                            f"The web server at {url} is serving a default or test page "
                            f"({label}), indicating it may not be properly configured "
                            f"for production use."),
                        tool="curl",
                        raw_output=content[:500],
                        source_type="primary",
                        force_risk="Low",
                        ip=_dp_ip,
                        port=_dp_port,
                        output_file=str(html_file),
                    )
                self._observe(
                    title=f"Default Page Detected — {label} ({url})",
                    description=f"Pattern matched: {label}",
                    tool="curl",
                    output_file=str(html_file),
                    output_text=label,
                    risk="Low",
                )
                break   # one finding per target is enough

    # ── 7. Security headers (shcheck) ─────────────────────────────────────────

    def _analyze_web_output(self, url: str, out_dir: Path, safe_name: str) -> None:
        """
        Walk all downloaded HTML files (index + spider tree) and create
        Informational / Low findings for:
          - Default / test pages
          - HTML forms (login, search, upload)
          - Software version disclosures (meta generator, Server/X-Powered-By)
          - Sensitive information patterns (IPs, emails, tokens, debug comments)
        """
        html_files: list[Path] = []
        index_file = out_dir / f"{safe_name}_index.html"
        if index_file.exists():
            html_files.append(index_file)
        spider_root = out_dir / "spider" / safe_name
        if spider_root.exists():
            html_files += [f for f in spider_root.rglob("*.html") if f.is_file()]
            html_files += [f for f in spider_root.rglob("*.htm")  if f.is_file()]

        if not html_files:
            return

        # Use a persistent seen set on ctx to avoid duplicate findings
        # across multiple _analyze_web_output calls (e.g. http + https same host)
        if not hasattr(self.ctx, '_web_analyze_seen'):
            self.ctx._web_analyze_seen = set()
        _seen = self.ctx._web_analyze_seen

        def _finding(title: str, desc: str, risk: str,
                     output_file: Path, raw: str = "") -> None:
            # Key on title + ip-part of url to deduplicate across http/https
            from urllib.parse import urlparse as _up
            _netloc = _up(url).netloc if url else url
            key = f"{title}|{_netloc}"
            if key in _seen:
                return
            _seen.add(key)
            _aw_ip, _aw_port = self.ctx.findings._extract_ip_port_from_url(url)
            self.ctx.findings.create(
                ctx=self.ctx,
                title=title,
                description=desc,
                tool="curl",
                raw_output=raw[:500] if raw else "",
                source_type="secondary",
                force_risk=risk,
                ip=_aw_ip, port=_aw_port,
                output_file=str(output_file),
            )

        DEFAULT_SIGS = [
            (r'Apache2?\s+(?:Default|Test|Ubuntu|Debian)\s+Page', "Apache default page"),
            (r'Welcome to nginx',                                   "nginx default page"),
            (r'IIS Windows Server',                                 "IIS default page"),
            (r'It works!',                                          "Apache 'It works!' page"),
            (r'phpinfo\(\)',                                        "PHP info page exposed"),
            (r'PHP Version',                                        "PHP info page exposed"),
            (r'Welcome to Tomcat',                                  "Tomcat default page"),
            (r'Congratulations.*WordPress',                         "WordPress default install"),
            (r'WordPress\s+Installation',                           "WordPress install page"),
            (r'Drupal.*installation\s+complete',                    "Drupal default install"),
            (r'<title>\s*Index of /',                               "Directory listing exposed"),
            (r'<title>\s*phpinfo',                                  "PHP info page exposed"),
        ]

        SENSITIVE = [
            (r'password\s*[=:]\s*["\']?(\S{4,60})',
             "Plaintext password in page source", "Low"),
            (r'(?:secret|api[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
             "Secret/API key exposed in page source", "Low"),
            (r'BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY',
             "Private key material in page source", "Low"),
            (r'<!--.*?(?:TODO|FIXME|HACK|XXX|REMOVE|DEBUG).*?-->',
             "Developer debug comment in page source", "Informational"),
            (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
             "Email address disclosed in page source", "Informational"),
        ]

        for html_file in html_files:
            try:
                content = html_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            file_label = html_file.name

            # Internal IPs
            priv_re = re.compile(
                r'\b(?:10\.\d+\.\d+\.\d+'
                r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'
                r'|192\.168\.\d+\.\d+)\b')
            for priv_ip in set(priv_re.findall(content)):
                self.ctx.ip_tracker.observe(
                    priv_ip,
                    subdevice=self.ctx.subdevice_key,
                    instance=self.ctx.instance_key)
                _finding(
                    f"Internal IP Disclosed in Web Page — {priv_ip}",
                    (f"Web page {file_label} at {url} references internal "
                     f"IP {priv_ip}."),
                    "Informational", html_file, priv_ip)

            # Default / test pages
            for pattern, label in DEFAULT_SIGS:
                if re.search(pattern, content, re.I | re.S):
                    if "directory listing" in label.lower():
                        _finding(
                            "Directory Listing Enabled",
                            "The web server is configured to display a browsable directory index, exposing file structure and potentially sensitive files to unauthenticated users.",
                            "Medium", html_file, label)
                    else:
                        _finding(
                            f"Default/Test Page Exposed — {label}",
                            (f"The web service at {url} serves a default or test "
                             f"page ({label}). This may indicate the application "
                             f"is unconfigured or a placeholder was not removed."),
                            "Informational", html_file, label)

            # Forms
            for m in re.finditer(r'<form[^>]*action=["\']?([^"\'>\s]*)',
                                  content, re.I):
                action  = m.group(1).strip()
                snippet = content[max(0, m.start()-50): m.start()+500].lower()
                if any(kw in snippet for kw in
                       ("password", "passwd", "login", "signin", "credential")):
                    _finding(
                        f"Login Form Identified — {url}",
                        (f"A login form was found at {url} "
                         f"(action='{action}'). Verify HTTPS is enforced and "
                         f"no default credentials exist."),
                        "Informational", html_file, f"action={action}")
                elif any(kw in snippet for kw in
                         ("upload", "file", "enctype")):
                    _finding(
                        f"File Upload Form Identified — {url}",
                        (f"A file upload form was detected at {url} "
                         f"(action='{action}'). Verify file-type and size "
                         f"restrictions are enforced server-side."),
                        "Low", html_file, f"action={action}")

            # Meta generator — software version
            for m in re.finditer(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                    content, re.I):
                sw = m.group(1).strip()
                if sw:
                    _finding(
                        f"Web Software Version Disclosed — {sw}",
                        (f"The HTML meta generator tag at {url} discloses "
                         f"software version: \"{sw}\". This aids CVE targeting."),
                        "Informational", html_file, sw)

            # Inline X-Powered-By / Server disclosures in page body
            for m in re.finditer(
                    r'(?:x-powered-by|server)[\s:]+([^\s<"\'\\n]{3,60})',
                    content, re.I):
                sw = m.group(1).strip().rstrip(",;")
                if sw and not sw.startswith("<"):
                    _finding(
                        f"Web Technology Version Disclosed — {sw}",
                        (f"The web page at {url} contains a software "
                         f"version disclosure: \"{sw}\"."),
                        "Informational", html_file, sw)

            # Sensitive patterns
            for pattern, label, risk in SENSITIVE:
                m = re.search(pattern, content, re.I | re.S)
                if m:
                    snippet_raw = content[max(0, m.start()-20): m.start()+80]
                    _finding(
                        f"{label} — {url}",
                        (f"{label} detected in {file_label} at {url}. "
                         f"Review and remove before production deployment."),
                        risk, html_file, snippet_raw)

class SSHModule(BaseModule):
    name            = "SSH"
    description     = "SSH protocol analysis and credential testing (concurrent)"
    concurrent_safe = True

    def run(self) -> None:
        self._mark_running()
        try:
            hosts   = self._target_hosts()
            out_dir = self.ctx.instance_dir / "SSH"
            out_dir.mkdir(parents=True, exist_ok=True)

            work = []
            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    port    = p["port"]
                    service = (p.get("service") or "").lower().strip()
                    is_ssh_service = "ssh" in service
                    is_default_ssh = (port == 22 and service in ("", "ssh", "unknown"))
                    if is_ssh_service or is_default_ssh:
                        work.append((ip, port))

            if not work:
                self._mark_na_complete("SSH")
                return

            with ThreadPoolExecutor(
                    max_workers=min(_MAX_SSH_WORKERS, len(work))) as pool:
                futures = {
                    pool.submit(self._test_ssh, ip, port, out_dir): (ip, port)
                    for ip, port in work
                }
                for fut in as_completed(futures):
                    ip, port = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.ctx.logger.warn(f"SSH test failed {ip}:{port}: {e}")

            self._mark_complete(f"SSH testing complete — {len(work)} service(s)")
        except Exception as e:
            self.ctx.logger.error(f"SSH module failed: {e}", exc=e)
            self._mark_error(str(e))
    def _test_ssh(self, ip: str, port: int, out_dir: Path) -> None:
        safe     = ip.replace(".", "_")
        nmap_out = out_dir / f"{safe}_{port}_nmap_ssh.txt"

        # ── nmap SSH scripts ──────────────────────────────────────────────
        run_tool(
            ["nmap", "-p", str(port), "--script",
             "ssh-auth-methods,ssh2-enum-algos,sshv1",
             ip],
            self.ctx, tool_name="nmap-ssh",
            output_file=nmap_out, timeout=90)

        if nmap_out.exists():
            content = nmap_out.read_text(errors="replace")
            self._observe(
                title=f"SSH Service Analysis — {ip}:{port}",
                description=f"nmap SSH script results for {ip}:{port}",
                tool="nmap",
                output_file=str(nmap_out),
                output_text=content[:1500],
                risk="Informational",
            )
            if "ssh-auth-methods" in content.lower():
                _gb_has_pw = ("password" in content.lower()
                              or "keyboard-interactive" in content.lower())
                _gb_has_pk = "publickey" in content.lower()
                if _gb_has_pw:
                    _gb_pw_only = not _gb_has_pk
                    _gb_pw_risk = "Medium" if _gb_pw_only else "Low"
                    _gb_pw_title = ("SSH Password-Only Authentication (No Public Key)"
                                    if _gb_pw_only
                                    else "SSH Password Authentication Enabled")
                    _gb_pw_desc = (
                        "The SSH server accepts password-based authentication"
                        + (" with no public key method available"
                           if _gb_pw_only else " alongside public key")
                        + ". Password authentication is susceptible to brute-force "
                        "attacks and does not enforce multi-factor authentication. "
                        "CIS Benchmark and DISA STIG mandate disabling password-based "
                        "SSH login in favor of public key authentication exclusively."
                    )
                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title=_gb_pw_title,
                        description=_gb_pw_desc,
                        remediation=(
                            "Disable PasswordAuthentication and "
                            "ChallengeResponseAuthentication in sshd_config. "
                            "Require public key authentication exclusively. "
                            "Deploy fail2ban or equivalent as a defense-in-depth measure."
                        ),
                        tool="nmap-ssh",
                        raw_output=content[:500],
                        source_type="primary",
                        force_risk=_gb_pw_risk,
                        ip=ip,
                        port=str(port),
                        output_file=str(nmap_out),
                    )
            # ── Parse ssh2-enum-algos for weak algorithm findings ─────────
            self._parse_ssh_algos(ip, port, content, nmap_out)

        # ── ssh-audit ─────────────────────────────────────────────────────
        # Offer to install if missing, then run if available.
        ssh_audit_bin = (shutil.which("ssh-audit")
                         or shutil.which("/usr/bin/ssh-audit")
                         or shutil.which("/usr/local/bin/ssh-audit"))
        if not ssh_audit_bin:
            if tool_available("ssh-audit"):
                ssh_audit_bin = "ssh-audit"
            else:
                # Offer apt install
                choice = console.prompt(
                    f"ssh-audit is not installed. It provides deep SSH configuration "
                    f"auditing (host keys, algorithms, CVEs).\n"
                    f"Install now? (apt install ssh-audit)",
                    options=["Yes, install ssh-audit", "Skip for this session"],
                    prompt_type="choice",
                )
                if "yes" in choice.lower() or choice.strip() == "1":
                    ok, out = _sudo_run(
                        ["apt-get", "install", "-y", "ssh-audit"],
                        timeout=120)
                    if ok:
                        self.ctx.logger.info("ssh-audit installed successfully.", tool="ssh-audit")
                        ssh_audit_bin = shutil.which("ssh-audit") or "ssh-audit"
                    else:
                        self.ctx.logger.warn(
                            f"ssh-audit install failed: {out[:200]}", tool="ssh-audit")

        if ssh_audit_bin:
            audit_out = out_dir / f"{safe}_{port}_ssh_audit.txt"
            audit_json = out_dir / f"{safe}_{port}_ssh_audit.json"
            # Run ssh-audit with text output and JSON output
            # ssh-audit writes its report to stdout.
            # -l is the log-level flag in some builds, not a logfile path.
            # Capture stdout via run_tool output_file (which redirects stdout).
            run_tool(
                [ssh_audit_bin, "-p", str(port), "--no-colors", ip],
                self.ctx, tool_name="ssh-audit",
                output_file=audit_out, timeout=60)
            # JSON output: --json writes JSON to stdout
            run_tool(
                [ssh_audit_bin, "-p", str(port), "--no-colors", "--json", ip],
                self.ctx, tool_name="ssh-audit",
                output_file=audit_json, timeout=60)
            if audit_out.exists():
                self._parse_ssh_audit(ip, port, audit_out, audit_json if audit_json.exists() else None)

    def _parse_ssh_algos(self, ip: str, port: int,
                          nmap_content: str, output_file: Path) -> None:
        """
        Parse nmap ssh2-enum-algos output and create findings for
        weak/deprecated cryptographic algorithms.
        """
        # Algorithms considered weak by current standards
        WEAK_ENC  = {"3des-cbc","blowfish-cbc","cast128-cbc","arcfour",
                     "arcfour128","arcfour256","rijndael-cbc@lysator.liu.se"}
        WEAK_MAC  = {"hmac-md5","hmac-md5-96","hmac-sha1-96",
                     "hmac-ripemd160","umac-64@openssh.com"}
        WEAK_KEX  = {"diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1",
                     "gss-group1-sha1-*"}
        WEAK_HOST = {"ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521",
                     "ssh-dss"}

        # Extract algo blocks from nmap output
        in_algo_section = False
        current_section = ""
        found_weak: list[tuple[str,str,str]] = []  # (algo, section, risk)

        for line in nmap_content.splitlines():
            stripped = line.strip()
            # Section headers like "encryption_algorithms:" or "kex_algorithms:"
            if stripped.endswith(":") and "algorithm" in stripped.lower():
                current_section = stripped.rstrip(":")
                in_algo_section = True
                continue
            if in_algo_section:
                if not stripped or stripped.startswith("|"):
                    algo = stripped.lstrip("|").strip()
                    if not algo:
                        in_algo_section = False
                        continue
                    algo_lc = algo.lower()
                    if "encryption" in current_section and algo_lc in WEAK_ENC:
                        found_weak.append((algo, "Encryption", "Medium"))
                    elif "mac" in current_section and algo_lc in WEAK_MAC:
                        found_weak.append((algo, "MAC", "Medium"))
                    elif "kex" in current_section and algo_lc in WEAK_KEX:
                        found_weak.append((algo, "Key Exchange", "High"))
                    elif "host" in current_section and algo_lc in WEAK_HOST:
                        found_weak.append((algo, "Host Key", "Low"))
                else:
                    in_algo_section = False

        # Simple regex pass as fallback
        for m in re.finditer(
                r'\|\s+([\.\w@\-]+)\s*\(weak\)', nmap_content, re.I):
            algo = m.group(1)
            if not any(w[0] == algo for w in found_weak):
                found_weak.append((algo, "Algorithm", "Medium"))

        for algo, section_name, risk in found_weak:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)",
                description="The SSH service is configured with one or more weaknesses including weak ciphers/MACs, SSHv1 support, permitted root login, or password-based authentication, increasing exposure to brute-force and protocol-level attacks.",
                remediation="Harden sshd_config to disable SSHv1, restrict ciphers and MACs to strong algorithms, disable root login, disable password authentication, and require public-key authentication only.",
                tool="nmap-ssh",
                raw_output=algo,
                source_type="primary",
                force_risk=risk,
                ip=ip,
                port=str(port),
                output_file=str(output_file),
            )

    def _parse_ssh_audit(self, ip: str, port: int, txt_file: Path,
                          json_file: Optional[Path]) -> None:
        """Parse ssh-audit output and create findings."""
        content = txt_file.read_text(errors="replace")
        output_files = [str(txt_file)]
        if json_file and json_file.exists():
            output_files.append(str(json_file))

        self._observe(
            title=f"SSH Audit — {ip}:{port}",
            description=f"ssh-audit configuration analysis for {ip}:{port}.",
            tool="ssh-audit",
            output_file=str(txt_file),
            output_text=content[:2000],
            risk="Informational",
        )

        # Risk-level markers in ssh-audit output
        # CRITICAL/WARN lines indicate weak or deprecated configuration
        RISK_MAP = {
            "crit":  "Critical",
            "fail":  "High",
            "warn":  "Medium",
            "info":  "Informational",
        }
        SEVERITY_RE = re.compile(
            r"\s*(crit|fail|warn|info)\s+(.+)", re.I)
        WEAK_ALGO_RE = re.compile(
            r"(diffie-hellman-group1|arcfour|blowfish|cast128|3des|"
            r"hmac-md5|hmac-sha1-96|hmac-ripemd|ecdsa-sha2-nistp)", re.I)
        CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.I)

        emitted: set = set()

        # Parse try json first for structured data, fall back to text
        findings_data = []
        if json_file and json_file.exists():
            try:
                import json as _json
                data = _json.loads(json_file.read_text(errors="replace"))
                for section in ("cves", "recommendations"):
                    for item in data.get(section, []):
                        desc = item.get("description", "") or item.get("text", "")
                        if desc:
                            sev  = item.get("level", "warn").lower()
                            risk = RISK_MAP.get(sev[:4], "Medium")
                            cves = CVE_RE.findall(desc)
                            findings_data.append((risk, desc[:200], cves))
            except Exception:
                pass

        # Text parsing for any unreported issues
        for line in content.splitlines():
            m = SEVERITY_RE.match(line)
            if not m:
                continue
            sev_raw = m.group(1).lower()
            desc    = m.group(2).strip()
            if not desc or len(desc) < 6:
                continue
            risk  = RISK_MAP.get(sev_raw[:4], "Medium")
            if risk == "Informational":
                continue
            cves  = [c.upper() for c in CVE_RE.findall(desc)]
            title = "SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)"
            dedup = (title, desc[:60])
            if dedup in emitted:
                continue
            emitted.add(dedup)
            self.ctx.findings.create(
                ctx=self.ctx,
                title=title,
                description="The SSH service is configured with one or more weaknesses including weak ciphers/MACs, SSHv1 support, permitted root login, or password-based authentication, increasing exposure to brute-force and protocol-level attacks.",
                remediation="Harden sshd_config to disable SSHv1, restrict ciphers and MACs to strong algorithms, disable root login, disable password authentication, and require public-key authentication only.",
                tool="ssh-audit",
                raw_output=line.strip(),
                source_type="primary",
                force_risk=risk,
                cve_ids=cves,
                ip=ip,
                port=str(port),
                output_files=output_files,
            )




# ---------------------------------------------------------------------------
# Nuclei Module — standalone vulnerability scanner
# ---------------------------------------------------------------------------

class NucleiModule(BaseModule):
    """
    Runs nuclei against every HTTP/HTTPS port in the project.
    Stores all output under instance_dir/Nuclei/, emits findings and
    observations so the Evidence/VIEW mechanism works as expected.
    """
    name            = "Nuclei"
    description     = "nuclei full vulnerability scanner against all web targets"
    concurrent_safe = True
    OUTPUT_PATTERNS = ["*_nuclei.txt", "nuclei_bulk.txt", "targets.txt"]

    def run(self) -> None:
        self._mark_running()
        try:
            hosts   = self._target_hosts()
            out_dir = self.ctx.instance_dir / "Nuclei"
            out_dir.mkdir(parents=True, exist_ok=True)

            HTTP_SVCS   = {"http","http-alt","http-proxy","www","webcache","openssl"}
            HTTPS_SVCS  = {"https","https-alt","ssl","tls"}
            HTTP_PORTS  = {80,8080,8000,8008,8081,8082,8880,3000,5000,9080}
            HTTPS_PORTS = {443,8443,4443,9443,10443}

            work: list[tuple] = []
            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    svc  = (p.get("service") or "").lower()
                    port = p["port"]
                    if svc in HTTPS_SVCS or port in HTTPS_PORTS:
                        work.append((f"https://{ip}:{port}", ip, port))
                    elif svc in HTTP_SVCS or port in HTTP_PORTS:
                        work.append((f"http://{ip}:{port}", ip, port))

            if not work:
                self._mark_na_complete("HTTP/HTTPS")
                return

            if not tool_available("nuclei"):
                choice = self._prompt(
                    "nuclei is not installed. Install now?",
                    options=["Yes — install nuclei", "No — skip"],
                    prompt_type="choice", skippable=True)
                if choice.startswith("Yes") or choice == "1":
                    _install_tool(
                        next(t for t in REQUIRED_TOOLS
                             if t["bin"] == "nuclei"), "go")
                if not tool_available("nuclei"):
                    self._mark_skipped("nuclei install failed")
                    return

            nuclei_bin = shutil.which("nuclei") or "nuclei"

            # Write a combined targets file for reference / evidence
            targets_file = out_dir / "targets.txt"
            targets_file.write_text(
                "\n".join(url for url, _, _ in work) + "\n")

            # Run nuclei per-target (-u URL) so each scan is independent.
            # Bulk -l mode can fail silently when the list file path has
            # spaces or when nuclei's own timeout kills the whole run.
            def _scan_url(url: str, ip: str, port: int) -> None:
                safe_tag = ip.replace(".", "_") + f"_{port}"
                out_file = out_dir / f"{safe_tag}_nuclei.txt"
                run_tool(
                    [nuclei_bin,
                     "-u", url,
                     "-severity", "critical,high,medium,low,info",
                     "-o", str(out_file),
                     "-silent", "-no-color"],
                    self.ctx, tool_name="nuclei",
                    output_file=out_file, timeout=300)
                if out_file.exists() and out_file.stat().st_size > 0:
                    content = out_file.read_text(errors="replace")
                    self._parse_nuclei_output(
                        content, out_file,
                        fallback_ip=ip, fallback_port=str(port))

            with ThreadPoolExecutor(
                    max_workers=min(_MAX_WEB_WORKERS, len(work)),
                    thread_name_prefix="nuclei") as pool:
                futures = {
                    pool.submit(_scan_url, url, ip, port): (url, ip, port)
                    for url, ip, port in work
                }
                for fut in as_completed(futures):
                    url, ip, port = futures[fut]
                    try:
                        fut.result(timeout=360)
                    except TimeoutError:
                        self.ctx.logger.warn(
                            f"Nuclei timed out for {url}", tool="nuclei")
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"Nuclei failed for {url}: {e}", tool="nuclei")

            self._mark_complete(f"Nuclei complete — {len(work)} target(s)")
        except Exception as e:
            self.ctx.logger.error(
                f"Nuclei module failed: {e}", exc=e, tool="nuclei")
            self._mark_error(str(e))
    def _parse_nuclei_output(self, content: str, out_file: Path,
                          fallback_ip: str = "", fallback_port: str = "") -> None:
        risk_map = {"critical":"Critical","high":"High","medium":"Medium",
                    "low":"Low","info":"Informational"}
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            sev_m = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
            if not sev_m:
                continue
            risk        = risk_map.get(sev_m.group(1).lower(), "Informational")
            tmpl_m      = re.match(r'\[([^\]]+)\]', line)
            template_id = tmpl_m.group(1).strip() if tmpl_m else ""

            # ── Extract URL / IP / Port from every line ───────────────────
            url_m      = re.search(r'https?://[^\s]+', line)
            target_url = url_m.group(0) if url_m else ""
            hm = re.search(r'https?://([^/:]+)(?::(\d+))?', target_url)
            if hm:
                fip  = hm.group(1)
                fprt = hm.group(2) if hm.group(2) else (
                    "443" if target_url.startswith("https") else "80")
            else:
                # Fallback: bare IP:port pattern anywhere in line
                bare_m = re.search(
                    r'(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?', line)
                fip  = bare_m.group(1) if bare_m else ""
                fprt = bare_m.group(2) if (bare_m and bare_m.group(2)) else ""
            # Final fallback: use the known target ip/port from _scan_url
            if not fip:
                fip  = fallback_ip
            if not fprt:
                fprt = fallback_port

            # ── Skip jlsec noise ──────────────────────────────────────────
            if re.search(r'jlsec', template_id, re.I):
                if not re.search(r'HTTP\.jl|URIs\.jl', line, re.I):
                    continue

            # ── False-positive CVEs (nmap-sourced etc.) ───────────────────
            cves = [c.upper() for c in re.findall(r'CVE-\d{4}-\d+', line, re.I)]
            if any(c in _NMAP_FP_SKIP for c in cves):
                continue

            # ── "— IP" garbage titles: template_id is just a dash/blank ──
            if re.match(r'^[-\s]+$', template_id) or not template_id:
                if not fip:
                    continue            # nothing useful in this line
                # Best effort: use the URL path as title
                path_m = re.search(r'https?://[^/\s]+(/.+?)(?:\s|$)', line)
                slug   = path_m.group(1).strip('/ ') if path_m else ""
                if slug:
                    readable = re.sub(r'[-_/]', ' ', slug).strip().title()
                else:
                    readable = "Web Service Finding"
                title = _fix_acronyms(f"{readable} — {fip}")
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}",
                    tool="nuclei", raw_output=line[:500],
                    source_type="primary", force_risk=risk, cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── SSL/TLS deprecated protocols → individual findings ─────────
            _proto_map = [
                (r'ssl-v2|sslv2',           "SSLv2",   "High"),
                (r'ssl-v3|sslv3',           "SSLv3",   "Medium"),
                (r'tls-1[_-]0|tlsv1[_-]0', "TLSv1.0", "Low"),
                (r'tls-1[_-]1|tlsv1[_-]1', "TLSv1.1", "Low"),
            ]
            proto_hit = None
            for pat, proto, proto_risk in _proto_map:
                if re.search(pat, template_id, re.I):
                    proto_hit = (proto, proto_risk)
                    break
            if proto_hit:
                proto, proto_risk = proto_hit
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"SSL/TLS - {proto} Enabled",
                    description=f"nuclei: {line[:300]}",
                    tool="nuclei", raw_output=line[:500],
                    source_type="primary",
                    force_risk=proto_risk, cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── SSL self-signed / expired / mismatch ─────────────────────
            if re.search(r'ssl.*self.*sign|self.*sign.*ssl', template_id, re.I):
                self.ctx.findings.create(
                    ctx=self.ctx, title="SSL/TLS Certificate: Self-Signed",
                    description="The server presented a self-signed TLS certificate that is not anchored to a publicly trusted CA, preventing clients from verifying the server's identity and enabling trivial MITM attacks.",
                    remediation="Replace self-signed certificates with certificates issued by a trusted CA; use ACME/Let's Encrypt for cost-free automation.",
                    tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Medium", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue
            if re.search(r'ssl.*expire|expire.*ssl|cert.*expir', template_id, re.I):
                self.ctx.findings.create(
                    ctx=self.ctx, title="SSL/TLS Certificate: Expired",
                    description="The server's TLS certificate has passed its expiry date, causing browser trust errors and indicating a breakdown in certificate lifecycle management.",
                    remediation="Renew the certificate immediately and implement automated renewal (e.g., ACME/Let's Encrypt) to prevent future expiry.",
                    tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="High", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue
            if re.search(r'ssl.*mismatch|mismatch.*ssl|hostname.*mismatch', template_id, re.I):
                self.ctx.findings.create(
                    ctx=self.ctx, title=f"Certificate Hostname Mismatch",
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── SSL issuer — strip IP from title ─────────────────────────
            if re.search(r'ssl-issuer|ssl.*issuer|cert.*issuer', template_id, re.I):
                issuer_m = re.search(r'issuer[:\s]+(.+?)(?:\s+\d{1,3}\.\d|$)',
                                     line, re.I)
                issuer = issuer_m.group(1).strip() if issuer_m else "Unknown"
                self.ctx.findings.create(
                    ctx=self.ctx, title=f"SSL Certificate Issuer — {issuer}",
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── OpenSSH version → Service Version Identified ─────────────
            if re.search(r'openssh-detect|openssh.*version', template_id, re.I):
                ver_m = re.search(r'OpenSSH[_\s]?(\S+)', line, re.I)
                ver   = ver_m.group(1).lstrip('_') if ver_m else ''
                title = _fix_acronyms(
                    f"Service Version Identified — OpenSSH{(' ' + ver) if ver else ''} ({fip}:{fprt})")
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── SMB Version Detect → Service Version Identified ──────────
            if re.search(r'smb-version|smb.*version.*detect|smb.*detect.*version',
                         template_id, re.I):
                ver_m = re.search(r'SMB[v\s]+([\d\.]+|v\d)', line, re.I)
                ver   = ver_m.group(1) if ver_m else ''
                title = _fix_acronyms(
                    f"Service Version Identified — SMB{(' ' + ver) if ver else ''} ({fip}:{fprt})")
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── Sshd Dropper → Service Version Identified ────────────────
            if re.search(r'sshd.*dropper|dropper.*sshd', template_id, re.I):
                ver_m = re.search(r'SSH[_\s-]?([\d\.]+)', line, re.I)
                ver   = ver_m.group(1) if ver_m else ''
                title = _fix_acronyms(
                    f"Service Version Identified — OpenSSH{(' ' + ver) if ver else ''} ({fip}:{fprt})")
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── MQTT unauthenticated broker → Service Version Identified ──
            if re.search(r'mqtt.*unauth|unauth.*mqtt', template_id, re.I):
                ver_m = re.search(r'MQTT[v\s]+([\d\.]+)', line, re.I)
                ver   = ver_m.group(1) if ver_m else ''
                title = _fix_acronyms(
                    f"Service Version Identified — MQTT{(' ' + ver) if ver else ''} ({fip}:{fprt})")
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── Map / Unauth Exposure → Low risk ─────────────────────────
            if re.search(r'map.*unauth|unauth.*map.*expos', template_id, re.I):
                readable = re.sub(r'[-_]', ' ', template_id).title()
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=_fix_acronyms(f"{readable} ({fip}:{fprt})"),
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Low", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── Tech-detect ───────────────────────────────────────────────
            if re.search(r'tech-detect', template_id, re.I):
                ver_m = re.search(r'version[:\s]+(\d[\d\.]+)', line, re.I)
                tech  = re.sub(r'tech-detect[:\-]?', '', template_id,
                               flags=re.I).strip('- _') or 'Technology'
                if ver_m:
                    title = _fix_acronyms(
                        f"Service Version Identified — {tech.strip()} {ver_m.group(1)} ({fip}:{fprt})")
                else:
                    title = _fix_acronyms(f"Technology Detected — {tech.strip()} ({fip})")
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── Robots.txt ────────────────────────────────────────────────
            if re.search(r'robots.*txt|robots-txt', template_id, re.I):
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"Robots.txt File Found ({fip}:{fprt})",
                    description=f"nuclei: {line[:300]}", tool="nuclei",
                    raw_output=line[:500], source_type="primary",
                    force_risk="Informational", cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── CVE template ID → descriptive name ───────────────────────
            cve_match = re.match(r'(CVE-\d{4}-\d+)', template_id, re.I)
            if cve_match:
                cve_id    = cve_match.group(1).upper()
                if cve_id in _NMAP_FP_SKIP:
                    continue
                known = _CVE_RENAME_MAP.get(cve_id, "")
                if known:
                    title = _fix_acronyms(f"{known} ({fip}:{fprt})")
                else:
                    title = _fix_acronyms(f"{cve_id} — {fip}:{fprt}")
                if cve_id not in cves:
                    cves.append(cve_id)
                self.ctx.findings.create(
                    ctx=self.ctx, title=title,
                    description=f"nuclei: {line[:300]}",
                    tool="nuclei", raw_output=line[:500],
                    source_type="primary", force_risk=risk, cve_ids=cves,
                    ip=fip, port=fprt, output_file=str(out_file))
                continue

            # ── Default: clean template_id into readable title ───────────
            readable = re.sub(r'[-_]', ' ', template_id).title()
            title    = _fix_acronyms(f"{readable} ({fip}:{fprt})" if fip else readable)
            self.ctx.findings.create(
                ctx=self.ctx, title=title,
                description=f"nuclei: {line[:300]}",
                tool="nuclei", raw_output=line[:500],
                source_type="primary", force_risk=risk, cve_ids=cves,
                ip=fip, port=fprt, output_file=str(out_file))


# ---------------------------------------------------------------------------
# SSL Module — sslscan + testssl.sh + shcheck per HTTPS port
# ---------------------------------------------------------------------------

class SSLModule(BaseModule):
    """
    Dedicated SSL/TLS assessment module.  For every HTTPS port discovered by
    NmapPort it runs sslscan, testssl.sh, and shcheck, collects all output
    files, and emits structured findings.  Tracks status and makes all output
    files available via the Evidence/VIEW mechanism.
    """
    name            = "SSL"
    description     = "SSL/TLS analysis: sslscan, testssl.sh, shcheck"
    concurrent_safe = True

    # Expected output filename patterns (used by MODULE_EVIDENCE in app.py)
    OUTPUT_PATTERNS = [
        "*_sslscan.txt",
        "*_testssl.txt",
        "*_testssl.json",
        "*_shcheck.txt",
    ]

    def run(self) -> None:
        self._mark_running()
        try:
            hosts   = self._target_hosts()
            out_dir = self.ctx.instance_dir / "SSL"
            out_dir.mkdir(parents=True, exist_ok=True)

            HTTPS_SVCS  = {"https","https-alt","ssl","tls"}
            HTTPS_PORTS = {443,8443,4443,9443,10443}

            work: list[tuple] = []
            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    svc  = (p.get("service") or "").lower()
                    ver  = (p.get("version") or "").lower()
                    port = p["port"]
                    if (svc in HTTPS_SVCS
                            or "https" in ver or "ssl" in ver
                            or port in HTTPS_PORTS):
                        work.append((ip, port, "https"))

            if not work:
                self._mark_na_complete("HTTPS/SSL")
                return

            with ThreadPoolExecutor(
                    max_workers=min(_MAX_WEB_WORKERS, len(work)),
                    thread_name_prefix="ssl-assess") as pool:
                futures = {
                    pool.submit(self._assess_ssl, ip, port, proto, out_dir): (ip, port)
                    for ip, port, proto in work
                }
                for fut in as_completed(futures):
                    ip, port = futures[fut]
                    try:
                        fut.result(timeout=600)
                    except TimeoutError:
                        self.ctx.logger.warn(
                            f"SSL assessment of {ip}:{port} timed out", tool="ssl")
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"SSL assessment of {ip}:{port} failed: {e}", tool="ssl")

            self._mark_complete(f"SSL/TLS assessed — {len(work)} target(s)")
        except Exception as e:
            self.ctx.logger.error(f"SSL module failed: {e}", exc=e, tool="ssl")
            self._mark_error(str(e))
    def _assess_ssl(self, ip: str, port: int, proto: str, out_dir: Path) -> None:
        safe = ip.replace(".", "_")
        url  = f"{proto}://{ip}:{port}"
        all_output_files: list[str] = []

        # ── sslscan ───────────────────────────────────────────────────────
        if tool_available("sslscan"):
            sslscan_out = out_dir / f"{safe}_{port}_sslscan.txt"
            rc, stdout, _ = run_tool(
                ["sslscan", "--no-failed", "--no-colour", url],
                self.ctx, tool_name="sslscan",
                output_file=sslscan_out, timeout=60)
            if sslscan_out.exists() and sslscan_out.stat().st_size > 0:
                all_output_files.append(str(sslscan_out))
                self._parse_sslscan(url, stdout or sslscan_out.read_text(errors="replace"),
                                     sslscan_out)

        # ── testssl.sh ────────────────────────────────────────────────────
        testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")
        if testssl_bin:
            testssl_out  = out_dir / f"{safe}_{port}_testssl.txt"
            testssl_json = out_dir / f"{safe}_{port}_testssl.json"
            run_tool(
                [testssl_bin,
                 "--quiet", "--color", "0",
                 "--warnings", "off",
                 "--logfile",  str(testssl_out),
                 "--jsonfile", str(testssl_json),
                 url],
                self.ctx, tool_name="testssl.sh", timeout=300)
            if testssl_out.exists() and testssl_out.stat().st_size > 0:
                all_output_files.append(str(testssl_out))
                self._parse_testssl(url, testssl_out)
            if testssl_json.exists() and testssl_json.stat().st_size > 0:
                all_output_files.append(str(testssl_json))

        # ── shcheck ───────────────────────────────────────────────────────
        shcheck_bin = (shutil.which("shcheck.py")
                       or shutil.which("shcheck"))
        if shcheck_bin:
            shcheck_out = out_dir / f"{safe}_{port}_shcheck.txt"
            run_tool(
                [shcheck_bin, "-d", url],
                self.ctx, tool_name="shcheck",
                output_file=shcheck_out, timeout=60)
            if shcheck_out.exists() and shcheck_out.stat().st_size > 0:
                all_output_files.append(str(shcheck_out))
                self._check_security_headers(url, out_dir, safe)

        # Emit an observation linking all output files
        if all_output_files:
            self._observe(
                title=f"SSL/TLS Assessment — {ip}:{port}",
                description=(f"sslscan, testssl.sh, and shcheck results for {ip}:{port}. "
                             f"{len(all_output_files)} output file(s) collected."),
                tool="ssl",
                output_file=all_output_files[0],
                output_text="",
                risk="Informational",
            )

    def _check_security_headers(self, url: str, out_dir: Path, safe: str) -> None:
        """
        Run shcheck.py to identify missing/misconfigured security headers.
        Falls back to a curl-based header check if shcheck is unavailable.
        """
        headers_dir = out_dir / "headers"
        headers_dir.mkdir(parents=True, exist_ok=True)
        out_file = headers_dir / f"{safe}_shcheck.txt"

        if tool_available("shcheck.py"):
            rc, stdout, stderr = run_tool(
                [shutil.which("shcheck.py") or "shcheck.py",
                 "-d", url],
                self.ctx, tool_name="shcheck", timeout=30)
            combined = (stdout + stderr).strip()
            out_file.write_text(combined)
            self._parse_shcheck_output(url, combined, out_file)
        else:
            # Fallback: check response headers directly with curl
            self.ctx.logger.info(
                "shcheck.py not available — using curl header fallback", tool="shcheck")
            # Headers file is now written to headers/ by _assess_target
            hdr_file = out_dir / "headers" / f"{safe}_headers.txt"
            if not hdr_file.exists():
                # Legacy fallback path
                hdr_file = out_dir / f"{safe}_headers.txt"
            if hdr_file.exists():
                self._parse_response_headers(url, hdr_file, headers_dir, safe)

    def _parse_shcheck_output(self, url: str, output: str, out_file: Path) -> None:
        """Parse shcheck output and create per-header findings for missing security headers."""
        missing  = re.findall(r'\[!\]\s*(.+?) is not set', output, re.I)
        present  = re.findall(r'\[✓\]\s*(.+?)\s*:', output, re.I)

        _sh_ip, _sh_port = self.ctx.findings._extract_ip_port_from_url(url)
        _HSTS = "Strict-Transport-Security"
        for header_name in missing:
            header_name = header_name.strip()
            if not header_name:
                continue
            _risk = "Medium" if header_name == _HSTS else "Low"
            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"Missing Security Header: {header_name}",
                description=(
                    f"The HTTP security header '{header_name}' is absent from {url}."),
                tool="shcheck",
                raw_output=output[:800],
                source_type="primary",
                force_risk=_risk,
                affected_component=header_name,
                ip=_sh_ip, port=_sh_port,
                output_file=str(out_file),
            )
        self._observe(
            title=f"Security Headers Analysis — {url}",
            description=(f"shcheck: {len(missing)} missing, {len(present)} present. "
                         f"Missing: {', '.join(missing) or 'none'}"),
            tool="shcheck",
            output_file=str(out_file),
            output_text=output[:2000],
            risk="Medium" if missing else "Informational",
        )

    def _parse_response_headers(self, url: str, hdr_file: Path,
                                  headers_dir: Path, safe: str) -> None:
        """Fallback: check raw curl response headers for missing security headers."""
        try:
            content = hdr_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        headers_present = [h for h in self._SECURITY_HEADERS
                           if h.lower() in content.lower()]
        headers_missing = [h for h in self._SECURITY_HEADERS
                           if h.lower() not in content.lower()]

        out_file = headers_dir / f"{safe}_header_check.txt"
        out_file.write_text(
            f"URL: {url}\n\nPresent:\n"
            + "\n".join(f"  + {h}" for h in headers_present)
            + "\n\nMissing:\n"
            + "\n".join(f"  - {h}" for h in headers_missing)
        )
        _sh_ip, _sh_port = self.ctx.findings._extract_ip_port_from_url(url)
        _HSTS = "Strict-Transport-Security"
        for _hdr in headers_missing:
            _risk = "Medium" if _hdr == _HSTS else "Low"
            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"Missing Security Header: {_hdr}",
                description=(
                    f"The HTTP security header '{_hdr}' is absent from {url}."),
                tool="curl",
                raw_output=content[:800],
                source_type="primary",
                force_risk=_risk,
                affected_component=_hdr,
                ip=_sh_ip, port=_sh_port,
                output_file=str(out_file),
            )
        self._observe(
            title=f"Security Headers Check — {url}",
            description=(f"{len(headers_missing)} missing / {len(headers_present)} present. "
                         f"Missing: {', '.join(headers_missing) or 'none'}"),
            tool="curl",
            output_file=str(out_file),
            output_text=out_file.read_text(),
            risk="Medium" if headers_missing else "Informational",
        )

    # ── 8. SSL analysis ───────────────────────────────────────────────────────

    def _ssl_analysis(self, url: str, out_dir: Path, safe: str) -> None:
        """Run sslscan and testssl.sh for SSL/TLS analysis of a single HTTPS URL."""
        ssl_dir = out_dir / "ssl"
        ssl_dir.mkdir(parents=True, exist_ok=True)

        if tool_available("sslscan"):
            sslscan_out = ssl_dir / f"{safe}_sslscan.txt"
            rc, stdout, _ = run_tool(
                ["sslscan", "--no-failed", "--no-colour", url],
                self.ctx, tool_name="sslscan",
                output_file=sslscan_out, timeout=60)
            self._parse_sslscan(url, stdout, sslscan_out)

        if tool_available("testssl.sh") or tool_available("testssl"):
            testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl") or "testssl.sh"
            testssl_out  = ssl_dir / f"{safe}_testssl.txt"
            testssl_json = ssl_dir / f"{safe}_testssl.json"
            run_tool(
                [testssl_bin,
                 "--quiet", "--color", "0",
                 "--warnings", "off",
                 "--logfile",  str(testssl_out),
                 "--jsonfile", str(testssl_json),
                 url],
                self.ctx, tool_name="testssl.sh", timeout=300)
            if testssl_out.exists() and testssl_out.stat().st_size > 0:
                self._parse_testssl(url, testssl_out)
            if testssl_json.exists() and testssl_json.stat().st_size > 0:
                self._parse_testssl_json(url, testssl_json, testssl_out)

    def _parse_sslscan(self, url: str, output: str, out_file: Path) -> None:
        """
        Create findings for weak SSL/TLS from sslscan output.

        Every check uses line-level matching so that lines containing
        'not vulnerable', 'disabled', or 'not' are not falsely triggered.
        Cipher-based inference detects SWEET32/BEAST/LUCKY13 from accepted ciphers.
        """
        # Each tuple: (pos_regex, neg_regex, title, risk, affected_component)
        checks = [
            (r'SSLv2\s+enabled',       None,                        "Deprecated Protocol Enabled: SSLv2",   "High",     ""),
            (r'SSLv3\s+enabled',       None,                        "Deprecated Protocol Enabled: SSLv3",   "Medium",   ""),
            (r'TLSv1\.0\s+enabled',    None,                        "Deprecated Protocol Enabled: TLSv1.0", "Medium",   ""),
            (r'TLSv1\.1\s+enabled',    None,                        "Deprecated Protocol Enabled: TLSv1.1", "Low",      ""),
            (r'NULL\s+cipher',         r'not\s+vuln|disabled|none', "Weak Cipher Identified",               "Critical", "NULL"),
            (r'\bRC4\b',               r'not\s+vuln|disabled|none', "Weak Cipher Identified",               "Medium",   "RC4"),
            (r'\bEXPORT\b',            r'not\s+vuln|disabled|none', "Weak Cipher Identified",               "Medium",   "EXPORT"),
            (r'\bDES\b(?!-CBC3)',       r'not\s+vuln|disabled|none', "Weak Cipher Identified",               "Medium",   "DES"),
            (r'MD5\s+signature',       r'not\s+vuln|disabled|none', "MD5 Signature Algorithm",              "Medium",   ""),
        ]
        _u    = re.match(r'https?://([^/:]+)(?::(\d+))?', url)
        _sip  = _u.group(1) if _u else ""
        _sprt = _u.group(2) if (_u and _u.group(2)) else (
            "443" if url.startswith("https") else "80")

        _tls10_enabled = False
        _cbc_ciphers:  list[str] = []
        _3des_ciphers: list[str] = []
        _RE_SS_CIPHER_LINE = re.compile(
            r'Accepted\s+(\S+)\s+\d+\s+bits\s+(\S+)', re.I)

        for line in output.splitlines():
            # Track TLS 1.0 state for BEAST inference
            if re.search(r'TLSv1\.0\s+enabled', line, re.I):
                _tls10_enabled = True
            # Collect accepted cipher names for cipher-based inference
            _cm = _RE_SS_CIPHER_LINE.match(line.strip())
            if _cm:
                _cn = _cm.group(2).strip()
                _cn_lo = _cn.lower()
                if "cbc" in _cn_lo:
                    _cbc_ciphers.append(_cn)
                if "3des" in _cn_lo or "des-cbc3" in _cn_lo:
                    _3des_ciphers.append(_cn)
            for pos_pat, neg_pat, title, risk, affected_comp in checks:
                if not re.search(pos_pat, line, re.I):
                    continue
                if neg_pat and re.search(neg_pat, line, re.I):
                    continue
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=title,
                    description=f"sslscan detected: {title}{' (' + affected_comp + ')' if affected_comp else ''} at {url}",
                    tool="sslscan",
                    raw_output=line.strip(),
                    source_type="primary",
                    force_risk=risk,
                    affected_component=affected_comp,
                    ip=_sip,
                    port=_sprt,
                    output_file=str(out_file),
                )
                break  # one match per line is enough

        # ── Cipher-based vulnerability inference ─────────────────────────────
        # SWEET32: 3DES cipher suites accepted → CVE-2016-2183
        if _3des_ciphers:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SSL/TLS Vulnerability: SWEET32",
                description=(
                    f"sslscan: 3DES cipher suites accepted — susceptible to SWEET32 "
                    f"birthday attack (CVE-2016-2183): {', '.join(_3des_ciphers[:5])}"
                ),
                tool="sslscan",
                raw_output=", ".join(_3des_ciphers[:10]),
                source_type="primary",
                # G4 (2026-06-11 review): risk lowered MEDIUM→LOW. SWEET32
                # requires GBs of identical-cipher traffic in a single session;
                # exploitable in theory, rare in practice. LOW per CVSS.
                force_risk="Low",
                cve_ids=["CVE-2016-2183"],
                ip=_sip, port=_sprt,
                output_file=str(out_file),
            )

        # BEAST: TLSv1.0 + CBC cipher suites → CVE-2011-3389
        if _tls10_enabled and _cbc_ciphers:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SSL/TLS Vulnerability: BEAST",
                description=(
                    "sslscan: TLSv1.0 enabled with CBC cipher suites — "
                    "susceptible to BEAST (CVE-2011-3389)"
                ),
                tool="sslscan",
                raw_output=", ".join(_cbc_ciphers[:10]),
                source_type="primary",
                # G4 (2026-06-11 review): risk lowered MEDIUM→LOW. BEAST is
                # largely client-side-mitigated (record splitting in all modern
                # browsers since 2012). LOW per CVSS.
                force_risk="Low",
                cve_ids=["CVE-2011-3389"],
                ip=_sip, port=_sprt,
                output_file=str(out_file),
            )

        # LUCKY13: any CBC cipher suites → CVE-2013-0169
        if _cbc_ciphers:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SSL/TLS Vulnerability: LUCKY13",
                description=(
                    "sslscan: CBC cipher suites accepted — "
                    "susceptible to LUCKY13 (CVE-2013-0169)"
                ),
                tool="sslscan",
                raw_output=", ".join(_cbc_ciphers[:10]),
                source_type="primary",
                # G4 (2026-06-11 review): risk lowered MEDIUM→LOW. LUCKY13
                # exploit is a timing attack requiring MITM + millions of
                # packets per byte recovered; LOW per CVSS.
                force_risk="Low",
                cve_ids=["CVE-2013-0169"],
                ip=_sip, port=_sprt,
                output_file=str(out_file),
            )

        # ── Heartbleed: whole-output section analysis ─────────────────────────────
        # More reliable than per-line matching — sslscan output format varies by version.
        # Find the Heartbleed section and fire only when a protocol line is VULNERABLE.
        _hb_m = re.search(r'Heartbleed.*?(?=\n\s*\n|\Z)', output, re.I | re.S)
        if _hb_m:
            _hb_section = _hb_m.group(0)
            _hb_vuln = [
                ln for ln in _hb_section.splitlines()
                if re.search(r'TLSv?[\d.]+|SSLv[\d.]+', ln, re.I)
                and not re.search(
                    r'not\s+vuln|not\s+affect|not\s+suscept|'
                    r'not\s+vulnerable|N/A|disabled|secure', ln, re.I)
                and re.search(r'vuln|heartbleed', ln, re.I)
            ]
            if _hb_vuln:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title='Heartbleed (CVE-2014-0160) Vulnerability Detected',
                    description=('sslscan confirmed Heartbleed vulnerability at ' + url
                                 + '. Affected: '
                                 + '; '.join(ln.strip() for ln in _hb_vuln)),
                    tool='sslscan',
                    raw_output=_hb_section[:500],
                    source_type='primary',
                    force_risk='Critical',
                    cve_ids=['CVE-2014-0160'],
                    ip=_sip,
                    port=_sprt,
                    output_file=str(out_file),
                )

    def _parse_testssl(self, url: str, out_file: Path) -> None:
        """
        Parse testssl.sh plain-text log for findings.
        testssl prefixes severity as WARN, MEDIUM, HIGH, CRITICAL or SEVERE.
        Lines starting with '(Not|OK|INFO|DEBUG|HINT)' are not vulnerabilities.
        """
        RISK_MAP = {
            "critical": "Critical",
            "severe":   "Critical",
            "high":     "High",
            "medium":   "Medium",
            "warn":     "Low",
            "low":      "Low",
        }
        # testssl finding line format:
        #   SEVERITY   Testing X ... VULNERABLE -- <description>
        #   or:
        #   SEVERITY   <id>  <description>
        finding_re = re.compile(
            r'^\s*(CRITICAL|SEVERE|HIGH|MEDIUM|WARN|LOW)\s+'
            r'(.+)',
            re.I
        )
        # Lines to skip
        skip_re = re.compile(
            r'not\s+vuln|not\s+offer|not\s+affect|not\s+suscept|'
            r'not\s+vulnerable|no\s+vuln|not\s+tested|'
            r'^[\s]*(OK|INFO|DEBUG|HINT|Done|--)|'            r'\bno\s+issue|benign',
            re.I
        )
        # testssl uses short IDs (T, F, C, etc.) before the description on some versions.
        # Strip single uppercase-letter prefixes so they don't become the entire label.
        testssl_id_re = re.compile(r'^([A-Z]{1,6})\s+(.+)')
        try:
            text = out_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        for line in text.splitlines():
            m = finding_re.match(line)
            if not m:
                continue
            severity_raw = m.group(1).lower()
            description  = m.group(2).strip()
            if skip_re.search(description):
                continue
            risk = RISK_MAP.get(severity_raw, "Medium")

            # Strip short testssl IDs like "T " or "F " at start of description
            id_m = testssl_id_re.match(description)
            if id_m and len(id_m.group(1)) <= 3:
                description = id_m.group(2).strip()
            if not description or description.upper() in ('T', 'F', 'C', 'S'):
                continue  # nothing meaningful

            # Extract ip/port from url
            _u = re.match(r'https?://([^/:]+)(?::(\d+))?', url)
            _tip  = _u.group(1) if _u else ""
            _tprt = _u.group(2) if (_u and _u.group(2)) else (
                "443" if url.startswith("https") else "80")

            desc_lower = description.lower()

            # Certificate validity period → standardised title + Low risk
            is_validity = (re.search(r'\d+\s*days?', description, re.I)
                           and re.search(r'valid|expir|certif', desc_lower))
            if is_validity:
                label, affected_comp = "SSL/TLS Certificate: Overly Long Expiry", ""
                risk  = "Low"
            else:
                label, affected_comp = self._testssl_label(description)

            # Drop noise findings where _testssl_label returned None
            if label is None:
                continue

            # Risk overrides for specific classes
            # Chain of trust incomplete
            if re.search(r'chain.*incomplete|incomplete.*chain', desc_lower):
                risk  = "Informational"
                label = "SSL/TLS Chain of Trust Incomplete"
            if re.search(r'certificate.*does not match|does not match.*suppli|'
                         r'neither.*CRL|no.*CRL.*no.*OCSP|not.*CRL.*OCSP|'
                         r'CRL.*OCSP|OCSP.*CRL|mismatch', desc_lower):
                risk = "Informational"
            if re.search(r'CBC.*obsolet|obsolet.*CBC', desc_lower):
                risk  = "Low"
                label = "SSL/TLS Vulnerability: Obsolete CBC Ciphers"

            # CVE extraction from description (e.g. "CVE-2013-0169")
            cve_list = re.findall(r'CVE-\d{4}-\d+', description, re.I)

            self.ctx.findings.create(
                ctx=self.ctx,
                title=label,
                description=f"testssl.sh: {description}",
                tool="testssl.sh",
                raw_output=line.strip(),
                source_type="primary",
                force_risk=risk,
                cve_ids=[c.upper() for c in cve_list],
                affected_component=affected_comp,
                ip=_tip,
                port=_tprt,
                output_file=str(out_file),
            )

    def _parse_testssl_json(self, url: str,
                             json_file: Path, txt_file: Path) -> None:
        """Parse testssl.sh JSON output for findings (richer than text log)."""
        try:
            data = json.loads(json_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        RISK_MAP = {
            "CRITICAL": "Critical", "SEVERE": "Critical",
            "HIGH":     "High",     "MEDIUM": "Medium",
            "WARN":     "Low",      "LOW":    "Low",
        }
        SKIP = {"OK", "INFO", "DEBUG", "HINT", "NOT_TESTED"}
        findings_list = data if isinstance(data, list) else data.get("findings", [])
        for entry in findings_list:
            severity = str(entry.get("severity", "")).upper()
            if severity in SKIP or not severity:
                continue
            finding_text = entry.get("finding", "")
            if re.search(r'not\s+vuln|not\s+offer|not\s+affect', finding_text, re.I):
                continue
            risk  = RISK_MAP.get(severity, "Medium")
            label, affected_comp = self._testssl_label(finding_text)
            if label is None:
                continue  # suppress noise
            # Extract ip/port from url
            _u = re.match(r'https?://([^/:]+)(?:(\d+))?', url)
            _tip  = _u.group(1) if _u else ""
            _tprt = _u.group(2) if (_u and _u.group(2)) else (
                "443" if url.startswith("https") else "80")
            cve_list = re.findall(r'CVE-\d{4}-\d+', finding_text, re.I)
            self.ctx.findings.create(
                ctx=self.ctx,
                title=label,
                description=f"testssl.sh: {finding_text}",
                tool="testssl.sh",
                raw_output=finding_text[:500],
                source_type="secondary",
                force_risk=risk,
                cve_ids=[c.upper() for c in cve_list],
                affected_component=affected_comp,
                ip=_tip,
                port=_tprt,
                output_file=str(txt_file),
            )

    def _testssl_label(self, text: str) -> "tuple[str, str] | tuple[None, None]":
        """
        Map a testssl.sh description string to a (canonical_title, affected_component) tuple.
        Returns (None, None) to signal the finding should be SUPPRESSED (noise).
        affected_component is non-empty only for weak cipher entries.
        """
        text = text.strip()
        # ── Suppress noise ──────────────────────────────────────────────────
        noise_patterns = [
            r'^offered$',              # bare "offered" with no context
            r'^not offered$',
            r'^Configuration Issue$',
            r'^\w{1,4}$',             # single short token (T, F, C, etc.)
        ]
        for np in noise_patterns:
            if re.match(np, text, re.I):
                return (None, None)  # caller must drop this finding

        # Each entry: (pattern, canonical_title, affected_component)
        # affected_component is non-empty only for weak cipher findings.
        mappings = [
            # Protocol versions
            (r'SSLv2',                           "Deprecated Protocol Enabled: SSLv2",              ""),
            (r'SSLv3',                           "Deprecated Protocol Enabled: SSLv3",              ""),
            (r'TLS\s*1\.0',                      "Deprecated Protocol Enabled: TLSv1.0",            ""),
            (r'TLS\s*1\.1',                      "Deprecated Protocol Enabled: TLSv1.1",            ""),
            # Known attacks — precise names aligned with Scattershot3/Fracture
            (r'Heartbleed',                      "Heartbleed (CVE-2014-0160) Vulnerability Detected", ""),
            (r'POODLE',                          "SSL/TLS Vulnerability: POODLE",                   ""),
            (r'BEAST',                           "SSL/TLS Vulnerability: BEAST",                    ""),
            (r'BREACH',                          "BREACH Attack (CVE-2013-3587)",                   ""),
            (r'CRIME',                           "SSL/TLS Vulnerability: CRIME",                    ""),
            (r'DROWN',                           "SSL/TLS Vulnerability: DROWN",                    ""),
            (r'SWEET32',                         "SSL/TLS Vulnerability: SWEET32",                  ""),
            (r'LUCKY\s*13',                      "SSL/TLS Vulnerability: LUCKY13",                  ""),
            (r'LOGJAM',                          "SSL/TLS Vulnerability: LOGJAM",                   ""),
            (r'FREAK',                           "SSL/TLS Vulnerability: FREAK",                    ""),
            (r'CCS\s+injection|CCS\s+vuln',      "OpenSSL CCS Injection (CVE-2014-0224)",           ""),
            (r'Ticketbleed',                     "Ticketbleed (CVE-2016-9244)",                     ""),
            (r'ROBOT',                           "ROBOT Attack (CVE-2017-13099)",                   ""),
            # Weak ciphers — emit "Weak Cipher Identified" with cipher in affected_component
            (r'\bRC4\b',                         "Weak Cipher Identified",                          "RC4"),
            (r'NULL\s+cipher',                   "Weak Cipher Identified",                          "NULL"),
            (r'EXPORT\s+cipher|export\s+grade',  "Weak Cipher Identified",                          "EXPORT"),
            (r'\b3DES\b',                        "Weak Cipher Identified",                          "3DES"),
            (r'\bDES\b',                         "Weak Cipher Identified",                          "DES"),
            (r'CBC.*obsolet|obsolet.*CBC',        "SSL/TLS Vulnerability: Obsolete CBC Ciphers",    ""),
            (r'MD5',                             "MD5 Signature Algorithm",                         ""),
            (r'SHA-?1\s+sign',                   "SHA-1 Signature Algorithm",                       ""),
            (r'weak.*DH|DH\s+\d{1,3}\s*bit',    "Weak DH Parameter",                              ""),
            (r'forward.secrecy|PFS',             "SSL/TLS Forward Secrecy: Not Supported",           ""),
            # Certificate issues
            (r'self.sign',                       "SSL/TLS Certificate: Self-Signed",                ""),
            (r'expir',                           "SSL/TLS Certificate: Expired",                    ""),
            (r'certificate.*does not match|does not match.*suppli',
                                                 "Certificate Hostname Mismatch",                   ""),
            (r'mismatch',                        "Certificate Hostname Mismatch",                   ""),
            (r'neither.*CRL.*OCSP|no.*CRL.*no.*OCSP|not.*CRL.*OCSP',
                                                 "No Certificate Revocation Information",           ""),
            (r'CRL.*OCSP|OCSP.*CRL',             "Missing CRL/OCSP URI",                           ""),
            # Cipher order
            (r'not.*cipher.*order|no.*cipher.*order|cipher.*order.*not',
                                                 "Server Does Not Specify Cipher Order",            ""),
            # Headers
            (r'HSTS',                            "Missing Security Header: Strict-Transport-Security", ""),
            # Potentially vulnerable (explicit label from testssl output)
            (r'potentially vulnerable|possibly vulnerable',
                                                 "Potentially Vulnerable — Manual Verification Needed", ""),
        ]
        for pattern, label, affected in mappings:
            if re.search(pattern, text, re.I):
                return (label, affected)
        # Fallback: clean up the raw text — better than "Configuration Issue"
        cleaned = re.sub(r'[\s_\-]+', ' ', text).strip()
        # Drop if the result is trivially short or uninformative
        if not cleaned or len(cleaned) < 4:
            return (None, None)
        return (_fix_acronyms(cleaned[:100]), "")

    # ── 9. Nuclei (with aggressive timeout guard) ─────────────────────────────


# ---------------------------------------------------------------------------
# SMB Module
# ---------------------------------------------------------------------------

class SMBModule(BaseModule):
    name            = "SMB"
    description     = "SMB enumeration, share discovery, and hash capture via Responder"
    concurrent_safe = True

    def run(self) -> None:
        self._mark_running()
        try:
            hosts   = self._target_hosts()
            out_dir = self.ctx.instance_dir / "SMB"
            out_dir.mkdir(parents=True, exist_ok=True)

            work          = []
            responder_proc = None
            responder_log  = out_dir / "_responder.log"

            # Start Responder in background if available
            if tool_available("responder") or tool_available("Responder"):
                responder_bin  = shutil.which("responder") or shutil.which("Responder")
                TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
                if responder_bin:
                    try:
                        pwd = _get_sudo_password()
                        responder_proc = subprocess.Popen(
                            ["sudo", "-S", responder_bin, "-I",
                             TEST_INTERFACE, "-wFb"],
                            stdin=subprocess.PIPE,
                            stdout=open(str(responder_log), "w"),
                            stderr=subprocess.STDOUT,
                        )
                        responder_proc.stdin.write((pwd + "\n").encode())
                        responder_proc.stdin.flush()
                        if _pause:
                            _pause.register(responder_proc, "responder")
                        self.ctx.progress.set_module_status(
                            self.ctx.subdevice_key, self.ctx.interface,
                            self.ctx.instance_key, "_responder_pid",
                            str(responder_proc.pid))
                    except Exception as e:
                        self.ctx.logger.warn(f"Could not start Responder: {e}")

            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    svc = (p.get("service") or "").lower()
                    if (svc in ("microsoft-ds", "netbios-ssn", "smb")
                            or p["port"] in (139, 445)):
                        work.append((ip, p["port"]))

            if not work:
                self._mark_na_complete("SMB")
                if responder_proc:
                    if _pause:
                        _pause.unregister(responder_proc.pid)
                    try:
                        responder_proc.terminate()
                        responder_proc.wait(timeout=5)
                    except Exception:
                        pass
                return
            else:
                with ThreadPoolExecutor(
                        max_workers=min(_MAX_SMB_WORKERS, len(work))) as pool:
                    futures = {
                        pool.submit(self._test_smb, ip, port, out_dir): (ip, port)
                        for ip, port in work
                    }
                    for fut in as_completed(futures):
                        ip, port = futures[fut]
                        try:
                            fut.result()
                        except Exception as e:
                            self.ctx.logger.warn(
                                f"SMB test failed {ip}:{port}: {e}")

            if responder_proc:
                if _pause:
                    _pause.unregister(responder_proc.pid)
                try:
                    responder_proc.terminate()
                    responder_proc.wait(timeout=5)
                except Exception:
                    pass
                if responder_log.exists():
                    self._analyze_responder(responder_log)

            if work:
                self._mark_complete(
                    f"SMB testing complete — {len(work)} service(s)")
        except Exception as e:
            self.ctx.logger.error(f"SMB module failed: {e}", exc=e)
            self._mark_error(str(e))
    def _test_smb(self, ip: str, port: int, out_dir: Path) -> None:
        safe     = ip.replace(".", "_")
        out_file = out_dir / f"{safe}_nmap_smb.txt"
        run_tool(
            ["nmap", "-p", str(port), "--script",
             "smb-enum-users,smb-enum-shares,smb-protocols,"
             "smb-security-mode,smb-os-discovery,smb-ls",
             ip],
            self.ctx, tool_name="nmap-smb",
            output_file=out_file, timeout=120)

        if out_file.exists():
            content = out_file.read_text(errors="replace")
            self._observe(
                title=f"SMB Service Analysis — {ip}:{port}",
                description=f"nmap SMB script results for {ip}:{port}",
                tool="nmap",
                output_file=str(out_file),
                output_text=content[:1500],
                risk="Informational",
            )
            if "anonymous" in content.lower():
                # Run smbmap to determine actual share permissions
                self._run_smbmap(ip, port, out_dir, safe, str(out_file))
            if "SMB Signing" in content and "disabled" in content.lower():
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="SMB Signing Disabled or Not Required",
                    description="SMB packet signing is not enforced on the server, allowing an attacker positioned between client and server to relay or tamper with SMB authentication and data.",
                    remediation="Enable and require SMB signing via Group Policy (RequireSecuritySignature=1) on all Windows systems to prevent NTLM relay attacks.",
                    tool="nmap-smb", raw_output=content[:500],
                    source_type="primary", force_risk="High",
                    ip=ip, port=str(port),
                    output_file=str(out_file),
                )

    def _run_smbmap(self, ip: str, port: int, out_dir: Path,
                    safe: str, nmap_out: str) -> None:
        """Run smbmap against an IP to determine anonymous share permissions."""
        # Ensure smbmap is available, install if not
        if not tool_available("smbmap"):
            self.ctx.logger.info("smbmap not found — attempting install", tool="smbmap")
            try:
                subprocess.run(
                    ["pip3", "install", "smbmap", "--break-system-packages"],
                    capture_output=True, timeout=60)
            except Exception:
                pass
            if not tool_available("smbmap"):
                try:
                    subprocess.run(
                        ["apt-get", "install", "-y", "smbmap"],
                        capture_output=True, timeout=120)
                except Exception:
                    pass
        if not tool_available("smbmap"):
            # Fall back to reporting plain anonymous access
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SMB Share Accessible Without Authentication",
                description="One or more SMB shares are accessible without valid credentials, allowing unauthenticated users to read or write files and potentially enumerate domain information.",
                remediation="Require authentication on all SMB shares, disable null-session and guest access, and enforce least-privilege ACLs on every share.",
                tool="nmap-smb", raw_output="",
                source_type="primary", force_risk="Critical",
                ip=ip, port=str(port), output_file=nmap_out)
            return

        smbmap_out = out_dir / f"{safe}_smbmap.txt"
        # Try standard smbmap invocation; fall back to python3 -m smbmap
        # Use --no-pass for anonymous access (avoids empty-string auth issues)
        smbmap_cmds = [
            ["smbmap", "-H", ip, "-P", str(port), "-u", "anonymous", "--no-pass"],
            ["smbmap", "-H", ip, "-P", str(port), "-u", "", "-p", ""],
            ["python3", "-m", "smbmap", "-H", ip, "-P", str(port),
             "-u", "anonymous", "--no-pass"],
        ]
        rc, stdout, stderr = -1, "", ""
        for _cmd in smbmap_cmds:
            _rc, _out, _err = run_tool(
                _cmd, self.ctx, tool_name="smbmap",
                output_file=smbmap_out, timeout=60)
            if _rc == 0 or (_out and len(_out.strip()) > 10):
                rc, stdout, stderr = _rc, _out, _err
                break
            rc, stdout, stderr = _rc, _out, _err
        combined = (stdout + stderr).strip()

        has_write = bool(re.search(r'WRITE|READ,\s*WRITE', combined, re.I))
        has_read  = bool(re.search(r'READ', combined, re.I))

        if has_write:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SMB Share Accessible Without Authentication",
                description="One or more SMB shares are accessible without valid credentials, allowing unauthenticated users to read or write files and potentially enumerate domain information.",
                remediation="Require authentication on all SMB shares, disable null-session and guest access, and enforce least-privilege ACLs on every share.",
                tool="smbmap", raw_output=combined[:500],
                source_type="primary", force_risk="Critical",
                ip=ip, port=str(port), output_file=str(smbmap_out))
        elif has_read:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SMB Share Accessible Without Authentication",
                description="One or more SMB shares are accessible without valid credentials, allowing unauthenticated users to read or write files and potentially enumerate domain information.",
                remediation="Require authentication on all SMB shares, disable null-session and guest access, and enforce least-privilege ACLs on every share.",
                tool="smbmap", raw_output=combined[:500],
                source_type="primary", force_risk="Critical",
                ip=ip, port=str(port), output_file=str(smbmap_out))
        else:
            # nmap saw anonymous but smbmap didn't confirm — report original
            self.ctx.findings.create(
                ctx=self.ctx,
                title="SMB Share Accessible Without Authentication",
                description="One or more SMB shares are accessible without valid credentials, allowing unauthenticated users to read or write files and potentially enumerate domain information.",
                remediation="Require authentication on all SMB shares, disable null-session and guest access, and enforce least-privilege ACLs on every share.",
                tool="nmap-smb", raw_output=combined[:200],
                source_type="primary", force_risk="Critical",
                ip=ip, port=str(port), output_file=nmap_out)

    def _analyze_responder(self, log_path: Path) -> None:
        """Parse Responder log for captured credentials and hashes."""
        try:
            content = log_path.read_text(errors="replace")
            if not content.strip():
                return
            self._observe(
                title=f"Responder Capture Log — {self.ctx.instance_key}",
                description="Responder passive capture session results.",
                tool="responder",
                output_file=str(log_path),
                output_text=content[:1500],
                risk="Informational",
            )
            # Cleartext credentials
            for m in re.finditer(
                r'(?:Username|User)\s*:\s*(.+?)\s+(?:Password|Pass)\s*:\s*(\S+)',
                content, re.IGNORECASE
            ):
                user, pwd = m.group(1).strip(), m.group(2).strip()
                # Try to extract source IP from the Responder log line
                _resp_ip = ""
                _ip_in_line = re.search(
                    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
                    m.group(0))
                if _ip_in_line:
                    _resp_ip = _ip_in_line.group(1)
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"Cleartext Credentials Captured — {user}",
                    description=(
                        f"Responder captured cleartext credentials for user '{user}' "
                        f"via network authentication poisoning."
                    ),
                    tool="responder", raw_output=f"user={user}",
                    source_type="primary", force_risk="Critical",
                    force_classification="Validated",
                    ip=_resp_ip,
                    output_file=str(log_path),
                )
            # NTLMv1 hashes
            for m in re.finditer(r'(NTLMv1-SSP Hash\s*:.+)', content):
                _ntlm_ip = ""
                _ntlm_m = re.search(
                    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
                    m.group(1))
                if _ntlm_m:
                    _ntlm_ip = _ntlm_m.group(1)
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="Responder Captured NTLMv1 Hashes",
                    description=(
                        "Responder captured NTLMv1 authentication hashes. NTLMv1 is "
                        "cryptographically weak and can be cracked offline rapidly."),
                    tool="responder", raw_output=m.group(1)[:200],
                    source_type="primary", force_risk="Critical",
                    ip=_ntlm_ip,
                    output_file=str(log_path),
                )
            # NTLMv2 hashes
            for m in re.finditer(r'(NTLMv2-SSP Hash\s*:.+)', content):
                _ntlm_ip = ""
                _ntlm_m = re.search(
                    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
                    m.group(1))
                if _ntlm_m:
                    _ntlm_ip = _ntlm_m.group(1)
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="NTLMv2 Hash Captured via Responder",
                    description="Responder captured NTLMv2 authentication hashes.",
                    tool="responder", raw_output=m.group(1)[:200],
                    source_type="primary", force_risk="High",
                    ip=_ntlm_ip,
                    output_file=str(log_path),
                )
        except Exception as e:
            self.ctx.logger.warn(f"Could not parse Responder log: {e}")


# ---------------------------------------------------------------------------
# NFS Module
# ---------------------------------------------------------------------------

class NFSModule(BaseModule):
    name            = "NFS"
    description     = "NFS share enumeration and access testing (concurrent)"
    concurrent_safe = True

    def run(self) -> None:
        self._mark_running()
        try:
            hosts   = self._target_hosts()
            out_dir = self.ctx.instance_dir / "NFS"
            out_dir.mkdir(parents=True, exist_ok=True)

            nfs_hosts = []
            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    if (p.get("service", "") in ("rpcbind", "nfs", "mountd")
                            or p["port"] in (111, 2049)):
                        nfs_hosts.append(ip)
                        break

            if not nfs_hosts:
                self._mark_na_complete("NFS/RPC")
                return

            with ThreadPoolExecutor(
                    max_workers=min(_MAX_NFS_WORKERS, len(nfs_hosts))) as pool:
                futures = {
                    pool.submit(self._scan_nfs_host, ip, out_dir): ip
                    for ip in nfs_hosts
                }
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.ctx.logger.warn(f"NFS scan error {ip}: {e}")

            self._mark_complete(f"NFS scan complete — {len(nfs_hosts)} host(s)")
        except Exception as e:
            self.ctx.logger.error(f"NFS failed: {e}", exc=e)
            self._mark_error(str(e))
    def _scan_nfs_host(self, ip: str, out_dir: Path) -> None:
        safe     = ip.replace(".", "_")
        out_file = out_dir / f"{safe}_nfs.txt"
        run_tool(
            ["nmap", "-p", "111,2049", "--script",
             "nfs-showmount,nfs-ls,nfs-statfs,rpcinfo", ip],
            self.ctx, tool_name="nmap",
            output_file=out_file, timeout=60)
        if not out_file.exists():
            return
        content = out_file.read_text(errors="replace")
        self._observe(
            title=f"Enumeration: NFS — {ip}",
            description=f"NFS/RPC nmap scripts for {ip}.",
            tool="nmap",
            output_file=str(out_file),
            output_text=content[:1500],
            risk="Informational",
        )
        if "nfs-showmount" in content.lower() or "nfs-ls" in content.lower():
            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"NFS Share Exposed — {ip}",
                description=f"NFS exports are visible on {ip}. "
                            f"Verify access controls and authentication.",
                tool="nmap", raw_output=content[:500],
                source_type="primary", force_risk="High",
                ip=ip,
                port="2049",
                output_file=str(out_file),
            )
        # Check for world-readable or no-auth exports
        if re.search(r'no_root_squash|nobody|everyone', content, re.I):
            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"NFS Insecure Export Options — {ip}",
                description=f"NFS export on {ip} uses insecure options "
                            f"(no_root_squash or open access).",
                tool="nmap", raw_output=content[:500],
                source_type="primary", force_risk="Critical",
                ip=ip,
                port="2049",
                output_file=str(out_file),
            )


# ---------------------------------------------------------------------------
# USB Modules
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# FTP Module
# ---------------------------------------------------------------------------

class FTPModule(BaseModule):
    name            = "FTP"
    description     = "FTP anonymous access testing via nmap scripts"
    concurrent_safe = True

    def run(self) -> None:
        self._mark_running()
        try:
            hosts   = self._target_hosts()
            out_dir = self.ctx.instance_dir / "FTP"
            out_dir.mkdir(parents=True, exist_ok=True)

            work = []
            for ip in hosts:
                for p in self.ctx.db.get_ports_for_host(ip, self.ctx):
                    if p["port"] in (20, 21):
                        work.append((ip, p["port"]))

            if not work:
                self._mark_na_complete("FTP")
                return

            with ThreadPoolExecutor(max_workers=min(4, len(work))) as pool:
                futures = {
                    pool.submit(self._test_ftp, ip, port, out_dir): (ip, port)
                    for ip, port in work
                }
                for fut in as_completed(futures):
                    ip, port = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.ctx.logger.warn(
                            f"FTP test failed {ip}:{port}: {e}", tool="ftp")

            self._mark_complete(f"FTP testing complete — {len(work)} port(s)")
        except Exception as e:
            self.ctx.logger.error(f"FTP module failed: {e}", exc=e, tool="ftp")
            self._mark_error(str(e))

    def _test_ftp(self, ip: str, port: int, out_dir: Path) -> None:
        safe     = ip.replace(".", "_")
        out_file = out_dir / f"{safe}_{port}_nmap_ftp.txt"
        run_tool(
            ["nmap", "-p", str(port),
             "--script", "ftp-anon,ftp-bounce,ftp-syst,banner",
             "--script-timeout", "15s", ip],
            self.ctx, tool_name="nmap-ftp",
            output_file=out_file, timeout=60)

        if not out_file.exists():
            return
        content = out_file.read_text(errors="replace")

        self._observe(
            title=f"FTP Service Analysis — {ip}:{port}",
            description=f"nmap FTP script results for {ip}:{port}",
            tool="nmap", output_file=str(out_file),
            output_text=content[:1500], risk="Informational")

        if re.search(r"ftp-anon.*?Anonymous.*?FTP.*?login.*?allowed",
                     content, re.I | re.S):
            m_listing = re.search(
                r"\|_(.+?)(?=\n\||$)", content, re.S)
            listing = m_listing.group(1).strip()[:400] if m_listing else ""
            self.ctx.findings.create(
                ctx=self.ctx,
                title="FTP Anonymous Login Permitted",
                description="The FTP service accepts the anonymous username without credentials, potentially exposing hosted files or allowing unauthenticated file upload."
                    + (f"\n\nAccessible content:\n{listing}" if listing else ""),
                remediation="Disable anonymous FTP in the server configuration; migrate file transfer to SFTP/FTPS and enforce authentication for all access.",
                tool="nmap-ftp", raw_output=content[:500],
                source_type="primary", force_risk="High",
                ip=ip, port=str(port), output_file=str(out_file))

        if re.search(r"ftp-bounce.*?bounce.*?working", content, re.I):
            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"FTP Bounce Attack Possible — {ip}:{port}",
                description=(
                    f"The FTP server on {ip}:{port} allows PORT commands that "
                    f"direct connections to arbitrary hosts. This enables internal "
                    f"host probing and firewall bypass."),
                tool="nmap-ftp", raw_output=content[:300],
                source_type="primary", force_risk="Medium",
                ip=ip, port=str(port), output_file=str(out_file))

# ---------------------------------------------------------------------------
# EthernetCleanup Module
# ---------------------------------------------------------------------------

class EthernetCleanupModule(BaseModule):
    """
    Runs at the end of Ethernet assessment.  If DhcpServerModule reconfigured
    the test interface (set ctx.config['_dhcp_server_ran']), this module:
      1. Terminates dnsmasq
      2. Flushes the static IP assigned for DHCP serving
      3. Requests a fresh DHCP lease via dhclient (best-effort)
    Always marks complete — cleanup failures are logged but not fatal.
    """
    name            = "EthernetCleanup"
    description     = "Revert test interface to normal settings after assessment"
    concurrent_safe = False

    def run(self) -> None:
        self._mark_running()
        try:
            link = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_link_alive")
            if link == "no":
                self._mark_na("Port is dead — no link detected")
                return

            TEST_INTERFACE = self.ctx.config.get(
                "_dhcp_server_iface",
                self.ctx.config.get("test_interface", "eth0"))

            flag_set    = bool(self.ctx.config.get("_dhcp_server_ran"))
            iface_dirty = _interface_has_dhcp_server_ip(TEST_INTERFACE)

            if not flag_set and not iface_dirty:
                self._mark_complete("Interface was not reconfigured — nothing to revert")
                return

            if not flag_set and iface_dirty:
                self.ctx.logger.warn(
                    f"{TEST_INTERFACE} has DHCP-server address but _dhcp_server_ran "
                    f"flag was not set — reverting stale configuration from prior run",
                    tool="ip")

            self.ctx.logger.info(
                f"Reverting {TEST_INTERFACE} after DHCP server mode…",
                tool="ip")

            pid = self.ctx.config.get("_dhcp_proc_pid")
            _revert_test_iface(TEST_INTERFACE, pid=pid, logger=self.ctx.logger)

            # Clear flags
            self.ctx.config.pop("_dhcp_server_ran",   None)
            self.ctx.config.pop("_dhcp_server_iface", None)
            self.ctx.config.pop("_dhcp_proc_pid",     None)

            self._mark_complete(f"Interface {TEST_INTERFACE} reverted")

        except Exception as e:
            self.ctx.logger.error(f"EthernetCleanup failed: {e}", exc=e, tool="ip")
            self._mark_error(str(e))


class UsbPowerModule(BaseModule):
    name        = "UsbPower"
    description = "Measure USB power characteristics"

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "UsbPower"
            out_dir.mkdir(parents=True, exist_ok=True)
            self._prompt_connected_photo(
                f"USB power measurement device connected to [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"Record the voltage and current readings from the USB power meter at "
                f"[{self.ctx.instance_loc}].",
                prompt_type="text", skippable=True)
            out_file = out_dir / f"{self.ctx.file_prefix}_usb_power.txt"
            out_file.write_text(f"Voltage/Current readings: {answer}\n")
            self._mark_complete("UsbPower recorded")
        except Exception as e:
            self._mark_error(str(e))


class KeyboardModule(BaseModule):
    name        = "Keyboard"
    description = "Test USB HID Keyboard functionality"

    def run(self) -> None:
        self._mark_running()
        try:
            self._prompt_connected_photo(
                f"USB keyboard connected to [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"Test keystrokes on the USB keyboard at [{self.ctx.instance_loc}]. "
                f"Was HID keyboard detected?",
                options=["Yes — keyboard detected", "No — not detected", "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "Keyboard"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{self.ctx.file_prefix}_keyboard.txt"
            out_file.write_text(f"Result: {answer}\n")
            if "yes" in answer.lower() or answer == "1":
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"USB HID Keyboard Accepted — {self.ctx.instance_key}",
                    description=f"The device at [{self.ctx.instance_loc}] accepted a USB keyboard.",
                    tool="manual", raw_output=answer,
                    source_type="primary", force_risk="Medium",
                    ip="",
                    output_file="",
                )
            self._mark_complete(f"Keyboard: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class KeyCombosModule(BaseModule):
    name        = "KeyCombos"
    description = "Test keyboard shortcut combinations (accessibility, debug modes)"

    def run(self) -> None:
        self._mark_running()
        try:
            combos = [
                "Ctrl+Alt+Del", "Ctrl+Alt+F1/F2 (TTY)", "Ctrl+Alt+T (terminal)",
                "Win+R", "Alt+F4", "Ctrl+Shift+Esc", "F1/F2/F10/F12 (BIOS/boot)",
            ]
            response_answer = self._prompt(
                f"Test the following key combinations on [{self.ctx.instance_loc}]:\n"
                + "\n".join(f"  • {c}" for c in combos)
                + "\n  Did any combination produce a result?",
                options=["Yes — one or more produced a result",
                         "No Response — none produced a result",
                         "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "KeyCombos"
            out_dir.mkdir(parents=True, exist_ok=True)

            if "skip" in response_answer.lower() or response_answer == "3":
                (out_dir / f"{self.ctx.file_prefix}_keycombos.txt").write_text(
                    "Effective combos: skipped\n")
                self._mark_complete("KeyCombos skipped")
                return

            no_response = (
                "no response" in response_answer.lower()
                or response_answer == "2"
            )

            if no_response:
                (out_dir / f"{self.ctx.file_prefix}_keycombos.txt").write_text(
                    "Effective combos: none — no combinations produced a result\n")
                self._mark_complete("KeyCombos tested — no response")
                return

            detail = self._prompt(
                f"Which combinations produced a result at [{self.ctx.instance_loc}]?",
                prompt_type="text")
            (out_dir / f"{self.ctx.file_prefix}_keycombos.txt").write_text(
                f"Effective combos: {detail}\n")
            if detail and detail.lower() not in ("skip", "none", ""):
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"Keyboard Shortcut Access — {self.ctx.instance_key}",
                    description=f"Key combinations produced responses: {detail}",
                    tool="manual", raw_output=detail,
                    source_type="primary", force_risk="Medium",
                    ip="",
                    output_file="",
                )
            self._mark_complete(f"KeyCombos tested: {detail}")
        except Exception as e:
            self._mark_error(str(e))


class MouseModule(BaseModule):
    name        = "Mouse"
    description = "Test USB HID Mouse functionality"

    def run(self) -> None:
        self._mark_running()
        try:
            self._prompt_connected_photo(
                f"USB mouse connected to [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"With a USB mouse at [{self.ctx.instance_loc}]: "
                f"was HID mouse detected and functional?",
                options=["Yes — mouse detected", "No — not detected", "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "Mouse"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{self.ctx.file_prefix}_mouse.txt").write_text(
                f"Result: {answer}\n")
            self._mark_complete(f"Mouse: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class BashBunnyModule(BaseModule):
    name        = "BashBunny"
    description = "BashBunny HID attack test"

    def run(self) -> None:
        self._mark_running()
        try:
            self._prompt_connected_photo(
                f"Bash Bunny (or HID attack device) inserted into [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"With the HID attack device at [{self.ctx.instance_loc}]: "
                f"was it accepted / did payloads execute?",
                options=["Yes — accepted and executed", "Accepted, no execution",
                         "Not accepted / rejected", "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "BashBunny"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{self.ctx.file_prefix}_bashbunny.txt").write_text(
                f"Result: {answer}\n")
            if "executed" in answer.lower():
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"HID Attack Device Executed Payload — {self.ctx.instance_key}",
                    description=f"A Bash Bunny payload executed on [{self.ctx.instance_loc}].",
                    tool="manual", raw_output=answer,
                    source_type="primary", force_risk="Critical",
                    ip="",
                    output_file="",
                )
            self._mark_complete(f"BashBunny: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class UsbMassStorageModule(BaseModule):
    name        = "UsbMassStorage"
    description = "Test USB Mass Storage device acceptance"

    def run(self) -> None:
        self._mark_running()
        try:
            self._prompt_connected_photo(
                f"USB mass storage device connected to [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"Was the USB mass storage device at [{self.ctx.instance_loc}] "
                f"accepted by the target?",
                options=["Yes — mass storage accepted and mounted",
                         "Partially — device enumerated but not mounted",
                         "No — device blocked or rejected",
                         "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "UsbMassStorage"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{self.ctx.file_prefix}_mass_storage.txt").write_text(
                f"Result: {answer}\n")
            lo = answer.lower()
            if "accepted" in lo or answer == "1":
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"USB Mass Storage Accepted — {self.ctx.instance_key}",
                    description=(
                        f"The device at [{self.ctx.instance_loc}] accepted a USB mass "
                        f"storage device and mounted it. Unrestricted USB storage access "
                        f"may allow data exfiltration or malware delivery."
                    ),
                    tool="manual", raw_output=answer,
                    source_type="primary", force_risk="High",
                    ip="", output_file="",
                )
            elif "partially" in lo or answer == "2":
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"USB Mass Storage Partially Accepted — {self.ctx.instance_key}",
                    description=(
                        f"The device at [{self.ctx.instance_loc}] enumerated a USB mass "
                        f"storage device but did not mount it. Partial acceptance may still "
                        f"allow device fingerprinting or driver-level attacks."
                    ),
                    tool="manual", raw_output=answer,
                    source_type="primary", force_risk="Medium",
                    ip="", output_file="",
                )
            self._mark_complete(f"UsbMassStorage: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class UsbEthernetAdapterModule(BaseModule):
    name        = "UsbEthernetAdapter"
    description = "Test USB-to-Ethernet adapter — run full network assessment via adapter"

    def run(self) -> None:
        self._mark_running()
        try:
            self._prompt_connected_photo(
                f"USB-to-Ethernet adapter connected to [{self.ctx.instance_loc}]")
            # Run the full Ethernet assessment pipeline through the adapter.
            # Photo is already complete (first USB module), so it is skipped
            # automatically by _run_sequential; EthernetIface prompts the user
            # to identify which interface the adapter created (e.g. eth1, enx...).
            orchestrator = InstanceOrchestrator(self.ctx, threading.Semaphore(1))
            orchestrator._run_ethernet_modules([], _MODULE_REGISTRY)
            self._mark_complete("UsbEthernetAdapter assessment complete")
        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Ethernet-tap / Tcpdump Modules
# ---------------------------------------------------------------------------

class TcpdumpRunningModule(BaseModule):
    name        = "Tcpdump_running"
    description = "Capture traffic while device is in normal operation"

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
            answer = self._prompt(
                f"Connect the Ethernet tap inline on [{self.ctx.instance_loc}]. "
                f"Ensure the device is powered on and in normal operation. "
                f"Press Enter to begin 300-second capture.",
                options=["Ready"], prompt_type="choice")
            self._prompt_connected_photo(
                f"Ethernet tap inline on [{self.ctx.instance_loc}]")
            out_dir = self.ctx.instance_dir / "Tcpdump_running"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{self.ctx.file_prefix}_running.pcap"
            run_tool(
                ["tcpdump", "-i", TEST_INTERFACE, "-w", str(out_file),
                 "-G", "300", "-W", "1"],
                self.ctx, tool_name="tcpdump", timeout=320)
            self._observe(
                title=f"Traffic Capture — Running Operation ({self.ctx.instance_key})",
                description=f"300-second tcpdump capture of [{self.ctx.instance_loc}] "
                            f"during normal device operation.",
                tool="tcpdump",
                output_file=str(out_file),
                risk="Informational",
            )
            self._mark_complete("Tcpdump running capture done")
        except Exception as e:
            self._mark_error(str(e))


class TcpdumpBootModule(BaseModule):
    name        = "Tcpdump_boot"
    description = "Capture traffic during device boot sequence"

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
            answer = self._prompt(
                f"Connect the Ethernet tap inline on [{self.ctx.instance_loc}]. "
                f"Power OFF the device, then press Enter — immediately power ON "
                f"the device to capture boot traffic.",
                options=["Ready — starting capture"], prompt_type="choice")
            self._prompt_connected_photo(
                f"Ethernet tap inline on [{self.ctx.instance_loc}]")
            out_dir = self.ctx.instance_dir / "Tcpdump_boot"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{self.ctx.file_prefix}_boot.pcap"
            run_tool(
                ["tcpdump", "-i", TEST_INTERFACE, "-w", str(out_file),
                 "-G", "180", "-W", "1"],
                self.ctx, tool_name="tcpdump", timeout=200)
            self._observe(
                title=f"Traffic Capture — Boot Sequence ({self.ctx.instance_key})",
                description=f"180-second tcpdump capture of [{self.ctx.instance_loc}] "
                            f"during device boot sequence.",
                tool="tcpdump",
                output_file=str(out_file),
                risk="Informational",
            )
            self._mark_complete("Tcpdump boot capture done")
        except Exception as e:
            self._mark_error(str(e))


class TcpdumpShutdownModule(BaseModule):
    name        = "Tcpdump_shutdown"
    description = "Capture traffic during device shutdown sequence"

    def run(self) -> None:
        self._mark_running()
        try:
            TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
            answer = self._prompt(
                f"With the Ethernet tap inline on [{self.ctx.instance_loc}], "
                f"press Enter — then immediately initiate device shutdown.",
                options=["Ready — starting capture"], prompt_type="choice")
            out_dir = self.ctx.instance_dir / "Tcpdump_shutdown"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{self.ctx.file_prefix}_shutdown.pcap"
            run_tool(
                ["tcpdump", "-i", TEST_INTERFACE, "-w", str(out_file),
                 "-G", "120", "-W", "1"],
                self.ctx, tool_name="tcpdump", timeout=140)
            self._observe(
                title=f"Traffic Capture — Shutdown Sequence ({self.ctx.instance_key})",
                description=f"120-second tcpdump capture of [{self.ctx.instance_loc}] "
                            f"during device shutdown.",
                tool="tcpdump",
                output_file=str(out_file),
                risk="Informational",
            )
            self._mark_complete("Tcpdump shutdown capture done")
        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Video Modules
# ---------------------------------------------------------------------------

class PortTypeModule(BaseModule):
    name        = "PortType"
    description = "Identify port direction — gates downstream modules"

    def run(self) -> None:
        self._mark_running()
        try:
            iface  = self.ctx.interface
            answer = self._prompt(
                f"What is the direction of this {iface} port [{self.ctx.instance_loc}]?\n"
                f"  Input        = device receives video (acts as display/sink)\n"
                f"  Output       = device transmits video (acts as source)\n"
                f"  Bidirectional = port can act as both",
                options=["Input", "Output", "Bidirectional", "Unknown"],
                prompt_type="choice")

            port_type = answer.strip().lower().split()[0]   # "input" / "output" / "bidirectional" / "unknown"

            # Persist for downstream modules
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_hdmi_port_type", port_type)

            out_dir = self.ctx.instance_dir / "PortType"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{self.ctx.file_prefix}_port_type.txt").write_text(
                f"Interface: {iface}\nPort: {self.ctx.instance_loc}\nType: {answer}\n")

            self.ctx.logger.info(f"Port type recorded: {port_type}", tool="PortType")
            self._mark_complete(f"Port type: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class VideoInputModule(BaseModule):
    name        = "Input"
    description = "Test video input signal on this port"

    def run(self) -> None:
        self._mark_running()
        try:
            iface     = self.ctx.interface
            port_type = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_hdmi_port_type")

            out_dir = self.ctx.instance_dir / "Input"
            out_dir.mkdir(parents=True, exist_ok=True)
            result_file = out_dir / f"{self.ctx.file_prefix}_input.txt"

            if port_type == "output":
                result_file.write_text(
                    f"Port: {self.ctx.instance_loc}\nType: output-only\n"
                    f"Result: N/A — input test not applicable to output-only port\n")
                self._mark_na("Port is output-only — input test not applicable")
                self._mark_connected_photo_na("Port is output-only")
                return

            self._prompt_connected_photo(
                f"video source connected to the {iface} INPUT port [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"Was the input signal from the video source detected and accepted at "
                f"[{self.ctx.instance_loc}]?",
                options=["Yes — input accepted", "No — input rejected"],
                prompt_type="choice", skippable=True)

            accepted = answer.lower().startswith("yes")
            result_file.write_text(
                f"Interface: {iface}\nPort: {self.ctx.instance_loc}\nResult: {answer}\n")

            # Persist for downstream modules
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_hdmi_input_accepted",
                "yes" if accepted else "no")

            self.ctx.logger.info(f"Input test: {answer}", tool="manual")

            if accepted:
                self._observe(
                    title=f"{iface} Input Signal Accepted — {self.ctx.instance_key}",
                    description=(
                        f"A video source connected to [{self.ctx.instance_loc}] "
                        f"was accepted by the device. The port is functional as an input."),
                    tool="manual",
                    output_file=str(result_file),
                    risk="Informational")
            else:
                self._observe(
                    title=f"{iface} Input Signal Rejected — {self.ctx.instance_key}",
                    description=(
                        f"A video source connected to [{self.ctx.instance_loc}] "
                        f"was not accepted by the device. The port did not produce "
                        f"a detectable input signal."),
                    tool="manual",
                    output_file=str(result_file),
                    risk="Informational")

            self._mark_complete(f"Video input: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class VideoOutputModule(BaseModule):
    name        = "Output"
    description = "Test video output signal on this port"

    def run(self) -> None:
        self._mark_running()
        try:
            iface     = self.ctx.interface
            port_type = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_hdmi_port_type")

            out_dir = self.ctx.instance_dir / "Output"
            out_dir.mkdir(parents=True, exist_ok=True)
            result_file = out_dir / f"{self.ctx.file_prefix}_output.txt"

            if port_type == "input":
                result_file.write_text(
                    f"Port: {self.ctx.instance_loc}\nType: input-only\n"
                    f"Result: N/A — output test not applicable to input-only port\n")
                self._mark_na("Port is input-only — output test not applicable")
                self._mark_connected_photo_na("Port is input-only")
                return

            self._prompt_connected_photo(
                f"video display/sink connected to the {iface} OUTPUT port [{self.ctx.instance_loc}]")
            answer = self._prompt(
                f"Was an output signal detected or displayed by the sink at "
                f"[{self.ctx.instance_loc}]?",
                options=["Yes — output detected", "No — no output"],
                prompt_type="choice", skippable=True)

            detected = answer.lower().startswith("yes")
            result_file.write_text(
                f"Interface: {iface}\nPort: {self.ctx.instance_loc}\nResult: {answer}\n")

            # Persist for downstream modules
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_hdmi_output_accepted",
                "yes" if detected else "no")

            self.ctx.logger.info(f"Output test: {answer}", tool="manual")

            if detected:
                self._observe(
                    title=f"{iface} Output Signal Detected — {self.ctx.instance_key}",
                    description=(
                        f"A display connected to [{self.ctx.instance_loc}] "
                        f"received and showed a video signal. The port is functional as an output."),
                    tool="manual",
                    output_file=str(result_file),
                    risk="Informational")
            else:
                self._observe(
                    title=f"{iface} Output Signal Not Detected — {self.ctx.instance_key}",
                    description=(
                        f"A display connected to [{self.ctx.instance_loc}] "
                        f"did not receive a detectable video signal."),
                    tool="manual",
                    output_file=str(result_file),
                    risk="Informational")

            self._mark_complete(f"Video output: {answer}")
        except Exception as e:
            self._mark_error(str(e))


class EDIDModule(BaseModule):
    name        = "EDID"
    description = "Read and analyse EDID data from the connected display"

    _IFACE_DRM_MAP = {"HDMI": "HDMI", "Dvi": "DVI", "Dp": "DP"}

    def _link_present(self) -> bool:
        def _flag(key):
            return self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, key) == "yes"
        return _flag("_hdmi_input_accepted") or _flag("_hdmi_output_accepted")

    def _read_edid_sysfs(self) -> bytes:
        drm_match = self._IFACE_DRM_MAP.get(self.ctx.interface, self.ctx.interface.upper())
        drm_root  = Path("/sys/class/drm")
        if not drm_root.exists():
            return b""
        for connector in sorted(drm_root.iterdir()):
            if drm_match not in connector.name.upper():
                continue
            edid_path = connector / "edid"
            if edid_path.exists():
                try:
                    data = edid_path.read_bytes()
                    if data:
                        self.ctx.logger.info(
                            f"EDID read from sysfs: {edid_path}", tool="sysfs")
                        return data
                except Exception:
                    pass
        return b""

    def _read_edid_get_edid(self) -> bytes:
        if not _auto_install_video_tool("get-edid"):
            return b""
        try:
            r = _hw_run(["get-edid"], self.ctx, tool_name="get-edid", timeout=15, text=False)
            if r.returncode == 0 and r.stdout:
                self.ctx.logger.info("EDID read via get-edid", tool="get-edid")
                return r.stdout
        except Exception as e:
            self.ctx.logger.warn(f"get-edid failed: {e}", tool="get-edid")
        return b""

    def _decode_edid(self, edid_bytes: bytes, out_dir: Path) -> str:
        if not _auto_install_video_tool("edid-decode"):
            return ""
        bin_path = out_dir / f"{self.ctx.file_prefix}_edid.bin"
        bin_path.write_bytes(edid_bytes)
        try:
            r = _hw_run(
                ["edid-decode", str(bin_path)], self.ctx,
                tool_name="edid-decode", output_file=bin_path, timeout=15)
            return (r.stdout + r.stderr).strip()
        except Exception as e:
            self.ctx.logger.warn(f"edid-decode failed: {e}", tool="edid-decode")
            return ""

    def _parse_manufacturer(self, decoded: str) -> str:
        for line in decoded.splitlines():
            s = line.strip().lower()
            if s.startswith("manufacturer:") or "monitor name" in s:
                return line.split(":", 1)[-1].strip()
        return ""

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "EDID"
            out_dir.mkdir(parents=True, exist_ok=True)

            if not self._link_present():
                (out_dir / f"{self.ctx.file_prefix}_edid_note.txt").write_text(
                    "No link established on Input or Output — EDID not applicable.\n")
                self._mark_na("No link established — EDID not applicable")
                return

            is_mac   = sys.platform == "darwin"
            is_linux = sys.platform.startswith("linux")

            # ── macOS: system_profiler ────────────────────────────────────────
            if is_mac:
                try:
                    r = subprocess.run(
                        ["system_profiler", "SPDisplaysDataType"],
                        capture_output=True, text=True, timeout=20)
                    info = r.stdout if r.returncode == 0 else ""
                except Exception:
                    info = ""
                info_file = out_dir / f"{self.ctx.file_prefix}_display_info.txt"
                info_file.write_text(info or "(no display info returned)\n")
                self.ctx.logger.info(
                    f"macOS display info: {len(info)} chars", tool="system_profiler")
                if info.strip():
                    self._observe(
                        title=f"Display Info Retrieved — {self.ctx.instance_key}",
                        description=(
                            f"Display information retrieved from macOS IORegistry "
                            f"for [{self.ctx.instance_loc}]."),
                        tool="system_profiler",
                        output_file=str(info_file),
                        output_text=info[:600],
                        risk="Informational")
                    self._mark_complete("Display info retrieved via system_profiler")
                else:
                    self._mark_complete("No display info returned by system_profiler")
                return

            # ── Linux: sysfs → get-edid → fallback ───────────────────────────
            edid_bytes = b""
            if is_linux:
                edid_bytes = self._read_edid_sysfs()
                if not edid_bytes:
                    edid_bytes = self._read_edid_get_edid()

            if not edid_bytes:
                note = (out_dir / f"{self.ctx.file_prefix}_edid_note.txt")
                note.write_text(
                    "EDID could not be read.\n"
                    "Tried: /sys/class/drm sysfs, get-edid.\n"
                    "Ensure a display is connected and the DRM driver is loaded.\n")
                self.ctx.logger.warn("EDID not readable", tool="edid")
                self._mark_complete("EDID not readable — sysfs and get-edid both failed")
                return

            # Save raw
            hex_file = out_dir / f"{self.ctx.file_prefix}_edid_raw.hex"
            hex_file.write_text(edid_bytes.hex())
            (out_dir / f"{self.ctx.file_prefix}_edid.bin").write_bytes(edid_bytes)
            self.ctx.logger.info(f"EDID: {len(edid_bytes)} bytes", tool="edid")

            # Decode
            decoded = self._decode_edid(edid_bytes, out_dir)
            decoded_file = out_dir / f"{self.ctx.file_prefix}_edid_decoded.txt"
            if decoded:
                decoded_file.write_text(decoded)
                self.ctx.logger.info("EDID decoded", tool="edid-decode")

            manufacturer = self._parse_manufacturer(decoded) if decoded else ""
            desc = f"EDID data ({len(edid_bytes)} bytes) retrieved from [{self.ctx.instance_loc}]."
            if manufacturer:
                desc += f"\nDevice identifies as: {manufacturer}."

            self._observe(
                title=f"EDID Data Retrieved — {self.ctx.instance_key}",
                description=desc,
                tool="edid-decode" if tool_available("edid-decode") else "sysfs",
                output_file=str(decoded_file if decoded else hex_file),
                output_text=(decoded[:800] if decoded else edid_bytes.hex()[:160]),
                risk="Informational")

            # Extension blocks beyond the base 128 bytes
            if len(edid_bytes) > 128:
                ext_count = len(edid_bytes) // 128 - 1
                self.ctx.logger.info(
                    f"EDID has {ext_count} extension block(s)", tool="edid")
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"EDID Extension Blocks Present — {self.ctx.instance_key}",
                    description=(
                        f"The EDID from [{self.ctx.instance_loc}] contains "
                        f"{ext_count} extension block(s) beyond the base 128-byte structure. "
                        f"Extension blocks may carry vendor-specific or additional capability "
                        f"data. Review the decoded output for unexpected content."),
                    tool="edid-decode",
                    source_type="primary",
                    force_risk="Informational")

            self._mark_complete(
                f"EDID: {len(edid_bytes)} bytes"
                + (f" — {manufacturer}" if manufacturer else ""))

        except Exception as e:
            self._mark_error(str(e))


class HdmiDDCModule(BaseModule):
    name        = "HdmiDDC"
    description = "Test DDC/CI display control channel accessibility"

    def _link_present(self) -> bool:
        def _flag(key):
            return self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, key) == "yes"
        return _flag("_hdmi_input_accepted") or _flag("_hdmi_output_accepted")

    # Error substrings that indicate i2c-dev / bus absence rather than a
    # genuine "no display connected" result.  Matching any of these means the
    # test could not run properly — it is NOT a clean "no display" result.
    _I2C_ERROR_MARKERS = (
        "no /dev/i2c",
        "i2c-dev",
        "unable to open",
        "no i2c buses",
        "bus count is 0",
        "permission denied",
        "open failed",
        "i2c bus",
    )

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "HdmiDDC"
            out_dir.mkdir(parents=True, exist_ok=True)

            if not self._link_present():
                (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                    "No link established — DDC/CI test not applicable.\n")
                self._mark_na("No link established — DDC/CI not applicable")
                return

            # ── Ensure i2c-dev kernel module is loaded (Linux only) ───────────
            if sys.platform.startswith("linux"):
                if not _ensure_i2c_dev():
                    # Module could not be loaded — prompt user to connect device
                    answer = self._prompt(
                        f"No I2C buses (/dev/i2c-*) are visible on this system.\n"
                        f"DDC/CI communication requires the i2c-dev kernel module "
                        f"and an HDMI/DisplayPort cable connected to a live display.\n\n"
                        f"Please connect the HDMI device to [{self.ctx.instance_loc}] "
                        f"and click Continue, or Cancel to mark this test as N/A.",
                        options=["Continue — device is now connected", "Cancel — mark as N/A"],
                        prompt_type="choice")
                    if answer.lower().startswith("cancel"):
                        (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                            "Tester cancelled DDC/CI test — no I2C device available.\n")
                        self._mark_na("No I2C device available — marked N/A by tester")
                        return
                    # Retry after user connected device
                    if not _ensure_i2c_dev():
                        (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                            "DDC/CI test aborted — /dev/i2c-* still not available "
                            "after tester confirmed device connection.\n")
                        self._mark_skipped(
                            "No I2C buses available — DDC/CI test could not run")
                        return

            # ── Auto-install ddcutil ──────────────────────────────────────────
            if not _auto_install_video_tool("ddcutil"):
                (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                    "ddcutil not available and auto-install failed.\n")
                self._mark_skipped("ddcutil not available — auto-install failed")
                return

            # ── Detect displays ───────────────────────────────────────────────
            detect_file = out_dir / f"{self.ctx.file_prefix}_ddc_detect.txt"
            self.ctx.logger.info("Running ddcutil detect…", tool="ddcutil")
            rc_detect, stdout_detect, stderr_detect = run_tool(
                ["ddcutil", "detect", "--brief"],
                self.ctx, tool_name="ddcutil",
                output_file=detect_file, timeout=30)
            detect_txt = detect_file.read_text() if detect_file.exists() else stdout_detect

            self.ctx.logger.info(
                f"ddcutil detect: rc={rc_detect}, {len(detect_txt)} chars",
                tool="ddcutil")

            # Check whether the output indicates an i2c infrastructure error
            # (as opposed to a genuine "no display connected" outcome).
            combined_lower = (detect_txt + "\n" + stderr_detect).lower()
            i2c_error = any(m in combined_lower for m in self._I2C_ERROR_MARKERS)

            if i2c_error:
                # ddcutil ran but couldn't access i2c buses — prompt for device
                self.ctx.logger.warn(
                    "ddcutil detect reported an I2C bus error — prompting for device",
                    tool="ddcutil")
                answer = self._prompt(
                    f"ddcutil could not access any I2C buses on this system.\n"
                    f"This usually means no display is connected to "
                    f"[{self.ctx.instance_loc}] or the cable is not fully seated.\n\n"
                    f"Please connect the HDMI device and click Continue, "
                    f"or Cancel to mark this test as N/A.\n\n"
                    f"ddcutil output:\n{(detect_txt + stderr_detect)[:300]}",
                    options=["Continue — device is now connected", "Cancel — mark as N/A"],
                    prompt_type="choice")
                if answer.lower().startswith("cancel"):
                    (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                        "Tester cancelled DDC/CI test after I2C bus error.\n"
                        + detect_txt + stderr_detect)
                    self._mark_na("I2C bus error — marked N/A by tester")
                    return
                # Re-run detect after user connected the device
                self.ctx.logger.info("Re-running ddcutil detect after device connection…",
                                     tool="ddcutil")
                rc_detect, stdout_detect, stderr_detect = run_tool(
                    ["ddcutil", "detect", "--brief"],
                    self.ctx, tool_name="ddcutil",
                    output_file=detect_file, timeout=30)
                detect_txt = detect_file.read_text() if detect_file.exists() else stdout_detect
                combined_lower = (detect_txt + "\n" + stderr_detect).lower()
                i2c_error = any(m in combined_lower for m in self._I2C_ERROR_MARKERS)
                if i2c_error:
                    (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                        "DDC/CI test aborted — I2C bus error persisted after device "
                        "connection.\n" + detect_txt + stderr_detect)
                    self._mark_skipped(
                        "I2C bus error persisted — DDC/CI test could not run")
                    return

            # A clean "no display" result: ddcutil ran successfully but found
            # no accessible DDC/CI displays.  This is a valid completed state.
            no_display = (
                not detect_txt.strip()
                or any(s in detect_txt for s in
                       ("No display", "Invalid display", "No monitors")))

            if no_display and not i2c_error:
                (out_dir / f"{self.ctx.file_prefix}_ddc_note.txt").write_text(
                    "ddcutil detected no accessible DDC/CI displays.\n" + detect_txt)
                self._mark_complete("No DDC/CI accessible displays detected")
                return

            # ── Capabilities (non-destructive read) ───────────────────────────
            caps_file = out_dir / f"{self.ctx.file_prefix}_ddc_capabilities.txt"
            self.ctx.logger.info("Reading DDC/CI capabilities…", tool="ddcutil")
            run_tool(
                ["ddcutil", "capabilities"],
                self.ctx, tool_name="ddcutil",
                output_file=caps_file, timeout=30)

            # ── VCP feature info (non-destructive read) ───────────────────────
            vcp_file = out_dir / f"{self.ctx.file_prefix}_ddc_vcpinfo.txt"
            self.ctx.logger.info("Reading VCP feature info…", tool="ddcutil")
            run_tool(
                ["ddcutil", "vcpinfo", "--brief"],
                self.ctx, tool_name="ddcutil",
                output_file=vcp_file, timeout=30)

            caps_txt = caps_file.read_text() if caps_file.exists() else ""
            self.ctx.logger.info("DDC/CI enumeration complete", tool="ddcutil")

            self._observe(
                title=f"DDC/CI Interface Accessible — {self.ctx.instance_key}",
                description=(
                    f"The DDC/CI display control channel is accessible on "
                    f"[{self.ctx.instance_loc}]. Control parameters "
                    f"(brightness, contrast, input source, power) are enumerable "
                    f"without authentication via ddcutil."),
                tool="ddcutil",
                output_file=str(caps_file),
                output_text=detect_txt[:400],
                risk="Low")

            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"DDC/CI Display Control Channel Accessible — {self.ctx.instance_key}",
                description=(
                    f"The DDC/CI (Display Data Channel Command Interface) is accessible "
                    f"on the {self.ctx.interface} port [{self.ctx.instance_loc}]. "
                    f"DDC/CI allows unauthenticated enumeration and modification of "
                    f"display parameters including power state, input source, brightness, "
                    f"and contrast. Evaluate whether this control surface is expected "
                    f"and appropriate for the device under test."),
                tool="ddcutil",
                source_type="primary",
                force_risk="Low")

            self._mark_complete("DDC/CI accessible — capabilities and VCP info collected")

        except Exception as e:
            self._mark_error(str(e))


class HdmiHDCPModule(BaseModule):
    name        = "HdmiHDCP"
    description = "Check HDCP content protection status via sysfs / system_profiler"

    _SYSFS_DRM    = Path("/sys/class/drm")
    _IFACE_DRM_MAP = {"HDMI": "HDMI", "Dvi": "DVI", "Dp": "DP"}

    def _link_present(self) -> bool:
        def _flag(key):
            return self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, key) == "yes"
        return _flag("_hdmi_input_accepted") or _flag("_hdmi_output_accepted")

    def _read_sysfs_hdcp(self) -> list[dict]:
        drm_match = self._IFACE_DRM_MAP.get(self.ctx.interface, self.ctx.interface.upper())
        results   = []
        if not self._SYSFS_DRM.exists():
            return results
        for connector in sorted(self._SYSFS_DRM.iterdir()):
            if drm_match not in connector.name.upper():
                continue
            entry = {"connector": connector.name}
            for attr in ("content_protection", "hdcp_content_type"):
                attr_path = connector / attr
                if attr_path.exists():
                    try:
                        entry[attr] = attr_path.read_text().strip()
                    except Exception:
                        entry[attr] = "unreadable"
            if len(entry) > 1:   # has at least one HDCP attribute
                results.append(entry)
        return results

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "HdmiHDCP"
            out_dir.mkdir(parents=True, exist_ok=True)
            hdcp_file = out_dir / f"{self.ctx.file_prefix}_hdcp_status.txt"

            if not self._link_present():
                hdcp_file.write_text(
                    "No link established — HDCP check not applicable.\n")
                self._mark_na("No link established — HDCP not applicable")
                return

            is_mac   = sys.platform == "darwin"
            is_linux = sys.platform.startswith("linux")

            result_lines: list[str] = []
            protection: Optional[str] = None

            # ── Linux: DRM sysfs ──────────────────────────────────────────────
            if is_linux:
                connectors = self._read_sysfs_hdcp()
                self.ctx.logger.info(
                    f"HDCP sysfs: {len(connectors)} connector(s) found", tool="sysfs")
                for c in connectors:
                    cp  = c.get("content_protection", "N/A")
                    cpt = c.get("hdcp_content_type",  "N/A")
                    result_lines.append(
                        f"Connector: {c['connector']}\n"
                        f"  content_protection: {cp}\n"
                        f"  hdcp_content_type:  {cpt}")
                    if protection is None:
                        protection = cp

            # ── macOS: system_profiler ────────────────────────────────────────
            if is_mac:
                try:
                    r = subprocess.run(
                        ["system_profiler", "SPDisplaysDataType"],
                        capture_output=True, text=True, timeout=15)
                    for line in r.stdout.splitlines():
                        if "hdcp" in line.lower() or "content protection" in line.lower():
                            result_lines.append(line.strip())
                            self.ctx.logger.info(
                                f"macOS HDCP line: {line.strip()}", tool="system_profiler")
                except Exception as e:
                    self.ctx.logger.warn(
                        f"system_profiler failed: {e}", tool="system_profiler")

            if result_lines:
                hdcp_file.write_text("\n".join(result_lines) + "\n")
            else:
                hdcp_file.write_text(
                    "HDCP status not readable via sysfs or system_profiler.\n"
                    "The system may not expose HDCP state, or no HDCP-capable "
                    "DRM driver is loaded for this connector.\n")

            # ── Observations and findings ─────────────────────────────────────
            if not result_lines:
                self._observe(
                    title=f"HDCP Status Not Readable — {self.ctx.instance_key}",
                    description=(
                        f"HDCP content protection status could not be determined "
                        f"for [{self.ctx.instance_loc}]. The DRM driver may not "
                        f"expose HDCP state via sysfs on this system."),
                    tool="sysfs",
                    output_file=str(hdcp_file),
                    risk="Informational")
                self._mark_complete("HDCP status not readable")
                return

            self._observe(
                title=f"HDCP Status Read — {self.ctx.instance_key}",
                description=(
                    f"HDCP content protection status read for [{self.ctx.instance_loc}].\n"
                    + "\n".join(result_lines[:6])),
                tool="sysfs",
                output_file=str(hdcp_file),
                output_text="\n".join(result_lines)[:600],
                risk="Informational")

            if protection and protection.lower() == "undesired":
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"HDCP Not Enforced — {self.ctx.instance_key}",
                    description=(
                        f"HDCP content protection is set to 'Undesired' on "
                        f"[{self.ctx.instance_loc}], meaning the device is not "
                        f"requesting or enforcing HDCP encryption on this port. "
                        f"This may permit capture of protected content if the port "
                        f"is intended to carry HDCP-protected media streams."),
                    tool="sysfs",
                    source_type="primary",
                    force_risk="Low")
            elif protection and protection.lower() == "desired":
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"HDCP Negotiation Incomplete — {self.ctx.instance_key}",
                    description=(
                        f"HDCP is requested ('Desired') on [{self.ctx.instance_loc}] "
                        f"but has not been established ('Enabled'). The device is "
                        f"attempting to enforce HDCP but either the connected device "
                        f"does not support it or negotiation failed."),
                    tool="sysfs",
                    source_type="primary",
                    force_risk="Informational")
            elif protection and protection.lower() == "enabled":
                self.ctx.logger.info("HDCP active (Enabled)", tool="sysfs")

            detail = f"HDCP: {protection}" if protection else "HDCP status read"
            self._mark_complete(detail)

        except Exception as e:
            self._mark_error(str(e))


class HdmiCECModule(BaseModule):
    name        = "HdmiCEC"
    description = "Enumerate CEC bus devices and assess exposure"

    # Strings in cec-client output that indicate the adapter could not open the bus
    _FAILURE_MARKERS = [
        "no adapter found",
        "failed to open",
        "unable to open",
        "opening a connection to the cec adapter failed",
        "could not open",
        "error opening",
        "no such file",
        "permission denied",
        "cec adapter not found",
    ]

    # Strings that confirm the adapter actually reached the CEC bus
    _VALID_SCAN_MARKERS = [
        "network scanning",
        "cec bus information",
        "device #",
    ]

    def _link_present(self) -> bool:
        def _flag(key):
            return self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, key) == "yes"
        return _flag("_hdmi_input_accepted") or _flag("_hdmi_output_accepted")

    def _probe_adapter(self, out_dir: Path) -> tuple[bool, str]:
        """
        Check whether a CEC adapter is present and recognised by the system.

        Two independent checks:
          1. /dev/cec* device nodes exist (Linux kernel CEC framework).
          2. cec-client -l reports at least one adapter.

        Returns (adapter_found: bool, detail_text: str).
        Detail text is saved as evidence regardless of outcome.
        """
        import glob as _glob
        import re   as _re

        lines: list[str] = []

        # ── 1. /dev/cec* device nodes ─────────────────────────────────────
        cec_nodes: list[str] = []
        if sys.platform.startswith("linux"):
            cec_nodes = sorted(_glob.glob("/dev/cec*"))
            lines.append(f"/dev/cec* nodes: {cec_nodes or 'none'}")
            self.ctx.logger.info(
                f"CEC device nodes: {cec_nodes or 'none'}", tool="cec-client")

        # ── 2. cec-client -l ─────────────────────────────────────────────
        list_output = ""
        try:
            r = _hw_run(
                ["cec-client", "-l"], self.ctx,
                tool_name="cec-client", timeout=10)
            list_output = (r.stdout + r.stderr).strip()
            lines.append(f"\ncec-client -l output:\n{list_output}")
            self.ctx.logger.info(
                f"cec-client -l: {list_output[:200]}", tool="cec-client")
        except Exception as e:
            lines.append(f"\ncec-client -l error: {e}")
            self.ctx.logger.warn(f"cec-client -l failed: {e}", tool="cec-client")

        detail = "\n".join(lines)
        (out_dir / f"{self.ctx.file_prefix}_cec_adapter.txt").write_text(detail + "\n")

        # Adapter present if either check confirms it
        if cec_nodes:
            return True, detail

        if list_output:
            lo = list_output.lower()
            # "found devices: N" where N > 0
            m = _re.search(r"found devices:\s*(\d+)", lo)
            if m and int(m.group(1)) > 0:
                return True, detail
            # Adapter detail lines without the "found devices" header
            if any(s in lo for s in ("com port", "/dev/cec", "pulse-eight", "usb")):
                return True, detail

        return False, detail

    def _scan_is_valid(self, output: str) -> bool:
        """
        Return True only when scan output shows the adapter successfully
        opened the CEC bus.  Empty output or output containing known failure
        strings is rejected so that a missing/disconnected adapter is never
        silently treated as a valid 'no devices' result.
        """
        if not output.strip():
            return False
        lo = output.lower()
        for marker in self._FAILURE_MARKERS:
            if marker in lo:
                self.ctx.logger.warn(
                    f"CEC scan failure marker detected: {marker!r}", tool="cec-client")
                return False
        return any(m in lo for m in self._VALID_SCAN_MARKERS)

    # Seconds to wait after starting cec-client before sending any command.
    # The adapter must poll for a free logical address before it can transmit;
    # skipping this wait causes errno=64 (ENONET / adapter not configured).
    _INIT_WAIT_S = 5

    def _run_cec_session(self, commands: list[tuple[str, int]],
                         out_dir: Path) -> str:
        """
        Run cec-client as a persistent process (no -s flag), wait for the
        adapter to claim a logical address, then send each (command, pause_s)
        pair in sequence via stdin.

        Without -s, cec-client stays alive between commands so initialization
        happens exactly once.  The full session stdout is saved to
        cec_session.txt and returned.

        Why not -s (single-command mode)?
            -s dispatches the command immediately on startup, before the kernel
            CEC driver has assigned a logical address.  The ioctl then returns
            errno=64 (ENONET — adapter not configured) for every transmit.
        """
        import threading

        session_file   = out_dir / f"{self.ctx.file_prefix}_cec_session.txt"
        output_parts: list[str] = []
        proc = None

        try:
            proc = subprocess.Popen(
                ["cec-client", "-d", "1"],
                stdin  = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.STDOUT,
                bufsize = 1,
                text    = True,
            )
            if _pause:
                _pause.register(proc, "cec-client")

            def _reader() -> None:
                try:
                    for line in iter(proc.stdout.readline, ""):
                        output_parts.append(line)
                except Exception:
                    pass

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()

            self.ctx.logger.info(
                f"cec-client started (pid={proc.pid}); waiting "
                f"{self._INIT_WAIT_S}s for adapter to claim logical address…",
                tool="cec-client")
            time.sleep(self._INIT_WAIT_S)

            for cmd, pause in commands:
                self.ctx.logger.info(
                    f"CEC → {cmd!r} (allow {pause}s for response)",
                    tool="cec-client")
                try:
                    proc.stdin.write(cmd + "\n")
                    proc.stdin.flush()
                except BrokenPipeError:
                    self.ctx.logger.warn(
                        f"CEC stdin closed before '{cmd}' could be sent",
                        tool="cec-client")
                    break
                time.sleep(pause)

            # Quit cleanly so the adapter releases its logical address
            try:
                proc.stdin.write("q\n")
                proc.stdin.flush()
            except Exception:
                pass

            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.ctx.logger.warn(
                    "cec-client did not exit cleanly — killing", tool="cec-client")
                proc.kill()
            finally:
                if _pause:
                    _pause.unregister(proc.pid)

            reader.join(timeout=5)

        except Exception as e:
            self.ctx.logger.warn(f"CEC session error: {e}", tool="cec-client")
            if proc:
                if _pause:
                    _pause.unregister(proc.pid)
                try:
                    proc.kill()
                except Exception:
                    pass

        session_output = "".join(output_parts)
        session_file.write_text(session_output)
        self.ctx.logger.info(
            f"CEC session complete — {len(session_output)} chars → {session_file.name}",
            tool="cec-client")
        return session_output

    def _parse_cec_devices(self, scan_output: str) -> list[dict]:
        """Parse cec-client scan output into structured device list."""
        devices: list[dict] = []
        current: dict       = {}
        for line in scan_output.splitlines():
            line = line.strip()
            if line.startswith("device #"):
                if current:
                    devices.append(current)
                parts   = line.split(":", 1)
                current = {
                    "logical_address": parts[0].replace("device #", "").strip(),
                    "device_type":     parts[1].strip() if len(parts) > 1 else "Unknown",
                }
            elif ":" in line and current:
                key, _, val = line.partition(":")
                current[key.strip().lower().replace(" ", "_")] = val.strip()
        if current:
            devices.append(current)
        return [d for d in devices if "logical_address" in d and "device_type" in d]

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "HdmiCEC"
            out_dir.mkdir(parents=True, exist_ok=True)

            # ── Interface guard ───────────────────────────────────────────────
            # CEC is carried on HDMI, SDI (via ancillary data), and DisplayPort
            # (via DP-CEC / AUX channel).  All three are valid test targets.
            _CEC_INTERFACES = {"HDMI", "sdi", "Dp"}
            if self.ctx.interface not in _CEC_INTERFACES:
                (out_dir / f"{self.ctx.file_prefix}_cec_note.txt").write_text(
                    f"CEC is not available on {self.ctx.interface} interfaces.\n")
                self._mark_na(f"CEC not applicable to {self.ctx.interface}")
                return

            if not self._link_present():
                (out_dir / f"{self.ctx.file_prefix}_cec_note.txt").write_text(
                    "No link established on Input or Output — CEC scan not applicable.\n")
                self._mark_na("No link established — CEC not applicable")
                return

            # ── Auto-install ──────────────────────────────────────────────────
            if not _auto_install_video_tool("cec-client"):
                (out_dir / f"{self.ctx.file_prefix}_cec_note.txt").write_text(
                    "cec-client not available and auto-install failed.\n")
                self._mark_skipped("cec-client not available — auto-install failed")
                self._mark_connected_photo_na("cec-client not available")
                return

            # ── Prompt: connect the HDMI-CEC adapter ─────────────────────────
            answer = self._prompt(
                f"Connect your HDMI-CEC adapter (e.g. Pulse-Eight USB-CEC) to this "
                f"machine and to the HDMI port under test [{self.ctx.instance_loc}].\n"
                f"Ensure the adapter appears as /dev/cec0 or is otherwise recognised "
                f"by cec-client before continuing.",
                options=["Ready — adapter connected", "Skip — no CEC adapter available"],
                prompt_type="choice")

            if answer.lower().startswith("skip"):
                (out_dir / f"{self.ctx.file_prefix}_cec_note.txt").write_text(
                    "Tester skipped CEC — no HDMI-CEC adapter available.\n")
                self._mark_skipped("No HDMI-CEC adapter available — skipped by tester")
                self._mark_connected_photo_na("No HDMI-CEC adapter available")
                return

            self._prompt_connected_photo(
                f"HDMI-CEC adapter connected to [{self.ctx.instance_loc}]")

            # ── Confirm adapter is recognised ─────────────────────────────────
            self.ctx.logger.info("Probing for CEC adapter…", tool="cec-client")
            adapter_found, adapter_detail = self._probe_adapter(out_dir)

            if not adapter_found:
                self.ctx.logger.warn(
                    "No CEC adapter detected after tester confirmed connection",
                    tool="cec-client")
                retry = self._prompt(
                    f"No HDMI-CEC adapter was detected by the system "
                    f"(no /dev/cec* node and cec-client -l found no adapters).\n"
                    f"Check that the adapter is fully seated and try again, or skip.",
                    options=["Retry — adapter is now connected", "Skip — cannot resolve"],
                    prompt_type="choice")

                if retry.lower().startswith("retry"):
                    adapter_found, adapter_detail = self._probe_adapter(out_dir)

                if not adapter_found:
                    note = (
                        "CEC test aborted — HDMI-CEC adapter not recognised by system.\n"
                        "Tester confirmed connection but cec-client -l and /dev/cec* "
                        "both reported no adapter.\n\n"
                        f"Adapter probe output:\n{adapter_detail}\n")
                    (out_dir / f"{self.ctx.file_prefix}_cec_note.txt").write_text(note)
                    self.ctx.logger.warn(
                        "CEC skipped — adapter probe failed after retry", tool="cec-client")
                    self._mark_skipped(
                        "HDMI-CEC adapter not recognised by system — test inconclusive")
                    return

            self.ctx.logger.info(
                "CEC adapter confirmed — starting session", tool="cec-client")

            # ── CEC session: scan + non-destructive probes in one process ─────
            # All commands run in a single cec-client process so the adapter
            # initializes once and the logical address is live for every command.
            session_output = self._run_cec_session(
                [
                    ("scan",            12),   # full bus poll — allow 12s
                    ("get cec version",  6),   # read-only version query
                    ("pow 0",            6),   # read-only power status of LA 0
                ],
                out_dir)

            session_file = out_dir / f"{self.ctx.file_prefix}_cec_session.txt"

            # Validate that the output shows the adapter reached the bus
            if not self._scan_is_valid(session_output):
                lo      = session_output.lower()
                failure = next(
                    (m for m in self._FAILURE_MARKERS if m in lo), None)
                reason  = (
                    f"failure marker '{failure}'" if failure
                    else "no expected scan markers found in output")
                note = (
                    f"CEC session output failed validation ({reason}).\n"
                    f"The adapter was recognised by the system but cec-client "
                    f"could not communicate on the CEC bus.\n"
                    f"Possible causes: adapter not physically on the CEC bus line, "
                    f"permission issue on /dev/cec0, or target does not support CEC.\n\n"
                    f"Session output (first 500 chars):\n{session_output[:500]}\n")
                (out_dir / f"{self.ctx.file_prefix}_cec_note.txt").write_text(note)
                self.ctx.logger.warn(
                    f"CEC session invalid: {reason}", tool="cec-client")
                self._mark_complete(
                    f"CEC inconclusive — adapter present but bus communication "
                    f"failed ({reason})")
                return

            devices = self._parse_cec_devices(session_output)
            self.ctx.logger.info(
                f"CEC session valid — {len(devices)} device(s)", tool="cec-client")

            # ── Observations and findings ─────────────────────────────────────
            if not devices:
                self._observe(
                    title=f"CEC Scan Complete — No Devices Responded — {self.ctx.instance_key}",
                    description=(
                        f"CEC bus scan on [{self.ctx.instance_loc}] completed with a "
                        f"confirmed adapter on the bus, but no devices responded. "
                        f"The target port may not implement CEC."),
                    tool="cec-client",
                    output_file=str(session_file),
                    output_text=session_output[:500],
                    risk="Informational")
                self._mark_complete(
                    "CEC scan complete — adapter confirmed, no devices responded")
                return

            dev_lines = []
            for d in devices:
                line = (
                    f"  Logical #{d['logical_address']}: {d['device_type']}"
                    + (f" — OSD: {d['osd_string']}"    if d.get("osd_string")    else "")
                    + (f" — Vendor: {d['vendor']}"      if d.get("vendor")       else "")
                    + (f" — Power: {d['power_status']}" if d.get("power_status") else ""))
                dev_lines.append(line)

            self._observe(
                title=f"Enumeration: CEC Devices — {self.ctx.instance_key}",
                description=(
                    f"CEC bus scan on [{self.ctx.instance_loc}] discovered "
                    f"{len(devices)} device(s):\n" + "\n".join(dev_lines)),
                tool="cec-client",
                output_file=str(session_file),
                output_text=session_output[:800],
                risk="Informational")

            self.ctx.findings.create(
                ctx=self.ctx,
                title=f"CEC Bus Devices Discoverable Without Authentication — {self.ctx.instance_key}",
                description=(
                    f"The CEC bus on [{self.ctx.instance_loc}] exposed "
                    f"{len(devices)} device(s) to unauthenticated enumeration. "
                    f"Device types, OSD names, vendor IDs, and power states "
                    f"are readable by any device connected to the HDMI link:\n\n"
                    + "\n".join(dev_lines)),
                tool="cec-client",
                source_type="primary",
                force_risk="Informational")

            power_devices = [
                d for d in devices
                if d.get("power_status", "").lower() in ("on", "standby")]
            if power_devices:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"CEC Power State Exposed — Unauthorised Control Possible — {self.ctx.instance_key}",
                    description=(
                        f"{len(power_devices)} device(s) on [{self.ctx.instance_loc}] "
                        f"reported their power state via CEC without authentication. "
                        f"Any HDMI source connected to this port can send CEC standby "
                        f"or power-on commands to these devices:\n\n"
                        + "\n".join(
                            f"  #{d['logical_address']}: {d['device_type']} "
                            f"(power: {d.get('power_status', 'unknown')})"
                            for d in power_devices)),
                    tool="cec-client",
                    source_type="primary",
                    force_risk="Low")

            self._mark_complete(
                f"CEC: {len(devices)} device(s) — "
                + ", ".join(d["device_type"] for d in devices))

        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Zigbee Modules  (tool TBD)
# ---------------------------------------------------------------------------

class ZigbeeSniffModule(BaseModule):
    name        = "Sniff"
    description = "Capture Zigbee traffic using a compatible USB dongle"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            answer = self._prompt(
                f"Connect a Zigbee sniffer dongle. Supported: CC2531 / Sonoff ZBDongle-E "
                f"(sniffer firmware → whsniff), CatSniffer (Zigbee firmware), RZUSBSTICK / "
                f"AVR Raven or ApiMote (KillerBee). Flash the board's sniffer firmware with "
                f"Quiver first. Testing port: [{self.ctx.instance_loc}]. Press Enter to begin.",
                options=["Ready"], prompt_type="choice")
            self._prompt_connected_photo(
                f"Zigbee sniffer dongle connected for [{self.ctx.instance_loc}]")
            out_dir = self.ctx.instance_dir / "Sniff"
            out_dir.mkdir(parents=True, exist_ok=True)

            # Capture tooling, in priority order:
            #   killerbee (zbstumbler/zbdump) — ApiMote / RZUSBSTICK / Raven
            #   whsniff                        — CC2531 / Sonoff ZBDongle-E / CatSniffer
            # If none is present we emit an explicit INFO "SKIPPED" finding so the
            # operator is never misled that a test ran.
            zb_tools = {
                "zbstumbler":  ["zbstumbler", "-w", str(out_dir / f"{self.ctx.file_prefix}_zigbee_stumbler.txt")],
                "zbdump":      ["zbdump", "-w", str(out_dir / f"{self.ctx.file_prefix}_zigbee_capture.pcap")],
            }
            found_tools = [k for k in zb_tools if _shu.which(k)]
            have_whsniff = _shu.which("whsniff") is not None
            if not found_tools and not have_whsniff:
                # Honest finding — testing did not happen.
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"ZigBee testing SKIPPED — no Zigbee sniffer binary found",
                    description=(
                        "Gearbox attempted a ZigBee passive sniff but found no capture "
                        "binary on PATH: neither the killerbee suite (zbstumbler / zbdump / "
                        "zbid — for ApiMote / RZUSBSTICK / Raven) nor whsniff (for CC2531 / "
                        "Sonoff ZBDongle-E / CatSniffer). ZigBee was NOT tested. Install "
                        "killerbee (github.com/riverloopsec/killerbee) or whsniff "
                        "(github.com/homewsn/whsniff) and re-run the module."),
                    tool="zigbee-sniff", raw_output="no killerbee/whsniff binaries on PATH",
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
                self._mark_complete("ZigBee sniff SKIPPED — no sniffer tool installed")
                return

            # Attempt the killerbee discovery tools with a generous 30-minute timeout.
            for tool, argv in zb_tools.items():
                if tool not in found_tools: continue
                try:
                    res = _sp.run(argv, capture_output=True, text=True,
                                    timeout=1800)
                    out_p = out_dir / f"{self.ctx.file_prefix}_{tool}.txt"
                    out_p.write_text(
                        f"$ {' '.join(argv)}\n\n"
                        f"── stdout ──\n{res.stdout}\n\n"
                        f"── stderr ──\n{res.stderr}\n", encoding="utf-8")
                except _sp.TimeoutExpired:
                    out_p = out_dir / f"{self.ctx.file_prefix}_{tool}.txt"
                    out_p.write_text(f"$ {' '.join(argv)}\n[TIMEOUT after 1800s]\n",
                                      encoding="utf-8")
                except Exception as exc:
                    out_p = out_dir / f"{self.ctx.file_prefix}_{tool}.txt"
                    out_p.write_text(f"$ {' '.join(argv)}\n[ERROR: {exc}]\n",
                                      encoding="utf-8")

            # whsniff (CC2531 / Sonoff / CatSniffer): capture the common Zigbee
            # channels to pcap. whsniff streams a pcap on stdout until terminated,
            # so each channel is bounded by a timeout.
            used = list(found_tools)
            if have_whsniff:
                for ch in (11, 15, 20, 25):
                    pcap = out_dir / f"{self.ctx.file_prefix}_whsniff_ch{ch}.pcap"
                    try:
                        with open(pcap, "wb") as fh:
                            _sp.run(["whsniff", "-c", str(ch)], stdout=fh,
                                    stderr=_sp.DEVNULL, timeout=60)
                    except _sp.TimeoutExpired:
                        pass  # expected — whsniff runs until killed
                    except Exception:
                        pass
                used.append("whsniff")
            self._mark_complete(f"ZigBee sniff via {','.join(used) or 'no capture'}")
        except Exception as e:
            self._mark_error(str(e))


class ZigbeeFloodModule(BaseModule):
    name        = "Flood"
    description = "Test Zigbee network resilience against flooding attacks"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            # G1 fix (2026-06-11 review): attempt zbassocflood /
            # zbpanidconflictflood if killerbee is installed; otherwise emit
            # an explicit "SKIPPED" finding instead of silently writing a
            # placeholder note as if the test ran.
            flood_tools = ["zbassocflood", "zbpanidconflictflood"]
            found = [t for t in flood_tools if _shu.which(t)]
            ans = self._prompt(
                f"Perform a Zigbee flood test against [{self.ctx.instance_loc}]. "
                + ("Tools detected: " + ", ".join(found) + ". " if found else
                   "No killerbee flood binaries detected — manual observation only. ")
                + f"Did the device respond abnormally?",
                options=["Yes — abnormal response / crash", "No — unaffected", "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "Flood"
            out_dir.mkdir(parents=True, exist_ok=True)
            if not found:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"ZigBee flood testing SKIPPED — no killerbee binary found",
                    description=("Gearbox could not run an active ZigBee flood test "
                                  "because no killerbee flood binary "
                                  "(zbassocflood / zbpanidconflictflood) is on PATH. "
                                  "Operator observation recorded: " + ans),
                    tool="killerbee", raw_output=ans,
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
            else:
                for tool in found:
                    out_p = out_dir / f"{self.ctx.file_prefix}_{tool}.txt"
                    try:
                        res = _sp.run([tool], capture_output=True, text=True,
                                        timeout=900)
                        out_p.write_text(f"$ {tool}\n\n── stdout ──\n{res.stdout}\n\n"
                                          f"── stderr ──\n{res.stderr}\n", encoding="utf-8")
                    except _sp.TimeoutExpired:
                        out_p.write_text(f"$ {tool}\n[TIMEOUT after 900s]\n", encoding="utf-8")
                    except Exception as exc:
                        out_p.write_text(f"$ {tool}\n[ERROR: {exc}]\n", encoding="utf-8")
            if "abnormal" in ans.lower() or "crash" in ans.lower():
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"Zigbee Device Susceptible to Flooding on {self.ctx.instance_key}",
                    description=(
                        f"The Zigbee device at {self.ctx.instance_loc} responded "
                        f"abnormally to a flood of Zigbee packets, indicating "
                        f"potential DoS vulnerability."
                    ),
                    tool="zigbee_flood", raw_output=ans,
                    source_type="primary", force_risk="High",
                    force_classification="Validated",
                    ip="",
                    output_file="",
                )
            self._mark_complete("Zigbee flood recorded")
        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Bluetooth / BLE Module  (zero-knowledge BR/EDR + LE assessment)
# ---------------------------------------------------------------------------
# One module, seven phases: hardware setup -> discovery -> enumeration ->
# pairing/SMP security -> passive sniff + crack -> active exploitation ->
# cleanup.  Detection is ORACLE-DRIVEN, not target-specific: the SMP AuthReq
# byte (SC / MITM / key-size bits), the ATT error opcodes (0x05/0x0F/0x08/0x0C)
# and the advertising address type / AD structures are all cleartext-observable,
# so the module rules out each pairing / GATT / privacy / CVE-family weakness
# generically without any prior knowledge of the device under test.

# BLE SIG Company Identifiers (subset) — used to fingerprint the SoC vendor from
# advertising Manufacturer-Specific Data and flag the matching CVE family.
_BT_COMPANY_IDS: dict[int, str] = {
    0x0000: "Ericsson", 0x0002: "Intel", 0x000A: "Cambridge Silicon Radio (CSR/Qualcomm)",
    0x000F: "Broadcom", 0x004C: "Apple", 0x0059: "Nordic Semiconductor",
    0x0075: "Samsung", 0x0087: "Garmin", 0x00E0: "Google",
    0x0107: "Espressif (ESP32)", 0x0134: "Telink Semiconductor",
    0x0157: "Anhui Huami", 0x0499: "Ruuvi", 0x02E5: "Espressif (ESP32)",
    0x0501: "Dialog Semiconductor", 0x030A: "STMicroelectronics",
    0x0018: "Texas Instruments", 0x01A9: "NXP", 0x0362: "Microchip",
}

# Chip-vendor -> memory-corruption CVE family it is historically exposed to
# (fingerprint-driven surface flag; confirmed only against SoC + SDK/firmware
# version, which the operator supplies).
_BT_VENDOR_CVE_FAMILY: dict[str, dict] = {
    "telink":     {"family": "SweynTooth", "note": "Telink BLE SoCs — incl. Zero-LTK Installation (CVE-2019-19194, security bypass)."},
    "espressif":  {"family": "BrakTooth", "note": "Espressif ESP32 BR/EDR — incl. Feature-Pages arbitrary code execution (CVE-2021-28139)."},
    "cypress":    {"family": "SweynTooth/BrakTooth", "note": "Cypress PSoC — Link-Layer Length Overflow (CVE-2019-16336) and BrakTooth slot overflows."},
    "nxp":        {"family": "SweynTooth", "note": "NXP KW41Z — Link-Layer Length Overflow (CVE-2019-17519)."},
    "dialog":     {"family": "SweynTooth", "note": "Dialog DA145xx/DA146xx — Truncated L2CAP / Silent Length Overflow (CVE-2019-17517/17518)."},
    "texas instruments": {"family": "SweynTooth/BrakTooth", "note": "TI CC2640R2/CC2540/CC2564C — Public-Key crash / AU-Rand flooding (CVE-2019-17520/19193)."},
    "stmicro":    {"family": "SweynTooth", "note": "STMicro BlueNRG-2/WB55 — Sequential ATT Deadlock (CVE-2019-19192)."},
    "microchip":  {"family": "SweynTooth", "note": "Microchip ATSAMB11 — Invalid L2CAP Fragment (CVE-2019-19195)."},
    "qualcomm":   {"family": "BrakTooth", "note": "Qualcomm CSR8811/8510 — LMP 2-DH1 overflow (CVE-2021-35093); some parts 'no fix planned'."},
    "cambridge silicon radio": {"family": "BrakTooth", "note": "CSR/Qualcomm — BrakTooth LMP overflows."},
    "broadcom":   {"family": "BleedingTooth/InternalBlue", "note": "Broadcom/Cypress controllers — EIR heap overflow (CVE-2019-11516); InternalBlue-class exposure."},
    "intel":      {"family": "BrakTooth", "note": "Intel AX200 — Invalid Timing Accuracy / Paging-Scan deadlock (CVE-2021-33139/33155)."},
}

# Hardware options offered at Phase 0.  quiver = the exact Quiver firmware-flash
# payload that provisions the board (see /opt/pr0t31n/Quiver).
_BT_HARDWARE: list[dict] = [
    {"key": "adapter", "sniffer": False, "crackle_ready": False,
     "label": "Built-in / USB BlueZ adapter (CSR / Intel / Realtek)",
     "quiver": None,
     "setup": ["No firmware flash needed. Plug in and `sudo hciconfig hci0 up`.",
               "Active GATT client + pairing negotiation ONLY — a normal HCI",
               "controller sees only its own traffic; it is NOT a promiscuous",
               "over-the-air sniffer, so it cannot passively capture a pairing",
               "for crackle. Pair it with a sniffer board (options 2-5) for the",
               "passive-crack and LESC-confirmation phases."]},
    {"key": "sniffle", "sniffer": True, "crackle_ready": True,
     "label": "TI CC1352P-4 / CC26x2R1 / Sonoff CC2652P — NCC Sniffle",
     "quiver": "FIRMWARE - Flash Sniffle firmware",
     "setup": ["Flash with Quiver payload: 'FIRMWARE - Flash Sniffle firmware'",
               "  (targets cc1352p4 / cc26x2r1; Sonoff via cc2538-bsl).",
               "Capture: sniff_receiver.py -s /dev/ttyACM0 -m <MAC> -o pairing.pcap",
               "  (omit -a so it FOLLOWS the target into the connection).",
               "Output linktype LE_LL_WITH_PHDR (256) → directly crackle-readable.",
               "TOP PICK for the capture→crackle / LESC-confirmation path."]},
    {"key": "nrfsniffer", "sniffer": True, "crackle_ready": False,
     "label": "Nordic nRF52840 / nRF52833 — nRF Sniffer for Wireshark",
     "quiver": "FIRMWARE - Flash nRF Sniffer firmware",
     "setup": ["Flash with Quiver payload: 'FIRMWARE - Flash nRF Sniffer firmware'",
               "  (targets nordic_nrf52840 / nrf52833_dk).",
               "Capture via the Wireshark nRF Sniffer extcap (GUI, follow device).",
               "Output linktype NORDIC_BLE (272) → NOT directly crackle-readable;",
               "convert with bsniffhub before cracking. Best Wireshark UX."]},
    {"key": "butterfly", "sniffer": True, "crackle_ready": True,
     "label": "Nordic nRF52840 — WHAD / ButteRFly (sniff + inject/MITM)",
     "quiver": "FIRMWARE - Flash ButteRFly (BLE MITM)",
     "setup": ["Flash with Quiver payload: 'FIRMWARE - Flash ButteRFly (BLE MITM)'",
               "  (targets nordic_nrf52840).",
               "Sniff: wsniff -i uart0 -o ble.pcap ble --follow-connection",
               "  → LE_LL_WITH_PHDR (256), crackle-ready.",
               "Also drives active link-layer MITM/injection via WHAD",
               "  (wble-central / wble-periph / wble-proxy)."]},
    {"key": "ubertooth", "sniffer": True, "crackle_ready": True,
     "label": "Ubertooth One — ubertooth-btle",
     "quiver": "FIRMWARE - Firmware Update (ubertooth-dfu)",
     "setup": ["Flash/update with Quiver payload: 'FIRMWARE - Firmware Update",
               "  (ubertooth-dfu)' (match host tools to firmware version).",
               "Capture: ubertooth-btle -f -t <MAC> -q crack.pcap",
               "  (-q = LL_WITH_PHDR 256, -c = PPI 192 — both crackle-native)."]},
    {"key": "microbit", "sniffer": True, "crackle_ready": True,
     "label": "BBC micro:bit ×1-3 — btlejack (follow / jam / hijack)",
     "quiver": None,
     "setup": ["Flash: btlejack -i  (writes firmware to every mounted micro:bit).",
               "Capture/follow: btlejack -f <access-addr> -x ll_phdr -o cap.pcap.",
               "Hijack an ESTABLISHED connection: btlejack -f <aa> -t -m 0x1fffffffff.",
               "micro:bit v2 / nRF52833 needs the separate btlejack-firmware-nrf52 build."]},
    {"key": "esp32", "sniffer": False, "crackle_ready": False,
     "label": "ESP32 (ESP-WROVER-KIT) — BrakTooth BR/EDR fuzzing",
     "quiver": None,
     "setup": ["Flash: python3 firmware.py flash /dev/ttyUSB1  (esptool).",
               "Fuzz/exploit BR/EDR: bin/bt_exploiter --host-port=/dev/ttyUSB1",
               "  --target=<MAC> --exploit=au_rand_flooding  (list: bt_fuzzer",
               "  --list-exploits). CLASSIC Bluetooth only — not a BLE sniffer."]},
    {"key": "catsniffer", "sniffer": True, "crackle_ready": True,
     "label": "CatSniffer v3 (CC1352P7) — Sniffle over the SAMD21 bridge",
     "quiver": "FIRMWARE - Flash Sniffle firmware",
     "setup": ["Flash with Quiver payload: 'FIRMWARE - Flash Sniffle firmware'",
               "  (targets catsniffer; CC1352P7 via the SAMD21 serial bootloader).",
               "Capture: sniff_receiver.py -s /dev/ttyACM0 -m <MAC> -o pairing.pcap",
               "  (same Sniffle host CLI as the TI LaunchXL boards).",
               "Output linktype LE_LL_WITH_PHDR (256) → crackle-readable. One board",
               "  also covers Zigbee + sub-GHz sniffing (swap firmware via Quiver)."]},
    {"key": "hackrf", "sniffer": True, "crackle_ready": False,
     "label": "HackRF One (+ PortaPack) — SDR BLE advertising sweep",
     "quiver": "FIRMWARE - Firmware Update (hackrf)",
     "setup": ["SDR capture of the 3 BLE advertising channels (37/38/39).",
               "Not a connection-follower: best for adv/discovery + spectrum, not",
               "  full LESC pairing capture (use a Sniffle board for that).",
               "Tooling: gr-bluetooth / ble sniffer flowgraphs; ubertooth-btle-style",
               "  decode. Wideband — pair with a Sniffle board for the crack phase."]},
]


def _bt_which(name: str) -> Optional[str]:
    """Locate a BT tool binary (PATH + common install dirs, incl. Sniffle CLI)."""
    p = shutil.which(name)
    if p:
        return p
    for cand in (f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}"):
        if os.path.exists(cand):
            return cand
    if name == "sniff_receiver.py":
        for cand in ("/opt/Sniffle/python_cli/sniff_receiver.py",
                     str(Path.home() / "Sniffle/python_cli/sniff_receiver.py")):
            if os.path.exists(cand):
                return cand
    if name == "crackle":
        for cand in ("/opt/crackle/crackle", "/usr/local/bin/crackle"):
            if os.path.exists(cand):
                return cand
    return None


def _bt_classify_address(mac: str, addr_type: str) -> tuple[str, bool, str]:
    """
    Classify a Bluetooth address for privacy.  Returns
    (classification, trackable, detail).

    Public (addr_type 'public') → permanent, trackable + OUI vendor leak.
    Random: top two bits of the most-significant octet decide the sub-type:
        0b11 Static Random     (fixed until reboot; often product-lifetime)
        0b10 Resolvable RPA    (privacy-correct IF it rotates)
        0b00 Non-Resolvable    (random, not resolvable)
    """
    at = (addr_type or "").strip().lower()
    if at in ("public", "0x00", "00", "le_public", "br/edr"):
        return ("Public", True,
                "Permanent factory MAC — trackable across time and location; leaks OUI/vendor.")
    # Random — inspect the MSB (first octet).
    try:
        msb = int(mac.split(":")[0], 16)
    except Exception:
        return ("Random (unknown sub-type)", True, "Random address; sub-type undetermined.")
    top2 = (msb >> 6) & 0b11
    if top2 == 0b11:
        return ("Static Random", True,
                "Static random address — fixed until device reboot; frequently stable for the "
                "product lifetime, so trackable in practice.")
    if top2 == 0b10:
        return ("Resolvable Private Address (RPA)", False,
                "RPA — privacy-correct provided it actually rotates (confirm with the rotation test).")
    return ("Non-Resolvable Random", False, "Non-resolvable random address.")


def _bt_parse_authreq(byte_val: int) -> dict:
    """Decode the SMP AuthReq byte (the pairing security-triage byte)."""
    return {
        "bonding":  (byte_val & 0b11) == 0b01,
        "mitm":     bool(byte_val & 0b100),      # bit 2
        "sc":       bool(byte_val & 0b1000),     # bit 3  (LE Secure Connections)
        "keypress": bool(byte_val & 0b10000),    # bit 4
        "ct2":      bool(byte_val & 0b100000),   # bit 5
    }


_BT_IO_CAP = {
    "0x00": "DisplayOnly", "0x01": "DisplayYesNo", "0x02": "KeyboardOnly",
    "0x03": "NoInputNoOutput", "0x04": "KeyboardDisplay",
    "displayonly": "DisplayOnly", "displayyesno": "DisplayYesNo",
    "keyboardonly": "KeyboardOnly", "noinputnooutput": "NoInputNoOutput",
    "keyboarddisplay": "KeyboardDisplay",
}


def _bt_parse_btmon_smp(text: str) -> dict:
    """
    Best-effort parse of decoded btmon output for SMP Pairing Request/Response
    security parameters.  Returns whatever it could recover:
        {sc, mitm, bonding, io_capability, max_key_size, legacy, saw_smp,
         saw_public_key, saw_confirm}
    LESC vs Legacy is inferred from the AuthReq SC bit AND the on-wire opcodes
    (Public Key 0x0c / DHKey Check 0x0d ⇒ LESC; Confirm 0x03 / Random 0x04 ⇒ Legacy).
    """
    res: dict = {"saw_smp": False}
    low = text.lower()
    if "smp" in low or "pairing request" in low or "pairing response" in low or "authreq" in low:
        res["saw_smp"] = True

    # Most reliable: btmon prints the raw AuthReq byte in parentheses, e.g.
    #   "Authentication requirement: Bonding, No MITM, No SC (0x01)"
    # Decode that byte directly rather than matching ambiguous "No MITM"/"MITM" text.
    m = re.search(r"authentication requirement:[^\n(]*\((0x[0-9a-f]+)\)", low)
    if m:
        bits = _bt_parse_authreq(int(m.group(1), 16))
        res["sc"], res["mitm"], res["bonding"] = bits["sc"], bits["mitm"], bits["bonding"]
    else:
        # Textual fallbacks — anchor on the negated forms first so "No MITM"/"No SC"
        # are never misread as the positive flag.
        m = re.search(r"secure connections:\s*(\w+)", low)   # some exporters use this form
        if m:
            res["sc"] = m.group(1) in ("true", "yes", "1", "enabled")
        elif re.search(r"\bno sc\b|no secure connections", low):
            res["sc"] = False
        elif re.search(r"\bsc\b|secure connections", low):
            res["sc"] = True
        m = re.search(r"\bmitm:\s*(\w+)", low)
        if m:
            res["mitm"] = m.group(1) in ("true", "yes", "1", "enabled")
        elif re.search(r"no mitm", low):
            res["mitm"] = False
        elif re.search(r"\bmitm\b", low):
            res["mitm"] = True

    m = re.search(r"max encryption key size:\s*(\d+)", low) or re.search(r"key size:\s*(\d+)", low)
    if m:
        res["max_key_size"] = int(m.group(1))
    m = re.search(r"io capability:\s*([a-z ]+?)\s*(?:\(0x|$|\n)", low)
    if m:
        res["io_capability"] = _BT_IO_CAP.get(m.group(1).strip(), m.group(1).strip().title())
    # On-wire LESC / Legacy tells (override AuthReq if the actual PDUs are seen).
    if "public key" in low or "dhkey check" in low:
        res["saw_public_key"] = True
        res["sc"] = True
    if "pairing confirm" in low or "pairing random" in low:
        res["saw_confirm"] = True
    if "sc" in res:
        res["legacy"] = not res["sc"]
    return res


def _bt_scan_btmgmt(ctx, out_dir: Path, secs: int) -> list[dict]:
    """Run `btmgmt find` and parse dev_found lines into device dicts."""
    devices: dict[str, dict] = {}
    out_file = out_dir / f"{ctx.file_prefix}_btmgmt_find.txt"
    try:
        rc, out, err = run_tool(["btmgmt", "find"], ctx, tool_name="btmgmt",
                                output_file=out_file, timeout=max(20, secs + 10))
    except Exception:
        return []
    for line in (out or "").splitlines():
        m = re.search(r"dev_found:\s*([0-9A-Fa-f:]{17})\s+type\s+(\S+)", line)
        if not m:
            continue
        mac = m.group(1).upper()
        d = devices.setdefault(mac, {"mac": mac, "addr_type": m.group(2),
                                     "name": "", "rssi": "", "uuids": [],
                                     "company_ids": [], "raw": []})
        rssi = re.search(r"rssi\s+(-?\d+)", line)
        if rssi:
            d["rssi"] = rssi.group(1)
        d["raw"].append(line.strip())
    # A second pass reads names from `btmgmt` name events if present.
    for line in (out or "").splitlines():
        m = re.search(r"([0-9A-Fa-f:]{17}).*name\s+(.+)$", line)
        if m and m.group(1).upper() in devices:
            devices[m.group(1).upper()]["name"] = m.group(2).strip()
    return list(devices.values())


def _bt_scan_bluetoothctl(ctx, out_dir: Path, secs: int) -> list[dict]:
    """Fallback discovery via a fed-stdin bluetoothctl session + `devices`."""
    out_file = out_dir / f"{ctx.file_prefix}_bluetoothctl_scan.txt"
    try:
        # `timeout` bounds the scan; then dump the device list.
        proc = subprocess.run(
            ["bash", "-c",
             f"(echo 'power on'; echo 'scan on'; sleep {max(8, secs)}; "
             f"echo 'devices'; echo 'scan off'; echo 'quit') | bluetoothctl"],
            capture_output=True, text=True, timeout=max(20, secs + 15))
        out = proc.stdout or ""
    except Exception:
        return []
    try:
        out_file.write_text(out, encoding="utf-8")
    except Exception:
        pass
    devices: dict[str, dict] = {}
    for line in out.splitlines():
        m = re.search(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)$", line)
        if not m:
            continue
        mac = m.group(1).upper()
        name = m.group(2).strip()
        d = devices.setdefault(mac, {"mac": mac, "addr_type": "", "name": "",
                                     "rssi": "", "uuids": [], "company_ids": [],
                                     "raw": []})
        if name and not name.startswith(mac):
            d["name"] = name
    return list(devices.values())


def _bt_parse_gatt_chars(raw: str) -> list[dict]:
    """
    Parse `gatttool --characteristics` output into a list of characteristics.
    gatttool prints e.g.:
      handle = 0x0002, char properties = 0x20, char value handle = 0x0003, uuid = ...
    Tolerates both '=' and ':' separators. Properties bitfield:
      0x02 Read · 0x04 WriteWithoutResp · 0x08 Write · 0x10 Notify · 0x20 Indicate
      0x40 Authenticated Signed Writes.
    """
    chars: list[dict] = []
    for line in (raw or "").splitlines():
        h = re.search(r"char value handle\s*[=:]\s*(0x[0-9a-fA-F]+)", line, re.I)
        if not h:
            continue
        p = re.search(r"char properties\s*[=:]\s*(0x[0-9a-fA-F]+)", line, re.I)
        u = re.search(r"uuid\s*[=:]\s*([0-9a-fA-F-]+)", line, re.I)
        props = int(p.group(1), 16) if p else 0
        chars.append({
            "handle":  h.group(1),
            "props":   props,
            "uuid":    (u.group(1) if u else ""),
            "readable": bool(props & 0x02),
            "writable": bool(props & (0x04 | 0x08 | 0x40)),
            "notify":   bool(props & (0x10 | 0x20)),
        })
    return chars


# ---------------------------------------------------------------------------

def _bt_tshark() -> Optional[str]:
    """Locate a tshark binary (PATH or the macOS Wireshark app bundle)."""
    for c in ("tshark", "/usr/bin/tshark", "/usr/local/bin/tshark",
              "/opt/homebrew/bin/tshark",
              "/Applications/Wireshark.app/Contents/MacOS/tshark"):
        p = shutil.which(c) if "/" not in c else (c if os.path.exists(c) else None)
        if p:
            return p
    return None


def _bt_aes_cmac(key: bytes, msg: bytes) -> Optional[bytes]:
    try:
        from cryptography.hazmat.primitives import cmac as _cm
        from cryptography.hazmat.primitives.ciphers import algorithms as _al
    except Exception:
        return None
    c = _cm.CMAC(_al.AES(key)); c.update(msg); return c.finalize()


def _bt_f4(u_hex: str, v_hex: str, x_hex: str, z: int, cfg) -> Optional[bytes]:
    """SMP f4(U,V,X,Z)=AES-CMAC_X(U||V||Z) with wire↔spec byte order / U-V order per cfg."""
    rev_pk, rev_nonce, rev_out, swap = cfg
    try:
        u = bytes.fromhex(u_hex); v = bytes.fromhex(v_hex); x = bytes.fromhex(x_hex)
    except Exception:
        return None
    if rev_pk:   u, v = u[::-1], v[::-1]
    if rev_nonce: x = x[::-1]
    if swap:     u, v = v, u
    out = _bt_aes_cmac(x, u + v + bytes([z]))
    if out is None:
        return None
    return out[::-1] if rev_out else out


def _bt_extract_smp_pairing(pcap: str, ctx) -> Optional[dict]:
    """tshark-extract the LESC Passkey-Entry material from a BLE pcap. Returns
    {pka,pkb,ic,ir,rc,rr} (initiator/responder confirms+randoms) or None when the
    capture lacks a public-key exchange (i.e. not LESC / no pairing on the air)."""
    tsh = _bt_tshark()
    if not tsh or not os.path.exists(pcap):
        return None
    cmd = [tsh, "-r", pcap, "-Y", "btsmp", "-T", "fields",
           "-e", "btle_rf.pdu_type", "-e", "btsmp.opcode", "-e", "btsmp.cfm_value",
           "-e", "btsmp.random_value", "-e", "btsmp.public_key_x"]
    try:
        rc, out, err = run_tool(cmd, ctx, tool_name="tshark", timeout=120)
    except Exception:
        return None
    rows = [l.split("\t") for l in (out or "").splitlines() if l.strip()]
    if not rows:
        return None
    dir_init = None
    for r in rows:                       # initiator = sender of Pairing Request (0x01)
        if len(r) >= 2 and r[1] == "0x01" and r[0]:
            dir_init = r[0]; break
    if dir_init is None:                 # fallback: sender of the first Public Key
        for r in rows:
            if len(r) >= 2 and r[1] == "0x0c" and r[0]:
                dir_init = r[0]; break
    if dir_init is None:
        return None
    _cl = lambda h: h.replace(":", "").strip().lower()
    pk = {}; conf = {"i": [], "r": []}; rnd = {"i": [], "r": []}
    for r in rows:
        while len(r) < 5:
            r.append("")
        d, op, cf, rn, pkx = r[0], r[1], r[2], r[3], r[4]
        if not op or not d:
            continue
        side = "i" if d == dir_init else "r"
        if op == "0x0c" and pkx:  pk[side] = _cl(pkx)
        elif op == "0x03" and cf: conf[side].append(_cl(cf))
        elif op == "0x04" and rn: rnd[side].append(_cl(rn))
    dd = lambda x: list(dict.fromkeys(x))    # drop link-layer retransmits, keep order
    if "i" not in pk or "r" not in pk:
        return None
    return {"pka": pk["i"], "pkb": pk["r"],
            "ic": dd(conf["i"]), "ir": dd(rnd["i"]),
            "rc": dd(conf["r"]), "rr": dd(rnd["r"])}


def _bt_recover_passkey(smp: dict) -> Optional[dict]:
    """Passive f4-brute recovery of a LESC Passkey-Entry PIN. Recovers the bit
    sequence independently from each side and cross-checks. Returns
    {pin, bits, two_sided, rounds, partial} or None."""
    from itertools import product as _prod

    def _side(confirms, randoms, u, v):
        if len(confirms) < 3 or len(randoms) < 3:
            return None
        best = (None, -1)
        for cfg in _prod((0, 1), (0, 1), (0, 1), (0, 1)):
            matched = 0
            for c in confirms:
                hit = False
                for n in randoms:
                    for z in (0, 1, 0x80, 0x81):
                        r = _bt_f4(u, v, n, z, cfg)
                        if r is not None and r.hex() == c:
                            hit = True; break
                    if hit:
                        break
                matched += hit
            if matched > best[1]:
                best = (cfg, matched)
        cfg, cnt = best
        if cfg is None or cnt < max(10, len(confirms) // 2):
            return None
        bits = []
        for c in confirms:
            got = None
            for n in randoms:
                for z in (0, 1, 0x80, 0x81):
                    r = _bt_f4(u, v, n, z, cfg)
                    if r is not None and r.hex() == c:
                        got = z & 1; break
                if got is not None:
                    break
            if got is not None:
                bits.append(got)
        return bits

    ib = _side(smp["ic"], smp["ir"], smp["pka"], smp["pkb"])
    rb = _side(smp["rc"], smp["rr"], smp["pkb"], smp["pka"])
    if not ib and not rb:
        return None
    use_i = bool(ib) and (not rb or len(ib) >= len(rb))
    cand = ib if use_i else rb
    two = None
    if ib and rb:
        s = "".join(map(str, cand))
        o = "".join(map(str, rb if use_i else ib))
        two = bool(o) and o in s
    if len(cand) < 20:
        return {"pin": None, "bits": cand, "two_sided": two,
                "rounds": len(cand), "partial": True}
    b = cand[:20]
    lsb = sum(v << i for i, v in enumerate(b))
    msb = sum(v << (19 - i) for i, v in enumerate(b))
    pin = lsb if lsb <= 999999 else (msb if msb <= 999999 else None)
    if pin is None:
        return None
    return {"pin": pin, "bits": b, "two_sided": two, "rounds": 20, "partial": False}


# Known-CVE Bluetooth attacks that need specialised tooling (InternalBlue / PoC
# suites / a second radio). Phase 5c presents each with its detection oracle and
# records the finding when the operator confirms the vulnerable condition — so
# every catalogued Bluetooth test can produce its finding honestly.
_BT_KNOWN_ATTACKS = [
    {"const": "T_KNOB", "label": "KNOB (CVE-2019-9506)", "risk": "High", "validated": True,
     "question": "Observe the negotiated BR/EDR encryption key entropy (InternalBlue reads the "
                 "LMP key-size negotiation, or HCI Read Encryption Key Size 0x1408). Did the link "
                 "accept fewer than 16 octets (BR/EDR down to 1)?",
     "options": ["Yes — <16 octets accepted", "No — enforces 16", "Not tested"],
     "vuln": "Yes — <16 octets accepted",
     "desc": "{mac} accepted a downgraded BR/EDR encryption key entropy (<16 octets, KNOB "
             "CVE-2019-9506). The key-size negotiation is not integrity-protected, so an in-range "
             "MITM forces a low-entropy key and brute-forces the session with no pairing.",
     "rem": "Patch the host to enforce a minimum encryption key size (≥7 octets BR/EDR, 16 for "
            "LESC) and abort shorter negotiations."},
    {"const": "T_BIAS", "label": "BIAS (CVE-2020-10135)", "risk": "High", "validated": True,
     "question": "Using a spoofed BD_ADDR of a previously-bonded peer (no link key), did the device "
                 "complete authentication as that peer — accepting a role switch or SC→legacy "
                 "downgrade without proving the link key?",
     "options": ["Yes — impersonation succeeded", "No — mutual auth enforced", "Not tested"],
     "vuln": "Yes — impersonation succeeded",
     "desc": "{mac} authenticated a spoofed previously-bonded peer without the link key (BIAS "
             "CVE-2020-10135) — it does not mandate mutual authentication / allows SC→legacy "
             "downgrade, so an attacker in range impersonates a trusted device.",
     "rem": "Enable Secure Connections Only mode and require mutual authentication in both "
            "directions."},
    {"const": "T_BLUR", "label": "BLURtooth (CVE-2020-15802)", "risk": "Medium", "validated": True,
     "question": "On a dual-mode (BR/EDR + LE) device, did triggering Cross-Transport Key Derivation "
                 "overwrite an authenticated bonding key with an unauthenticated/weaker one without "
                 "user approval?",
     "options": ["Yes — CTKD overwrite allowed", "No — 5.1 restrictions enforced",
                 "Not dual-mode / not tested"],
     "vuln": "Yes — CTKD overwrite allowed",
     "desc": "{mac} permits Cross-Transport Key Derivation to overwrite an authenticated key "
             "(BLURtooth CVE-2020-15802), silently weakening the paired relationship and enabling "
             "MITM on a link the user believes is securely bonded.",
     "rem": "Apply BT 5.1 CTKD restrictions that forbid overwriting authenticated keys or "
            "downgrading key strength."},
    {"const": "T_BLUFFS", "label": "BLUFFS (CVE-2023-24023)", "risk": "High", "validated": False,
     "question": "Does the device allow a low session-key-diversifier entropy / repeatable session "
                 "key derivation (BLUFFS, breaking forward & future secrecy across sessions)?",
     "options": ["Yes — low/repeatable session key", "No — SC-only + fixed key derivation",
                 "Not tested"],
     "vuln": "Yes — low/repeatable session key",
     "desc": "{mac} is susceptible to BLUFFS (CVE-2023-24023): weak/repeatable session-key "
             "derivation breaks forward and future secrecy, letting an in-range attacker force key "
             "reuse and impersonate the device across sessions.",
     "rem": "Reject low negotiated key lengths, adopt the SIG key-derivation fix, and use Secure "
            "Connections Only."},
    {"const": "T_BLESA", "label": "BLESA reconnection spoofing (CVE-2020-9770)", "risk": "High",
     "validated": True,
     "question": "Spoof the peripheral's BD_ADDR and let the central RECONNECT: did the central "
                 "accept data on reconnection WITHOUT enforcing re-authentication/encryption?",
     "options": ["Yes — cleartext data accepted on reconnect", "No — authenticated reconnect",
                 "Not tested"],
     "vuln": "Yes — cleartext data accepted on reconnect",
     "desc": "The central for {mac} accepted spoofed peripheral data on reconnection without "
             "re-authentication (BLESA CVE-2020-9770). An attacker spoofing the peripheral address "
             "can feed forged data (e.g. medical telemetry) to the consuming device.",
     "rem": "Enforce mandatory authenticated + encrypted reconnection before accepting any data "
            "from a previously-bonded peer."},
    {"const": "T_INVALID_CURVE", "label": "Invalid-curve (CVE-2018-5383)", "risk": "Medium",
     "validated": False,
     "question": "Submit an ECDH public key with a zeroed Y-coordinate during pairing (InternalBlue-"
                 "class rig): did the stack ACCEPT the off-curve/fixed-coordinate key instead of "
                 "rejecting it?",
     "options": ["Yes — off-curve key accepted", "No — validates public key", "Not tested"],
     "vuln": "Yes — off-curve key accepted",
     "desc": "{mac} does not validate the peer ECDH public key (CVE-2018-5383) — an in-range MITM "
             "present during pairing can force the shared secret into a small subgroup and recover "
             "the session key.",
     "rem": "Update to post-2018 firmware/OS that mandates ECDH public-key on-curve validation."},
    {"const": "T_LL_FUZZ", "label": "Link-Layer malformed-PDU crash", "risk": "High",
     "validated": True,
     "question": "Sending malformed Link-Layer / HCI PDUs (SweynTooth / BrakTooth PoC, or a fuzzer), "
                 "did the device crash, deadlock, or reboot?",
     "options": ["Yes — crashed/deadlocked/rebooted", "No — handled cleanly", "Not tested"],
     "vuln": "Yes — crashed/deadlocked/rebooted",
     "desc": "{mac} crashed or deadlocked on a malformed Link-Layer/HCI PDU (the SweynTooth/"
             "BrakTooth/BlueFrag class, CWE-20/787). A malformed advertising/connect/control PDU — "
             "often broadcast with no address needed — denies service and can escalate to RCE on "
             "vulnerable stacks.",
     "rem": "Update controller firmware and host stack (PDU length/format validation, buffer "
            "bounding); disable unused profiles; rate-limit."},
]


class BluetoothModule(BaseModule):
    """
    Zero-knowledge Bluetooth (BR/EDR + BLE) security assessment.

    Runs the full chain — hardware setup, discovery, GATT/SDP enumeration,
    pairing/SMP security triage, passive sniff + crackle, active exploitation,
    and cleanup — against whatever the device under test exposes, ruling out
    each known vulnerability class from cleartext-observable signals.  No target
    identity is assumed, so it surfaces (for example) a static-passkey LESC
    device from generic pairing analysis alone.
    """
    name        = "Bluetooth"
    description = "Zero-knowledge BR/EDR + BLE assessment (discovery → pairing → exploitation)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_DISCOVERED   = "Bluetooth Device Discovered"
    T_GATT_ENUM    = "BLE GATT Service Enumerated"
    T_SDP_ENUM     = "Classic Bluetooth SDP Service Enumerated"
    T_ADDR_STATIC  = "Static or Public Bluetooth Address — Device Trackable"
    T_ID_LEAK      = "Sensitive Identifier Broadcast in Advertising Data"
    T_JUSTWORKS    = "Just Works Pairing — No MITM Protection"
    T_LEGACY       = "LE Legacy Pairing — Passively Decryptable"
    T_STATIC_PK    = "Static or Reused BLE Passkey"
    T_METHOD_CONF  = "Bluetooth Pairing Method Confusion"
    T_DOWNGRADE    = "Bluetooth Pairing Security Downgrade Accepted"
    T_SHORT_KEY    = "Short Bluetooth Encryption Key Negotiated"
    T_INVALID_CURVE= "Bluetooth ECDH Public Key Not Validated (CVE-2018-5383)"
    T_KNOB         = "KNOB — Bluetooth Encryption Key Entropy Downgrade (CVE-2019-9506)"
    T_BLUFFS       = "BLUFFS — Bluetooth Forward/Future Secrecy Weakness (CVE-2023-24023)"
    T_BIAS         = "BIAS — Bluetooth Impersonation (CVE-2020-10135)"
    T_BLUR         = "BLURtooth — Cross-Transport Key Overwrite (CVE-2020-15802)"
    T_BLESA        = "BLESA — BLE Reconnection Spoofing (CVE-2020-9770)"
    T_UNAUTH_READ  = "Unauthenticated GATT Characteristic Read"
    T_UNAUTH_WRITE = "Unauthenticated GATT Characteristic Write"
    T_UNAUTH_NOTIFY= "Unauthenticated GATT Notification/Indication Stream"
    T_SWEYNTOOTH   = "SweynTooth BLE SoC Vulnerability Surface"
    T_BRAKTOOTH    = "BrakTooth BR/EDR SoC Vulnerability Surface"
    T_BLEEDINGTOOTH= "BleedingTooth Linux BlueZ Kernel Vulnerability Surface"
    T_BLUEBORNE    = "BlueBorne Bluetooth Stack Vulnerability Surface"
    T_LESC_OK      = "LE Secure Connections Confirmed (Passively Uncrackable)"
    T_PASSKEY_RECOVERED = "BLE LESC Passkey Recovered from Passive Capture"
    T_BLUESMACK    = "BlueSmack / L2CAP Echo Denial of Service"
    T_DOS_FLOOD    = "Bluetooth Connection Exhaustion / l2ping Flood"
    T_LL_FUZZ      = "Bluetooth Link-Layer Malformed-PDU Crash"
    T_SKIPPED      = "Bluetooth Testing SKIPPED — No Adapter or Sniffer Available"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "Bluetooth" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane BLE defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "bluetooth"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [Bluetooth] {msg}", tool=self.name)
        except Exception:
            pass

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"BluetoothModule v{VERSION} started for [{self.ctx.instance_loc}]")
            hw = self._phase0_hardware()
            if hw is None:
                return  # skipped — honest finding already emitted
            devices = self._phase1_discovery(hw)
            targets = self._phase1_select(devices)
            if not targets:
                self._mark_complete("Discovery complete — no in-scope target selected")
                return
            for dev in targets:
                self._assess_device(hw, dev)
            self._phase6_cleanup(targets)
            self._mark_complete(
                f"Bluetooth assessment complete — {len(targets)} device(s) tested")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — hardware selection + setup ────────────────────────────────
    def _phase0_hardware(self) -> Optional[dict]:
        self._event("Phase 0 — hardware selection & setup")
        labels = [h["label"] for h in _BT_HARDWARE]
        choice = self._prompt(
            "Select the Bluetooth testing hardware in use. Passive sniffing / "
            "crackle / LESC-confirmation require a flashed sniffer board (options "
            "2-6); option 1 covers active GATT + pairing only.\n"
            "Refer to Quiver to flash the board's firmware before continuing.",
            options=labels + ["Skip Bluetooth testing"],
            prompt_type="choice", skippable=True)

        hw = next((h for h in _BT_HARDWARE if h["label"] == choice), None)
        if hw is None or (choice or "").lower().startswith("skip"):
            # Operator skipped, or no hardware — honest SKIPPED finding.
            self._f(self.T_SKIPPED,
                    "No Bluetooth adapter or sniffer was selected for this instance, "
                    "so Bluetooth/BLE testing was NOT performed. Attach a BlueZ adapter "
                    "for active GATT/pairing work, or flash a sniffer board via Quiver "
                    "(Sniffle / nRF Sniffer / ButteRFly / Ubertooth) for passive capture "
                    "and re-run the module.",
                    "Informational", tool="bluetooth")
            self._mark_complete("Bluetooth SKIPPED — no hardware selected")
            return None

        # Print the board-specific setup / Quiver-flash guidance to the log.
        self.ctx.logger.info(f"Selected BT hardware: {hw['label']}", tool=self.name)
        if hw.get("quiver"):
            self.ctx.logger.info(
                f"Flash via Quiver payload: '{hw['quiver']}'", tool=self.name)
        for ln in hw["setup"]:
            self.ctx.logger.info(f"  {ln}", tool=self.name)
        setup_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_hardware_setup.txt"
        try:
            setup_txt.write_text(
                f"Bluetooth testing hardware: {hw['label']}\n"
                + (f"Quiver flash payload: {hw['quiver']}\n" if hw.get("quiver") else "")
                + "\n" + "\n".join(hw["setup"]) + "\n", encoding="utf-8")
        except Exception:
            pass
        self._prompt_connected_photo(
            f"{hw['label']} connected for [{self.ctx.instance_loc}]")

        # Verify at least one usable BlueZ tool or the chosen sniffer CLI is present.
        have_bluez = any(_bt_which(t) for t in ("bluetoothctl", "btmgmt", "hcitool"))
        if not have_bluez and not hw["sniffer"]:
            self._f(self.T_SKIPPED,
                    "The selected adapter option requires the BlueZ stack "
                    "(bluetoothctl / btmgmt / hcitool) but none was found on PATH. "
                    "Install bluez (see install.py Phase 4b) and re-run.",
                    "Informational", tool="bluetooth")
            self._mark_complete("Bluetooth SKIPPED — BlueZ not installed")
            return None
        # Bring the local controller up (best-effort).
        if have_bluez:
            try:
                run_tool(["hciconfig", "hci0", "up"], self.ctx,
                         tool_name="hciconfig", timeout=15)
            except Exception:
                pass
        return hw

    # ── Phase 1 — discovery (zero-knowledge) ────────────────────────────────
    def _phase1_discovery(self, hw: dict) -> list[dict]:
        self._event("Phase 1 — discovery (BR/EDR + LE)")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Discovering Bluetooth devices…")
        out_dir = self._dir("01_discovery")
        # Ground-truth OTA capture during the scan (best-effort; needs root).
        try:
            btmon_f = out_dir / f"{self.ctx.file_prefix}_btmon_discovery.btsnoop"
            if _bt_which("btmon"):
                run_tool(["bash", "-c",
                          f"timeout 18 btmon -w {btmon_f} >/dev/null 2>&1 || true"],
                         self.ctx, tool_name="btmon", timeout=30)
        except Exception:
            pass

        devices = _bt_scan_btmgmt(self.ctx, out_dir, 15) if _bt_which("btmgmt") else []
        if not devices and _bt_which("bluetoothctl"):
            devices = _bt_scan_bluetoothctl(self.ctx, out_dir, 15)
        # hcitool lescan fallback (deprecated but ubiquitous).
        if not devices and _bt_which("hcitool"):
            try:
                lescan = out_dir / f"{self.ctx.file_prefix}_hcitool_lescan.txt"
                run_tool(["bash", "-c",
                          "timeout 15 hcitool lescan --duplicates || true"],
                         self.ctx, tool_name="hcitool", output_file=lescan, timeout=25)
                for line in lescan.read_text(errors="replace").splitlines():
                    m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(.*)$", line)
                    if m:
                        devices.append({"mac": m.group(1).upper(),
                                        "addr_type": "", "name": m.group(2).strip(),
                                        "rssi": "", "uuids": [], "company_ids": [],
                                        "raw": []})
            except Exception:
                pass

        # Deduplicate by MAC.
        uniq: dict[str, dict] = {}
        for d in devices:
            uniq.setdefault(d["mac"], d)
        devices = list(uniq.values())
        self.ctx.logger.info(f"Discovered {len(devices)} Bluetooth device(s)", tool=self.name)

        for d in devices:
            loc = d["mac"] + (f" ({d['name']})" if d.get("name") else "")
            self._f(self.T_DISCOVERED,
                    f"A Bluetooth device was discovered during zero-knowledge scanning: "
                    f"{loc}. Address type: {d.get('addr_type') or 'unknown'}; "
                    f"RSSI: {d.get('rssi') or 'n/a'}; name: {d.get('name') or 'n/a'}. "
                    f"Its presence and advertising data expand the wireless attack surface.",
                    "Informational", tool="bluetooth", ip=d["mac"],
                    affected_component=d.get("name", ""))
            self._privacy_checks(d)
        return devices

    def _privacy_checks(self, d: dict) -> None:
        """E.1 static/public address + E.2 identifier leakage in advertising."""
        klass, trackable, detail = _bt_classify_address(d["mac"], d.get("addr_type", ""))
        if trackable:
            self._f(self.T_ADDR_STATIC,
                    f"Device {d['mac']} advertises with a {klass} address. {detail} A "
                    f"body-worn or clinical device with a stable address can be tracked "
                    f"and correlated to a person across time and location. Only a rotating "
                    f"Resolvable Private Address (RPA) provides LE privacy.",
                    "Medium", tool="bluetooth", ip=d["mac"],
                    remediation="Enable LE Privacy with frequently-rotating Resolvable "
                                "Private Addresses; distribute the IRK only to bonded peers.")
        name = (d.get("name") or "")
        if re.search(r"\b(sn|serial|s/n)\b", name, re.I) or re.search(r"\d{4,}", name):
            self._f(self.T_ID_LEAK,
                    f"Device {d['mac']} broadcasts a potentially sensitive identifier in its "
                    f"advertising name/data ('{name}'). Serial numbers, patient IDs or per-unit "
                    f"tokens in the clear defeat address privacy (the stable string becomes the "
                    f"tracking key) and disclose asset information to any passive listener.",
                    "High", tool="bluetooth", ip=d["mac"],
                    remediation="Remove serials/patient identifiers from the advertised device "
                                "name and manufacturer data; expose per-unit IDs only via an "
                                "authenticated, bonded GATT read.")

    def _phase1_select(self, devices: list[dict]) -> list[dict]:
        if not devices:
            return []
        opts = [f"{d['mac']} — {d.get('name') or '(no name)'} "
                f"[{d.get('addr_type') or '?'}, RSSI {d.get('rssi') or '?'}]"
                for d in devices]
        ans = self._prompt(
            "Select the in-scope device(s) under test to assess (zero-knowledge — "
            "pick the target Bluetooth interface). Choose 'All discovered' to assess "
            "every device, or 'None' to stop after discovery.",
            options=["All discovered"] + opts + ["None"],
            prompt_type="choice", skippable=True)
        if not ans or ans.lower().startswith("none"):
            return []
        if ans.lower().startswith("all"):
            return devices
        for d, o in zip(devices, opts):
            if o == ans:
                return [d]
        return devices[:1]

    # ── per-device assessment (phases 2-5) ──────────────────────────────────
    def _assess_device(self, hw: dict, dev: dict) -> None:
        mac = dev["mac"]
        self._event(f"Assessing {mac} — phases 2-5")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", f"Assessing {mac}…")
        self._phase2_enumerate(dev)
        smp = self._phase3_pairing(dev)
        self._phase4_sniff_crack(hw, dev, smp)
        self._phase5_active(hw, dev, smp)
        self._phase5_cve_surface(dev)
        self._phase5_known_attacks(dev)

    # ── Phase 2 — GATT / SDP enumeration ────────────────────────────────────
    def _phase2_enumerate(self, dev: dict) -> None:
        mac = dev["mac"]
        self._event(f"Phase 2 — enumeration {mac}")
        out_dir = self._dir("02_enumeration")
        atype = "random" if "random" in (dev.get("addr_type") or "").lower() else "public"

        # BLE GATT (gatttool — deprecated but ubiquitous; bleak/bluetoothctl also work).
        if _bt_which("gatttool"):
            prim = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_gatt_primary.txt"
            chars = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_gatt_chars.txt"
            try:
                run_tool(["gatttool", "-b", mac, "-t", atype, "--primary"],
                         self.ctx, tool_name="gatttool", output_file=prim, timeout=40)
                rc, out, err = run_tool(
                    ["gatttool", "-b", mac, "-t", atype, "--characteristics"],
                    self.ctx, tool_name="gatttool", output_file=chars, timeout=60)
                svc_ct = len([l for l in (out or "").splitlines() if "handle" in l.lower()])
                self._f(self.T_GATT_ENUM,
                        f"The GATT server on {mac} was enumerated without prior knowledge, "
                        f"exposing {svc_ct or 'multiple'} characteristic(s)/service(s). Service "
                        f"and characteristic layout discloses device function and defines the "
                        f"read/write attack surface tested in later phases.",
                        "Informational", tool="gatttool", ip=mac,
                        output_file=str(chars))
                dev["_gatt_chars_file"] = str(chars)
                dev["_gatt_raw"] = out or ""
                dev["_chars"] = _bt_parse_gatt_chars(out or "")
            except Exception as e:
                self.ctx.logger.warn(f"gatttool enumeration failed for {mac}: {e}", tool=self.name)

        # Classic SDP (BR/EDR).
        if _bt_which("sdptool"):
            sdp = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_sdp.txt"
            try:
                rc, out, err = run_tool(["sdptool", "browse", mac], self.ctx,
                                        tool_name="sdptool", output_file=sdp, timeout=40)
                if out and "Service Name" in out:
                    self._f(self.T_SDP_ENUM,
                            f"Classic Bluetooth (BR/EDR) SDP services were enumerated on {mac}. "
                            f"Exposed service records (RFCOMM/L2CAP channels, profiles such as "
                            f"SPP/DUN/PAN) widen the BR/EDR attack surface.",
                            "Informational", tool="sdptool", ip=mac, output_file=str(sdp))
            except Exception:
                pass

    # ── Phase 3 — pairing / SMP security triage ─────────────────────────────
    def _phase3_pairing(self, dev: dict) -> dict:
        mac = dev["mac"]
        self._event(f"Phase 3 — pairing/SMP {mac}")
        out_dir = self._dir("03_pairing")
        smp: dict = {}

        # Capture a decoded btmon transcript while attempting to pair, so the SMP
        # Pairing Request/Response security bits are observed on the wire.
        smp_txt = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_smp_btmon.txt"
        btmon_proc = None
        btmon_fh = None
        try:
            if _bt_which("btmon"):
                btmon_fh = open(smp_txt, "w")
                btmon_proc = subprocess.Popen(
                    ["btmon"], stdout=btmon_fh, stderr=subprocess.STDOUT)
                if _pause:
                    _pause.register(btmon_proc, "btmon")
                time.sleep(0.5)
        except Exception:
            btmon_proc = None

        # Attempt a normal pairing (records the negotiated model regardless of outcome).
        try:
            subprocess.run(
                ["bash", "-c",
                 f"(echo 'power on'; echo 'agent KeyboardDisplay'; echo 'default-agent'; "
                 f"echo 'pair {mac}'; sleep 8; echo 'quit') | bluetoothctl"],
                capture_output=True, text=True, timeout=30)
        except Exception:
            pass
        time.sleep(1.0)
        if btmon_proc:
            if _pause:
                _pause.unregister(btmon_proc.pid)
            try:
                btmon_proc.terminate(); btmon_proc.wait(timeout=5)
            except Exception:
                try: btmon_proc.kill()
                except Exception: pass
        if btmon_fh:
            try: btmon_fh.close()
            except Exception: pass

        text = ""
        try:
            text = smp_txt.read_text(errors="replace")
        except Exception:
            pass
        smp = _bt_parse_btmon_smp(text)

        # If btmon gave us nothing usable, fall back to an operator observation prompt.
        if not smp.get("saw_smp"):
            ans = self._prompt(
                f"SMP could not be auto-captured for {mac}. From a Wireshark/btmon capture "
                f"of the pairing, what did the SMP Pairing Request/Response show? "
                f"(LE Secure Connections bit, MITM bit, association model).",
                options=["LESC (SC=1) + MITM/Passkey/NumComp",
                         "LESC (SC=1) + Just Works (MITM=0)",
                         "LE Legacy (SC=0)",
                         "Could not determine / not captured"],
                prompt_type="choice", skippable=True)
            a = (ans or "").lower()
            if "legacy" in a:
                smp = {"sc": False, "legacy": True, "saw_smp": True, "_operator": True}
            elif "just works" in a:
                smp = {"sc": True, "mitm": False, "legacy": False, "saw_smp": True, "_operator": True}
            elif "lesc" in a:
                smp = {"sc": True, "mitm": True, "legacy": False, "saw_smp": True, "_operator": True}

        self._emit_pairing_findings(dev, smp, str(smp_txt))
        self._downgrade_probe(dev, out_dir)
        return smp

    def _emit_pairing_findings(self, dev: dict, smp: dict, evidence: str) -> None:
        mac = dev["mac"]
        sc = smp.get("sc")
        mitm = smp.get("mitm")
        keysz = smp.get("max_key_size")
        io = smp.get("io_capability", "")

        # A.2 — LE Legacy (SC=0) → passively decryptable if sniffed.
        if sc is False or smp.get("legacy") is True:
            self._f(self.T_LEGACY,
                    f"{mac} negotiated LE Legacy pairing (SMP Secure Connections bit = 0). "
                    f"Legacy pairing derives the session key from a weak Temporary Key "
                    f"(Just Works TK=0; Passkey Entry TK is a ~20-bit 6-digit value), so a "
                    f"passively-sniffed pairing can be decrypted offline with crackle, "
                    f"recovering the LTK and all future bonded traffic.",
                    "High", tool="bluetooth", ip=mac, output_file=evidence,
                    cve_ids=[], remediation="Require LE Secure Connections (ECDH P-256); "
                    "reject SC=0 on hardware that supports LESC (BLE 4.2+).")
        # A.1 — Just Works / no MITM.
        if mitm is False or _BT_IO_CAP.get(str(io).lower(), io) == "NoInputNoOutput":
            self._f(self.T_JUSTWORKS,
                    f"{mac} accepted Just Works pairing (SMP MITM-protection bit = 0"
                    + (f", IO capability {io}" if io else "") + "). Just Works provides no "
                    f"man-in-the-middle protection, so an active attacker in range can "
                    f"interpose during pairing and relay/modify the connection.",
                    "High", tool="bluetooth", ip=mac, output_file=evidence,
                    remediation="Provision real IO capability and set MITM=1 (LESC Numeric "
                    "Comparison or Passkey Entry); where no IO exists, use OOB pairing.")
        # A.5b — short encryption key.
        if isinstance(keysz, int) and keysz < 16:
            self._f(self.T_SHORT_KEY,
                    f"{mac} negotiated a maximum encryption key size of {keysz} bytes "
                    f"(< 16). Short keys reduce brute-force cost and are the BLE analogue of "
                    f"the KNOB attack; a value near the 7-byte floor is a serious weakness.",
                    "High", tool="bluetooth", ip=mac, output_file=evidence,
                    remediation="Enforce a 16-byte encryption key floor and abort pairing "
                    "on any shorter negotiated size.")
        # LESC confirmed (good) — informational, and the passkey/static-credential check.
        if sc is True and not smp.get("legacy"):
            self._f(self.T_LESC_OK,
                    f"{mac} completed LE Secure Connections pairing (ECDH P-256). The session "
                    f"key is never transmitted, so the pairing is NOT passively crackable — "
                    f"crackle cannot recover the key. Residual risk shifts to implementation "
                    f"flaws (static passkey, debug keys, downgrade acceptance).",
                    "Informational", tool="bluetooth", ip=mac, output_file=evidence)
            # A.3 — static/reused passkey under LESC Passkey Entry (the static-passkey-class finding).
            ans = self._prompt(
                f"{mac} uses LE Secure Connections. Is the 6-digit pairing passkey FIXED — "
                f"printed on the enclosure, in the manual/firmware, or identical across units "
                f"— rather than a fresh random value shown per pairing?",
                options=["Yes — fixed/printed/shared passkey", "No — fresh random per pairing",
                         "Unknown"], prompt_type="choice", skippable=True)
            if (ans or "").lower().startswith("yes"):
                smp["_static_passkey_confirmed"] = True   # picked up by phase 4 if the PIN is recovered
                self._f(self.T_STATIC_PK,
                        f"{mac} authenticates LESC pairing with a static/reused passkey. A "
                        f"hard-coded or shared passkey (CWE-798) defeats the MITM protection "
                        f"of LESC Passkey Entry: anyone who can read the printed/ documented "
                        f"value can complete an authenticated man-in-the-middle relay, "
                        f"reducing LESC to Just Works in practice.",
                        "High", tool="bluetooth", ip=mac, output_file=evidence,
                        remediation="Use a fresh, random, per-pairing passkey that is never "
                        "hard-coded, printed, or reused across units; prefer Numeric "
                        "Comparison or OOB where the UI allows.")
        # A.4 — method confusion (operator-observed; only asked when a display+keyboard mix exists).
        # A.6 — invalid-curve is a re-pair-window probe; flagged as surface below.

    def _downgrade_probe(self, dev: dict, out_dir: Path) -> None:
        """A.5 — non-MITM downgrade-susceptibility test. Our host pairs DIRECTLY with the
        device (one legitimate endpoint, no interposition) offering weakened terms:
          Probe A (SC-Only): Secure Connections cleared → does it accept LE Legacy?
          Probe B (MITM):    IO cap NoInputNoOutput     → does it accept Just Works (no MITM)?
        Each probe UNPAIRS first so a STORED bond cannot re-encrypt on the old key and
        masquerade as a fresh acceptance (the stale-bond false positive)."""
        mac = dev["mac"]
        if not _bt_which("btmgmt"):
            return
        log = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_downgrade.txt"

        def _probe(sc, iocap, tag):
            # Purge any bond first → a genuine fresh pairing, then set the weakened offer.
            plog = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_dg_{tag}.txt"
            try:
                rc, out, err = run_tool(
                    ["bash", "-c",
                     f"btmgmt unpair {mac} >/dev/null 2>&1; "
                     f"(echo 'remove {mac}'; echo quit) | bluetoothctl >/dev/null 2>&1; "
                     f"btmgmt sc {sc}; btmgmt io-cap {iocap}; "
                     f"(echo 'pair {mac}'; sleep 7; echo quit) | bluetoothctl; "
                     f"(echo 'remove {mac}'; echo quit) | bluetoothctl >/dev/null 2>&1"],
                    self.ctx, tool_name="btmgmt", output_file=plog, timeout=45)
                blob = (out or "") + (err or "")
            except Exception:
                return None
            if re.search(r"pairing successful|paired:\s*yes|bonded:\s*yes", blob, re.I):
                return True
            if re.search(r"pairing failed|authentication failed|rejected|not supported|"
                         r"not available", blob, re.I):
                return False
            return None      # inconclusive — couldn't connect/observe a fresh pairing

        sc_ok = _probe("off", "KeyboardDisplay", "sc")      # Probe A — SC-Only enforcement
        jw_ok = _probe("on",  "NoInputNoOutput", "mitm")    # Probe B — MITM enforcement
        try:
            run_tool(["bash", "-c", "btmgmt sc on >/dev/null 2>&1 || true"],
                     self.ctx, tool_name="btmgmt", timeout=10)
        except Exception:
            pass

        if sc_ok:
            self._f(self.T_DOWNGRADE,
                    f"{mac} completed a fresh pairing after Secure Connections was cleared "
                    f"(SC=0, forced LE Legacy) — it does NOT enforce Secure Connections Only. "
                    f"An active in-range attacker can downgrade the pairing to crackable LE "
                    f"Legacy, and with a known/static passkey passively decrypt sessions.",
                    "High", tool="bluetooth", ip=mac, output_file=str(log),
                    force_classification="Validated",
                    remediation="Enable Secure Connections Only mode (Security Mode 1 Level 4) "
                    "and abort any SC=0 pairing offer.")
        if jw_ok:
            self._f(self.T_JUSTWORKS,
                    f"{mac} completed an unauthenticated Just Works bond when offered a "
                    f"NoInputNoOutput IO capability — it does NOT require MITM protection. An "
                    f"attacker presenting 'no I/O' bonds via Just Works with no passkey at all, "
                    f"then interposes on the connection.",
                    "High", tool="bluetooth", ip=mac, output_file=str(log),
                    force_classification="Validated",
                    remediation="Require MITM protection (LESC Numeric Comparison / unique "
                    "per-pairing passkey / OOB) for any bond that grants access to sensitive "
                    "functionality; gate sensitive GATT behind an authenticated bond.")
        if sc_ok is None and jw_ok is None:
            self.ctx.logger.info(
                f"Downgrade probe INCONCLUSIVE for {mac} — could not connect/observe a fresh "
                f"pairing (a lingering bond that keeps reconnecting, or an advertising/timing "
                f"issue). Purge the device (btmgmt unpair + rm /var/lib/bluetooth) and re-run.",
                tool=self.name)

    # ── Phase 4 — passive sniff + crackle ───────────────────────────────────
    def _phase4_sniff_crack(self, hw: dict, dev: dict, smp: dict) -> None:
        mac = dev["mac"]
        self._event(f"Phase 4 — sniff + crack {mac}")
        out_dir = self._dir("04_sniff_crack")

        if not hw.get("sniffer"):
            self.ctx.logger.info(
                "Selected hardware is not a passive sniffer — skipping capture→crack. "
                "Flash a Sniffle/Ubertooth/ButteRFly board via Quiver for this phase.",
                tool=self.name)
            return

        pcap = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_pairing.pcap"
        captured = False

        # Sniffle host CLI (crackle-ready LE_LL_WITH_PHDR).
        sniffle = _bt_which("sniff_receiver.py")
        if hw["key"] in ("sniffle", "butterfly", "catsniffer") and sniffle:
            self._prompt(
                f"Ready to passively capture a pairing for {mac}. When you press Ready, "
                f"trigger a fresh pairing on the device under test (e.g. open its app and "
                f"pair) so the SMP exchange is captured. Press Ready to start the sniffer.",
                options=["Ready"], prompt_type="choice")
            port = next((p for p in ("/dev/ttyACM0", "/dev/ttyUSB0", "/dev/ttyACM1")
                         if os.path.exists(p)), "/dev/ttyACM0")
            try:
                run_tool(["bash", "-c",
                          f"timeout 45 python3 {sniffle} -s {port} -m {mac} "
                          f"-o {pcap} >/dev/null 2>&1 || true"],
                         self.ctx, tool_name="sniff_receiver.py", timeout=60)
                captured = pcap.exists() and pcap.stat().st_size > 0
            except Exception:
                pass
        elif hw["key"] == "ubertooth" and _bt_which("ubertooth-btle"):
            self._prompt(f"Trigger a pairing on {mac} after pressing Ready (Ubertooth capture).",
                         options=["Ready"], prompt_type="choice")
            try:
                run_tool(["bash", "-c",
                          f"timeout 45 ubertooth-btle -f -t {mac} -q {pcap} "
                          f">/dev/null 2>&1 || true"],
                         self.ctx, tool_name="ubertooth-btle", timeout=60)
                captured = pcap.exists() and pcap.stat().st_size > 0
            except Exception:
                pass
        else:
            self.ctx.logger.info(
                f"No capture CLI found for hardware '{hw['key']}'. Capture the pairing to "
                f"{pcap.name} manually (see hardware setup notes) then re-run crackle.",
                tool=self.name)

        # crackle — attempt to recover the key from the captured pairing.
        crackle = _bt_which("crackle")
        if captured and crackle:
            crk = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_crackle.txt"
            dec = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_decrypted.pcap"
            try:
                rc, out, err = run_tool([crackle, "-i", str(pcap), "-o", str(dec)],
                                        self.ctx, tool_name="crackle", output_file=crk, timeout=120)
                blob = (out or "") + (err or "")
                if re.search(r"ltk found|tk found|cracked", blob, re.I):
                    self._f(self.T_LEGACY,
                            f"A passively-captured pairing for {mac} was decrypted with crackle "
                            f"— the Long-Term Key was recovered from sniffed traffic, confirming "
                            f"the link is passively decryptable. Evidence: {crk.name}. All data "
                            f"exchanged under this key (and future bonded sessions) is exposed.",
                            "High", tool="crackle", ip=mac, output_file=str(crk),
                            output_files=[str(pcap), str(dec)],
                            force_classification="Validated",
                            remediation="Require LE Secure Connections; a device whose pairing "
                            "crackle can decrypt is using crackable LE Legacy pairing.")
                elif re.search(r"secure connections|not.*legacy|unable to crack", blob, re.I):
                    self._f(self.T_LESC_OK,
                            f"crackle could NOT decrypt the captured pairing for {mac} — it "
                            f"reported LE Secure Connections. This positively confirms LESC "
                            f"(ECDH P-256): the session key never crossed the air and the link "
                            f"is not passively crackable. Evidence: {crk.name}.",
                            "Informational", tool="crackle", ip=mac, output_file=str(crk),
                            output_files=[str(pcap)])
            except Exception as e:
                self.ctx.logger.warn(f"crackle failed for {mac}: {e}", tool=self.name)
        elif captured and not crackle:
            self.ctx.logger.info(
                "crackle not installed — pcap captured but not analysed. Build crackle "
                "(install.py Phase 4b) and run: crackle -i <pcap>.", tool=self.name)

        # LESC Passkey Entry passive recovery — the LESC counterpart to crackle.
        # crackle only breaks LE Legacy; a captured LESC Passkey Entry pairing still
        # leaks the 6-digit passkey, which is recoverable offline from the per-round
        # commitments via the f4 (AES-CMAC) brute (validated on both initiator and
        # responder halves).
        if captured:
            smp_cap = _bt_extract_smp_pairing(str(pcap), self.ctx)
            if smp_cap and (len(smp_cap["ic"]) + len(smp_cap["rc"])) >= 10:
                rec = _bt_recover_passkey(smp_cap)
                ev = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_passkey_recovery.txt"
                if rec and not rec.get("partial") and rec.get("pin") is not None:
                    try:
                        ev.write_text(
                            "LESC Passkey Entry — passive passkey recovery (f4 brute)\n"
                            f"target:  {mac}\n"
                            f"rounds:  {rec['rounds']}   two-sided agreement: {rec['two_sided']}\n"
                            f"bits (round1→20): {''.join(map(str, rec['bits']))}\n"
                            f"RECOVERED PASSKEY: {rec['pin']:06d}\n", encoding="utf-8")
                    except Exception:
                        pass
                    self._f(self.T_PASSKEY_RECOVERED,
                            f"The LE Secure Connections Passkey Entry passkey for {mac} was "
                            f"RECOVERED offline from the passively-captured pairing: {rec['pin']:06d}. "
                            f"Each round's Pairing Confirm (f4 = AES-CMAC over the cleartext public "
                            f"keys + the revealed nonce + one passkey bit) was brute-forced one bit "
                            f"across 20 rounds; the initiator and responder halves agree independently "
                            f"(two-sided check: {rec['two_sided']}). No active MITM and no physical "
                            f"access to the printed value were needed. If this passkey is static or "
                            f"reused it authenticates every future session and every unit that shares "
                            f"it, reducing LESC Passkey Entry to Just Works.",
                            "High", tool="ble-passkey-recover", ip=mac,
                            output_file=str(ev), output_files=[str(pcap)],
                            force_classification="Validated",
                            remediation="Use a fresh, random, single-use passkey per pairing that is "
                            "never printed, hard-coded, or reused; a passkey a single sniffed pairing "
                            "reveals provides no MITM protection under LESC.")
                    # A recovered static passkey is the strongest possible evidence for the
                    # static-passkey finding; record it validated with the concrete value.
                    if smp.get("_static_passkey_confirmed"):
                        self._f(self.T_STATIC_PK,
                                f"{mac} uses a STATIC LESC passkey that was recovered from a single "
                                f"passive capture ({rec['pin']:06d}) AND confirmed reused/printed. "
                                f"Anyone who sniffs one pairing, or reads the documented value, "
                                f"completes an authenticated MITM against every session.",
                                "High", tool="ble-passkey-recover", ip=mac,
                                output_file=str(ev), force_classification="Validated",
                                remediation="Issue a fresh random per-pairing passkey; never reuse or "
                                "print it.")
                elif rec and rec.get("partial"):
                    self.ctx.logger.info(
                        f"LESC Passkey Entry pairing detected for {mac} but only {rec['rounds']}/20 "
                        f"rounds captured — recover the PIN by re-capturing one complete fresh "
                        f"pairing (force a re-pair while sniffing).", tool=self.name)

    # ── Phase 5 — active exploitation ───────────────────────────────────────
    def _phase5_active(self, hw: dict, dev: dict, smp: dict) -> None:
        mac = dev["mac"]
        self._event(f"Phase 5 — active exploitation {mac}")
        out_dir = self._dir("05_active")
        atype = "random" if "random" in (dev.get("addr_type") or "").lower() else "public"

        # D.1 — unauthenticated GATT read (read every readable characteristic on an
        # UNPAIRED link). ATT Read Response with a value (no 0x05/0x0F error) = exposed.
        chars = dev.get("_chars", [])
        if _bt_which("gatttool") and chars:
            readable = [c for c in chars if c["readable"]]
            read_ok, read_denied = [], 0
            rd = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_unauth_read.txt"
            lines = []
            for c in readable[:40]:
                h = c["handle"]
                try:
                    rc, out, err = run_tool(["gatttool", "-b", mac, "-t", atype,
                                             "--char-read", "-a", h],
                                            self.ctx, tool_name="gatttool", timeout=20)
                    blob = (out or "") + (err or "")
                    lines.append(f"{h} ({c['uuid']}): {blob.strip()}")
                    if re.search(r"characteristic value/descriptor:\s*[0-9a-f]", blob, re.I):
                        read_ok.append(h)
                    elif re.search(r"insufficient authentication|insufficient encryption|"
                                   r"authoriz", blob, re.I):
                        read_denied += 1
                except Exception:
                    pass
            try: rd.write_text("\n".join(lines), encoding="utf-8")
            except Exception: pass
            if read_ok:
                self._f(self.T_UNAUTH_READ,
                        f"{len(read_ok)} GATT characteristic(s) on {mac} returned data over an "
                        f"UNPAIRED, unencrypted link (ATT Read Response with a value, no 0x05/"
                        f"0x0F error). Handles: {', '.join(read_ok[:12])}. Any listener in range "
                        f"can read this data; if it is PHI/telemetry the exposure is severe.",
                        "High", tool="gatttool", ip=mac, output_file=str(rd),
                        remediation="Set encryption/authentication-required permissions on "
                        "sensitive characteristics; gate PHI behind LESC-authenticated bonding.")

        # D.2 — unauthenticated WRITE. SAFETY: never blind-fuzz a live medical actuator.
        writable = [c["handle"] for c in chars if c["writable"]]
        if writable:
            ans = self._prompt(
                f"{len(writable)} writable characteristic(s) were found on {mac}. Attempting a "
                f"write on an UNPAIRED link tests for unauthenticated device control (CWE-306). "
                f"SAFETY: only proceed on a bench unit or with a known-benign/no-op value — do "
                f"NOT blind-write a control point on a live medical device. Attempt a benign "
                f"test write now?",
                options=["Yes — benign write authorized (bench/no-op)",
                         "No — record as untested"], prompt_type="choice", skippable=True)
            if (ans or "").lower().startswith("yes"):
                wr = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_unauth_write.txt"
                h = writable[0]
                try:
                    rc, out, err = run_tool(["gatttool", "-b", mac, "-t", atype,
                                             "--char-write-req", "-a", h, "-n", "00"],
                                            self.ctx, tool_name="gatttool",
                                            output_file=wr, timeout=20)
                    blob = (out or "") + (err or "")
                    if re.search(r"written successfully", blob, re.I):
                        self._f(self.T_UNAUTH_WRITE,
                                f"A GATT write to {mac} handle {h} SUCCEEDED over an unpaired, "
                                f"unencrypted link (ATT Write Response, no security error). "
                                f"Unauthenticated write access to device characteristics permits "
                                f"configuration change, actuation, or firmware/OTA abuse without "
                                f"any credential — the highest-impact GATT finding.",
                                "Critical", tool="gatttool", ip=mac, output_file=str(wr),
                                force_classification="Validated",
                                remediation="Require an authenticated + encrypted + bonded link "
                                "(LESC + MITM) for all writes; add application-layer "
                                "authorization (signed/challenge-response commands) to control "
                                "points and OTA.")
                except Exception:
                    pass

        # D.3 — unauthenticated notification/indication subscription. Enabling a CCCD
        # (0x2902 → 0x0001) on an UNPAIRED link without an ATT security error means the
        # device streams telemetry to any listener with no authentication.
        notify_chars = [c for c in chars if c.get("notify")]
        if _bt_which("gatttool") and notify_chars:
            nz = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_unauth_notify.txt"
            sub_ok = []
            lines = []
            for c in notify_chars[:20]:
                try:
                    cccd = "0x%04x" % (int(c["handle"], 16) + 1)   # CCCD usually follows the value handle
                    rc, out, err = run_tool(["gatttool", "-b", mac, "-t", atype,
                                             "--char-write-req", "-a", cccd, "-n", "0100"],
                                            self.ctx, tool_name="gatttool", timeout=20)
                    blob = (out or "") + (err or "")
                    lines.append(f"{c['handle']} CCCD {cccd}: {blob.strip()}")
                    if re.search(r"written successfully", blob, re.I):
                        sub_ok.append(c["handle"])
                except Exception:
                    pass
            try: nz.write_text("\n".join(lines), encoding="utf-8")
            except Exception: pass
            if sub_ok:
                self._f(self.T_UNAUTH_NOTIFY,
                        f"{len(sub_ok)} notify/indicate characteristic(s) on {mac} accepted a CCCD "
                        f"subscription over an UNPAIRED, unencrypted link (ATT Write Response on the "
                        f"0x2902 descriptor, no 0x05/0x0F error). Handles: {', '.join(sub_ok[:12])}. "
                        f"Any in-range listener can stream the device's telemetry/notifications with "
                        f"no authentication — severe when the stream carries PHI.",
                        "High", tool="gatttool", ip=mac, output_file=str(nz),
                        remediation="Require encryption/authentication on the CCCD and its source "
                        "characteristic; do not start notifications before authenticated bonding.")

        # Active MITM relay — requires 2 adapters / relay tooling; operator-driven.
        mitm_tools = [t for t in ("gattacker", "btlejuice", "mirage", "wble-proxy") if _bt_which(t)]
        ans = self._prompt(
            f"Active MITM/GATT-relay against {mac}: interpose a cloned peripheral between the "
            f"central (phone/app) and the device to relay & modify traffic. "
            + ("Detected relay tooling: " + ", ".join(mitm_tools) + ". " if mitm_tools
               else "No relay framework (gattacker/btlejuice/WHAD) detected on PATH. ")
            + "Was an active MITM successfully established (traffic relayed / device actuated "
            "through the relay)?",
            options=["Yes — MITM established / device actuated via relay",
                     "No — MITM blocked / not attempted",
                     "Not tested (no second adapter)"],
            prompt_type="choice", skippable=True)
        if (ans or "").lower().startswith("yes"):
            self._f(self.T_METHOD_CONF,
                    f"An active man-in-the-middle relay was established against {mac}: an "
                    f"attacker interposed between the central and the device and relayed/modified "
                    f"GATT traffic. Combined with a Just-Works/static-passkey/downgrade weakness "
                    f"this yields full control of the session (see the pairing findings for the "
                    f"enabling condition).",
                    "High", tool="bluetooth", ip=mac, force_classification="Validated",
                    remediation="Enforce LESC with real MITM protection (Numeric Comparison / "
                    "unique per-pairing passkey / OOB) and authenticated reconnection so a "
                    "relayed peripheral cannot complete pairing.")

        # DoS — BlueSmack / l2ping flood. Authorized + bounded only.
        if _bt_which("l2ping"):
            ans = self._prompt(
                f"Denial-of-service probe against {mac} (BlueSmack — oversized L2CAP echo / "
                f"l2ping flood). This can hang or reboot the device. Run a BOUNDED, authorized "
                f"DoS probe now?",
                options=["Yes — authorized, bounded DoS probe", "No — skip DoS"],
                prompt_type="choice", skippable=True)
            if (ans or "").lower().startswith("yes"):
                dz = out_dir / f"{self.ctx.file_prefix}_{mac.replace(':','')}_l2ping.txt"
                degraded = None
                try:
                    run_tool(["bash", "-c",
                              f"timeout 20 l2ping -i hci0 -s 600 -c 30 -f {mac} || true"],
                             self.ctx, tool_name="l2ping", output_file=dz, timeout=35)
                    obs = self._prompt(
                        f"Did {mac} become unresponsive, disconnect, or reboot during the probe?",
                        options=["Yes — device degraded/rebooted", "No — unaffected"],
                        prompt_type="choice", skippable=True)
                    degraded = (obs or "").lower().startswith("yes")
                except Exception:
                    pass
                if degraded:
                    self._f(self.T_BLUESMACK,
                            f"{mac} degraded or reset under a bounded L2CAP echo/l2ping flood "
                            f"(BlueSmack). The stack does not rate-limit or bound oversized echo "
                            f"requests, allowing an in-range attacker to deny service.",
                            "Medium", tool="l2ping", ip=mac, output_file=str(dz),
                            force_classification="Validated",
                            remediation="Patch the stack (input-length validation), rate-limit/"
                            "throttle L2CAP echo and connection requests, and make the radio "
                            "non-connectable when unused.")

                # Connection-exhaustion variant: rapid l2ping flood to consume slots.
                obs2 = self._prompt(
                    f"Connection-exhaustion probe: a high-rate l2ping flood was applied to {mac}. "
                    f"Did it start REFUSING or resetting connections (slots exhausted)?",
                    options=["Yes — connections refused/reset", "No — unaffected", "Not tested"],
                    prompt_type="choice", skippable=True)
                if (obs2 or "").lower().startswith("yes"):
                    self._f(self.T_DOS_FLOOD,
                            f"{mac} refused or reset connections under a sustained l2ping / "
                            f"connection-open flood — it does not rate-limit inbound connection "
                            f"requests or cap concurrent connections, so an in-range attacker can "
                            f"exhaust its connection slots and deny service to legitimate centrals.",
                            "Medium", tool="l2ping", ip=mac, output_file=str(dz),
                            force_classification="Validated",
                            remediation="Rate-limit inbound connection requests, cap concurrent "
                            "connections, recover gracefully, and make the radio non-connectable "
                            "when idle.")

    # ── Phase 5b — CVE-family surface from chip / stack fingerprint ──────────
    def _phase5_cve_surface(self, dev: dict) -> None:
        mac = dev["mac"]
        # Vendor from OUI (first 3 octets) — best-effort via btmgmt/company data.
        vendor = ""
        for cid in dev.get("company_ids", []):
            nm = _BT_COMPANY_IDS.get(cid, "")
            if nm:
                vendor = nm.lower(); break
        if not vendor:
            ans = self._prompt(
                f"To rule out chip-specific memory-corruption CVE families for {mac}, provide "
                f"the Bluetooth SoC vendor if known (from FCC ID / teardown / DIS manufacturer). "
                f"Select the closest match.",
                options=["Telink", "Espressif (ESP32)", "Cypress/Infineon", "Nordic",
                         "Texas Instruments", "Dialog", "NXP", "STMicro", "Qualcomm/CSR",
                         "Broadcom", "Intel", "Unknown / skip"],
                prompt_type="choice", skippable=True)
            vendor = (ans or "").lower()

        for key, info in _BT_VENDOR_CVE_FAMILY.items():
            if key in vendor:
                fam = info["family"]
                title = (self.T_SWEYNTOOTH if "SweynTooth" in fam and "Brak" not in fam
                         else self.T_BRAKTOOTH if fam == "BrakTooth"
                         else self.T_SWEYNTOOTH)
                if fam.startswith("BleedingTooth"):
                    title = self.T_BLEEDINGTOOTH
                self._f(title,
                        f"The Bluetooth SoC in {mac} ({vendor}) belongs to a vendor with known "
                        f"{fam} firmware vulnerabilities. {info['note']} Exposure is decided by "
                        f"the exact SoC part and SDK/firmware version — confirm the running "
                        f"firmware against the vendor advisory (several are safety-relevant per "
                        f"the FDA/CISA SweynTooth advisory ICS-ALERT-20-063-01). Validate on a "
                        f"non-production unit with the corresponding PoC (SweynTooth / BrakTooth).",
                        "High", tool="bluetooth", ip=mac,
                        force_classification="Potential",
                        remediation="Update the Bluetooth controller firmware/SDK to a patched "
                        "release; where the SoC is end-of-life ('no fix planned'), apply "
                        "architectural mitigations (disable unused profiles, restrict pairing, "
                        "physical/RF controls).")
                break

        # BleedingTooth / BlueBorne are host-stack (the DUT's OS/kernel) — operator-supplied.
        ans = self._prompt(
            f"Host Bluetooth stack of {mac}'s controller-side software, if it is a "
            f"Linux/Android system (rules out BleedingTooth / BlueBorne). What is the OS / "
            f"kernel / patch level?",
            options=["Linux kernel < 5.9 (unpatched BlueZ)",
                     "Android security patch < 2017-09",
                     "Patched / current",
                     "Not applicable / embedded RTOS",
                     "Unknown"], prompt_type="choice", skippable=True)
        a = (ans or "").lower()
        if "kernel < 5.9" in a:
            self._f(self.T_BLEEDINGTOOTH,
                    f"The Linux host behind {mac} runs an unpatched BlueZ kernel (< 5.9), exposing "
                    f"the BleedingTooth family — BadKarma (CVE-2020-12351, L2CAP heap type-"
                    f"confusion → zero-click kernel RCE), BadChoice (CVE-2020-12352 info leak), "
                    f"BadVibes (CVE-2020-24490 BLE ext-advertising heap overflow).",
                    "High", tool="bluetooth", ip=mac, force_classification="Potential",
                    remediation="Patch the kernel to 5.9+ (or vendor backport); set "
                    "CONFIG_BT_HS=n to remove the A2MP path; rfkill unused radios.")
        elif "android security patch < 2017-09" in a:
            self._f(self.T_BLUEBORNE,
                    f"The Android host behind {mac} predates the 2017-09 security patch, exposing "
                    f"BlueBorne (CVE-2017-0781/0782 BNEP heap overflow → RCE; CVE-2017-0785 SDP "
                    f"info leak; CVE-2017-1000251 Linux L2CAP RCE). BlueBorne needs only that "
                    f"Bluetooth is on — 'non-discoverable' is not a mitigation.",
                    "High", tool="bluetooth", ip=mac, force_classification="Potential",
                    remediation="Apply the 2017-09+ vendor security patches; disable Bluetooth "
                    "when unused.")

    # ── Phase 5c — known-CVE attack triage (specialised tooling) ─────────────
    def _phase5_known_attacks(self, dev: dict) -> None:
        """Present each known-CVE attack (KNOB / BIAS / BLURtooth / BLUFFS / BLESA /
        invalid-curve / LL-fuzz) with its detection oracle and record the finding when
        the operator confirms the vulnerable result. These require InternalBlue / PoC
        suites / a second radio, so the module gathers the observed result rather than
        pretending to automate them — every catalogued test can still produce a finding."""
        mac = dev["mac"]
        self._event(f"Phase 5c — known-CVE attack triage {mac}")
        go = self._prompt(
            f"Run the known-CVE Bluetooth attack triage for {mac}? These attacks (KNOB, BIAS, "
            f"BLURtooth, BLUFFS, BLESA, CVE-2018-5383, LL-fuzz) need specialised tooling "
            f"(InternalBlue / PoC suites / a second radio); you confirm the observed result and "
            f"Gearbox records the finding. SAFETY: several are destructive — bench units only.",
            options=["Yes — run triage", "Skip"], prompt_type="choice", skippable=True)
        if not go or go.lower().startswith("skip"):
            return
        for atk in _BT_KNOWN_ATTACKS:
            ans = self._prompt(f"[{atk['label']}] {atk['question']}",
                               options=atk["options"], prompt_type="choice", skippable=True)
            if ans and ans.strip() == atk["vuln"]:
                self._f(getattr(self, atk["const"]),
                        atk["desc"].format(mac=mac),
                        atk["risk"], tool="bluetooth", ip=mac,
                        force_classification="Validated" if atk.get("validated") else "Potential",
                        remediation=atk["rem"])

    # ── Phase 6 — cleanup ───────────────────────────────────────────────────
    def _phase6_cleanup(self, targets: list[dict]) -> None:
        self._event("Phase 6 — cleanup (unpair / restore)")
        if not _bt_which("bluetoothctl"):
            return
        for dev in targets:
            try:
                subprocess.run(
                    ["bash", "-c",
                     f"(echo 'remove {dev['mac']}'; echo 'quit') | bluetoothctl"],
                    capture_output=True, text=True, timeout=15)
            except Exception:
                pass
        try:
            run_tool(["bash", "-c", "btmgmt sc on || true"], self.ctx,
                     tool_name="btmgmt", timeout=15)
        except Exception:
            pass


# ===========================================================================
# WiFi interface module  (integrated 2026-08-13 from _frag/WiFi.py)
# ===========================================================================
# ---------------------------------------------------------------------------
# WiFi / 802.11 Module  (zero-knowledge wireless-interface assessment)
# ---------------------------------------------------------------------------
# One module, five phases: hardware / monitor-mode setup -> discovery
# (airodump + iw scan -> APs, encryption, channel, WPS, PMF/802.11w) ->
# per-AP analysis (WPS pixie-dust, PMKID/handshake capturability, PMF deauth,
# WPA3-transition downgrade, evil-twin feasibility, deauth DoS) -> cleanup.
# Detection is ORACLE-DRIVEN from cleartext-observable radio signals: the
# beacon/RSN Information Element (privacy bit, pairwise/AKM suites, RSN
# capability MFP bits), the WPS IE, and the association/EAPOL exchange are all
# passively readable, so each weakness class is ruled out generically without
# any prior knowledge of the target network.  Anything that could disrupt a
# LIVE medical device (deauthentication, association floods, active PMKID
# solicitation, evil-twin) is gated behind an explicit operator confirmation
# and defaults to non-destructive passive capture.

# Wireless test hardware offered at Phase 0.  quiver = the Quiver firmware/setup
# payload that provisions the board where applicable (see /opt/pr0t31n/Quiver).
_WIFI_HARDWARE: list[dict] = [
    {"key": "alfa_acm", "monitor": True, "injection": True, "dualband": True,
     "label": "Alfa AWUS036ACM (MediaTek MT7612U) — dual-band a/b/g/n/ac",
     "quiver": None,
     "setup": ["No firmware flash — mt76x2u driver is in-tree on modern kernels.",
               "Plug in, then `sudo airmon-ng check kill; sudo airmon-ng start wlan0`.",
               "Dual-band (2.4 + 5 GHz) monitor + frame injection — TOP PICK for",
               "  WPA2/WPA3, PMKID, handshake capture and 802.11w deauth testing.",
               "Verify injection with `aireplay-ng --test <mon>`."]},
    {"key": "alfa_neh", "monitor": True, "injection": True, "dualband": False,
     "label": "Alfa AWUS036NEH (Ralink RT3070) — 2.4 GHz b/g/n",
     "quiver": None,
     "setup": ["In-tree rt2800usb driver. `airmon-ng start wlan0`.",
               "2.4 GHz only — good injection range for legacy/WPA2 networks;",
               "  cannot see or test 5 GHz APs (use the ACM for dual-band)."]},
    {"key": "alfa_h", "monitor": True, "injection": True, "dualband": False,
     "label": "Alfa AWUS036H (Realtek RTL8187) — 2.4 GHz b/g (legacy)",
     "quiver": None,
     "setup": ["rtl8187 driver. `airmon-ng start wlan0`.",
               "Legacy 802.11b/g — strongest choice for WEP / older-AP work and",
               "  aireplay fragmentation/chopchop; no n/ac support."]},
    {"key": "pineapple", "monitor": True, "injection": True, "dualband": True,
     "label": "Hak5 WiFi Pineapple Mark VII — recon / PineAP / evil-twin",
     "quiver": "PAYLOAD - WiFi Pineapple recon",
     "setup": ["Standalone appliance — SSH to root@172.16.42.1 or drive its web UI.",
               "Recon dashboard performs the AP/client scan; PineAP provides the",
               "  rogue-AP / evil-twin / karma capability tested in Phase 2.",
               "Handshakes land in /root/handshakes; pull them for aircrack/hashcat.",
               "Use its own USB-Ethernet management link, NOT as a host mon iface."]},
    {"key": "wifiduck", "monitor": False, "injection": False, "dualband": False,
     "label": "Hak5 WiFi Duck (ESP8266) — wireless BadUSB / beacon+deauth payloads",
     "quiver": "PAYLOAD - WiFi Duck",
     "setup": ["ESP8266-based wireless keystroke-injection (BadUSB) tool — it is",
               "  NOT an 802.11 monitor-capture adapter and cannot sniff EAPOL.",
               "Auxiliary use only: beacon-spam / targeted-deauth payloads and",
               "  wireless HID injection. Pair with an Alfa adapter for capture."]},
]


def _wifi_which(name: str) -> Optional[str]:
    """Locate an 802.11 tool binary (PATH + common install dirs)."""
    p = shutil.which(name)
    if p:
        return p
    for cand in (f"/usr/bin/{name}", f"/usr/local/bin/{name}",
                 f"/usr/sbin/{name}", f"/sbin/{name}", f"/opt/{name}"):
        if os.path.exists(cand):
            return cand
    return None


def _wifi_have_toolkit() -> bool:
    """True when at least the core aircrack-ng suite (airodump/airmon) is present."""
    return bool(_wifi_which("airodump-ng") and _wifi_which("airmon-ng"))


def _wifi_list_ifaces() -> list[str]:
    """Enumerate wireless interface names via /sys/class/net (best-effort)."""
    ifaces: list[str] = []
    try:
        for n in sorted(os.listdir("/sys/class/net")):
            if os.path.isdir(f"/sys/class/net/{n}/wireless") or \
               os.path.exists(f"/sys/class/net/{n}/phy80211"):
                ifaces.append(n)
    except Exception:
        pass
    return ifaces


def _wifi_norm_bssid(b: str) -> str:
    return (b or "").strip().upper()


def _wifi_enc_class(privacy: str, cipher: str, auth: str) -> dict:
    """
    Classify an AP's encryption from airodump CSV fields.
    Returns {open, wep, wpa, wpa2, wpa3, transition, psk, enterprise, label}.
    """
    p = (privacy or "").upper()
    c = (cipher or "").upper()
    a = (auth or "").upper()
    out = {"open": False, "wep": False, "wpa": False, "wpa2": False,
           "wpa3": False, "transition": False, "psk": False,
           "enterprise": False, "label": p or "unknown"}
    if not p or p in ("OPN", "OPEN"):
        out["open"] = True
        out["label"] = "Open (no encryption)"
        return out
    if "WEP" in p:
        out["wep"] = True
        out["label"] = "WEP"
        return out
    if "WPA3" in p or "SAE" in a:
        out["wpa3"] = True
    if "WPA2" in p:
        out["wpa2"] = True
    if p == "WPA" or ("WPA" in p and "WPA2" not in p and "WPA3" not in p):
        out["wpa"] = True
    # airodump prints joint "WPA2 WPA3" and both AKMs for transition-mode SAE/PSK.
    if out["wpa3"] and (out["wpa2"] or "PSK" in a):
        out["transition"] = True
    if "MGT" in a or "802.1X" in a or "EAP" in a:
        out["enterprise"] = True
    if "PSK" in a or "SAE" in a:
        out["psk"] = True
    out["label"] = p
    return out


def _wifi_parse_airodump_csv(path: Path) -> tuple[list[dict], list[dict]]:
    """
    Parse an airodump-ng CSV (--output-format csv).  Returns (aps, clients).
    AP dict: bssid, channel, privacy, cipher, auth, power, beacons, essid, hidden.
    """
    aps: list[dict] = []
    clients: list[dict] = []
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return aps, clients
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("bssid,") and "essid" in low:
            section = "ap";      continue
        if low.startswith("station mac"):
            section = "client";  continue
        cols = [c.strip() for c in line.split(",")]
        if section == "ap" and len(cols) >= 14:
            bssid = _wifi_norm_bssid(cols[0])
            if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", bssid):
                continue
            essid = cols[13].strip()
            aps.append({
                "bssid": bssid, "channel": cols[3].strip(),
                "privacy": cols[5].strip(), "cipher": cols[6].strip(),
                "auth": cols[7].strip(), "power": cols[8].strip(),
                "beacons": cols[9].strip(),
                "essid": essid,
                "hidden": (essid == "" or essid.startswith("\\x00")
                           or set(essid) == {"\x00"}),
                "clients": [], "wps": None, "wps_locked": None,
                "mfp_capable": None, "mfp_required": None, "akm": set(),
            })
        elif section == "client" and len(cols) >= 6:
            sta = _wifi_norm_bssid(cols[0])
            ap = _wifi_norm_bssid(cols[5])
            if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", sta):
                clients.append({"mac": sta, "ap": ap, "power": cols[3].strip()})
    for cl in clients:
        for ap in aps:
            if ap["bssid"] == cl["ap"]:
                ap["clients"].append(cl["mac"])
    return aps, clients


def _wifi_parse_iw_scan(text: str) -> dict:
    """
    Parse `iw dev <iface> scan` output into {bssid_upper: attrs}.
    attrs: ssid, hidden, wep, wpa, wpa2, wpa3, akm(set), mfp_capable,
    mfp_required, wps, wps_locked.
    """
    out: dict[str, dict] = {}
    cur: Optional[dict] = None
    for raw in (text or "").splitlines():
        m = re.match(r"^BSS\s+([0-9a-fA-F:]{17})", raw)
        if m:
            cur = {"ssid": "", "hidden": False, "wep": False, "wpa": False,
                   "wpa2": False, "wpa3": False, "akm": set(),
                   "mfp_capable": False, "mfp_required": False,
                   "wps": False, "wps_locked": False, "privacy": False}
            out[m.group(1).upper()] = cur
            continue
        if cur is None:
            continue
        s = raw.strip()
        sm = re.match(r"^SSID:\s*(.*)$", s)
        if sm:
            ssid = sm.group(1)
            cur["ssid"] = ssid
            if ssid == "" or "\\x00" in ssid or set(ssid) == {"\x00"}:
                cur["hidden"] = True
            continue
        if s.startswith("RSN:"):
            cur["wpa2"] = True
            continue
        if s.startswith("WPA:"):
            cur["wpa"] = True
            continue
        if s.startswith("WPS:"):
            cur["wps"] = True
            continue
        if "capability" in s.lower() and "privacy" in s.lower():
            cur["privacy"] = True
        if "Authentication suites:" in s:
            if "SAE" in s:
                cur["wpa3"] = True
                cur["akm"].add("SAE")
            if "PSK" in s:
                cur["akm"].add("PSK")
            if re.search(r"\bIEEE 802\.1X\b|\bEAP\b|\b1X\b", s):
                cur["akm"].add("802.1X")
            continue
        if "Capabilities:" in s and ("MFP" in s):
            if "MFP-required" in s:
                cur["mfp_required"] = True
            if "MFP-capable" in s:
                cur["mfp_capable"] = True
            continue
        if "AP setup locked" in s:
            cur["wps_locked"] = True
    return out


class WiFiModule(BaseModule):
    """
    Zero-knowledge 802.11 Wi-Fi assessment of a device's wireless interface.

    Runs the full chain — monitor-mode setup, discovery, and per-AP analysis —
    against whatever wireless network the device under test exposes or joins,
    ruling out each known weakness (open/WEP, WPS/pixie-dust, capturable
    PSK handshake / clientless PMKID, missing 802.11w PMF, WPA3-transition
    downgrade, rogue-AP/evil-twin, deauth DoS) from cleartext-observable beacon
    and RSN-IE signals.  Destructive tests (deauth, association flood, active
    PMKID solicitation, evil-twin) are operator-gated and default off.
    """
    name        = "WiFi"
    description = "Zero-knowledge 802.11 assessment (monitor setup → discovery → per-AP analysis)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_DISCOVERED   = "Wi-Fi Network Discovered"
    T_OPEN         = "Open Wi-Fi Network — No Encryption"
    T_WEP          = "WEP Encryption in Use"
    T_HANDSHAKE    = "WPA/WPA2-PSK Handshake Capturable"
    T_PMKID        = "WPA PMKID Capturable (Clientless)"
    T_WPS_ON       = "WPS Enabled"
    T_WPS_PIXIE    = "WPS Pixie-Dust Vulnerable"
    T_NO_PMF       = "Missing 802.11w Management Frame Protection"
    T_WPA3_DOWN    = "WPA3 Transition Mode Downgrade"
    T_EVIL_TWIN    = "Rogue Access Point / Evil Twin Feasible"
    T_DEAUTH_DOS   = "Wi-Fi Deauthentication Denial of Service"
    T_SKIPPED      = "Wi-Fi Testing SKIPPED — No Wireless Adapter or Toolkit Available"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "WiFi" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane 802.11 defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "wifi"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [WiFi] {msg}", tool=self.name)
        except Exception:
            pass

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"WiFiModule v{VERSION} started for [{self.ctx.instance_loc}]")
            hw = self._phase0_hardware()
            if hw is None:
                return  # skipped — honest finding already emitted
            aps = self._phase1_discovery(hw)
            targets = self._phase1_select(aps)
            if not targets:
                self._phase_cleanup(hw)
                self._mark_complete("Discovery complete — no in-scope AP selected")
                return
            for ap in targets:
                self._assess_ap(hw, ap)
            self._phase_cleanup(hw)
            self._mark_complete(
                f"Wi-Fi assessment complete — {len(targets)} network(s) tested")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — hardware / monitor-mode setup ─────────────────────────────
    def _phase0_hardware(self) -> Optional[dict]:
        self._event("Phase 0 — hardware selection & monitor-mode setup")
        labels = [h["label"] for h in _WIFI_HARDWARE]
        choice = self._prompt(
            "Select the Wi-Fi testing adapter in use. Monitor-mode capture, PMKID, "
            "handshake and 802.11w/deauth testing require a monitor+injection adapter "
            "(Alfa ACM/NEH/H or Pineapple). The WiFi Duck is a BadUSB/beacon tool only "
            "and cannot sniff EAPOL.\n"
            "Refer to Quiver to provision the Pineapple / WiFi Duck payload first.",
            options=labels + ["Skip Wi-Fi testing"],
            prompt_type="choice", skippable=True)

        hw = next((h for h in _WIFI_HARDWARE if h["label"] == choice), None)
        if hw is None or (choice or "").lower().startswith("skip"):
            self._f(self.T_SKIPPED,
                    "No Wi-Fi monitor-mode adapter was selected for this instance, so "
                    "802.11 testing was NOT performed. Attach an Alfa AWUS036ACM/NEH/H "
                    "(or drive the WiFi Pineapple Mark VII) and install the aircrack-ng "
                    "suite (see install.py), then re-run the module.",
                    "Informational", tool="wifi")
            self._mark_complete("Wi-Fi SKIPPED — no adapter selected")
            return None

        if not hw.get("monitor"):
            self._f(self.T_SKIPPED,
                    f"The selected device ({hw['label']}) is not an 802.11 monitor-mode "
                    "capture adapter, so passive Wi-Fi capture (discovery / PMKID / "
                    "handshake) could not be performed. Use an Alfa AWUS036ACM/NEH/H or "
                    "the WiFi Pineapple for the capture phases.",
                    "Informational", tool="wifi")
            self._mark_complete("Wi-Fi SKIPPED — non-capture device selected")
            return None

        if not _wifi_have_toolkit():
            self._f(self.T_SKIPPED,
                    "The aircrack-ng suite (airmon-ng / airodump-ng) was not found on "
                    "PATH, so Wi-Fi testing was NOT performed. Install aircrack-ng "
                    "(see install.py) and re-run the module.",
                    "Informational", tool="wifi")
            self._mark_complete("Wi-Fi SKIPPED — aircrack-ng not installed")
            return None

        # Log board-specific setup guidance.
        self.ctx.logger.info(f"Selected Wi-Fi hardware: {hw['label']}", tool=self.name)
        if hw.get("quiver"):
            self.ctx.logger.info(
                f"Provision via Quiver payload: '{hw['quiver']}'", tool=self.name)
        for ln in hw["setup"]:
            self.ctx.logger.info(f"  {ln}", tool=self.name)
        setup_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_hardware_setup.txt"
        try:
            setup_txt.write_text(
                f"Wi-Fi testing hardware: {hw['label']}\n"
                + (f"Quiver payload: {hw['quiver']}\n" if hw.get("quiver") else "")
                + "\n" + "\n".join(hw["setup"]) + "\n", encoding="utf-8")
        except Exception:
            pass
        self._prompt_connected_photo(
            f"{hw['label']} connected for [{self.ctx.instance_loc}]")

        # Choose the managed wireless interface.
        ifaces = _wifi_list_ifaces()
        iface = ""
        if ifaces:
            ans = self._prompt(
                "Select the wireless interface for this adapter (managed name, e.g. "
                "wlan0). airmon-ng will place it into monitor mode.",
                options=ifaces + ["Enter manually"], prompt_type="choice")
            iface = ans if ans in ifaces else ""
        if not iface:
            iface = (self._prompt(
                "Enter the wireless interface name (e.g. wlan0):",
                prompt_type="text", skippable=True) or "").strip() or "wlan0"

        # Passive managed-mode scan FIRST (RSN/MFP/WPA3/WPS/hidden detail).
        iw_map: dict = {}
        if _wifi_which("iw"):
            iw_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_iw_scan.txt"
            try:
                rc, out, err = run_tool(
                    ["bash", "-c", f"timeout 30 iw dev {iface} scan 2>&1 || true"],
                    self.ctx, tool_name="iw", output_file=iw_txt, timeout=45)
                iw_map = _wifi_parse_iw_scan(out or "")
            except Exception as e:
                self.ctx.logger.warn(f"iw scan failed on {iface}: {e}", tool=self.name)

        # Bring up monitor mode (best-effort — needs root).
        mon = ""
        try:
            run_tool(["airmon-ng", "check", "kill"], self.ctx,
                     tool_name="airmon-ng", timeout=30)
            mstart = self._dir("00_setup") / f"{self.ctx.file_prefix}_airmon_start.txt"
            rc, out, err = run_tool(["airmon-ng", "start", iface], self.ctx,
                                    tool_name="airmon-ng", output_file=mstart, timeout=45)
            blob = (out or "") + (err or "")
            mm = re.search(r"(?:monitor mode.*?on|\[phy\d+\])\s*(\w+mon|mon\d+|\w+)", blob)
            for cand in re.findall(r"\b(\w*mon\d*|\w+mon)\b", blob):
                if cand:
                    mon = cand; break
        except Exception as e:
            self.ctx.logger.warn(f"airmon-ng start failed: {e}", tool=self.name)
        if not mon:
            mon = (self._prompt(
                f"Could not auto-detect the monitor interface for {iface}. Enter the "
                f"monitor interface name (e.g. {iface}mon or wlan0mon), or Skip:",
                prompt_type="text", skippable=True) or "").strip()
        if not mon:
            mon = f"{iface}mon"
        self.ctx.logger.info(f"Monitor interface: {mon}", tool=self.name)
        return {"hw": hw, "iface": iface, "mon": mon, "iw_map": iw_map}

    # ── Phase 1 — discovery ─────────────────────────────────────────────────
    def _phase1_discovery(self, hw: dict) -> list[dict]:
        self._event("Phase 1 — discovery (airodump scan)")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Scanning for Wi-Fi networks…")
        out_dir = self._dir("01_discovery")
        mon = hw["mon"]
        prefix = out_dir / f"{self.ctx.file_prefix}_airodump"
        csv_path = Path(str(prefix) + "-01.csv")

        # Bounded passive airodump sweep across all channels.
        try:
            run_tool(["bash", "-c",
                      f"timeout 30 airodump-ng --write {prefix} --output-format csv "
                      f"--write-interval 1 {mon} >/dev/null 2>&1 || true"],
                     self.ctx, tool_name="airodump-ng", output_file=csv_path, timeout=45)
        except Exception as e:
            self.ctx.logger.warn(f"airodump-ng sweep failed: {e}", tool=self.name)

        aps, clients = _wifi_parse_airodump_csv(csv_path)
        if not aps:
            # Fallback: try the last CSV airodump wrote (numbering may differ).
            for cand in sorted(out_dir.glob(f"{self.ctx.file_prefix}_airodump-*.csv")):
                aps, clients = _wifi_parse_airodump_csv(cand)
                if aps:
                    csv_path = cand; break

        # Merge iw-scan RSN/MFP/WPS/hidden detail onto matching BSSIDs.
        iw_map = hw.get("iw_map") or {}
        for ap in aps:
            info = iw_map.get(ap["bssid"])
            if info:
                ap["mfp_capable"]  = info.get("mfp_capable")
                ap["mfp_required"] = info.get("mfp_required")
                ap["wps"]          = info.get("wps")
                ap["wps_locked"]   = info.get("wps_locked")
                ap["akm"]          = info.get("akm") or set()
                if info.get("wpa3"): ap["_iw_wpa3"] = True
                if info.get("hidden"): ap["hidden"] = True
                if info.get("ssid") and ap["hidden"]:
                    ap["essid_leak"] = info["ssid"]

        self.ctx.logger.info(f"Discovered {len(aps)} Wi-Fi network(s)", tool=self.name)
        for ap in aps:
            enc = _wifi_enc_class(ap["privacy"], ap["cipher"], ap["auth"])
            ap["_enc"] = enc
            ssid = ap["essid"] or (ap.get("essid_leak") or "(hidden)")
            self._f(self.T_DISCOVERED,
                    f"A Wi-Fi network was discovered during zero-knowledge scanning: "
                    f"SSID '{ssid}', BSSID {ap['bssid']}, channel {ap['channel']}, "
                    f"encryption {enc['label']}, {len(ap['clients'])} associated "
                    f"client(s). Its beacon and RSN Information Element expand the "
                    f"wireless attack surface and drive the per-AP analysis.",
                    "Informational", tool="airodump-ng", ip=ap["bssid"],
                    affected_component=ssid, output_file=str(csv_path))
            # Whole-scan weaknesses visible without target selection.
            if enc["open"]:
                self._f(self.T_OPEN,
                        f"Network '{ssid}' ({ap['bssid']}) is an OPEN Wi-Fi network with "
                        f"no link-layer encryption. All traffic to and from any associated "
                        f"device is transmitted in cleartext and is readable, injectable, "
                        f"and modifiable by any listener in radio range.",
                        "High", tool="airodump-ng", ip=ap["bssid"],
                        affected_component=ssid, output_file=str(csv_path),
                        remediation="Deploy WPA3-SAE (or WPA2-PSK/Enterprise at minimum) "
                        "with 802.11w PMF required; never operate a medical device on an "
                        "open SSID.")
            elif enc["wep"]:
                self._f(self.T_WEP,
                        f"Network '{ssid}' ({ap['bssid']}) uses WEP, a cryptographically "
                        f"broken cipher. The RC4/IV key can be recovered from captured "
                        f"traffic in minutes (aircrack-ng PTW/chopchop/fragmentation), "
                        f"fully exposing all traffic and granting network access.",
                        "Critical", tool="airodump-ng", ip=ap["bssid"],
                        affected_component=ssid, output_file=str(csv_path),
                        cve_ids=[], remediation="Immediately replace WEP with WPA3-SAE "
                        "(or WPA2-CCMP with a strong passphrase) and 802.11w PMF; WEP has "
                        "no secure configuration.")
        return aps

    def _phase1_select(self, aps: list[dict]) -> list[dict]:
        if not aps:
            return []
        opts = []
        for ap in aps:
            ssid = ap["essid"] or (ap.get("essid_leak") or "(hidden)")
            opts.append(f"{ap['bssid']} — {ssid} [ch {ap['channel']}, "
                        f"{ap.get('_enc',{}).get('label', ap['privacy'] or '?')}]")
        ans = self._prompt(
            "Select the in-scope Wi-Fi network(s) under test — pick the AP the device "
            "under test hosts or connects to. Choose 'All discovered' to assess every "
            "network, or 'None' to stop after discovery.",
            options=["All discovered"] + opts + ["None"],
            prompt_type="choice", skippable=True)
        if not ans or ans.lower().startswith("none"):
            return []
        if ans.lower().startswith("all"):
            return aps
        for ap, o in zip(aps, opts):
            if o == ans:
                return [ap]
        return aps[:1]

    # ── Phase 2 — per-AP analysis ───────────────────────────────────────────
    def _assess_ap(self, hw: dict, ap: dict) -> None:
        bssid = ap["bssid"]
        ssid = ap["essid"] or (ap.get("essid_leak") or "(hidden)")
        self._event(f"Assessing {bssid} ({ssid})")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", f"Assessing {ssid}…")
        enc = ap.get("_enc") or _wifi_enc_class(ap["privacy"], ap["cipher"], ap["auth"])
        self._analyze_pmf(hw, ap, enc)
        self._analyze_wpa3(hw, ap, enc)
        self._analyze_wps(hw, ap)
        self._analyze_pmkid(hw, ap, enc)
        self._analyze_handshake(hw, ap, enc)
        self._analyze_evil_twin(hw, ap, enc)
        self._analyze_deauth_dos(hw, ap, enc)

    def _analyze_pmf(self, hw: dict, ap: dict, enc: dict) -> None:
        """Missing 802.11w PMF → beacon/deauth spoofing & client eviction."""
        if enc["open"] or enc["wep"]:
            return  # PMF is an RSN concept; open/WEP already flagged.
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        mfp_req = ap.get("mfp_required")
        mfp_cap = ap.get("mfp_capable")
        # Only flag when we positively observed that PMF is NOT required.
        if mfp_req is True:
            return
        if mfp_req is None and mfp_cap is None:
            ans = self._prompt(
                f"802.11w PMF status for '{ssid}' ({bssid}) could not be auto-read from "
                f"the RSN capabilities. From a Wireshark/iw view of the beacon RSN IE, is "
                f"Management Frame Protection REQUIRED (MFPR bit set)?",
                options=["MFP required (MFPR=1)", "MFP capable only (optional)",
                         "MFP absent (no PMF)", "Unknown"],
                prompt_type="choice", skippable=True)
            a = (ans or "").lower()
            if "required" in a:
                return
            if "unknown" in a or not a:
                return
        loc_file = str(self._dir("00_setup") / f"{self.ctx.file_prefix}_iw_scan.txt")
        self._f(self.T_NO_PMF,
                f"Network '{ssid}' ({bssid}) does not REQUIRE 802.11w Management Frame "
                f"Protection (MFPR bit clear in the RSN capabilities). Unprotected "
                f"management frames let an in-range attacker forge deauthentication/"
                f"disassociation frames to evict clients at will and force EAPOL "
                f"re-handshakes for offline cracking — a reliable availability and "
                f"handshake-harvesting primitive against the device under test.",
                "Medium", tool="iw", ip=bssid, affected_component=ssid,
                output_file=loc_file,
                remediation="Set Protected Management Frames to 'required' (802.11w MFPR) "
                "on the AP and device; WPA3-SAE mandates PMF. Where clients cannot support "
                "it, at minimum enable PMF-capable and prioritise a WPA3 migration.")

    def _analyze_wpa3(self, hw: dict, ap: dict, enc: dict) -> None:
        """WPA3 transition (mixed SAE+PSK) → offline downgrade to WPA2."""
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        akm = ap.get("akm") or set()
        transition = enc.get("transition") or (
            ap.get("_iw_wpa3") and ("PSK" in akm) and ("SAE" in akm))
        if not transition:
            return
        loc_file = str(self._dir("00_setup") / f"{self.ctx.file_prefix}_iw_scan.txt")
        self._f(self.T_WPA3_DOWN,
                f"Network '{ssid}' ({bssid}) advertises WPA3 in transition (mixed) mode — "
                f"the RSN IE offers both SAE (WPA3) and PSK (WPA2) AKM suites on the same "
                f"SSID. A rogue AP that advertises only WPA2-PSK forces a supplicant to "
                f"fall back to the WPA2 4-way handshake, which is then captured and cracked "
                f"offline (the Dragonblood transition-mode downgrade). The SAE upgrade "
                f"provides no protection while WPA2 fallback is accepted.",
                "Medium", tool="iw", ip=bssid, affected_component=ssid,
                output_file=loc_file,
                remediation="Move to WPA3-only (SAE) mode with PMF required once all "
                "clients support it; disable the WPA2 transition fallback for sensitive "
                "networks so a downgraded handshake cannot be solicited.")

    def _analyze_wps(self, hw: dict, ap: dict) -> None:
        """WPS enabled → external-registrar PIN brute / pixie-dust."""
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        mon = hw["mon"]
        out_dir = self._dir("02_wps")
        wps_on = ap.get("wps")
        wash_file = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_wash.txt"
        if wps_on is None and _wifi_which("wash"):
            try:
                rc, out, err = run_tool(
                    ["bash", "-c",
                     f"timeout 20 wash -i {mon} 2>&1 | grep -i '{bssid}' || true"],
                    self.ctx, tool_name="wash", output_file=wash_file, timeout=35)
                wps_on = bool((out or "").strip())
                ap["wps_locked"] = ap.get("wps_locked") or bool(
                    re.search(r"\byes\b", out or "", re.I))
            except Exception:
                pass
        if not wps_on:
            return
        self._f(self.T_WPS_ON,
                f"Network '{ssid}' ({bssid}) advertises Wi-Fi Protected Setup (WPS). The "
                f"8-digit registrar PIN is validated in two independently-checkable halves, "
                f"reducing the effective keyspace to ~11,000 attempts (online brute) and "
                f"often to a single offline computation (pixie-dust). Recovering the PIN "
                f"yields the WPA passphrase regardless of its strength.",
                "Medium", tool="wash", ip=bssid, affected_component=ssid,
                output_file=str(wash_file),
                remediation="Disable WPS entirely (external-registrar and PIN methods). "
                "If push-button is operationally required, ensure the PIN method is off and "
                "an AP-side lockout throttles failed registrar attempts.")

        # Pixie-dust is an ACTIVE registrar exchange — SAFETY-gated.
        if not (_wifi_which("reaver") or _wifi_which("bully")):
            return
        ans = self._prompt(
            f"WPS is enabled on '{ssid}' ({bssid}). A pixie-dust attack sends live WPS "
            f"registrar (M1-M3) frames to test for low-entropy E-S1/E-S2 nonce reuse "
            f"(offline PIN recovery). This is an ACTIVE association exchange. SAFETY: only "
            f"run against an authorised, non-production AP — it can disrupt a live device. "
            f"Attempt a bounded pixie-dust probe now?",
            options=["Yes — authorised, bounded pixie-dust probe",
                     "No — record WPS enabled only"],
            prompt_type="choice", skippable=True)
        if not (ans or "").lower().startswith("yes"):
            return
        chan = ap.get("channel") or "1"
        pix = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_pixie.txt"
        vulnerable = None
        try:
            rc, out, err = run_tool(
                ["bash", "-c",
                 f"timeout 90 reaver -i {mon} -b {bssid} -c {chan} -K 1 -N -vvv || true"],
                self.ctx, tool_name="reaver", output_file=pix, timeout=120)
            blob = (out or "") + (err or "")
            if re.search(r"pixie[- ]?dust|WPS pin:|WPA PSK:|pin cracked|"
                         r"\[\+\] pin\b", blob, re.I):
                vulnerable = True
        except Exception:
            pass
        if vulnerable is None:
            obs = self._prompt(
                f"Did the pixie-dust probe recover the WPS PIN / WPA passphrase for {bssid}?",
                options=["Yes — PIN/PSK recovered", "No — not vulnerable / failed"],
                prompt_type="choice", skippable=True)
            vulnerable = (obs or "").lower().startswith("yes")
        if vulnerable:
            self._f(self.T_WPS_PIXIE,
                    f"'{ssid}' ({bssid}) is vulnerable to the WPS pixie-dust attack: the "
                    f"registrar's E-S1/E-S2 Diffie-Hellman nonces are predictable, allowing "
                    f"the WPS PIN — and therefore the WPA passphrase — to be recovered "
                    f"offline in seconds without any online guessing. Full network access "
                    f"follows regardless of passphrase strength.",
                    "High", tool="reaver", ip=bssid, affected_component=ssid,
                    output_file=str(pix), force_classification="Validated",
                    cve_ids=[], remediation="Disable WPS entirely; the underlying nonce-"
                    "generation weakness cannot be configured away. Rotate the WPA "
                    "passphrase after disabling, as it is considered compromised.")

    def _analyze_pmkid(self, hw: dict, ap: dict, enc: dict) -> None:
        """Clientless PMKID capture (RSN) → offline WPA-PSK cracking."""
        if not (enc.get("wpa") or enc.get("wpa2")) or enc.get("enterprise"):
            return
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        if not (_wifi_which("hcxdumptool") and _wifi_which("hcxpcapngtool")):
            return
        ans = self._prompt(
            f"Clientless PMKID capture against '{ssid}' ({bssid}): hcxdumptool sends a "
            f"single association request to solicit the RSN PMKID (no client needed), then "
            f"hcxpcapngtool converts it to a hashcat-22000 hash for offline PSK cracking. "
            f"This is an ACTIVE association to the target AP only (filtered). SAFETY: run "
            f"only against an authorised AP. Attempt the PMKID capture now?",
            options=["Yes — authorised PMKID capture (target-filtered)",
                     "No — skip PMKID"],
            prompt_type="choice", skippable=True)
        if not (ans or "").lower().startswith("yes"):
            return
        out_dir = self._dir("03_pmkid")
        mon = hw["mon"]
        chan = ap.get("channel") or "1"
        pcapng = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_pmkid.pcapng"
        hashf = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_pmkid.hc22000"
        bssid_nc = bssid.replace(":", "").lower()
        captured = False
        try:
            run_tool(["bash", "-c",
                      f"timeout 40 hcxdumptool -i {mon} -o {pcapng} -c {chan} "
                      f"--filtermode=2 --filterlist_ap={bssid_nc} --enable_status=1 "
                      f">/dev/null 2>&1 || true"],
                     self.ctx, tool_name="hcxdumptool", output_file=pcapng, timeout=60)
            if pcapng.exists() and pcapng.stat().st_size > 0:
                rc, out, err = run_tool(
                    ["hcxpcapngtool", "-o", str(hashf), str(pcapng)],
                    self.ctx, tool_name="hcxpcapngtool", output_file=hashf, timeout=60)
                blob = (out or "") + (err or "")
                if re.search(r"PMKID", blob, re.I) and hashf.exists() \
                        and hashf.stat().st_size > 0:
                    captured = True
        except Exception as e:
            self.ctx.logger.warn(f"PMKID capture failed for {bssid}: {e}", tool=self.name)
        if captured:
            self._f(self.T_PMKID,
                    f"An RSN PMKID was captured from '{ssid}' ({bssid}) with a single "
                    f"association request and no connected client (hcxdumptool → "
                    f"hcxpcapngtool, hashcat mode 22000). The PMKID is derived from the "
                    f"PMK, so the WPA/WPA2-PSK passphrase can be recovered offline at full "
                    f"GPU speed; a weak or default passphrase is trivially cracked, "
                    f"granting full network access.",
                    "Medium", tool="hcxdumptool", ip=bssid, affected_component=ssid,
                    output_file=str(hashf), output_files=[str(pcapng)],
                    force_classification="Validated",
                    remediation="Use a long (>15 char) random WPA passphrase or migrate to "
                    "WPA3-SAE (SAE is not PMKID-crackable); disable PMKID caching on the AP "
                    "where the platform allows.")

    def _analyze_handshake(self, hw: dict, ap: dict, enc: dict) -> None:
        """WPA/WPA2-PSK 4-way handshake capturability (passive; deauth gated)."""
        if not (enc.get("wpa") or enc.get("wpa2")) or enc.get("enterprise"):
            return
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        mon = hw["mon"]
        chan = ap.get("channel") or "1"
        out_dir = self._dir("04_handshake")
        prefix = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_hs"
        cap = Path(str(prefix) + "-01.cap")
        # Passive targeted capture window.
        try:
            run_tool(["bash", "-c",
                      f"timeout 35 airodump-ng -c {chan} --bssid {bssid} -w {prefix} "
                      f"--output-format pcap {mon} >/dev/null 2>&1 || true"],
                     self.ctx, tool_name="airodump-ng", output_file=cap, timeout=55)
        except Exception:
            pass
        # Optionally force a re-handshake with a bounded deauth (SAFETY-gated).
        if ap.get("clients") and _wifi_which("aireplay-ng"):
            ans = self._prompt(
                f"'{ssid}' ({bssid}) has {len(ap['clients'])} associated client(s) but no "
                f"handshake was captured passively. A bounded deauthentication (a few "
                f"frames) would force a client to re-handshake so it can be captured. "
                f"SAFETY: deauth briefly disconnects the client — do NOT run against a live "
                f"medical device mid-procedure. Send a bounded deauth to capture a handshake?",
                options=["Yes — authorised, bounded deauth to capture",
                         "No — passive only"], prompt_type="choice", skippable=True)
            if (ans or "").lower().startswith("yes"):
                sta = ap["clients"][0]
                try:
                    run_tool(["bash", "-c",
                              f"timeout 20 aireplay-ng --deauth 3 -a {bssid} -c {sta} "
                              f"{mon} >/dev/null 2>&1 || true"],
                             self.ctx, tool_name="aireplay-ng", timeout=35)
                    run_tool(["bash", "-c",
                              f"timeout 25 airodump-ng -c {chan} --bssid {bssid} -w {prefix} "
                              f"--output-format pcap {mon} >/dev/null 2>&1 || true"],
                             self.ctx, tool_name="airodump-ng", output_file=cap, timeout=45)
                except Exception:
                    pass
        # Confirm handshake presence with aircrack-ng.
        got = None
        if cap.exists() and cap.stat().st_size > 0 and _wifi_which("aircrack-ng"):
            ac = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_aircrack.txt"
            try:
                rc, out, err = run_tool(["bash", "-c",
                                         f"echo | aircrack-ng {cap} 2>&1 || true"],
                                        self.ctx, tool_name="aircrack-ng",
                                        output_file=ac, timeout=45)
                if re.search(r"\(\s*[1-9]\d*\s+handshake", out or "", re.I) or \
                        re.search(r"1 handshake", out or "", re.I):
                    got = str(ac)
            except Exception:
                pass
        if got:
            self._f(self.T_HANDSHAKE,
                    f"A WPA/WPA2-PSK 4-way EAPOL handshake for '{ssid}' ({bssid}) was "
                    f"captured. The handshake is a verifiable offline oracle for the PSK: it "
                    f"can be run against dictionaries and GPU rules (aircrack-ng / hashcat "
                    f"mode 22000) at no network cost. A weak, default, or reused passphrase "
                    f"is recoverable, granting full access to the wireless network.",
                    "Medium", tool="aircrack-ng", ip=bssid, affected_component=ssid,
                    output_file=got, output_files=[str(cap)],
                    force_classification="Validated",
                    remediation="Use a long random WPA passphrase (>15 chars) or migrate to "
                    "WPA3-SAE, which is resistant to offline handshake cracking; require "
                    "802.11w PMF to raise the cost of forcing a re-handshake.")

    def _analyze_evil_twin(self, hw: dict, ap: dict, enc: dict) -> None:
        """Rogue-AP / evil-twin feasibility — operator-observed, active setup."""
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        rogue_tools = [t for t in ("bettercap", "hostapd", "airbase-ng", "eaphammer")
                       if _wifi_which(t)]
        hint = ("Detected tooling: " + ", ".join(rogue_tools) + ". " if rogue_tools
                else "No evil-twin framework (bettercap/hostapd/airbase-ng) on PATH; "
                     "the WiFi Pineapple PineAP can also host the rogue AP. ")
        ans = self._prompt(
            f"Rogue-AP / evil-twin feasibility for '{ssid}' ({bssid}): stand up an AP "
            f"cloning this SSID (optionally PMF-less / WPA2-only to force a downgrade) and "
            f"see whether the device under test associates or leaks credentials to it. "
            f"{hint}SAFETY: an evil twin can capture a live device onto an attacker network "
            f"— run only when authorised. Did the device associate to / accept the rogue AP?",
            options=["Yes — device associated / credentials captured via rogue AP",
                     "No — device rejected the rogue AP",
                     "Not tested"],
            prompt_type="choice", skippable=True)
        if (ans or "").lower().startswith("yes"):
            self._f(self.T_EVIL_TWIN,
                    f"The device under test associated with a rogue access point cloning "
                    f"'{ssid}' ({bssid}) instead of authenticating the real AP. Without "
                    f"server-certificate validation / PMF / a mutually-authenticated "
                    f"association, an evil twin in range can capture the device onto an "
                    f"attacker-controlled network, intercept and modify its traffic, and "
                    f"harvest credentials (captive-portal or EAP relay).",
                    "High", tool="bettercap", ip=bssid, affected_component=ssid,
                    force_classification="Validated",
                    remediation="Require WPA3-SAE with PMF (mutual authentication), or for "
                    "Enterprise validate the RADIUS server certificate and pin the CA on "
                    "the client so a rogue AP cannot complete association.")

    def _analyze_deauth_dos(self, hw: dict, ap: dict, enc: dict) -> None:
        """Deauthentication / disassociation flood DoS — SAFETY-gated, bounded."""
        bssid = ap["bssid"]
        ssid = ap["essid"] or "(hidden)"
        mon = hw["mon"]
        if ap.get("mfp_required") is True:
            return  # PMF-required networks resist forged deauth.
        if not (_wifi_which("mdk4") or _wifi_which("aireplay-ng")):
            return
        ans = self._prompt(
            f"Deauthentication DoS probe against '{ssid}' ({bssid}): a bounded burst of "
            f"forged deauth/disassoc frames tests whether an attacker can knock the device "
            f"off the network (only possible when 802.11w PMF is not required). SAFETY: "
            f"this WILL disconnect the device — do NOT run against a live medical device in "
            f"use. Run a bounded, authorised deauth DoS probe now?",
            options=["Yes — authorised, bounded deauth DoS probe", "No — skip DoS"],
            prompt_type="choice", skippable=True)
        if not (ans or "").lower().startswith("yes"):
            return
        out_dir = self._dir("05_dos")
        dz = out_dir / f"{self.ctx.file_prefix}_{bssid.replace(':','')}_deauth.txt"
        chan = ap.get("channel") or "1"
        degraded = None
        try:
            if _wifi_which("aireplay-ng"):
                run_tool(["bash", "-c",
                          f"timeout 15 aireplay-ng --deauth 10 -a {bssid} {mon} "
                          f">/dev/null 2>&1 || true"],
                         self.ctx, tool_name="aireplay-ng", output_file=dz, timeout=30)
            else:
                run_tool(["bash", "-c",
                          f"timeout 15 mdk4 {mon} d -c {chan} -B {bssid} "
                          f">/dev/null 2>&1 || true"],
                         self.ctx, tool_name="mdk4", output_file=dz, timeout=30)
            obs = self._prompt(
                f"Did the device under test on '{ssid}' disconnect, drop traffic, or fail "
                f"during the bounded deauth probe?",
                options=["Yes — device disconnected / disrupted", "No — unaffected"],
                prompt_type="choice", skippable=True)
            degraded = (obs or "").lower().startswith("yes")
        except Exception:
            pass
        if degraded:
            self._f(self.T_DEAUTH_DOS,
                    f"The device under test on '{ssid}' ({bssid}) was disconnected by a "
                    f"bounded forged-deauthentication burst. Because 802.11w PMF is not "
                    f"required, any in-range attacker can spoof management frames to deny "
                    f"the device network connectivity at will — a persistent availability "
                    f"attack against a wireless-dependent medical or clinical device.",
                    "Medium", tool="aireplay-ng", ip=bssid, affected_component=ssid,
                    output_file=str(dz), force_classification="Validated",
                    remediation="Enable 802.11w Protected Management Frames as REQUIRED "
                    "(mandatory under WPA3-SAE) so forged deauth/disassoc frames are "
                    "rejected; add wired/failover connectivity for safety-critical functions.")

    # ── Phase 3 — cleanup (restore managed mode) ────────────────────────────
    def _phase_cleanup(self, hw: dict) -> None:
        self._event("Phase 3 — cleanup (stop monitor mode)")
        mon = hw.get("mon")
        if mon and _wifi_which("airmon-ng"):
            try:
                run_tool(["airmon-ng", "stop", mon], self.ctx,
                         tool_name="airmon-ng", timeout=30)
            except Exception:
                pass
        # Best-effort: restore NetworkManager if we killed it in Phase 0.
        if _wifi_which("systemctl"):
            try:
                run_tool(["bash", "-c",
                          "systemctl start NetworkManager 2>/dev/null || true"],
                         self.ctx, tool_name="systemctl", timeout=20)
            except Exception:
                pass


# ===========================================================================
# SubGHz interface module  (integrated 2026-08-13 from _frag/SubGHz.py)
# ===========================================================================
# ===========================================================================
# SubGHz — Sub-GHz RF (300–928 MHz) security assessment module
#   Inserted into gearbox.py (os, re, time, subprocess, shutil, json, Path,
#   Optional, run_tool, BaseModule, console, findings, VERSION already in scope).
# ===========================================================================

# ── hardware roster (mirrors _BT_HARDWARE convention) ──────────────────────
_SUBGHZ_HARDWARE: list[dict] = [
    {"key": "yardstick", "tx_capable": True, "sdr": False,
     "label": "Great Scott YARD Stick One (rfcat) — TX/RX 300-928 MHz OOK/ASK/FSK/MSK",
     "quiver": None,
     "setup": ["No flash needed for stock RfCat firmware; `rfcat -r` opens the shell.",
               "Capture:  rfcat  (setFreq/setMdmModulation, RFrecv() to record bytes).",
               "Replay:   RFxmit(<captured bytes>)  — TX-capable, gate behind operator OK.",
               "Best for fixed/rolling-code REMOTE capture + benign bench replay."]},
    {"key": "hackrf", "tx_capable": True, "sdr": True,
     "label": "HackRF One + PortaPack — wideband SDR (1 MHz-6 GHz), hackrf_transfer/sweep",
     "quiver": None,
     "setup": ["No flash needed; `hackrf_info` confirms the board.",
               "Survey:   hackrf_sweep -f 300:928 -1 -r sweep.csv  (spectrum bins).",
               "Capture:  hackrf_transfer -r capture.iq8 -f 433920000 -s 2000000 -n <samples>.",
               "Replay:   hackrf_transfer -t capture.iq8 -f 433920000 -s 2000000 (bench only).",
               "rtl_433 can also drive HackRF via SoapySDR (-d driver=hackrf)."]},
    {"key": "rtlsdr", "tx_capable": False, "sdr": True,
     "label": "RTL-SDR (RTL2832U) — RX-only dongle for rtl_433 decode/survey",
     "quiver": None,
     "setup": ["Plug in; `rtl_test` confirms the dongle.",
               "Decode:   rtl_433 -f 433.92M -A -F json  (auto-decodes ~250 protocols).",
               "RX-ONLY — cannot transmit, so replay/jam tests need YardStick/HackRF."]},
    {"key": "catsniffer", "tx_capable": True, "sdr": False,
     "label": "CatSniffer (CC1352P) — multiprotocol sub-GHz sniffer/transceiver",
     "quiver": "FIRMWARE - Flash CatSniffer sub-GHz sniffer",
     "setup": ["Flash the sub-GHz sniffer firmware via Quiver, then attach at /dev/ttyACM0.",
               "Sniffs 315/433/868/915 MHz; pipe to Wireshark or SmartRF for decode.",
               "Also drives rfcat-style TX for controlled replay on supported builds."]},
    {"key": "flipper", "tx_capable": True, "sdr": False,
     "label": "Flipper Zero (CC1101) — sub-GHz capture/replay (315/433/868/915 MHz)",
     "quiver": None,
     "setup": ["Use the on-device Sub-GHz app: Read / Read RAW to capture, Save to .sub.",
               "Frequency Analyzer locates the active carrier before capturing.",
               "Send/Replay a saved .sub — TX-capable; gate behind operator confirmation.",
               "Operator-driven: record the captured/replayed .sub filename for evidence."]},
]

# Canonical sub-GHz ISM survey frequencies (rtl_433 -f accepts M suffix).
_SUBGHZ_FREQS: list[str] = ["315M", "390M", "433.92M", "868.3M", "915M"]

# rtl_433 model-family classification (substrings, lowercased).
_SUBGHZ_ROLLING_MODELS: tuple = (
    "keeloq", "hcs", "rolling", "nice-flor", "somfy", "security+", "secplus",
    "hormann", "faac-slh",
)
_SUBGHZ_COMMAND_MODELS: tuple = (
    "pt2262", "ev1527", "princeton", "holtek", "came", "nice-flo", "chamberlain",
    "liftmaster", "genie", "linear", "interlogix", "x10", "doorbell", "remote",
    "gate", "garage", "keyfob", "key fob", "switch", "dsc", "honeywell-security",
)


def _subghz_which(name: str) -> Optional[str]:
    """Locate a sub-GHz tool binary (PATH + common install dirs)."""
    p = shutil.which(name)
    if p:
        return p
    for cand in (f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}"):
        if os.path.exists(cand):
            return cand
    return None


def _subghz_available() -> dict:
    """Return {tool: path-or-None} for every CLI this module can drive."""
    return {t: _subghz_which(t) for t in
            ("rfcat", "rtl_433", "hackrf_transfer", "hackrf_sweep", "urh_cli",
             "rtl_test", "hackrf_info")}


def _subghz_parse_rtl433_json(text: str) -> list[dict]:
    """
    Parse rtl_433 `-F json` output (one JSON object per decoded frame, NDJSON).
    Returns a de-duplicated list of {model, id, freq, fields, raw} records.
    """
    seen: dict = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{") or not line.endswith("}"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        model = str(obj.get("model", "")).strip()
        if not model:
            continue
        dev_id = str(obj.get("id", obj.get("device", ""))).strip()
        freq = obj.get("freq", obj.get("frequency", ""))
        key = f"{model}|{dev_id}|{freq}"
        if key in seen:
            continue
        # Data fields = everything except housekeeping keys.
        skip = {"time", "model", "id", "device", "freq", "frequency",
                "rssi", "snr", "noise", "mod", "protocol", "channel"}
        fields = {k: v for k, v in obj.items() if k not in skip}
        seen[key] = {"model": model, "id": dev_id, "freq": freq,
                     "fields": fields, "raw": line}
    return list(seen.values())


def _subghz_classify(model: str) -> str:
    """Return 'rolling' | 'command' | 'telemetry' for an rtl_433 model name."""
    m = (model or "").lower()
    for s in _SUBGHZ_ROLLING_MODELS:
        if s in m:
            return "rolling"
    for s in _SUBGHZ_COMMAND_MODELS:
        if s in m:
            return "command"
    return "telemetry"


class SubGHzModule(BaseModule):
    """
    Zero-knowledge Sub-GHz RF (300–928 MHz) security assessment.

    Surveys the sub-GHz ISM bands for the device-under-test's remotes,
    telemetry, and sensor links; captures active carriers; and rules out the
    known weakness classes for low-power RF control channels — fixed
    (replayable) codes, rolling-code presence, cleartext telemetry, an
    unauthenticated OOK/FSK command channel, replay-attack feasibility, and
    jamming susceptibility.  Every over-the-air test that could disrupt a LIVE
    device (replay TX, jamming) is gated behind explicit operator confirmation
    and defaults to passive receive + decode only.
    """
    name        = "SubGHz"
    description = "Zero-knowledge sub-GHz RF assessment (survey → capture → analysis)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_SIGNAL    = "Sub-GHz Signal Detected"
    T_TELEMETRY = "Unencrypted Sub-GHz Telemetry Decoded"
    T_FIXEDCODE = "Fixed-Code Sub-GHz Remote — Replayable"
    T_ROLLING   = "Rolling-Code Sub-GHz Remote Detected"
    T_REPLAY    = "Sub-GHz Replay Attack Feasible"
    T_CMDCHAN   = "Unauthenticated Sub-GHz Command Channel (OOK/FSK)"
    T_NOAUTH    = "Missing Message Authentication on Sub-GHz Link"
    T_JAMMING   = "Sub-GHz Jamming Susceptibility"
    T_SKIPPED   = "Sub-GHz Testing SKIPPED — No SDR/Radio Hardware Available"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "SubGHz" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane sub-GHz defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "subghz"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [SubGHz] {msg}", tool=self.name)
        except Exception:
            pass

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"SubGHzModule v{VERSION} started for [{self.ctx.instance_loc}]")
            hw = self._phase0_hardware()
            if hw is None:
                return  # skipped — honest finding already emitted
            decoded = self._phase1_survey(hw)
            cap = self._phase2_capture(hw)
            self._phase3_analysis(hw, decoded, cap)
            self._mark_complete(
                f"Sub-GHz assessment complete — {len(decoded)} signal(s) decoded")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — hardware selection + tool check ───────────────────────────
    def _phase0_hardware(self) -> Optional[dict]:
        self._event("Phase 0 — hardware selection & setup")
        labels = [h["label"] for h in _SUBGHZ_HARDWARE]
        choice = self._prompt(
            "Select the Sub-GHz (300–928 MHz) testing radio in use. RX-only decode "
            "needs an RTL-SDR or HackRF (rtl_433); capture+replay needs a TX-capable "
            "radio (YARD Stick One / HackRF / CatSniffer / Flipper Zero).\n"
            "Refer to Quiver to flash a sniffer board's firmware before continuing.",
            options=labels + ["Skip Sub-GHz testing"],
            prompt_type="choice", skippable=True)

        hw = next((h for h in _SUBGHZ_HARDWARE if h["label"] == choice), None)
        if hw is None or (choice or "").lower().startswith("skip"):
            self._f(self.T_SKIPPED,
                    "No sub-GHz radio was selected for this instance, so 300–928 MHz "
                    "RF testing was NOT performed. Attach an RTL-SDR or HackRF for "
                    "spectrum survey + rtl_433 decode, or a YARD Stick One / CatSniffer "
                    "/ Flipper Zero for capture-and-replay work, and re-run the module.",
                    "Informational")
            self._mark_complete("Sub-GHz SKIPPED — no radio selected")
            return None

        self.ctx.logger.info(f"Selected sub-GHz radio: {hw['label']}", tool=self.name)
        if hw.get("quiver"):
            self.ctx.logger.info(
                f"Flash via Quiver payload: '{hw['quiver']}'", tool=self.name)
        for ln in hw["setup"]:
            self.ctx.logger.info(f"  {ln}", tool=self.name)
        setup_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_hardware_setup.txt"
        try:
            setup_txt.write_text(
                f"Sub-GHz testing radio: {hw['label']}\n"
                + (f"Quiver flash payload: {hw['quiver']}\n" if hw.get("quiver") else "")
                + "\n" + "\n".join(hw["setup"]) + "\n", encoding="utf-8")
        except Exception:
            pass
        self._prompt_connected_photo(
            f"{hw['label']} connected for [{self.ctx.instance_loc}]")

        tools = _subghz_available()
        hw["_tools"] = tools
        have_any = any(tools.get(t) for t in
                       ("rtl_433", "hackrf_sweep", "hackrf_transfer", "rfcat"))
        # Flipper/CatSniffer are operator-driven (on-device), so they don't need a
        # host CLI; only fail-skip when NO host tool AND no operator-driven radio.
        operator_driven = hw["key"] in ("flipper", "catsniffer")
        if not have_any and not operator_driven:
            self._f(self.T_SKIPPED,
                    "The selected radio requires a host CLI (rtl_433 / hackrf_sweep / "
                    "hackrf_transfer / rfcat) but none was found on PATH. Install the "
                    "sub-GHz toolchain (see install.py) and re-run.",
                    "Informational")
            self._mark_complete("Sub-GHz SKIPPED — no CLI toolchain installed")
            return None
        return hw

    # ── Phase 1 — spectrum survey + protocol decode ─────────────────────────
    def _phase1_survey(self, hw: dict) -> list[dict]:
        self._event("Phase 1 — spectrum survey & decode")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Surveying 300–928 MHz…")
        out_dir = self._dir("01_survey")
        tools = hw.get("_tools", {})
        decoded: list[dict] = []

        # A — wideband spectrum sweep (HackRF): records power per frequency bin.
        if tools.get("hackrf_sweep"):
            sweep = out_dir / f"{self.ctx.file_prefix}_hackrf_sweep.csv"
            run_tool(["hackrf_sweep", "-f", "300:928", "-1", "-r", str(sweep)],
                     self.ctx, tool_name="hackrf_sweep", output_file=sweep, timeout=120)

        # B — protocol decode across the ISM bands (rtl_433 -A analyze + JSON).
        if tools.get("rtl_433"):
            for freq in _SUBGHZ_FREQS:
                jf = out_dir / f"{self.ctx.file_prefix}_rtl433_{freq.replace('.', '_')}.json"
                rc, out, err = run_tool(
                    ["rtl_433", "-f", freq, "-A", "-F", "json", "-T", "20"],
                    self.ctx, tool_name="rtl_433", output_file=jf, timeout=45)
                recs = _subghz_parse_rtl433_json(out or "")
                for r in recs:
                    r["_survey_freq"] = freq
                    r["_evidence"] = str(jf)
                    decoded.append(r)
                if recs:
                    self._f(self.T_SIGNAL,
                            f"An active sub-GHz transmission was detected and decoded at "
                            f"{freq} during zero-knowledge survey: "
                            f"{', '.join(sorted({x['model'] for x in recs}))}. Its presence "
                            f"expands the wireless attack surface of the device under test.",
                            "Informational", ip=freq, output_file=str(jf),
                            affected_component="; ".join(sorted({x['model'] for x in recs})))
        else:
            # No host decoder — record that survey is operator-driven for this radio.
            self.ctx.logger.info(
                "No rtl_433 on PATH — spectrum decode is operator-driven for this radio "
                "(use the Flipper Frequency Analyzer / CatSniffer capture).",
                tool=self.name)

        self.ctx.logger.info(
            f"Survey decoded {len(decoded)} distinct sub-GHz signal(s)", tool=self.name)
        return decoded

    # ── Phase 2 — targeted capture (passive receive) ────────────────────────
    def _phase2_capture(self, hw: dict) -> Optional[Path]:
        self._event("Phase 2 — targeted capture")
        out_dir = self._dir("02_capture")
        tools = hw.get("_tools", {})

        ans = self._prompt(
            "Trigger the device's remote/transmitter (press the key fob / actuate the "
            "control) so its carrier can be captured. Which frequency should be captured? "
            "(Receive-only — no transmission is performed in this step.)",
            options=[f"{f} — capture now" for f in _SUBGHZ_FREQS]
                    + ["Skip capture (survey only)"],
            prompt_type="choice", skippable=True)
        if not ans or ans.lower().startswith("skip"):
            return None
        freq = ans.split(" ")[0]
        hz = _subghz_freq_to_hz(freq)

        # HackRF raw-IQ capture (passive RX) — the canonical replay source file.
        if tools.get("hackrf_transfer") and hz:
            cap = out_dir / f"{self.ctx.file_prefix}_capture_{freq.replace('.', '_')}.iq8"
            run_tool(["hackrf_transfer", "-r", str(cap), "-f", str(hz),
                      "-s", "2000000", "-n", "16000000"],
                     self.ctx, tool_name="hackrf_transfer", output_file=None, timeout=60)
            if cap.exists() and cap.stat().st_size > 0:
                self.ctx.logger.info(f"Captured raw IQ → {cap}", tool=self.name)
                return cap

        # YARD Stick One / on-device capture is operator-driven — record the artifact.
        note = self._prompt(
            f"Capture {freq} with the {hw['label']} (rfcat RFrecv / Flipper 'Read RAW' → "
            f"Save .sub / CatSniffer capture). Enter the saved capture filename, or 'skip'.",
            prompt_type="text", skippable=True)
        if note and not note.lower().startswith("skip"):
            man = out_dir / f"{self.ctx.file_prefix}_operator_capture_ref.txt"
            try:
                man.write_text(f"Frequency: {freq}\nOperator capture reference: {note}\n",
                               encoding="utf-8")
            except Exception:
                pass
            self.ctx.logger.info(
                f"Operator recorded capture: {note} @ {freq}", tool=self.name)
            return man
        return None

    # ── Phase 3 — analysis (fixed/rolling/telemetry) + gated replay/jam ──────
    def _phase3_analysis(self, hw: dict, decoded: list[dict], cap: Optional[Path]) -> None:
        self._event("Phase 3 — analysis")
        out_dir = self._dir("03_analysis")
        tools = hw.get("_tools", {})

        rolling = [r for r in decoded if _subghz_classify(r["model"]) == "rolling"]
        command = [r for r in decoded if _subghz_classify(r["model"]) == "command"]
        telem   = [r for r in decoded if _subghz_classify(r["model"]) == "telemetry"]

        # A — cleartext telemetry (sensor data decoded in the clear → CWE-319).
        if telem:
            models = sorted({r["model"] for r in telem})
            ev = out_dir / f"{self.ctx.file_prefix}_telemetry.txt"
            try:
                ev.write_text("\n".join(r["raw"] for r in telem), encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_TELEMETRY,
                    f"rtl_433 decoded {len(telem)} sub-GHz telemetry/sensor frame(s) in the "
                    f"clear from: {', '.join(models)}. The payload fields were recovered "
                    f"without any key, proving the link carries device data with no "
                    f"transport encryption. Any passive listener in range can read, log, "
                    f"and correlate this data.",
                    "Medium", output_file=str(ev),
                    affected_component="; ".join(models),
                    remediation="Encrypt the RF payload (authenticated AEAD) or move "
                                "sensitive telemetry to an authenticated, encrypted channel; "
                                "avoid transmitting patient/asset data as cleartext RF.")

        # B — fixed-code command channel (replayable static code → CWE-294/306/347).
        if command:
            models = sorted({r["model"] for r in command})
            ev = out_dir / f"{self.ctx.file_prefix}_fixedcode.txt"
            try:
                ev.write_text("\n".join(r["raw"] for r in command), encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_FIXEDCODE,
                    f"A fixed-code sub-GHz remote/command protocol was decoded: "
                    f"{', '.join(models)}. Fixed-code (static OOK/ASK) remotes transmit the "
                    f"identical code on every actuation, so a single captured frame can be "
                    f"re-transmitted to reproduce the command (garage/gate/relay/keyfob "
                    f"class). The captured code is the credential.",
                    "High", output_file=str(ev),
                    affected_component="; ".join(models),
                    remediation="Replace fixed-code remotes with rolling-code (KeeLoq/HCS) "
                                "or, preferably, an authenticated challenge-response link; "
                                "add message authentication + anti-replay counters.")
            self._f(self.T_CMDCHAN,
                    f"The sub-GHz control channel ({', '.join(models)}) accepts commands "
                    f"with no authentication of the sender — the demodulated OOK/FSK frame "
                    f"is a bare command with no signature or nonce. An attacker who can "
                    f"transmit on the band can inject commands the device will act on.",
                    "High", output_file=str(ev), affected_component="; ".join(models),
                    remediation="Require signed/authenticated commands (HMAC or public-key) "
                                "with a monotonic counter or nonce; reject unauthenticated frames.")
            self._f(self.T_NOAUTH,
                    f"No message-integrity/authentication was observed on the sub-GHz link "
                    f"for {', '.join(models)}; frames carry no MAC/signature, so their "
                    f"contents can be forged or replayed undetected (CWE-345/CWE-347).",
                    "Medium", output_file=str(ev), affected_component="; ".join(models),
                    remediation="Add per-message authentication (AEAD or signature) and "
                                "reject frames failing integrity verification.")

        # C — rolling-code presence (defensive control — good, but note rolljam risk).
        if rolling:
            models = sorted({r["model"] for r in rolling})
            ev = out_dir / f"{self.ctx.file_prefix}_rollingcode.txt"
            try:
                ev.write_text("\n".join(r["raw"] for r in rolling), encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_ROLLING,
                    f"A rolling-code sub-GHz remote was detected: {', '.join(models)}. "
                    f"Rolling codes defeat naive single-frame replay (a positive control), "
                    f"but remain susceptible to jam-and-capture ('RollJam') and to "
                    f"weak-cipher/seed-recovery attacks against some KeeLoq variants. "
                    f"Confirm the receiver enforces a strict forward-only counter window.",
                    "Low", output_file=str(ev), affected_component="; ".join(models),
                    remediation="Keep firmware current; enforce a tight rolling-counter "
                                "resync window; prefer AES-based rolling schemes over "
                                "legacy KeeLoq; consider bidirectional authenticated pairing.")

        # D — replay-attack feasibility (SAFETY: operator-confirmed benign replay only).
        self._gated_replay(hw, cap, out_dir, bool(command))

        # E — jamming susceptibility (SAFETY: operator-observed only, no TX by default).
        self._gated_jamming(hw, out_dir)

    def _gated_replay(self, hw: dict, cap: Optional[Path],
                      out_dir: Path, have_command: bool) -> None:
        tools = hw.get("_tools", {})
        can_tx = hw.get("tx_capable") and (tools.get("hackrf_transfer") or tools.get("rfcat"))
        prelude = ("A captured frame is available. " if cap else
                   "No host capture is on file (operator/on-device capture may exist). ")
        ans = self._prompt(
            prelude +
            "Replay testing re-transmits a captured sub-GHz command to prove an attacker "
            "could reproduce it. SAFETY: only replay against a BENCH unit or with a "
            "known-benign/no-op command — do NOT re-transmit a control command to a LIVE "
            "medical device. Attempt an operator-authorized benign replay now?",
            options=["Yes — benign replay authorized (bench/no-op)",
                     "Observed — replay already reproduced the command (operator report)",
                     "No — record as untested"],
            prompt_type="choice", skippable=True)
        low = (ans or "").lower()
        if low.startswith("no") or not ans:
            return

        replayed = False
        rlog = out_dir / f"{self.ctx.file_prefix}_replay.txt"
        if low.startswith("yes") and can_tx and cap and str(cap).endswith(".iq8") \
                and tools.get("hackrf_transfer"):
            hz = _subghz_freq_to_hz(_subghz_freq_from_name(cap.name)) or 433920000
            rc, out, err = run_tool(
                ["hackrf_transfer", "-t", str(cap), "-f", str(hz),
                 "-s", "2000000"],
                self.ctx, tool_name="hackrf_transfer", output_file=rlog, timeout=45)
            replayed = (rc == 0)
        obs = self._prompt(
            "Did the device RESPOND to the replayed frame (actuated / state changed / "
            "command reproduced)?",
            options=["Yes — device actuated by the replay",
                     "No — device did not respond"],
            prompt_type="choice", skippable=True)
        if low.startswith("observed") or (obs or "").lower().startswith("yes"):
            try:
                rlog.write_text(
                    f"Replay {'transmitted via hackrf_transfer' if replayed else 'operator-observed'}; "
                    f"capture={cap}; device actuated: yes\n", encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_REPLAY,
                    "A captured sub-GHz command was re-transmitted and the device under test "
                    "acted on it, confirming a working replay attack: no rolling counter, "
                    "nonce, or authentication prevented reuse of the recorded frame. An "
                    "attacker who records one legitimate transmission can reproduce the "
                    "command at will.",
                    "Critical" if have_command else "High",
                    output_file=str(rlog), force_classification="Validated",
                    remediation="Adopt authenticated, anti-replay commanding (rolling "
                                "counter + MAC, or challenge-response); reject any frame "
                                "whose counter/nonce has already been seen.")

    def _gated_jamming(self, hw: dict, out_dir: Path) -> None:
        # No jamming is transmitted by this tool — susceptibility is operator-observed
        # to avoid disrupting a live device / neighbouring equipment.
        ans = self._prompt(
            "Jamming susceptibility: a controlled sub-GHz noise/carrier on the device's "
            "band can block its receiver (denial of service). SAFETY: Gearbox does NOT "
            "transmit a jamming signal — perform any controlled jamming test only on a "
            "bench unit in an RF-isolated setup, then report the observation. Was the "
            "device's RF link disrupted by a controlled jamming test?",
            options=["Yes — link disrupted under controlled jamming (bench)",
                     "No — device tolerated the jamming test",
                     "Not tested"],
            prompt_type="choice", skippable=True)
        low = (ans or "").lower()
        if not low.startswith("yes"):
            return
        jlog = out_dir / f"{self.ctx.file_prefix}_jamming.txt"
        try:
            jlog.write_text("Operator-observed: controlled jamming disrupted the sub-GHz "
                            "link (bench).\n", encoding="utf-8")
        except Exception:
            pass
        self._f(self.T_JAMMING,
                "Under a controlled, operator-observed test the device's sub-GHz link was "
                "disrupted by narrowband jamming, denying legitimate commands/telemetry "
                "(availability loss). Low-power ISM control channels have no inherent "
                "jamming resistance; combined with jam-and-replay this also enables "
                "rolling-code capture. Evaluate whether loss of the RF channel has a "
                "safety impact for this device.",
                "Medium", output_file=str(jlog), force_classification="Validated",
                remediation="Add jamming/loss-of-link detection with a fail-safe state; "
                            "use frequency agility or a diverse secondary channel for "
                            "safety-critical control; alert on sustained RF interference.")


def _subghz_freq_to_hz(freq: str) -> Optional[int]:
    """Convert an rtl_433-style frequency string ('433.92M') to integer Hz."""
    if not freq:
        return None
    m = re.match(r"([0-9.]+)\s*([mMkK]?)", str(freq).strip())
    if not m:
        return None
    try:
        val = float(m.group(1))
    except Exception:
        return None
    unit = m.group(2).lower()
    if unit == "m":
        return int(val * 1_000_000)
    if unit == "k":
        return int(val * 1_000)
    return int(val)


def _subghz_freq_from_name(name: str) -> str:
    """Recover a frequency token ('433_92' → '433.92M') from a capture filename."""
    m = re.search(r"(\d{3})[._](\d{1,3})?", name or "")
    if not m:
        m2 = re.search(r"(\d{3,4})", name or "")
        return (m2.group(1) + "M") if m2 else ""
    whole = m.group(1)
    frac = m.group(2) or ""
    return (f"{whole}.{frac}M" if frac else f"{whole}M")


# ===========================================================================
# UWB interface module  (integrated 2026-08-13 from _frag/UWB.py)
# ===========================================================================
# ---------------------------------------------------------------------------
# UWB Module  (IEEE 802.15.4z Ultra-Wideband ranging / RTLS / secure-access)
# ---------------------------------------------------------------------------
# One module, three phases: hardware setup -> device discovery (anchor/tag
# blink & ranging frames) -> ranging security.  UWB attack tooling is sparse
# and mostly research-grade, so detection is capture + protocol-analysis driven
# and, where no automated oracle exists, operator-observation driven.  The
# module is HONEST: when no sniffer board / capture is available it emits an
# explicit SKIPPED finding and never pretends a test ran.  Anything that could
# disrupt a live medical asset-tracking / access-control deployment (relay,
# distance-reduction, replay, jamming) is gated behind an operator confirmation
# and defaults to passive capture.
#
# Grounding (real weakness classes):
#   * IEEE 802.15.4z HRP secure ranging relies on the Scrambled Timestamp
#     Sequence (STS); ranging with STS mode 0 (no STS) has no cryptographic
#     integrity and is trivially relayed/replayed.  (CWE-294/300/347)
#   * "Ghost Peak" (USENIX Security 2022) — practical over-the-air distance-
#     reduction against HRP UWB, demonstrated on Apple U1, NXP Trimension
#     SR040/SR150 and Qorvo DW3000.
#   * FiRa Consortium / Apple Nearby Interaction define the STS-based secure
#     ranging profile these findings map against.

# Sniffer / analysis CLIs the module will look for on PATH.  UWB tooling has no
# packaged standard binary — most captures come off a DWM3001C UCI stream or a
# DW3000 API sniffer build — so an absent tool is the COMMON case and drives the
# honest SKIPPED path plus the operator-supplied-capture fallback.
_UWB_SNIFFER_BINS = ("uwb-sniffer", "dw3000-sniffer", "uwbsniff", "uci-sniffer")

# Hardware offered at Phase 0.  quiver = the Quiver firmware-flash payload that
# provisions the board's UWB sniffer/UCI firmware (see /opt/pr0t31n/Quiver).
_UWB_HARDWARE = [
    {"key": "heltec", "label": "Heltec UWB dongle (DW3000, USB-serial UCI)",
     "quiver": "FIRMWARE - Flash UWB sniffer firmware",
     "setup": ["USB DW3000 dongle. Flash the UCI/sniffer firmware via Quiver,",
               "  then it presents a serial UCI stream on /dev/ttyACM0.",
               "Passive listen only — set the same channel/preamble as the DUT",
               "  (channel 5 or 9, PRF 64 MHz) to observe blink & ranging frames.",
               "No standard PATH binary — capture the UCI text/pcapng and import it."]},
    {"key": "dwm3001cdk", "label": "Qorvo DWM3001CDK (nRF52833 + DW3110)",
     "quiver": "FIRMWARE - Flash DWM3001C sniffer firmware",
     "setup": ["Flash the DWM3001C-starter-firmware (Uberi) or Qorvo UCI build",
               "  via Quiver; exposes a USB CDC UCI console.",
               "Acts as an HRP UWB packet analyser: set channel, preamble code,",
               "  preamble length, STS mode/length to match the DUT and log frames.",
               "TOP PICK for STS-presence analysis and ranging-frame capture."]},
    {"key": "dwm3000evb", "label": "DWM3000EVB shield + ST Nucleo",
     "quiver": "FIRMWARE - Flash DW3000 API sniffer",
     "setup": ["Mount the DWM3000EVB Arduino shield on a Nucleo (F429/L476);",
               "  flash the DW3000 API 'rx sniff' example via Quiver / STM32CubeIDE.",
               "Streams received PHR/payload + STS diagnostics over the ST-Link",
               "  virtual COM port; log to a text file and import it here."]},
]


def _uwb_which(name):
    """Locate a UWB sniffer/analysis binary (PATH + common install dirs)."""
    p = shutil.which(name)
    if p:
        return p
    for cand in (f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}"):
        if os.path.exists(cand):
            return cand
    return None


def _uwb_available_sniffer():
    """Return the first UWB sniffer CLI found on PATH, else ''."""
    for b in _UWB_SNIFFER_BINS:
        if _uwb_which(b):
            return b
    return ""


def _uwb_parse_capture(text):
    """
    Best-effort parse of a UWB sniffer / UCI / DW3000-API capture transcript.

    UWB tooling output is not standardised, so this matches the cleartext tokens
    that appear across UCI logs, DW3000 rx-sniff dumps and Wireshark 802.15.4
    dissections.  Returns whatever it could recover:
        {devices:[{addr,kind}], ranging_seen, blink_seen,
         sts_seen, sts_mode_zero, cleartext_payload, frame_types:set}
    STS presence is inferred from an explicit STS/STS_MODE token; STS mode 0
    (or "no sts" / "sts off") means no secure-ranging protection.
    """
    res = {"devices": [], "ranging_seen": False, "blink_seen": False,
           "sts_seen": False, "sts_mode_zero": False,
           "cleartext_payload": False, "frame_types": set()}
    low = (text or "").lower()

    # Ranging frame types (two-way ranging poll/response/final; TDoA blink).
    for kind, pats in (
        ("poll",     (r"\bpoll\b", r"rframe.*poll", r"twr.*poll")),
        ("response", (r"\bresponse\b", r"\bresp\b")),
        ("final",    (r"\bfinal\b",)),
        ("blink",    (r"\bblink\b", r"tdoa")),
        ("ranging",  (r"\branging\b", r"\btwr\b", r"ds-twr", r"ss-twr")),
    ):
        if any(re.search(p, low) for p in pats):
            res["frame_types"].add(kind)
    res["ranging_seen"] = bool(res["frame_types"] & {"poll", "response", "final", "ranging"})
    res["blink_seen"]   = "blink" in res["frame_types"]

    # STS presence / mode.  "sts mode 0" / "sts: 0" / "sts off" / "no sts" == none.
    if re.search(r"\bsts\b", low):
        res["sts_seen"] = True
        m = re.search(r"sts[_ ]?mode\s*[:=]?\s*(\d+)", low) or re.search(r"\bsts\s*[:=]\s*(\d+)", low)
        if m and int(m.group(1)) == 0:
            res["sts_mode_zero"] = True
    if re.search(r"no\s*sts|sts\s*(off|disabled|none)|without\s*sts", low):
        res["sts_seen"] = True
        res["sts_mode_zero"] = True

    # Cleartext positioning / payload — distances, coordinates or a decoded
    # MAC payload printed in the clear alongside the ranging frame.
    if re.search(r"distance\s*[:=]\s*[\d.]+|range\s*[:=]\s*[\d.]+|\bx\s*[:=]\s*-?[\d.]+.*\by\s*[:=]", low) \
       or re.search(r"payload\s*[:=]\s*[0-9a-f]{2}", low):
        res["cleartext_payload"] = True

    # Devices — EUI-64 long address or 16-bit short address in blink/ranging frames.
    seen = {}
    for m in re.finditer(r"\b((?:[0-9a-f]{2}[:\- ]){7}[0-9a-f]{2})\b", low):
        addr = re.sub(r"[\- ]", ":", m.group(1)).upper()
        seen.setdefault(addr, {"addr": addr, "kind": "EUI-64"})
    for m in re.finditer(r"(?:short[_ ]?addr|src|source|dst)\s*[:=]\s*(0x[0-9a-f]{4})\b", low):
        addr = m.group(1).upper()
        seen.setdefault(addr, {"addr": addr, "kind": "short-16"})
    res["devices"] = list(seen.values())
    return res


class UWBModule(BaseModule):
    """
    Ultra-Wideband (IEEE 802.15.4z) ranging / RTLS / secure-access assessment.

    Covers UWB used for medical asset-tracking (RTLS anchors/tags) and UWB
    access control.  Three phases — hardware setup, device discovery (anchor/tag
    blink & ranging frames), ranging security — rule out the known secure-ranging
    weakness classes (missing STS, unauthenticated ranging, distance-reduction /
    relay / replay susceptibility, cleartext positioning) from passively-captured
    frames plus operator observation, without assuming target identity.  Active
    tests that could disrupt a live deployment are gated behind operator confirm.
    """
    name        = "UWB"
    description = "IEEE 802.15.4z UWB assessment (discovery -> ranging security)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_DETECTED   = "UWB Device Detected"
    T_SKIPPED    = "UWB Testing SKIPPED — No Sniffer or UWB Hardware Available"
    T_NO_STS     = "UWB Ranging Without Scrambled Timestamp Sequence (STS)"
    T_UNAUTH     = "Unauthenticated UWB Ranging Exchange"
    T_DISTANCE   = "UWB Ranging Susceptible to Distance-Reduction (Ghost Peak) Attack"
    T_RELAY      = "UWB Ranging Susceptible to Relay Attack"
    T_REPLAY     = "Replay of UWB Ranging Frames Accepted"
    T_CLEARTEXT  = "Cleartext UWB Positioning or Payload Data"
    T_STATIC_STS = "UWB Static or Non-Rotating Ranging Key (STS Reuse)"
    T_JAMMING    = "UWB Ranging Susceptible to Jamming / Denial of Service"
    T_LEGACY     = "UWB Legacy (Pre-802.15.4z) Ranging — No Secure Ranging Support"
    T_TRACKABLE  = "UWB Device Trackable via Static Address in Blink Frames"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "UWB" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane UWB defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "uwb"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [UWB] {msg}", tool=self.name)
        except Exception:
            pass

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"UWBModule v{VERSION} started for [{self.ctx.instance_loc}]")
            hw = self._phase0_hardware()
            if hw is None:
                return  # skipped — honest finding already emitted
            cap = self._phase1_capture(hw)
            if cap is None:
                return  # skipped — honest finding already emitted
            parsed = self._phase1_discovery(cap)
            self._phase2_ranging_security(hw, cap, parsed)
            self._mark_complete("UWB assessment complete")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — hardware selection + setup ────────────────────────────────
    def _phase0_hardware(self):
        self._event("Phase 0 — hardware selection & setup")
        labels = [h["label"] for h in _UWB_HARDWARE]
        choice = self._prompt(
            "Select the UWB testing hardware in use. All options are PASSIVE "
            "listeners — set the sniffer to the DUT's channel / preamble / STS "
            "config before capturing. Refer to Quiver to flash the board's "
            "firmware before continuing.",
            options=labels + ["Skip UWB testing"],
            prompt_type="choice", skippable=True)

        hw = next((h for h in _UWB_HARDWARE if h["label"] == choice), None)
        if hw is None or (choice or "").lower().startswith("skip"):
            self._f(self.T_SKIPPED,
                    "No UWB sniffer board (Heltec UWB dongle / Qorvo DWM3001CDK / "
                    "DWM3000EVB+Nucleo) was selected for this instance, so UWB "
                    "(IEEE 802.15.4z ranging / RTLS / secure-access) testing was NOT "
                    "performed. Flash a UWB sniffer via Quiver and re-run the module, "
                    "or import an existing DW3000/UCI capture.",
                    "Informational", tool="uwb")
            self._mark_complete("UWB SKIPPED — no hardware selected")
            return None

        self.ctx.logger.info(f"Selected UWB hardware: {hw['label']}", tool=self.name)
        if hw.get("quiver"):
            self.ctx.logger.info(f"Flash via Quiver payload: '{hw['quiver']}'", tool=self.name)
        for ln in hw["setup"]:
            self.ctx.logger.info(f"  {ln}", tool=self.name)
        setup_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_hardware_setup.txt"
        try:
            setup_txt.write_text(
                f"UWB testing hardware: {hw['label']}\n"
                + (f"Quiver flash payload: {hw['quiver']}\n" if hw.get("quiver") else "")
                + "\n" + "\n".join(hw["setup"]) + "\n", encoding="utf-8")
        except Exception:
            pass
        self._prompt_connected_photo(
            f"{hw['label']} connected for [{self.ctx.instance_loc}]")
        return hw

    # ── Phase 1a — passive capture (sniffer CLI or operator-supplied file) ───
    def _phase1_capture(self, hw):
        self._event("Phase 1 — passive UWB capture")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Capturing UWB frames…")
        out_dir = self._dir("01_capture")
        cap = {"text": "", "files": []}

        sniffer = _uwb_available_sniffer()
        if sniffer:
            cap_txt = out_dir / f"{self.ctx.file_prefix}_{sniffer}_capture.txt"
            try:
                rc, out, err = run_tool(
                    [sniffer, "--listen", "--timeout", "60"], self.ctx,
                    tool_name=sniffer, output_file=cap_txt, timeout=90)
                cap["text"] += (out or "")
                cap["files"].append(str(cap_txt))
                self.ctx.logger.info(
                    f"UWB passive capture via {sniffer} complete", tool=self.name)
            except Exception as e:
                self.ctx.logger.warn(f"UWB sniffer {sniffer} failed: {e}", tool=self.name)

        # Operator-supplied capture — the common path (no PATH binary for most
        # DW3000/UCI rigs). Import a UCI text log / DW3000 rx-sniff dump / pcapng.
        ans = self._prompt(
            "If you captured UWB frames off the board (DWM3001C UCI console, "
            "DW3000 rx-sniff dump, or a Wireshark 802.15.4 pcapng), provide the "
            "capture file to import for analysis. Otherwise skip.",
            prompt_type="file", skippable=True)
        if ans and ans.lower() not in ("skip", "") and os.path.exists(ans):
            try:
                dest = out_dir / f"{self.ctx.file_prefix}_operator_capture{Path(ans).suffix or '.txt'}"
                shutil.copy2(ans, str(dest))
                cap["files"].append(str(dest))
                try:
                    cap["text"] += "\n" + dest.read_text(errors="replace")
                except Exception:
                    pass  # binary pcapng — kept as evidence, parsed via operator prompts
                self.ctx.logger.info(f"Imported operator UWB capture: {dest.name}", tool=self.name)
            except Exception as e:
                self.ctx.logger.warn(f"Could not import capture {ans}: {e}", tool=self.name)

        if not cap["files"]:
            self._f(self.T_SKIPPED,
                    "No UWB sniffer binary was found on PATH and no capture file "
                    "was supplied, so no UWB frames could be analysed. UWB testing "
                    "was NOT performed. Flash a UWB sniffer via Quiver (Heltec / "
                    "DWM3001CDK / DWM3000EVB) to capture the DUT's ranging/blink "
                    "frames, or import a DW3000/UCI capture, then re-run.",
                    "Informational", tool="uwb")
            self._mark_complete("UWB SKIPPED — no sniffer tool or capture available")
            return None
        return cap

    # ── Phase 1b — device discovery ─────────────────────────────────────────
    def _phase1_discovery(self, cap):
        self._event("Phase 1 — device discovery")
        parsed = _uwb_parse_capture(cap.get("text", ""))
        evidence = cap["files"][0] if cap["files"] else ""

        if not parsed["devices"]:
            # Fall back to an operator observation so a binary-only pcapng still
            # yields a discovery record rather than silently finding nothing.
            ans = self._prompt(
                "No UWB device addresses were auto-parsed from the capture. From "
                "your analysis (Wireshark 802.15.4 / UCI log), were any UWB anchors "
                "or tags observed transmitting blink or ranging frames?",
                options=["Yes — anchors/tags observed", "No — no UWB frames seen"],
                prompt_type="choice", skippable=True)
            if ans and ans.lower().startswith("yes"):
                parsed["devices"].append({"addr": "(observed, address not parsed)",
                                          "kind": "operator"})

        for d in parsed["devices"]:
            addr = d["addr"]
            self._f(self.T_DETECTED,
                    f"A UWB device was detected during passive capture: {addr} "
                    f"({d['kind']} address). Frame types observed: "
                    f"{', '.join(sorted(parsed['frame_types'])) or 'unspecified'}. "
                    f"Its presence on the IEEE 802.15.4z channel confirms a live "
                    f"ranging/RTLS attack surface (asset-tracking tag/anchor or "
                    f"secure-access ranging peer).",
                    "Informational", tool="uwb", ip=addr,
                    output_file=evidence, affected_component=d["kind"])
        self.ctx.logger.info(
            f"Discovered {len(parsed['devices'])} UWB device(s)", tool=self.name)
        return parsed

    # ── Phase 2 — ranging security ──────────────────────────────────────────
    def _phase2_ranging_security(self, hw, cap, parsed):
        self._event("Phase 2 — ranging security")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Analysing UWB ranging security…")
        out_dir = self._dir("02_ranging")
        evidence = cap["files"][0] if cap["files"] else ""

        # ── Secure-ranging profile — STS presence (the central 802.15.4z control) ──
        sts_ans = self._prompt(
            "SECURE RANGING (IEEE 802.15.4z): does the DUT's ranging use the "
            "Scrambled Timestamp Sequence (STS)? STS is the cryptographic PHY "
            "field that authenticates the ranging timestamp; without it (STS mode "
            "0 / legacy 802.15.4a) ranging is unauthenticated and relay/replay/"
            "distance-reduction attacks succeed trivially."
            + (" [auto-analysis: STS field NOT seen in capture]"
               if not parsed["sts_seen"] else
               " [auto-analysis: STS mode 0 / disabled in capture]"
               if parsed["sts_mode_zero"] else
               " [auto-analysis: STS field present in capture]"),
            options=["STS present (secure ranging, 802.15.4z)",
                     "No STS — STS mode 0 / disabled",
                     "Legacy 802.15.4a device — no STS capability",
                     "Could not determine"],
            prompt_type="choice", skippable=True)
        a = (sts_ans or "").lower()
        no_sts = ("no sts" in a or "mode 0" in a or "legacy" in a
                  or (not sts_ans and (parsed["sts_mode_zero"] or not parsed["sts_seen"])))

        try:
            (out_dir / f"{self.ctx.file_prefix}_sts_analysis.txt").write_text(
                f"STS auto-analysis: sts_seen={parsed['sts_seen']} "
                f"sts_mode_zero={parsed['sts_mode_zero']}\n"
                f"Operator observation: {sts_ans or '(none)'}\n"
                f"Frame types: {sorted(parsed['frame_types'])}\n", encoding="utf-8")
        except Exception:
            pass

        if no_sts:
            self._f(self.T_NO_STS,
                    "The UWB ranging exchange does not carry a Scrambled Timestamp "
                    "Sequence (STS mode 0 / disabled, or a legacy 802.15.4a device). "
                    "STS is the IEEE 802.15.4z cryptographic PHY field that binds the "
                    "ranging timestamp to a secret; without it the time-of-flight can "
                    "be forged, so relay, replay and distance-reduction attacks are "
                    "not cryptographically prevented.",
                    "High", tool="uwb", ip="", output_file=evidence,
                    remediation="Enable IEEE 802.15.4z HRP secure ranging with STS "
                                "(FiRa PDoA/OWR or DS-TWR with STS), provisioned via a "
                                "per-session key; disable legacy 802.15.4a ranging.")
            self._f(self.T_UNAUTH,
                    "Ranging frames are exchanged without cryptographic "
                    "authentication of the timestamp, so a receiver cannot verify "
                    "that a poll/response/final actually originated from the claimed "
                    "peer at the measured distance. Unauthenticated ranging under-"
                    "pins the relay and distance-reduction attacks below.",
                    "High", tool="uwb", ip="", output_file=evidence,
                    remediation="Require STS-authenticated secure ranging and reject "
                                "ranging rounds that omit or fail STS verification.")
            if "legacy" in a:
                self._f(self.T_LEGACY,
                        "The device appears to support only pre-802.15.4z (802.15.4a "
                        "HRP) ranging, which has no secure-ranging (STS) capability at "
                        "all. Such devices cannot be made secure by configuration and "
                        "must be replaced for any security-relevant ranging use.",
                        "Medium", tool="uwb", ip="", output_file=evidence,
                        remediation="Replace legacy 802.15.4a-only UWB parts with "
                                    "802.15.4z STS-capable silicon (e.g. DW3000-class) "
                                    "for access control or safety-critical asset "
                                    "tracking.")

        # ── Distance-reduction (Ghost Peak) susceptibility ──────────────────
        dist_ans = self._prompt(
            "ACTIVE / SAFETY-GATED — Distance-reduction (Ghost Peak): a physical-"
            "layer attacker can inject an early cipher-guessed STS/preamble to make "
            "the ranging peer measure a SHORTER distance than real, defeating "
            "proximity-based access control. Testing needs an over-the-air injector "
            "and can disturb a live ranging link. Do you want to record a distance-"
            "reduction assessment? (Ghost Peak affected Apple U1, NXP SR040/SR150, "
            "Qorvo DW3000.)",
            options=["DUT susceptible (no STS / demonstrated reduction)",
                     "DUT resistant (STS enforced, no reduction observed)",
                     "Not tested — passive only"],
            prompt_type="choice", skippable=True)
        da = (dist_ans or "").lower()
        if "susceptible" in da or (not dist_ans and no_sts):
            self._f(self.T_DISTANCE,
                    "The UWB ranging is susceptible to a distance-reduction ('Ghost "
                    "Peak') attack: without enforced STS integrity an over-the-air "
                    "adversary can cause the peer to report a shorter-than-actual "
                    "distance. Where UWB gates physical access or presence (secure "
                    "entry, unlock-on-approach, RTLS geofencing), an attacker can "
                    "appear 'in range' from outside the intended zone.",
                    "High", tool="uwb", ip="", output_file=evidence,
                    force_classification=("Validated" if "susceptible" in da else ""),
                    remediation="Enforce STS with a minimum acceptable STS quality/"
                                "confidence, reject ranging with low STS-figure-of-"
                                "merit, and add an application-layer distance bound / "
                                "multi-anchor cross-check.")

        # ── Relay susceptibility ────────────────────────────────────────────
        relay_ans = self._prompt(
            "ACTIVE / SAFETY-GATED — Relay attack: two back-to-back radios forward "
            "the ranging exchange to make a distant tag/anchor appear adjacent "
            "(classic RTLS/access-control relay). Without STS, UWB does not detect "
            "the relay. Record a relay assessment?",
            options=["DUT susceptible (relay succeeded / no STS)",
                     "DUT resistant (STS-bound, relay rejected)",
                     "Not tested — passive only"],
            prompt_type="choice", skippable=True)
        ra = (relay_ans or "").lower()
        if "susceptible" in ra or (not relay_ans and no_sts):
            self._f(self.T_RELAY,
                    "The UWB ranging is susceptible to a relay attack: an attacker "
                    "relaying the ranging frames between a genuine tag and anchor can "
                    "make a far peer appear in proximity. STS-based secure ranging "
                    "binds the timing to a secret and is the defined mitigation; its "
                    "absence leaves proximity guarantees unenforced.",
                    "High", tool="uwb", ip="", output_file=evidence,
                    force_classification=("Validated" if "susceptible" in ra else ""),
                    remediation="Enable STS secure ranging and bind the ranging "
                                "result to an authenticated session; do not treat a "
                                "UWB distance as trustworthy without STS verification.")

        # ── Replay of ranging frames ────────────────────────────────────────
        replay_ans = self._prompt(
            "Replay: were previously-captured UWB ranging frames (poll/response/"
            "final or blink) replayed and ACCEPTED by the peer? Acceptance implies "
            "no per-session STS/nonce freshness. (Passive capture then re-inject.)",
            options=["Yes — replayed frames accepted",
                     "No — replay rejected (fresh STS/nonce)",
                     "Not tested"],
            prompt_type="choice", skippable=True)
        rpa = (replay_ans or "").lower()
        if rpa.startswith("yes"):
            self._f(self.T_REPLAY,
                    "Previously-captured UWB ranging frames were replayed and "
                    "accepted by the ranging peer, showing the exchange lacks a "
                    "per-session freshness guarantee (fresh STS / nonce / counter). "
                    "Replayable ranging enables spoofed presence and distance in "
                    "RTLS and access-control use.",
                    "High", tool="uwb", ip="", output_file=evidence,
                    force_classification="Validated",
                    remediation="Derive a fresh STS per ranging session from a "
                                "monotonic counter / nonce and reject frames whose "
                                "STS does not match the current session.")

        # ── STS reuse / static ranging key ──────────────────────────────────
        if parsed["sts_seen"] and not no_sts:
            key_ans = self._prompt(
                "STS is present. Is the STS/ranging key rotated per session, or is "
                "the same STS seed/key reused across ranging rounds (observable as a "
                "repeating STS pattern)? Reuse degrades STS back toward replayability.",
                options=["Rotated per session (good)",
                         "Static / reused STS seed observed",
                         "Could not determine"],
                prompt_type="choice", skippable=True)
            if "static" in (key_ans or "").lower() or "reused" in (key_ans or "").lower():
                self._f(self.T_STATIC_STS,
                        "The STS appears to be derived from a static or reused seed/"
                        "key rather than rotated per ranging session. A predictable "
                        "or repeating STS erodes the integrity guarantee it is meant "
                        "to provide, moving the system back toward replay and "
                        "distance-manipulation exposure.",
                        "Medium", tool="uwb", ip="", output_file=evidence,
                        remediation="Provision a per-session STS from a rotating key "
                                    "(FiRa dynamic STS / per-session key derivation); "
                                    "never ship a fixed STS_KEY/STS_IV in firmware.")

        # ── Cleartext positioning / payload ─────────────────────────────────
        if parsed["cleartext_payload"]:
            self._f(self.T_CLEARTEXT,
                    "Positioning data (measured distance/coordinates) or a MAC-layer "
                    "payload was observed in the clear in the UWB capture. Cleartext "
                    "RTLS position data discloses the location of tracked assets "
                    "(and, in a clinical setting, potentially staff/patients) to any "
                    "passive UWB listener and defeats location privacy.",
                    "Medium", tool="uwb", ip="", output_file=evidence,
                    remediation="Encrypt/authenticate the ranging-result and any MAC "
                                "payload at the application layer; do not broadcast "
                                "resolved positions or asset identifiers in cleartext.")

        # ── Static-address trackability (privacy) ───────────────────────────
        static_dev = next((d for d in parsed["devices"]
                           if d["kind"] in ("EUI-64", "short-16")), None)
        if static_dev and parsed["blink_seen"]:
            self._f(self.T_TRACKABLE,
                    f"UWB blink/ranging frames broadcast a stable device address "
                    f"({static_dev['addr']}, {static_dev['kind']}). A tag that emits "
                    f"a fixed address in every blink can be tracked and correlated to "
                    f"the asset (or person) it is attached to by any passive UWB "
                    f"receiver, defeating location privacy for the RTLS deployment.",
                    "Medium", tool="uwb", ip=static_dev["addr"], output_file=evidence,
                    remediation="Rotate the tag's transmitted address/identifier "
                                "(privacy-preserving randomised addressing) and expose "
                                "the stable identity only under an authenticated session.")

        # ── Jamming / DoS (destructive — gated) ─────────────────────────────
        jam_ans = self._prompt(
            "DESTRUCTIVE / SAFETY-GATED — Jamming (UWBAD-class): a co-channel UWB "
            "jammer can deny ranging, dropping RTLS tracking or forcing an access "
            "system to fail-open/closed. This will disrupt a LIVE deployment — only "
            "proceed with authorisation and out-of-band coordination. Record a "
            "jamming/DoS observation?",
            options=["DUT ranging denied under jamming (DoS confirmed)",
                     "DUT tolerated jamming (ranging continued)",
                     "Not tested — non-destructive default"],
            prompt_type="choice", skippable=True)
        ja = (jam_ans or "").lower()
        if "denied" in ja or "confirmed" in ja:
            self._f(self.T_JAMMING,
                    "Under a co-channel UWB jammer the DUT's ranging was denied, "
                    "confirming a denial-of-service exposure. Loss of ranging can "
                    "drop safety/asset-tracking (RTLS goes blind) or push a UWB "
                    "access-control system into an unsafe fail state.",
                    "Medium", tool="uwb", ip="", output_file=evidence,
                    force_classification="Validated",
                    remediation="Define a safe fail state on ranging loss, add "
                                "jam/interference detection and alerting, and avoid "
                                "using UWB ranging as the sole gate for safety-"
                                "critical access.")
        elif jam_ans and "tolerated" in ja:
            self.ctx.logger.info("UWB jamming test: DUT tolerated jamming", tool=self.name)


# ===========================================================================
# SmartCard interface module  (integrated 2026-08-13 from _frag/SmartCard.py)
# ===========================================================================
# ---------------------------------------------------------------------------
# Smart Card / PC-SC Module  (contact + contactless smart-card auth assessment)
# ---------------------------------------------------------------------------
# One module, six phases: reader/tool detection -> card ATR fingerprint ->
# serial-number entropy -> unauthenticated APDU probing (SELECT + READ BINARY)
# -> GlobalPlatform default-key / lifecycle triage -> (operator-gated) default
# PIN test.  Detection is ORACLE-DRIVEN: the ATR bytes, the ISO-7816 status
# words (0x9000 vs 0x6982), the GlobalPlatform card-lifecycle state and the
# gp default-key SCP authentication result are all directly observable, so the
# module rules out each CVM / key / cleartext-data weakness without any prior
# knowledge of the card under test.  Everything default is NON-DESTRUCTIVE
# (read-only SELECT/READ + read-only gp -info); the only PIN-verify path that
# can decrement a retry counter and lock a LIVE card is gated behind an
# explicit operator confirmation (§ SAFETY).

# Well-known transparent elementary files worth a non-destructive READ BINARY.
# EF.DIR (2F00) and EF.ATR/INFO (2F01) live directly under the MF on most
# ISO-7816 cards and legitimately carry cleartext application/asset data — a
# READ that returns 0x9000 + bytes *before any VERIFY* proves the file is
# reachable with no cardholder verification.
_SMARTCARD_CANDIDATE_EFS: list[tuple[str, str]] = [
    ("2F00", "EF.DIR — application directory"),
    ("2F01", "EF.ATR / EF.INFO — card information"),
]

# GlobalPlatformPro / gpshell default "test" key set (40..4F).  A card whose
# Issuer Security Domain still authenticates an SCP secure channel with this
# key has never had its manufacturing keys rotated.
_SMARTCARD_DEFAULT_GP_KEY = "404142434445464748494A4B4C4D4E4F"

# GlobalPlatform card-lifecycle states that indicate the card manager was never
# transitioned to its locked production state (SECURED / CARD_LOCKED).
_SMARTCARD_INSECURE_LIFECYCLE = ("OP_READY", "INITIALIZED")

# A very small, well-published set of factory-default user PINs.  Used ONLY in
# the operator-gated, single-attempt default-PIN path — never iterated.
_SMARTCARD_DEFAULT_PINS = ["1234", "0000", "00000000", "12345678", "11111111"]


def _smartcard_which(name: str) -> str:
    """shutil.which wrapper (returns '' when the binary is absent)."""
    return shutil.which(name) or ""


def _smartcard_pcscd_running() -> bool:
    """Best-effort check that the PC/SC daemon is reachable."""
    try:
        p = subprocess.run(["pgrep", "-x", "pcscd"], capture_output=True, text=True, timeout=5)
        return p.returncode == 0
    except Exception:
        return False


def _smartcard_parse_atr(text: str) -> str:
    """Extract the first ATR hex string from pcsc_scan / opensc-tool output."""
    if not text:
        return ""
    m = re.search(r"ATR:\s*([0-9A-Fa-f ]{6,})", text)
    if m:
        return re.sub(r"\s+", " ", m.group(1).strip()).upper()
    # opensc-tool --atr prints a bare colon/space separated hex line.
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:\s]){5,}[0-9A-Fa-f]{2}", line):
            return re.sub(r"[:\s]+", " ", line).upper()
    return ""


def _smartcard_parse_readers(text: str) -> list[str]:
    """Parse reader names from pcsc_scan / opensc-tool --list-readers output."""
    readers: list[str] = []
    for line in (text or "").splitlines():
        m = re.match(r"\s*(?:Reader\s+\d+:|\d+\s+)(.+\S)", line)
        if m and "no reader" not in line.lower():
            name = m.group(1).strip()
            if name and name not in readers:
                readers.append(name)
    return readers


def _smartcard_parse_sw(text: str) -> str:
    """Return the ISO-7816 status word (e.g. '9000') from opensc-tool output."""
    m = re.search(r"SW1?\s*=?\s*0x([0-9A-Fa-f]{2}).{0,4}SW2\s*=?\s*0x([0-9A-Fa-f]{2})", text or "")
    if m:
        return (m.group(1) + m.group(2)).upper()
    m = re.search(r"Received.*?([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s*$", text or "", re.M)
    if m:
        return (m.group(1) + m.group(2)).upper()
    return ""


def _smartcard_parse_apdu_data(text: str) -> str:
    """Return response-data hex (excluding the trailing SW) from an APDU reply."""
    if not text:
        return ""
    m = re.search(r"Received[^\n]*:\s*\n?((?:[0-9A-Fa-f]{2}[:\s]*)+)", text)
    if not m:
        return ""
    data = re.sub(r"[:\s]+", " ", m.group(1).strip()).upper()
    # opensc-tool prints the SW on the "Received (SW1=..,SW2=..)" line, so the
    # captured block is response data only — return every byte.
    return " ".join(data.split())


def _smartcard_ascii_strings(hex_str: str, minlen: int = 4) -> list[str]:
    """Extract printable ASCII runs from a space-separated hex byte string."""
    out: list[str] = []
    cur = ""
    for tok in (hex_str or "").split():
        try:
            b = int(tok, 16)
        except ValueError:
            continue
        if 0x20 <= b <= 0x7E:
            cur += chr(b)
        else:
            if len(cur) >= minlen:
                out.append(cur)
            cur = ""
    if len(cur) >= minlen:
        out.append(cur)
    return out


def _smartcard_serial_predictable(serial: str) -> tuple[bool, str]:
    """
    Heuristic: does a card serial look low-entropy / sequential / predictable?
    Returns (predictable, reason).  Conservative — only flags obvious cases.
    """
    s = re.sub(r"[\s:]+", "", serial or "").upper()
    if not s or len(s) < 4:
        return False, ""
    digits = re.sub(r"[^0-9A-F]", "", s)
    if not digits:
        return False, ""
    # All-zero prefix with a tiny numeric tail (0000000000000042).
    if re.fullmatch(r"0*[0-9A-F]{1,4}", s):
        return True, "serial is a zero-padded small value with almost no entropy"
    # Strictly ascending or descending consecutive nibble sequence.
    try:
        vals = [int(c, 16) for c in s]
        asc = all(vals[i + 1] - vals[i] == 1 for i in range(len(vals) - 1))
        desc = all(vals[i] - vals[i + 1] == 1 for i in range(len(vals) - 1))
        if asc or desc:
            return True, "serial is a monotonic sequential run of nibbles"
    except ValueError:
        pass
    # Single repeated character (AAAAAAAA / 11111111).
    if len(set(s)) == 1:
        return True, "serial is a single repeated character"
    return False, ""


class SmartCardModule(BaseModule):
    """
    Smart-card / PC-SC security assessment for devices using contact or
    contactless smart-card authentication.

    Uses an Identiv SCR3310 (or any PC/SC) reader to detect the card, fingerprint
    its ATR, sample its serial-number entropy, probe for unauthenticated APDU
    access to sensitive files (weak/absent CVM), triage GlobalPlatform card-
    manager keys / lifecycle state, and — only under explicit operator
    confirmation — test a single well-known default PIN.  Detection is oracle-
    driven from ISO-7816 status words and gp's SCP authentication result, so no
    card identity is assumed.
    """
    name        = "SmartCard"
    description = "PC/SC smart-card assessment (reader → ATR → APDU/CVM → GlobalPlatform keys)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_READER_DETECTED = "Smart Card Reader Detected"
    T_DETECTED        = "Smart Card Detected"
    T_ATR             = "Smart Card ATR Fingerprinted"
    T_SERIAL_PRED     = "Predictable Smart Card Serial Number"
    T_WEAK_CVM        = "Weak or Absent Cardholder Verification Method"
    T_UNAUTH_APDU     = "Unauthenticated APDU Access to Sensitive File"
    T_DEFAULT_GP      = "Default GlobalPlatform Card Manager Keys"
    T_CLEARTEXT       = "Cleartext Data Object Readable on Smart Card"
    T_DEFAULT_PIN     = "Default or Known Smart Card PIN Accepted"
    T_LIFECYCLE       = "Insecure GlobalPlatform Card Lifecycle State"
    T_NO_SECMSG       = "No Secure Messaging — Cleartext APDU Channel"
    T_SKIPPED         = "SmartCard Testing SKIPPED — No PC/SC Reader or Tools Available"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "SmartCard" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane smart-card defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "opensc-tool"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [SmartCard] {msg}", tool=self.name)
        except Exception:
            pass

    # ── APDU helper (non-destructive by default) ────────────────────────────
    def _apdu(self, apdu_hex: str, out_file: Path, timeout: int = 30) -> tuple[str, str]:
        """
        Send one raw APDU via opensc-tool --send-apdu.
        Returns (status_word, response_data_hex).  Never raises.
        """
        colon = ":".join(apdu_hex.split())
        try:
            rc, out, err = run_tool(
                ["opensc-tool", "--send-apdu", colon],
                self.ctx, tool_name="opensc-tool", output_file=out_file, timeout=timeout)
        except Exception as e:
            self.ctx.logger.warn(f"APDU {apdu_hex} failed: {e}", tool=self.name)
            return "", ""
        blob = (out or "") + "\n" + (err or "")
        return _smartcard_parse_sw(blob), _smartcard_parse_apdu_data(blob)

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"SmartCardModule v{VERSION} started for [{self.ctx.instance_loc}]")
            if not self._phase0_setup():
                return  # skipped — honest finding already emitted
            card = self._phase1_detect()
            if not card.get("present"):
                self._mark_complete("Reader ready — no card presented")
                return
            self._phase2_fingerprint(card)
            self._phase3_apdu_cvm(card)
            self._phase4_globalplatform(card)
            self._phase5_default_pin(card)
            self._mark_complete("Smart-card assessment complete")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — reader / toolchain detection ──────────────────────────────
    def _phase0_setup(self) -> bool:
        self._event("Phase 0 — reader & toolchain detection")
        have = {t: _smartcard_which(t) for t in ("pcsc_scan", "opensc-tool", "gp")}
        if not have["pcsc_scan"] and not have["opensc-tool"]:
            self._f(self.T_SKIPPED,
                    "Smart-card testing was NOT performed: neither pcsc_scan (pcsc-tools) "
                    "nor opensc-tool (OpenSC) was found on PATH. Connect an Identiv SCR3310 "
                    "(or any PC/SC) reader, install pcsc-tools + opensc (and, for card-manager "
                    "key testing, GlobalPlatformPro 'gp'), start pcscd, and re-run the module.",
                    "Informational", tool="opensc-tool")
            self._mark_complete("SmartCard SKIPPED — pcsc-tools/opensc not installed")
            return False

        self._prompt(
            f"Connect the Identiv SCR3310 (USB-A or USB-C) PC/SC reader and insert the "
            f"smart card under test for [{self.ctx.instance_loc}]. Ensure pcscd is running. "
            f"Press Enter to begin detection.",
            options=["Ready"], prompt_type="choice")
        self._prompt_connected_photo(
            f"Identiv SCR3310 PC/SC reader connected for [{self.ctx.instance_loc}]")

        if not _smartcard_pcscd_running():
            self.ctx.logger.warn(
                "pcscd does not appear to be running — detection may fail. "
                "Start it with: sudo systemctl start pcscd", tool=self.name)
        return True

    # ── Phase 1 — reader + card presence detection ──────────────────────────
    def _phase1_detect(self) -> dict:
        self._event("Phase 1 — reader & card detection")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Detecting reader & card…")
        out_dir = self._dir("01_detect")
        card: dict = {"present": False, "atr": "", "readers": []}

        # pcsc_scan snapshot (loops forever — bound it with timeout, like the
        # Bluetooth module bounds btmon).
        scan_txt = out_dir / f"{self.ctx.file_prefix}_pcsc_scan.txt"
        scan_out = ""
        if _smartcard_which("pcsc_scan"):
            try:
                run_tool(["bash", "-c", f"timeout 8 pcsc_scan || true"],
                         self.ctx, tool_name="pcsc_scan", output_file=scan_txt, timeout=20)
                scan_out = scan_txt.read_text(errors="replace")
            except Exception as e:
                self.ctx.logger.warn(f"pcsc_scan failed: {e}", tool=self.name)

        # opensc-tool reader list + ATR (authoritative for later APDU work).
        lr_txt = out_dir / f"{self.ctx.file_prefix}_opensc_readers.txt"
        atr_txt = out_dir / f"{self.ctx.file_prefix}_opensc_atr.txt"
        lr_out = atr_out = ""
        if _smartcard_which("opensc-tool"):
            try:
                run_tool(["opensc-tool", "--list-readers"], self.ctx,
                         tool_name="opensc-tool", output_file=lr_txt, timeout=30)
                lr_out = lr_txt.read_text(errors="replace")
            except Exception:
                pass
            try:
                run_tool(["opensc-tool", "--atr"], self.ctx,
                         tool_name="opensc-tool", output_file=atr_txt, timeout=30)
                atr_out = atr_txt.read_text(errors="replace")
            except Exception:
                pass

        readers = _smartcard_parse_readers(scan_out) or _smartcard_parse_readers(lr_out)
        card["readers"] = readers
        for r in readers:
            self._f(self.T_READER_DETECTED,
                    f"A PC/SC smart-card reader was detected: '{r}'. The reader provides the "
                    f"contact/contactless channel used for all subsequent card testing.",
                    "Informational", tool="pcsc_scan", affected_component=r,
                    output_file=str(scan_txt if scan_out else lr_txt))

        atr = _smartcard_parse_atr(atr_out) or _smartcard_parse_atr(scan_out)
        card["atr"] = atr
        card["present"] = bool(atr) or bool(re.search(r"card inserted|Card state.*present", scan_out, re.I))
        if card["present"]:
            loc = readers[0] if readers else "PC/SC reader"
            self._f(self.T_DETECTED,
                    f"A smart card was detected in {loc} during zero-knowledge scanning"
                    + (f" (ATR {atr})" if atr else "") + ". Its presence confirms a live "
                    f"smart-card authentication surface for the device under test.",
                    "Informational", tool="pcsc_scan",
                    output_file=str(scan_txt if scan_out else atr_txt))
        else:
            self.ctx.logger.info("No card ATR observed — reader present but no card.", tool=self.name)
        return card

    # ── Phase 2 — ATR fingerprint + serial-number entropy ───────────────────
    def _phase2_fingerprint(self, card: dict) -> None:
        self._event("Phase 2 — ATR fingerprint & serial entropy")
        out_dir = self._dir("02_fingerprint")
        atr = card.get("atr", "")

        # ATR analysis (pcsc_tools ships ATR_analysis; opensc-tool --name maps
        # the ATR to a known card model when possible).
        name_txt = out_dir / f"{self.ctx.file_prefix}_opensc_name.txt"
        card_name = ""
        if _smartcard_which("opensc-tool"):
            try:
                rc, out, err = run_tool(["opensc-tool", "--name"], self.ctx,
                                        tool_name="opensc-tool", output_file=name_txt, timeout=30)
                card_name = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
            except Exception:
                pass
        if atr:
            self._f(self.T_ATR,
                    f"The card's Answer-To-Reset (ATR) was fingerprinted: {atr}"
                    + (f" — identified as '{card_name}'." if card_name and "unknown" not in card_name.lower() else ".")
                    + " The ATR discloses the card platform / chip / operating system and "
                    "defines the applet and CVM surface tested in later phases.",
                    "Informational", tool="opensc-tool", affected_component=card_name,
                    output_file=str(name_txt))

        # Serial number (works for PKCS#15 / GlobalPlatform cards).
        serial_txt = out_dir / f"{self.ctx.file_prefix}_opensc_serial.txt"
        serial = ""
        if _smartcard_which("opensc-tool"):
            try:
                rc, out, err = run_tool(["opensc-tool", "--serial"], self.ctx,
                                        tool_name="opensc-tool", output_file=serial_txt, timeout=30)
                m = re.search(r"([0-9A-Fa-f]{2}(?:[:\s][0-9A-Fa-f]{2}){3,})", out or "")
                serial = m.group(1).strip() if m else ""
            except Exception:
                pass
        if serial:
            predictable, reason = _smartcard_serial_predictable(serial)
            if predictable:
                self._f(self.T_SERIAL_PRED,
                        f"The card serial number ({serial}) appears predictable: {reason}. "
                        f"A guessable or sequential serial lets an attacker enumerate or clone "
                        f"card identity, forge enrolment records, or correlate a card to a holder "
                        f"without physical access.",
                        "Low", tool="opensc-tool", affected_component=serial,
                        output_file=str(serial_txt),
                        remediation="Issue cards with cryptographically-random, high-entropy "
                                    "serial/UID values; never derive the identifier from a "
                                    "sequential batch counter.")

    # ── Phase 3 — unauthenticated APDU probing / CVM triage ─────────────────
    def _phase3_apdu_cvm(self, card: dict) -> None:
        self._event("Phase 3 — unauthenticated APDU probing (SELECT + READ BINARY)")
        if not _smartcard_which("opensc-tool"):
            return
        out_dir = self._dir("03_apdu")

        # Select the Master File first (non-destructive).
        self._apdu("00 A4 00 00 02 3F 00",
                   out_dir / f"{self.ctx.file_prefix}_select_mf.txt")

        readable_any = False
        for fid, label in _SMARTCARD_CANDIDATE_EFS:
            sel_f = out_dir / f"{self.ctx.file_prefix}_select_{fid}.txt"
            sw_sel, _ = self._apdu(f"00 A4 00 00 02 {fid[:2]} {fid[2:]}", sel_f)
            if sw_sel and not sw_sel.startswith("90") and sw_sel[:2] not in ("61", "62", "63"):
                continue  # file absent / not selectable
            rd_f = out_dir / f"{self.ctx.file_prefix}_read_{fid}.txt"
            # READ BINARY, no prior VERIFY — this is the CVM oracle.
            sw_rd, data = self._apdu("00 B0 00 00 00", rd_f)
            if sw_rd.startswith("90") and data:
                readable_any = True
                self._f(self.T_UNAUTH_APDU,
                        f"The elementary file {fid} ({label}) was read via a raw READ BINARY "
                        f"APDU that returned status word 0x{sw_rd} with data, WITHOUT any prior "
                        f"cardholder verification (no PIN/VERIFY was presented). Any party with "
                        f"brief physical access to the card and a $30 reader can extract this "
                        f"file's contents.",
                        "High", tool="opensc-tool", affected_component=f"EF {fid}",
                        output_file=str(rd_f),
                        remediation="Protect sensitive elementary files with a CVM (PIN/biometric) "
                                    "access condition and enforce it in the card OS access rules; "
                                    "require secure messaging for READ BINARY on protected files.")
                strings = _smartcard_ascii_strings(data)
                if strings:
                    self._f(self.T_CLEARTEXT,
                            f"Data read from EF {fid} without authentication contains cleartext "
                            f"printable strings (e.g. {', '.join(repr(s) for s in strings[:4])}). "
                            f"Sensitive data objects stored and returned in the clear disclose "
                            f"asset, holder or configuration information to anyone who can read the card.",
                            "Medium", tool="opensc-tool", affected_component=f"EF {fid}",
                            output_file=str(rd_f),
                            remediation="Store sensitive data objects encrypted or behind a CVM; "
                                        "do not return holder/asset identifiers from unauthenticated files.")
                self._f(self.T_NO_SECMSG,
                        f"The card returned sensitive file data from EF {fid} over a cleartext "
                        f"(plain) APDU channel with no secure messaging applied. A passive USB or "
                        f"contactless interceptor can capture the exchange verbatim.",
                        "Medium", tool="opensc-tool", affected_component=f"EF {fid}",
                        output_file=str(rd_f),
                        remediation="Mandate GlobalPlatform / ISO-7816 secure messaging (C-MAC + "
                                    "C-ENC) for all commands that carry or return sensitive data.")
            elif sw_rd in ("6982",):
                self.ctx.logger.info(
                    f"EF {fid} correctly refused READ BINARY without CVM (SW 6982).", tool=self.name)

        if readable_any:
            self._f(self.T_WEAK_CVM,
                    "The card served sensitive file content in response to raw READ BINARY APDUs "
                    "with no Cardholder Verification Method enforced (no PIN was required, and the "
                    "card did not answer 0x6982 'security status not satisfied'). Authentication to "
                    "the card is effectively absent for the affected files.",
                    "High", tool="opensc-tool",
                    remediation="Define and enforce a CVM (PIN, PACE, or on-card biometric) access "
                                "condition on every protected file and command; verify the card "
                                "returns 0x6982 for unauthenticated access.")

    # ── Phase 4 — GlobalPlatform default keys / lifecycle ───────────────────
    def _phase4_globalplatform(self, card: dict) -> None:
        self._event("Phase 4 — GlobalPlatform key & lifecycle triage")
        if not _smartcard_which("gp"):
            self.ctx.logger.info(
                "GlobalPlatformPro 'gp' not on PATH — skipping card-manager key test.",
                tool=self.name)
            return
        out_dir = self._dir("04_globalplatform")
        info_txt = out_dir / f"{self.ctx.file_prefix}_gp_info.txt"

        # gp -info authenticates the ISD SCP secure channel with the DEFAULT
        # test key (40..4F).  Success => the manufacturing keys were never
        # rotated.  This is a READ-ONLY operation (no applet install/delete).
        rc, out, err = 0, "", ""
        try:
            rc, out, err = run_tool(["gp", "-info"], self.ctx,
                                    tool_name="gp", output_file=info_txt, timeout=60)
        except Exception as e:
            self.ctx.logger.warn(f"gp -info failed: {e}", tool=self.name)
            return
        blob = (out or "") + "\n" + (err or "")
        auth_ok = rc == 0 and re.search(
            r"Key\s*Version|SCP0?[123]|Card\s*Data|GlobalPlatform|lifecycle|CardRecognition",
            blob, re.I)
        auth_fail = re.search(r"authenticat\w+\s+fail|wrong\s+key|6982|6300|Strict\s+mode", blob, re.I)

        if auth_ok and not auth_fail:
            self._f(self.T_DEFAULT_GP,
                    "The card's GlobalPlatform Issuer Security Domain authenticated a secure "
                    f"channel using the DEFAULT test key set ({_SMARTCARD_DEFAULT_GP_KEY}, the "
                    "gp/gpshell 40..4F factory key). An attacker with the card can open the same "
                    "channel to install, delete, or replace applets and read/rotate keys — full "
                    "card-manager compromise.",
                    "Critical", tool="gp", output_file=str(info_txt),
                    cve_ids=[],
                    remediation="Rotate the ISD keys (ENC/MAC/KEK) to unique, per-card random "
                                "values before deployment via GlobalPlatform PUT KEY; never ship "
                                "cards on the 40..4F default key set.")
            # Lifecycle state (only meaningful once we can talk to the ISD).
            m = re.search(r"(OP_READY|INITIALIZED|SECURED|CARD_LOCKED|TERMINATED)", blob, re.I)
            state = m.group(1).upper() if m else ""
            if state in _SMARTCARD_INSECURE_LIFECYCLE:
                self._f(self.T_LIFECYCLE,
                        f"The GlobalPlatform card lifecycle state is {state}, not SECURED. A card "
                        f"left in {state} permits card-content management and key setup operations "
                        f"that should be closed off once the card is issued.",
                        "Medium", tool="gp", affected_component=state,
                        output_file=str(info_txt),
                        remediation="Transition the card to the SECURED lifecycle state (and lock "
                                    "the card manager) as part of issuance so pre-personalisation "
                                    "management commands are no longer accepted.")
        else:
            self.ctx.logger.info(
                "gp -info did not authenticate with the default key — ISD keys appear rotated.",
                tool=self.name)

    # ── Phase 5 — default PIN test (SAFETY-gated, single attempt) ───────────
    def _phase5_default_pin(self, card: dict) -> None:
        self._event("Phase 5 — default PIN test (operator-gated)")
        if not _smartcard_which("opensc-tool"):
            return
        ans = self._prompt(
            "SAFETY: attempt a SINGLE bounded default-PIN VERIFY against the card?\n"
            "A wrong PIN decrements the card's retry counter and can permanently LOCK a "
            "LIVE medical/production card. Only proceed on a card you may risk. Gearbox will "
            "try at most ONE well-known default PIN and stop — it will NOT brute force.\n"
            "Choose the action:",
            options=["Yes — try one default PIN (risk acknowledged)",
                     "No — skip (non-destructive, recommended)"],
            prompt_type="choice", skippable=True)
        if not ans or not ans.lower().startswith("yes"):
            self.ctx.logger.info(
                "Operator declined the default-PIN test — skipped (non-destructive).",
                tool=self.name)
            return

        out_dir = self._dir("05_pin")
        pin = _SMARTCARD_DEFAULT_PINS[0]  # single attempt only — no iteration
        pin_hex = " ".join(f"{ord(c):02X}" for c in pin)
        lc = f"{len(pin):02X}"
        verify_f = out_dir / f"{self.ctx.file_prefix}_verify_default_pin.txt"
        # ISO-7816 VERIFY: 00 20 00 80 Lc <PIN>  (P2=80 = global PIN ref).
        sw, _ = self._apdu(f"00 20 00 80 {lc} {pin_hex}", verify_f)
        observed = self._prompt(
            f"opensc-tool VERIFY returned status word 0x{sw or '????'} for default PIN '{pin}'. "
            f"Record the operator's observation (did the card accept the PIN / how many tries remain?).",
            options=["PIN ACCEPTED (0x9000)", "PIN rejected — tries remain",
                     "Card locked / other"], prompt_type="choice", skippable=True)
        if sw.startswith("90") or (observed or "").lower().startswith("pin accepted"):
            self._f(self.T_DEFAULT_PIN,
                    f"The card accepted a well-known factory default PIN ('{pin}') via an ISO-7816 "
                    f"VERIFY command (SW 0x{sw or '9000'}). Anyone in possession of the card can "
                    f"satisfy cardholder verification and unlock CVM-protected files and operations.",
                    "High", tool="opensc-tool", output_file=str(verify_f),
                    remediation="Force a PIN change away from all factory defaults at first use; "
                                "enforce PIN complexity and a low retry counter with a secure "
                                "unblock (PUK) procedure.")
        else:
            self.ctx.logger.info(
                f"Default PIN '{pin}' rejected (SW 0x{sw or '????'}) — no default-PIN finding. "
                f"Operator note: {observed}", tool=self.name)


# ===========================================================================
# ZWave interface module  (integrated 2026-08-13 from _frag/ZWave.py)
# ===========================================================================
# ---------------------------------------------------------------------------
# Z-Wave Module  (868/908 MHz sub-GHz mesh — passive-first assessment)
# ---------------------------------------------------------------------------
# One module, four phases: hardware setup -> passive Z-Wave frame capture ->
# node enumeration -> security triage.  Detection is ORACLE-DRIVEN from the
# cleartext-observable Z-Wave frame header: the HomeID / NodeID fields and the
# Command Class byte are transmitted in the clear on every frame, and the
# Security (S0, CC 0x98) / Security_2 (S2, CC 0x9F) encapsulation command
# classes are self-identifying, so the module rules out each weakness class
# (no-security, S0 legacy key-exchange, S2 downgrade, replay) generically
# without any prior knowledge of the device under test.
#
# SAFETY: anything that could disrupt a LIVE device (forced re-inclusion to
# capture the S0 key exchange, command replay, NonceGet flooding) is gated
# behind an explicit operator confirmation and defaults to a passive,
# non-destructive observation.  Passive capture + parsing is always preferred.

# Z-Wave regional PHY frequencies (SDR centre frequency, in Hz).
_ZWAVE_REGIONS: list[dict] = [
    {"label": "US / North America — 908.42 MHz", "freq": "908420000", "mhz": "908.42", "code": "US"},
    {"label": "EU — 868.42 MHz",                 "freq": "868420000", "mhz": "868.42", "code": "EU"},
    {"label": "ANZ — 921.42 MHz",                "freq": "921420000", "mhz": "921.42", "code": "ANZ"},
    {"label": "Hong Kong — 919.82 MHz",          "freq": "919820000", "mhz": "919.82", "code": "HK"},
    {"label": "India — 865.22 MHz",              "freq": "865220000", "mhz": "865.22", "code": "IN"},
    {"label": "Japan — 922.5 MHz",               "freq": "922500000", "mhz": "922.5",  "code": "JP"},
]

# Hardware options offered at Phase 0.  quiver = the Quiver firmware-flash
# payload that provisions the board (see /opt/pr0t31n/Quiver).
_ZWAVE_HARDWARE: list[dict] = [
    {"key": "hackrf", "sdr": True, "tx_capable": True,
     "label": "HackRF One — EZ-Wave / scapy-radio (GNU Radio SDR)",
     "quiver": "FIRMWARE - Firmware Update (hackrf)",
     "setup": ["Update host tools/firmware via Quiver: 'FIRMWARE - Firmware Update (hackrf)'.",
               "Passive scan:  ezstumbler.py -p -t 30              (discover HomeIDs/NodeIDs).",
               "Interrogate:   ezrecon.py -i <HomeID> -n <NodeID>  (version/CC/config).",
               "Fingerprint:   ezfingerprint.py -i <HomeID> -n <NodeID> (3rd vs 5th gen PHY).",
               "scapy-radio provides the GNU Radio Z-Wave PHY blocks for capture + TX.",
               "HackRF can TRANSMIT — replay / downgrade tests are RF-active (gated)."]},
    {"key": "catsniffer", "sdr": False, "tx_capable": False,
     "label": "CatSniffer (TI CC1352 multiprotocol) — Z-Wave sniffer firmware",
     "quiver": "FIRMWARE - Flash CatSniffer Sub-GHz sniffer",
     "setup": ["Flash Z-Wave/Sub-GHz sniffer firmware via Quiver: 'FIRMWARE - Flash CatSniffer Sub-GHz sniffer'.",
               "Serial capture via SerialPassthrough / pycatsniffer bridged into Wireshark.",
               "Passive receive only on this firmware — no RF injection.",
               "TOP PICK for clean passive Z-Wave frame capture (hardware PHY, low CPU)."]},
    {"key": "rtlsdr", "sdr": True, "tx_capable": False,
     "label": "RTL-SDR — waving-z / rtl_433 (passive receive only)",
     "quiver": None,
     "setup": ["No firmware flash needed. Plug in and confirm with rtl_test.",
               "waving-z:  rtl_sdr -f <freq> -s 2000000 -g 25 - | ./wave-in -",
               "rtl_433:   rtl_433 -f <freq> -R <zwave-decoder>   (partial Z-Wave support).",
               "RECEIVE ONLY — cannot transmit, so replay/downgrade tests are unavailable."]},
]

# Z-Wave Security encapsulation Command Classes (self-identifying, in the clear).
_ZW_CC_SECURITY_S0 = 0x98   # COMMAND_CLASS_SECURITY      (S0 legacy)
_ZW_CC_SECURITY_S2 = 0x9F   # COMMAND_CLASS_SECURITY_2    (S2)

# A subset of common actuator/sensor command classes whose presence in the
# CLEAR (not wrapped in 0x98/0x9F) means the control channel is unencrypted.
_ZW_CC_NAMES: dict[int, str] = {
    0x20: "Basic", 0x25: "Binary Switch", 0x26: "Multilevel Switch",
    0x62: "Door Lock", 0x63: "User Code", 0x40: "Thermostat Mode",
    0x43: "Thermostat Setpoint", 0x71: "Alarm/Notification",
    0x30: "Binary Sensor", 0x31: "Multilevel Sensor", 0x5A: "Device Reset Locally",
    0x98: "Security (S0)", 0x9F: "Security_2 (S2)", 0x84: "Wake Up",
    0x86: "Version", 0x72: "Manufacturer Specific", 0x70: "Configuration",
}


def _zwave_which(name: str) -> Optional[str]:
    """Locate a Z-Wave SDR tool (PATH + common EZ-Wave / waving-z install dirs)."""
    p = shutil.which(name)
    if p:
        return p
    for cand in (f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}"):
        if os.path.exists(cand):
            return cand
    if name in ("ezstumbler.py", "ezrecon.py", "ezfingerprint.py"):
        for base in ("/opt/EZ-Wave/tools", str(Path.home() / "EZ-Wave/tools")):
            cand = os.path.join(base, name)
            if os.path.exists(cand):
                return cand
    if name in ("wave-in", "wave-out", "waving-z"):
        for base in ("/opt/waving-z", "/opt/waving-z/build", str(Path.home() / "waving-z")):
            cand = os.path.join(base, name if name != "waving-z" else "wave-in")
            if os.path.exists(cand):
                return cand
    return None


def _zwave_classify_cc(cc_byte: int) -> tuple[str, bool]:
    """
    Classify a Z-Wave Command Class byte's security posture.
    Returns (security_class, encrypted):
      0x98 -> ("S0", True)   0x9F -> ("S2", True)   anything else -> ("none", False)
    """
    if cc_byte == _ZW_CC_SECURITY_S0:
        return ("S0", True)
    if cc_byte == _ZW_CC_SECURITY_S2:
        return ("S2", True)
    return ("none", False)


def _zwave_parse_frames(text: str) -> list[dict]:
    """
    Best-effort parse of captured Z-Wave frames from ezstumbler / waving-z /
    rtl_433 textual output into frame dicts:
        {home_id, src, dst, cc, cc_name, security, encrypted, raw}

    Two grounded shapes are recognised:
      1. Structured lines that name the fields, e.g.
           "HomeID: 0xE1F2A3B4  Src: 01  Dst: 05  CC: 0x25 (Binary Switch)"
         (ezstumbler / waving-z decoded output).
      2. Raw hex frames — HomeID is the leading 4 bytes; the Command Class byte
         follows the frame-control/length/dest header (offset 7 in a singlecast
         frame).  Used as a fallback when only a hex dump is available.
    """
    frames: list[dict] = []
    seen: set = set()
    low = text or ""

    # Shape 1 — labelled fields.
    for line in low.splitlines():
        hid = re.search(r"home\s*id[:=]?\s*(?:0x)?([0-9a-fA-F]{8})", line, re.I)
        if not hid:
            continue
        home = hid.group(1).upper()
        src = re.search(r"\bsrc(?:\s*node)?[:=]?\s*(?:0x)?([0-9a-fA-F]{1,3})", line, re.I)
        dst = re.search(r"\bdst(?:\s*node)?[:=]?\s*(?:0x)?([0-9a-fA-F]{1,3})", line, re.I)
        cc = re.search(r"\bcc[:=]?\s*(?:0x)?([0-9a-fA-F]{2})", line, re.I)
        cc_byte = int(cc.group(1), 16) if cc else -1
        sec, enc = _zwave_classify_cc(cc_byte) if cc_byte >= 0 else ("unknown", False)
        key = (home, src.group(1) if src else "", dst.group(1) if dst else "", cc_byte)
        if key in seen:
            continue
        seen.add(key)
        frames.append({
            "home_id":  home,
            "src":      (src.group(1).upper() if src else ""),
            "dst":      (dst.group(1).upper() if dst else ""),
            "cc":       cc_byte,
            "cc_name":  _ZW_CC_NAMES.get(cc_byte, "unknown"),
            "security": sec,
            "encrypted": enc,
            "raw":      line.strip()[:200],
        })

    if frames:
        return frames

    # Shape 2 — raw hex-frame fallback.
    for m in re.finditer(r"((?:[0-9a-fA-F]{2}[\s:]?){9,})", low):
        octets = re.findall(r"[0-9a-fA-F]{2}", m.group(1))
        if len(octets) < 9:
            continue
        home = "".join(octets[0:4]).upper()
        try:
            src = octets[4].upper()
            dst = octets[6].upper()
            cc_byte = int(octets[7], 16)
        except (IndexError, ValueError):
            continue
        sec, enc = _zwave_classify_cc(cc_byte)
        key = (home, src, dst, cc_byte)
        if key in seen:
            continue
        seen.add(key)
        frames.append({
            "home_id":  home, "src": src, "dst": dst, "cc": cc_byte,
            "cc_name":  _ZW_CC_NAMES.get(cc_byte, "unknown"),
            "security": sec, "encrypted": enc, "raw": m.group(1).strip()[:200],
        })
    return frames


class ZWaveModule(BaseModule):
    """
    Zero-knowledge Z-Wave (868/908 MHz) security assessment.

    Runs the full chain — hardware setup, passive frame capture, node
    enumeration, and security triage — against whatever Z-Wave mesh the device
    under test participates in, ruling out each known weakness class
    (unencrypted control, S0 legacy key exchange, S2→S0 downgrade, replay,
    NonceGet DoS) from cleartext-observable frame headers.  No HomeID/NodeID is
    assumed; discovery is passive and the RF-active tests are operator-gated.
    """
    name        = "ZWave"
    description = "Zero-knowledge Z-Wave assessment (capture → enumeration → security triage)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_DETECTED     = "Z-Wave Device Detected"
    T_ENUM         = "Z-Wave Network Enumerated"
    T_UNENCRYPTED  = "Unencrypted Z-Wave Control Frames"
    T_S0_LEGACY    = "Z-Wave S0 Legacy Security Class in Use"
    T_S0_KEYEXTRACT= "Z-Wave S0 Network Key Extractable on Inclusion"
    T_ZSHAVE       = "Z-Wave S2 Security Downgrade to S0 Accepted"
    T_REPLAY       = "Z-Wave Command Replay Accepted"
    T_S2_OK        = "Z-Wave S2 Secure Class Confirmed"
    T_NONCE_DOS    = "Z-Wave S0 NonceGet Denial-of-Service Exposure"
    T_SKIPPED      = "Z-Wave Testing SKIPPED — No SDR or Sniffer Available"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "ZWave" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane Z-Wave defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "ezwave"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [ZWave] {msg}", tool=self.name)
        except Exception:
            pass

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"ZWaveModule v{VERSION} started for [{self.ctx.instance_loc}]")
            hw = self._phase0_hardware()
            if hw is None:
                return  # skipped — honest finding already emitted
            frames = self._phase1_capture(hw)
            homes = self._phase2_enumerate(frames)
            self._phase3_security(hw, frames, homes)
            self._mark_complete(
                f"Z-Wave assessment complete — {len(frames)} frame(s), "
                f"{len(homes)} HomeID(s)")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — hardware selection + setup ────────────────────────────────
    def _phase0_hardware(self) -> Optional[dict]:
        self._event("Phase 0 — hardware selection & setup")
        labels = [h["label"] for h in _ZWAVE_HARDWARE]
        choice = self._prompt(
            "Select the Z-Wave testing hardware in use. Passive capture works "
            "with any option; RF-active tests (replay / downgrade) require a "
            "TX-capable SDR (HackRF).\n"
            "Refer to Quiver to flash the board's firmware before continuing.",
            options=labels + ["Skip Z-Wave testing"],
            prompt_type="choice", skippable=True)

        hw = next((h for h in _ZWAVE_HARDWARE if h["label"] == choice), None)
        if hw is None or (choice or "").lower().startswith("skip"):
            self._f(self.T_SKIPPED,
                    "No Z-Wave SDR or sniffer was selected for this instance, so "
                    "Z-Wave testing was NOT performed. Attach a HackRF One (EZ-Wave / "
                    "scapy-radio), a CatSniffer flashed with Sub-GHz firmware, or an "
                    "RTL-SDR (waving-z / rtl_433) and re-run the module.",
                    "Informational", tool="ezwave")
            self._mark_complete("Z-Wave SKIPPED — no hardware selected")
            return None

        # Region / frequency selection (868 EU vs 908 US, etc.).
        reg_labels = [r["label"] for r in _ZWAVE_REGIONS]
        reg_choice = self._prompt(
            "Select the Z-Wave regional frequency the device under test operates on "
            "(this sets the SDR centre frequency for capture).",
            options=reg_labels, prompt_type="choice", skippable=True)
        region = next((r for r in _ZWAVE_REGIONS if r["label"] == reg_choice),
                      _ZWAVE_REGIONS[0])
        hw = dict(hw)
        hw["region"] = region

        self.ctx.logger.info(
            f"Selected Z-Wave hardware: {hw['label']} @ {region['mhz']} MHz "
            f"({region['code']})", tool=self.name)
        if hw.get("quiver"):
            self.ctx.logger.info(
                f"Flash via Quiver payload: '{hw['quiver']}'", tool=self.name)
        for ln in hw["setup"]:
            self.ctx.logger.info(f"  {ln}", tool=self.name)
        setup_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_hardware_setup.txt"
        try:
            setup_txt.write_text(
                f"Z-Wave testing hardware: {hw['label']}\n"
                f"Region: {region['label']} (centre freq {region['freq']} Hz)\n"
                + (f"Quiver flash payload: {hw['quiver']}\n" if hw.get("quiver") else "")
                + "\n" + "\n".join(hw["setup"]) + "\n", encoding="utf-8")
        except Exception:
            pass
        self._prompt_connected_photo(
            f"{hw['label']} connected for [{self.ctx.instance_loc}]")

        # Verify at least one usable capture CLI is present.
        have_tool = any(_zwave_which(t) for t in
                        ("ezstumbler.py", "wave-in", "rtl_433", "rtl_sdr"))
        if not have_tool:
            self._f(self.T_SKIPPED,
                    "The selected hardware requires a Z-Wave capture CLI (EZ-Wave "
                    "ezstumbler.py, waving-z wave-in, or rtl_433 / rtl_sdr) but none "
                    "was found on PATH. Install EZ-Wave / waving-z / rtl-sdr "
                    "(see install.py) and re-run.",
                    "Informational", tool="ezwave")
            self._mark_complete("Z-Wave SKIPPED — capture CLI not installed")
            return None
        return hw

    # ── Phase 1 — passive frame capture ─────────────────────────────────────
    def _phase1_capture(self, hw: dict) -> list[dict]:
        self._event("Phase 1 — passive Z-Wave frame capture")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Capturing Z-Wave frames…")
        out_dir = self._dir("01_capture")
        freq = hw.get("region", _ZWAVE_REGIONS[0])["freq"]
        text = ""

        # Preferred: EZ-Wave passive stumble (decodes HomeID/NodeID/CC directly).
        ez = _zwave_which("ezstumbler.py")
        if ez:
            cap = out_dir / f"{self.ctx.file_prefix}_ezstumbler.txt"
            try:
                rc, out, err = run_tool(
                    ["python2", ez, "-p", "-t", "45"], self.ctx,
                    tool_name="ezstumbler", output_file=cap, timeout=90)
                text += (out or "")
            except Exception as e:
                self.ctx.logger.warn(f"ezstumbler capture failed: {e}", tool=self.name)

        # waving-z passive receive (rtl_sdr | wave-in pipeline).
        if not text.strip():
            wi = _zwave_which("wave-in")
            if wi and _zwave_which("rtl_sdr"):
                cap = out_dir / f"{self.ctx.file_prefix}_wavingz.txt"
                try:
                    rc, out, err = run_tool(
                        ["bash", "-c",
                         f"timeout 45 rtl_sdr -f {freq} -s 2000000 -g 25 - 2>/dev/null "
                         f"| {wi} - || true"],
                        self.ctx, tool_name="wave-in", output_file=cap, timeout=90)
                    text += (out or "")
                except Exception as e:
                    self.ctx.logger.warn(f"waving-z capture failed: {e}", tool=self.name)

        # rtl_433 fallback (partial Z-Wave decode).
        if not text.strip() and _zwave_which("rtl_433"):
            cap = out_dir / f"{self.ctx.file_prefix}_rtl433.txt"
            try:
                rc, out, err = run_tool(
                    ["bash", "-c", f"timeout 45 rtl_433 -f {freq} -F json || true"],
                    self.ctx, tool_name="rtl_433", output_file=cap, timeout=90)
                text += (out or "")
            except Exception as e:
                self.ctx.logger.warn(f"rtl_433 capture failed: {e}", tool=self.name)

        frames = _zwave_parse_frames(text)
        self.ctx.logger.info(
            f"Captured {len(frames)} Z-Wave frame(s)", tool=self.name)

        # If nothing was captured, fall back to an operator observation prompt so
        # the run is honest about whether the mesh was actually seen.
        if not frames:
            ans = self._prompt(
                "No Z-Wave frames were auto-captured. From a Wireshark/CatSniffer "
                "capture, was any Z-Wave traffic (HomeID / NodeID / Command Class) "
                "observed on this frequency?",
                options=["Yes — traffic observed (record manually)",
                         "No — no Z-Wave traffic seen"],
                prompt_type="choice", skippable=True)
            if not ans or ans.lower().startswith("no"):
                self._f(self.T_SKIPPED,
                        "No Z-Wave frames were captured and the operator confirmed no "
                        "traffic was observed on the selected frequency. Z-Wave security "
                        "triage could not be performed — verify the device is powered, "
                        "on-frequency, and actively transmitting, then re-run.",
                        "Informational", tool="ezwave",
                        output_file=str(out_dir))
        return frames

    # ── Phase 2 — node enumeration ──────────────────────────────────────────
    def _phase2_enumerate(self, frames: list[dict]) -> dict:
        self._event("Phase 2 — node enumeration")
        homes: dict[str, set] = {}
        for fr in frames:
            hid = fr["home_id"]
            homes.setdefault(hid, set())
            for nid in (fr.get("src"), fr.get("dst")):
                if nid:
                    homes[hid].add(nid)

        out_dir = self._dir("02_enumeration")
        for hid, nodes in homes.items():
            node_list = ", ".join(sorted(nodes)) or "unknown"
            evid = out_dir / f"{self.ctx.file_prefix}_homeid_{hid}.txt"
            try:
                evid.write_text(
                    f"HomeID: 0x{hid}\nNodeIDs observed: {node_list}\n\n"
                    + "\n".join(fr["raw"] for fr in frames if fr["home_id"] == hid)
                    + "\n", encoding="utf-8")
            except Exception:
                pass
            # E.1 — discovery INFO (one per HomeID).
            self._f(self.T_DETECTED,
                    f"A Z-Wave network was detected during passive capture: "
                    f"HomeID 0x{hid} with {len(nodes)} NodeID(s) observed ({node_list}). "
                    f"The HomeID and NodeIDs are transmitted in the clear on every frame "
                    f"and confirm a live Z-Wave mesh in RF range of the device under test.",
                    "Informational", tool="ezwave", ip=f"0x{hid}",
                    output_file=str(evid))
            # E.2 — node enumeration (mesh topology disclosure).
            self._f(self.T_ENUM,
                    f"The Z-Wave mesh under HomeID 0x{hid} was enumerated passively from "
                    f"cleartext frame headers, disclosing {len(nodes)} NodeID(s) "
                    f"({node_list}) and their command-class traffic. Node enumeration maps "
                    f"the controller/slave topology and defines the per-node attack surface "
                    f"assessed in the security phase.",
                    "Informational", tool="ezwave", ip=f"0x{hid}",
                    output_file=str(evid))
        return homes

    # ── Phase 3 — security triage ───────────────────────────────────────────
    def _phase3_security(self, hw: dict, frames: list[dict], homes: dict) -> None:
        self._event("Phase 3 — Z-Wave security triage")
        out_dir = self._dir("03_security")

        # Per-HomeID security posture from the observed command-class mix.
        for hid in homes:
            hframes = [f for f in frames if f["home_id"] == hid]
            has_s0 = any(f["security"] == "S0" for f in hframes)
            has_s2 = any(f["security"] == "S2" for f in hframes)
            # Cleartext control frames = a non-security CC carrying an actionable
            # actuator/lock/sensor command class in the clear.
            cleartext = [f for f in hframes
                         if f["security"] == "none" and f["cc"] in _ZW_CC_NAMES
                         and f["cc"] not in (_ZW_CC_SECURITY_S0, _ZW_CC_SECURITY_S2)]
            evid = out_dir / f"{self.ctx.file_prefix}_security_{hid}.txt"
            try:
                evid.write_text(
                    f"HomeID 0x{hid} security posture\n"
                    f"  S0 frames: {sum(1 for f in hframes if f['security']=='S0')}\n"
                    f"  S2 frames: {sum(1 for f in hframes if f['security']=='S2')}\n"
                    f"  cleartext control frames: {len(cleartext)}\n\n"
                    + "\n".join(f"{f['cc_name']} (CC 0x{f['cc']:02x}) sec={f['security']}"
                                for f in hframes if f["cc"] >= 0)
                    + "\n", encoding="utf-8")
            except Exception:
                pass

            # A.1 — unencrypted control frames (no S0/S2).
            if cleartext:
                ccs = ", ".join(sorted({f["cc_name"] for f in cleartext}))
                self._f(self.T_UNENCRYPTED,
                        f"HomeID 0x{hid} carries actionable control traffic in the CLEAR — "
                        f"no S0 (CC 0x98) or S2 (CC 0x9F) encapsulation was observed on "
                        f"command class(es): {ccs}. Any passive listener can read device "
                        f"state and, with a TX-capable radio, forge or replay commands "
                        f"(lock/unlock, switch on/off, alarm suppression) at will.",
                        "High", tool="ezwave", ip=f"0x{hid}", output_file=str(evid),
                        remediation="Enforce S2 (Security_2) on every node; remove any node "
                        "that cannot be securely included; never operate actuators or locks "
                        "over unencrypted command classes.")

            # A.2 — S0 legacy security in use.
            if has_s0 and not has_s2:
                self._f(self.T_S0_LEGACY,
                        f"HomeID 0x{hid} uses the legacy S0 Security command class (CC 0x98). "
                        f"S0 relies on AES-OFB/CBC-MAC with a network key that is exchanged at "
                        f"inclusion under a HARDCODED all-zero temporary key "
                        f"(0x00000000000000000000000000000000); an attacker who captures the "
                        f"inclusion handshake recovers the network key and can decrypt and "
                        f"forge all S0 traffic thereafter. S0 also lacks the anti-replay and "
                        f"forward-secrecy properties of S2.",
                        "Medium", tool="ezwave", ip=f"0x{hid}", output_file=str(evid),
                        cve_ids=[], remediation="Migrate all nodes to S2; retire S0-only "
                        "devices. If S0 is unavoidable, perform inclusion inside a shielded "
                        "enclosure so the key exchange cannot be sniffed.")
                # The S0 hardcoded-key inclusion weakness (surface flag).
                self._f(self.T_S0_KEYEXTRACT,
                        f"Because HomeID 0x{hid} uses S0, its network key is derivable by any "
                        f"attacker who captures a device inclusion: the Network Key Set frame "
                        f"is encrypted only under the well-known temporary key "
                        f"0x00000000000000000000000000000000, so the S0 network key can be "
                        f"extracted offline and every past/future S0 frame decrypted. "
                        f"Re-inclusion of a node (e.g. after a power loss) re-exposes the key.",
                        "High", tool="ezwave", ip=f"0x{hid}", output_file=str(evid),
                        remediation="Use S2 (ECDH-authenticated key exchange with out-of-band "
                        "DSK) so the network key is never sent under a hardcoded key; shield "
                        "any required S0 inclusion.")

            # A.3 — S2 confirmed (the good case).
            if has_s2:
                self._f(self.T_S2_OK,
                        f"HomeID 0x{hid} was observed using the S2 Security_2 command class "
                        f"(CC 0x9F). S2 performs an ECDH (Curve25519) authenticated key "
                        f"exchange with an out-of-band DSK and provides per-frame nonce-based "
                        f"anti-replay, so its control traffic is not passively decryptable or "
                        f"trivially replayable. Confirm ALL nodes are S2 and that no S0 "
                        f"fallback is permitted.",
                        "Informational", tool="ezwave", ip=f"0x{hid}", output_file=str(evid))

        # ── RF-ACTIVE tests (gated — could disrupt a live device) ───────────
        tx_ok = hw.get("tx_capable")
        self._active_downgrade_probe(out_dir, homes, tx_ok)
        self._active_replay_probe(out_dir, homes, tx_ok)
        self._nonce_dos_probe(out_dir, homes)

    def _active_downgrade_probe(self, out_dir: Path, homes: dict, tx_ok: bool) -> None:
        """Z-Shave S2→S0 downgrade — RF-active; operator-gated, non-destructive default."""
        if not homes:
            return
        note = ("This transmits a forged KEX_REPORT during an inclusion and could "
                "disrupt a LIVE device." if tx_ok else
                "The selected radio is receive-only, so this can only be OBSERVED, "
                "not driven.")
        ans = self._prompt(
            f"SAFETY GATE — Z-Shave S2→S0 downgrade test. {note} "
            f"During a device inclusion, did the controller ACCEPT a KEX_REPORT that "
            f"negotiated the security class DOWN to S0 (i.e. no S2-only enforcement)?",
            options=["Yes — downgrade to S0 accepted",
                     "No — S2-only enforced / downgrade rejected",
                     "Not tested / skip"],
            prompt_type="choice", skippable=True)
        a = (ans or "").lower()
        if a.startswith("yes"):
            evid = out_dir / f"{self.ctx.file_prefix}_zshave_downgrade.txt"
            try:
                evid.write_text(f"Operator observation: {ans}\n", encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_ZSHAVE,
                    "During inclusion the controller accepted a downgrade of the negotiated "
                    "security class from S2 to the legacy S0 command class (the 'Z-Shave' "
                    "attack). An attacker in RF range at inclusion time can force S0, then "
                    "recover the network key via the hardcoded all-zero temporary key and "
                    "control the device. S2-only inclusion is not being enforced.",
                    "High", tool="ezwave", output_file=str(evid),
                    force_classification="Validated",
                    remediation="Enforce S2-only inclusion with no S0 fallback; reject any "
                    "KEX_REPORT that requests a lower security class; require out-of-band DSK "
                    "verification at inclusion.")

    def _active_replay_probe(self, out_dir: Path, homes: dict, tx_ok: bool) -> None:
        """Command replay of unencrypted frames — RF-active; operator-gated."""
        if not homes:
            return
        if not tx_ok:
            self.ctx.logger.info(
                "Replay test skipped — selected radio cannot transmit.", tool=self.name)
            return
        ans = self._prompt(
            "SAFETY GATE — Z-Wave command replay. This RETRANSMITS a previously captured "
            "unencrypted command frame and WILL actuate the device if accepted (e.g. "
            "unlock a lock, toggle a switch). Only proceed on a device authorised for "
            "active testing. Did the device ACT on the replayed frame?",
            options=["Yes — device acted on the replay",
                     "No — replay rejected / no effect",
                     "Do not run / skip"],
            prompt_type="choice", skippable=True)
        a = (ans or "").lower()
        if a.startswith("yes"):
            evid = out_dir / f"{self.ctx.file_prefix}_replay.txt"
            try:
                evid.write_text(f"Operator observation: {ans}\n", encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_REPLAY,
                    "A previously captured unencrypted (or S0) Z-Wave command frame was "
                    "retransmitted and the device acted on it, confirming no effective "
                    "anti-replay protection. An attacker can record a legitimate command "
                    "(lock/unlock, on/off) and replay it later to actuate the device without "
                    "the network key.",
                    "High", tool="ezwave", output_file=str(evid),
                    force_classification="Validated",
                    remediation="Enforce S2, whose Singlecast nonce/SPAN sequencing rejects "
                    "replayed frames; never operate actuators over unencrypted or S0 command "
                    "classes.")

    def _nonce_dos_probe(self, out_dir: Path, homes: dict) -> None:
        """S0-No-More NonceGet DoS exposure — surface flag; default non-destructive."""
        if not homes:
            return
        ans = self._prompt(
            "SAFETY GATE — S0 'NonceGet' Denial-of-Service exposure (S0-No-More). Flooding "
            "a gateway with S0 NonceGet requests can EXHAUST its nonce table and HALT the "
            "whole mesh — do NOT run this against a live medical device. Based on the "
            "gateway's behaviour, does it accept unauthenticated S0 NonceGet requests "
            "(making it DoS-exposed)?",
            options=["Yes — accepts unauthenticated NonceGet (exposed)",
                     "No — rate-limited / S2-only",
                     "Do not test / skip"],
            prompt_type="choice", skippable=True)
        a = (ans or "").lower()
        if a.startswith("yes"):
            evid = out_dir / f"{self.ctx.file_prefix}_nonce_dos.txt"
            try:
                evid.write_text(f"Operator observation: {ans}\n", encoding="utf-8")
            except Exception:
                pass
            self._f(self.T_NONCE_DOS,
                    "The Z-Wave gateway accepts unauthenticated S0 NonceGet requests. An "
                    "attacker can flood NonceGet frames (the 'S0-No-More' attack) to exhaust "
                    "the gateway's nonce state and block legitimate S0 encryption, halting "
                    "the mesh — a denial-of-service that requires only RF range and a valid "
                    "included NodeID.",
                    "Medium", tool="ezwave", output_file=str(evid),
                    remediation="Migrate off S0 to S2; rate-limit NonceGet handling; drop "
                    "NonceGet requests from NodeIDs that are not actively transacting.")


# ===========================================================================
# LoRa interface module  (integrated 2026-08-13 from _frag/LoRa.py)
# ===========================================================================
# ---------------------------------------------------------------------------
# LoRa / LoRaWAN Module  (passive PHY capture + LoRaWAN security triage)
# ---------------------------------------------------------------------------
# One module, three phases: hardware setup -> LoRa capture -> LoRaWAN security.
# Detection is grounded in cleartext-observable radio signals: the LoRaWAN MHDR
# MType (top 3 bits of the first PHYPayload byte) reveals Join-Request /
# Join-Accept vs data uplinks (ABP vs OTAA), the FHDR carries the DevAddr and a
# 16-bit frame counter, and — for proprietary (non-LoRaWAN) LoRa — the whole
# payload is app data.  The module rules out each known LoRaWAN weakness class
# (static ABP session keys, OTAA join replay from missing DevNonce tracking,
# default/weak AppKey, missing frame-counter validation, cleartext application
# payload, pre-1.1 join-replay exposure) from a passive capture plus bounded
# operator confirmation, never assuming a specific device identity.  Anything
# that could disrupt a LIVE medical device (frame replay / injection into the
# network) is gated behind an explicit operator confirmation and defaults to
# non-destructive passive capture.

# Region -> default uplink centre frequency (Hz, as a string for the CLIs) and
# the ISM band label.  The operator selects the region at Phase 0.
_LORA_REGIONS: dict[str, dict] = {
    "EU868":   {"freq": "868.1e6", "band": "863-870 MHz (EU868)"},
    "US915":   {"freq": "903.9e6", "band": "902-928 MHz (US915)"},
    "AS923":   {"freq": "923.2e6", "band": "915-928 MHz (AS923)"},
    "AU915":   {"freq": "915.2e6", "band": "915-928 MHz (AU915)"},
    "IN865":   {"freq": "865.0625e6", "band": "865-867 MHz (IN865)"},
    "EU433":   {"freq": "433.175e6", "band": "433 MHz (EU433)"},
}

# Hardware options offered at Phase 0.  quiver = the exact Quiver firmware-flash
# payload that provisions the board (see /opt/pr0t31n/Quiver).  Boards flashed
# with single-channel-sniffer firmware emit decoded LoRa/LoRaWAN frames over the
# USB serial port; SDRs feed rtl_433 (ISM survey) + URH (raw IQ capture).
_LORA_HARDWARE: list[dict] = [
    {"key": "heltec", "serial": True, "sdr": False,
     "label": "Heltec LoRa32 v3 (SX1262) — single-channel LoRa sniffer firmware",
     "quiver": "FIRMWARE - Flash LoRa single-channel sniffer",
     "baud": 115200,
     "setup": ["Flash with Quiver payload: 'FIRMWARE - Flash LoRa single-channel",
               "  sniffer' (targets heltec_wifi_lora_32_V3 / SX1262).",
               "Set the sniffer to the region's uplink channel + SF before capture.",
               "Decoded frames (MHDR / DevAddr / FCnt / FRMPayload) stream over the",
               "  USB CDC serial port at 115200 baud — captured to a .txt transcript."]},
    {"key": "lilygo", "serial": True, "sdr": False,
     "label": "LilyGo LoRa32 (T3, SX1276/78) — single-channel LoRa sniffer firmware",
     "quiver": "FIRMWARE - Flash LoRa single-channel sniffer",
     "baud": 115200,
     "setup": ["Flash with Quiver payload: 'FIRMWARE - Flash LoRa single-channel",
               "  sniffer' (targets ttgo-lora32-v21 / SX1276).",
               "Single channel + single spreading factor at a time — sweep SF7-SF12",
               "  across the region's uplink channels to maximise capture coverage.",
               "Decoded frames stream over the USB serial port (115200 baud)."]},
    {"key": "sdr", "serial": False, "sdr": True,
     "label": "RTL-SDR / HackRF — rtl_433 ISM survey + URH raw LoRa IQ capture",
     "quiver": None,
     "baud": 0,
     "setup": ["No firmware flash needed. rtl_433 surveys co-located ISM devices",
               "  in the LoRa band but does NOT demodulate CSS LoRa itself.",
               "URH (urh_cli) captures raw IQ at the region's centre frequency for",
               "  offline LoRa demodulation / crib-drag analysis.",
               "For decoded LoRaWAN frames prefer a single-channel-sniffer board",
               "  (options 1-2); this SDR path yields a raw capture + survey."]},
]

# LoRaWAN MHDR MType (bits 7:5 of the first PHYPayload byte) -> message class.
_LORA_MTYPE: dict[int, str] = {
    0: "Join-Request", 1: "Join-Accept", 2: "Unconfirmed Data Up",
    3: "Unconfirmed Data Down", 4: "Confirmed Data Up",
    5: "Confirmed Data Down", 6: "RFU", 7: "Proprietary",
}


def _lora_which(name: str) -> Optional[str]:
    """Locate a LoRa/SDR tool binary (PATH + common install dirs + urh source)."""
    p = shutil.which(name)
    if p:
        return p
    cands = [f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}"]
    if name in ("urh_cli", "urh_cli.py"):
        cands += ["/usr/local/bin/urh_cli", "/usr/bin/urh_cli",
                  "/opt/urh/src/urh/cli/urh_cli.py"]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def _lora_serial_ports() -> list[str]:
    """Return candidate USB-serial ports a flashed LoRa board is likely on."""
    return [p for p in ("/dev/ttyACM0", "/dev/ttyUSB0", "/dev/ttyACM1",
                        "/dev/ttyUSB1") if os.path.exists(p)]


def _lora_mtype_name(first_byte: int) -> str:
    return _LORA_MTYPE.get((first_byte >> 5) & 0x07, "Unknown")


def _lora_looks_cleartext(data: bytes) -> bool:
    """True when >70% of the payload bytes are printable ASCII — a strong hint
    the application layer shipped its data in the clear (raw LoRa, or a LoRaWAN
    FRMPayload that was never app-layer encrypted)."""
    if len(data) < 4:
        return False
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
    return (printable / len(data)) > 0.70


def _lora_parse_frames(text: str) -> list[dict]:
    """Best-effort parse of a single-channel-sniffer transcript.

    Accepts several common firmware output styles and extracts one dict per
    decoded frame: {mtype, mtype_raw, devaddr, fcnt, phy_hex, cleartext}.
    Recognises (a) an explicit 'PHYPayload: <hex>' field, and (b) any standalone
    hex token of >= 12 bytes on a line (the raw PHYPayload most firmwares print).
    """
    frames: list[dict] = []
    seen: set = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.search(r"PHYPayload\s*[:=]\s*([0-9A-Fa-f]{24,})", line)
        hexes: list[str] = []
        if m:
            hexes.append(m.group(1))
        else:
            for tok in re.findall(r"\b([0-9A-Fa-f]{24,})\b", line):
                if len(tok) % 2 == 0:
                    hexes.append(tok)
        for h in hexes:
            h = h.lower()
            if h in seen:
                continue
            seen.add(h)
            try:
                blob = bytes.fromhex(h)
            except ValueError:
                continue
            if len(blob) < 8:
                continue
            first = blob[0]
            mt = (first >> 5) & 0x07
            fr = {"mtype": _lora_mtype_name(first), "mtype_raw": mt,
                  "devaddr": "", "fcnt": None, "phy_hex": h, "cleartext": False}
            if mt in (2, 3, 4, 5) and len(blob) >= 8:
                # FHDR: DevAddr(4, little-endian) | FCtrl(1) | FCnt(2, LE)
                fr["devaddr"] = "".join(f"{b:02X}" for b in blob[1:5][::-1])
                fr["fcnt"] = blob[6] | (blob[7] << 8)
                fopts_len = blob[5] & 0x0F
                body = blob[8 + fopts_len:]
                if len(body) > 1:  # FPort(1) + FRMPayload
                    fr["cleartext"] = _lora_looks_cleartext(body[1:])
            elif mt == 7:  # Proprietary / raw LoRa — entire payload is app data
                fr["cleartext"] = _lora_looks_cleartext(blob)
            frames.append(fr)
    return frames


class LoRaModule(BaseModule):
    """
    Passive LoRa / LoRaWAN (433 / 868 / 915 MHz) security assessment.

    Runs hardware setup -> passive LoRa capture -> LoRaWAN security triage
    against whatever the device under test transmits, ruling out each known
    LoRaWAN weakness class from cleartext-observable radio signals (MHDR MType,
    DevAddr, frame counter, FRMPayload printability) plus bounded operator
    confirmation.  Defaults to non-destructive passive capture; any replay /
    injection that could disrupt a live medical device is gated behind an
    explicit operator confirmation.
    """
    name        = "LoRa"
    description = "LoRa / LoRaWAN passive assessment (capture → LoRaWAN security triage)"

    # ── finding-title constants (kept in lockstep with findings_catalogue.json) ──
    T_TX_DETECTED  = "LoRa Transmission Detected"
    T_LORAWAN_NET  = "LoRaWAN Network Traffic Detected"
    T_RAW_UNENC    = "Raw LoRa Payload Transmitted Without Encryption"
    T_ABP_STATIC   = "LoRaWAN ABP Activation — Static Session Keys"
    T_OTAA_REPLAY  = "LoRaWAN OTAA Join Replay — Missing DevNonce Tracking"
    T_DEFAULT_KEY  = "LoRaWAN Default or Weak AppKey"
    T_FCNT_REPLAY  = "LoRaWAN Missing Frame-Counter Validation"
    T_CLEARTEXT    = "LoRaWAN Cleartext Application Payload"
    T_V10_JOIN     = "LoRaWAN 1.0.x — No Join-Request Replay Protection"
    T_SKIPPED      = "LoRa Testing SKIPPED — No SDR or LoRa Radio Available"

    # ── convenience wrappers ────────────────────────────────────────────────
    def _dir(self, sub: str) -> Path:
        d = self.ctx.instance_dir / "LoRa" / sub
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _f(self, title: str, description: str, risk: str, **kw) -> None:
        """Thin findings.create wrapper with sane LoRa defaults."""
        self.ctx.findings.create(
            ctx=self.ctx, title=title, description=description,
            tool=kw.pop("tool", "lora"), source_type="primary",
            force_risk=risk, **kw)

    def _event(self, msg: str) -> None:
        """Persist a timestamped phase EVENT to the on-disk audit log (§14j)."""
        try:
            self.ctx.logger.info(f"EVENT [LoRa] {msg}", tool=self.name)
        except Exception:
            pass

    # ── main ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._mark_running()
        try:
            self._event(f"LoRaModule v{VERSION} started for [{self.ctx.instance_loc}]")
            hw = self._phase0_hardware()
            if hw is None:
                return  # skipped — honest finding already emitted
            region, frames, cap_file = self._phase1_capture(hw)
            self._phase2_lorawan(hw, region, frames, cap_file)
            self._mark_complete(
                f"LoRa assessment complete — {len(frames)} frame(s) parsed")
        except Exception as e:
            self._mark_error(str(e))

    # ── Phase 0 — hardware selection + setup ────────────────────────────────
    def _phase0_hardware(self) -> Optional[dict]:
        self._event("Phase 0 — hardware selection & setup")
        labels = [h["label"] for h in _LORA_HARDWARE]
        choice = self._prompt(
            "Select the LoRa testing hardware in use. Options 1-2 are LoRa32 boards "
            "flashed with single-channel-sniffer firmware (decoded frames over USB "
            "serial); option 3 is an SDR (rtl_433 ISM survey + URH raw IQ capture).\n"
            "Refer to Quiver to flash the board's firmware before continuing.",
            options=labels + ["Skip LoRa testing"],
            prompt_type="choice", skippable=True)

        hw = next((h for h in _LORA_HARDWARE if h["label"] == choice), None)
        if hw is None or (choice or "").lower().startswith("skip"):
            self._f(self.T_SKIPPED,
                    "No SDR or LoRa radio was selected for this instance, so LoRa / "
                    "LoRaWAN testing was NOT performed. Flash a Heltec LoRa32 v3 or "
                    "LilyGo LoRa32 with single-channel-sniffer firmware via Quiver, or "
                    "attach an RTL-SDR / HackRF (rtl_433 + urh_cli), and re-run the module.",
                    "Informational", tool="lora")
            self._mark_complete("LoRa SKIPPED — no hardware selected")
            return None

        self.ctx.logger.info(f"Selected LoRa hardware: {hw['label']}", tool=self.name)
        if hw.get("quiver"):
            self.ctx.logger.info(
                f"Flash via Quiver payload: '{hw['quiver']}'", tool=self.name)
        for ln in hw["setup"]:
            self.ctx.logger.info(f"  {ln}", tool=self.name)
        setup_txt = self._dir("00_setup") / f"{self.ctx.file_prefix}_hardware_setup.txt"
        try:
            setup_txt.write_text(
                f"LoRa testing hardware: {hw['label']}\n"
                + (f"Quiver flash payload: {hw['quiver']}\n" if hw.get("quiver") else "")
                + "\n" + "\n".join(hw["setup"]) + "\n", encoding="utf-8")
        except Exception:
            pass
        self._prompt_connected_photo(
            f"{hw['label']} connected for [{self.ctx.instance_loc}]")

        # Verify the required capture tooling / port is present for the chosen path.
        if hw["serial"] and not _lora_serial_ports():
            self._f(self.T_SKIPPED,
                    "The selected LoRa32 sniffer board exposes no USB serial port "
                    "(/dev/ttyACM* or /dev/ttyUSB*). Flash the single-channel-sniffer "
                    "firmware via Quiver and confirm the board enumerates, then re-run.",
                    "Informational", tool="lora")
            self._mark_complete("LoRa SKIPPED — no serial port for sniffer board")
            return None
        if hw["sdr"] and not (_lora_which("rtl_433") or _lora_which("urh_cli")):
            self._f(self.T_SKIPPED,
                    "The SDR path requires rtl_433 and/or URH (urh_cli) but neither was "
                    "found on PATH. Install rtl-433 and universal-radio-hacker "
                    "(see install.py LoRa phase) and re-run.",
                    "Informational", tool="lora")
            self._mark_complete("LoRa SKIPPED — rtl_433/urh_cli not installed")
            return None
        return hw

    # ── Phase 1 — passive LoRa capture ──────────────────────────────────────
    def _phase1_capture(self, hw: dict) -> tuple:
        self._event("Phase 1 — passive LoRa capture")
        self.ctx.progress.set_module_status(
            self.ctx.subdevice_key, self.ctx.interface, self.ctx.instance_key,
            self.name, "running", "Capturing LoRa traffic…")
        out_dir = self._dir("01_capture")

        region = self._prompt(
            "Which regional LoRa band is the device under test operating in? "
            "(sets the capture centre frequency).",
            options=list(_LORA_REGIONS.keys()) + ["Unknown / EU868 default"],
            prompt_type="choice", skippable=True)
        rkey = region if region in _LORA_REGIONS else "EU868"
        freq = _LORA_REGIONS[rkey]["freq"]
        band = _LORA_REGIONS[rkey]["band"]

        dur = 90
        cap_file = out_dir / f"{self.ctx.file_prefix}_lora_capture_{rkey}.txt"
        frames: list[dict] = []

        if hw["serial"]:
            port = _lora_serial_ports()[0]
            self._prompt(
                f"Ready to passively capture decoded LoRa frames on {band} from {port}. "
                f"Ensure the sniffer board is tuned to the device's uplink channel + SF, "
                f"then trigger a transmission on the device under test (e.g. force a "
                f"sensor reading or a fresh join). Press Ready to start the {dur}s capture.",
                options=["Ready"], prompt_type="choice")
            try:
                run_tool(["bash", "-c",
                          f"stty -F {port} {hw['baud']} raw -echo 2>/dev/null; "
                          f"timeout {dur} cat {port} 2>/dev/null || true"],
                         self.ctx, tool_name="lora-sniffer",
                         output_file=cap_file, timeout=dur + 20)
            except Exception as e:
                self.ctx.logger.warn(f"serial capture failed: {e}", tool=self.name)
        else:
            # SDR path: rtl_433 ISM survey (JSON) + URH raw IQ capture (best-effort).
            if _lora_which("rtl_433"):
                survey = out_dir / f"{self.ctx.file_prefix}_rtl433_survey_{rkey}.json"
                try:
                    run_tool(["bash", "-c",
                              f"timeout {dur} rtl_433 -f {freq} -F json -M time "
                              f"> {survey} 2>/dev/null || true"],
                             self.ctx, tool_name="rtl_433",
                             output_file=survey, timeout=dur + 20)
                except Exception:
                    pass
            if _lora_which("urh_cli"):
                iq = out_dir / f"{self.ctx.file_prefix}_urh_lora_{rkey}.complex"
                urh = _lora_which("urh_cli")
                runner = (["python3", urh] if urh.endswith(".py") else [urh])
                self._prompt(
                    f"Ready to capture raw LoRa IQ at {freq} Hz ({band}) with URH. "
                    f"Trigger a transmission on the device under test, then press Ready.",
                    options=["Ready"], prompt_type="choice")
                try:
                    run_tool(["bash", "-c",
                              f"timeout {dur} {' '.join(runner)} --receive "
                              f"--device RTL-SDR --frequency {freq} --sample-rate 1e6 "
                              f"--file {iq} >/dev/null 2>&1 || true"],
                             self.ctx, tool_name="urh_cli",
                             output_file=iq, timeout=dur + 20)
                except Exception:
                    pass
            # An SDR can't hand back decoded LoRaWAN frames without offline demod, so
            # let the operator paste a decoded PHYPayload transcript if they have one.
            paste = self._prompt(
                "If you have decoded LoRaWAN PHYPayload hex (from URH demod, a gateway "
                "log, or a single-channel sniffer), paste one hex frame per line to "
                "seed the LoRaWAN triage, or type 'skip'.",
                prompt_type="text", skippable=True)
            if paste and paste.lower() != "skip":
                cap_file.write_text(paste, encoding="utf-8")

        try:
            frames = _lora_parse_frames(cap_file.read_text(errors="replace")) \
                if cap_file.exists() else []
        except Exception:
            frames = []
        self.ctx.logger.info(
            f"Parsed {len(frames)} LoRa frame(s) from capture", tool=self.name)

        # Discovery findings — LoRa transmission + (if MType matches) LoRaWAN traffic.
        if frames:
            mtypes = sorted({f["mtype"] for f in frames})
            self._f(self.T_TX_DETECTED,
                    f"LoRa transmissions were captured on {band} during passive scanning: "
                    f"{len(frames)} frame(s) observed (MType(s): {', '.join(mtypes)}). "
                    f"Confirmed live LoRa radio activity expands the wireless attack "
                    f"surface and defines the targets for LoRaWAN security triage.",
                    "Informational", tool="lora", output_file=str(cap_file))
            if any(f["mtype_raw"] in (0, 1, 2, 3, 4, 5) for f in frames):
                devaddrs = sorted({f["devaddr"] for f in frames if f["devaddr"]})
                self._f(self.T_LORAWAN_NET,
                        f"LoRaWAN protocol traffic was identified in the capture "
                        f"(Join and/or MAC data frames). DevAddr(s): "
                        f"{', '.join(devaddrs) or 'n/a'}. The MHDR/FHDR structure confirms "
                        f"a LoRaWAN network is in range and reachable to a passive listener.",
                        "Informational", tool="lora", output_file=str(cap_file))
        return rkey, frames, cap_file

    # ── Phase 2 — LoRaWAN security triage ───────────────────────────────────
    def _phase2_lorawan(self, hw: dict, region: str, frames: list, cap_file: Path) -> None:
        self._event("Phase 2 — LoRaWAN security triage")
        evid = str(cap_file)

        saw_join = any(f["mtype_raw"] in (0, 1) for f in frames)
        saw_data = any(f["mtype_raw"] in (2, 3, 4, 5) for f in frames)
        saw_proprietary = any(f["mtype_raw"] == 7 for f in frames)
        cleartext_frames = [f for f in frames if f["cleartext"]]

        # --- Raw (non-LoRaWAN) LoRa with cleartext payload -------------------
        if saw_proprietary and any(f["cleartext"] for f in frames if f["mtype_raw"] == 7):
            self._f(self.T_RAW_UNENC,
                    "A proprietary (non-LoRaWAN) LoRa frame carried an application payload "
                    "that decodes to printable/structured cleartext, indicating the payload "
                    "is transmitted without any encryption. Any passive listener in radio "
                    "range can read sensor/telemetry data and, absent a MIC, forge or replay "
                    "commands to the device.",
                    "High", tool="lora", output_file=evid,
                    cve_ids=[], remediation="Encrypt and authenticate the application payload "
                    "(AES-CTR/GCM with a per-device key + a monotonic counter), or adopt "
                    "LoRaWAN and rely on its MIC + FRMPayload encryption.")

        # --- Activation model: ABP vs OTAA ----------------------------------
        model = self._prompt(
            "How is the device under test activated onto the LoRaWAN network? "
            + ("(a Join-Request/Accept was seen in the capture → OTAA is in use). "
               if saw_join else
               "(only data frames were seen — no Join in this capture). "),
            options=["OTAA (Over-The-Air Activation — join procedure)",
                     "ABP (Activation By Personalization — static keys)",
                     "Unknown / not determined"],
            prompt_type="choice", skippable=True)
        m = (model or "").lower()
        is_abp = m.startswith("abp") or (saw_data and not saw_join and "otaa" not in m)
        is_otaa = m.startswith("otaa") or saw_join

        # --- ABP static session keys ----------------------------------------
        if is_abp:
            self._f(self.T_ABP_STATIC,
                    "The device is activated by ABP, so the NwkSKey and AppSKey are "
                    "provisioned as static, long-lived key material rather than derived "
                    "per session by a join. On a device reset the frame counter returns to "
                    "zero while the keys stay the same — reusing the counter (the AES-CTR "
                    "IV) across sessions enables a known-plaintext / crib-dragging attack "
                    "and lets previously-captured uplinks be replayed.",
                    "High", tool="lora", output_file=evid,
                    remediation="Prefer OTAA so fresh session keys are derived per join; "
                    "if ABP is mandatory, persist the frame counters across reboots, never "
                    "reset them, and rotate the session keys on a schedule.")

        # --- OTAA join replay (missing DevNonce tracking, <1.1) -------------
        if is_otaa:
            ver = self._prompt(
                "Which LoRaWAN version does the device/network implement, and does the "
                "network server persist and reject previously-seen DevNonce values?",
                options=["1.0.x AND server does NOT track/reject repeated DevNonce",
                         "1.0.x with a bounded DevNonce cache (still replay-window exposed)",
                         "1.1 (monotonic DevNonce counter + join-server nonce tracking)",
                         "Unknown"],
                prompt_type="choice", skippable=True)
            v = (ver or "").lower()
            if v.startswith("1.0"):
                self._f(self.T_OTAA_REPLAY,
                        "The device uses OTAA under LoRaWAN 1.0.x, where the end device "
                        "cannot detect a repeated Join-Accept and the network server only "
                        "remembers a bounded number of recent DevNonce values. A captured "
                        "Join-Request can be replayed after that window rolls over, forcing "
                        "a re-join and a session-key reset an attacker can exploit for "
                        "denial-of-service or to pin the device to attacker-observable keys.",
                        "High", tool="lora", output_file=evid,
                        cve_ids=[], remediation="Upgrade to LoRaWAN 1.1 (monotonic DevNonce "
                        "counter enforced by the join server); where 1.0.x is required, "
                        "persist the full DevNonce history per device and reject any repeat.")
                self._f(self.T_V10_JOIN,
                        "The network operates LoRaWAN 1.0.x, in which Join-Request messages "
                        "carry no replay protection prior to the 1.1 DevNonce counter. This "
                        "is a protocol-version exposure independent of a specific replay "
                        "observation and applies to every OTAA device on the network.",
                        "Medium", tool="lora", output_file=evid,
                        remediation="Migrate the network and devices to LoRaWAN 1.1, which "
                        "adds monotonic DevNonce handling and join-server nonce tracking.")

        # --- Default / weak AppKey ------------------------------------------
        keyq = self._prompt(
            "Is the root AppKey (OTAA) or the session keys (ABP) a default, all-zero, "
            "sequential, vendor-shared, or DevEUI-derived value — i.e. printed on the "
            "device, in the manual/firmware, or identical across a production batch?",
            options=["Yes — default/weak/shared/derivable key",
                     "No — unique random per device, provisioned securely",
                     "Unknown"],
            prompt_type="choice", skippable=True)
        if (keyq or "").lower().startswith("yes"):
            self._f(self.T_DEFAULT_KEY,
                    "The device's LoRaWAN root/session key is default, all-zero, "
                    "vendor-shared, or derivable from the DevEUI (a hard-coded credential). "
                    "Recovering the AppKey lets an attacker derive the session keys, decrypt "
                    "all FRMPayloads, forge a valid MIC, and impersonate the device — "
                    "collapsing the entire LoRaWAN security model for that node.",
                    "Critical", tool="lora", output_file=evid,
                    force_classification="Validated",
                    remediation="Provision a unique, random, secret AppKey per device at "
                    "manufacture; never print, log, share, or derive it from public "
                    "identifiers; store it in a secure element and rotate on compromise.")

        # --- Missing frame-counter validation (replay) ----------------------
        # Passive hint: a repeated FCnt in the capture already indicates weak
        # replay handling. An active replay into a LIVE network could disrupt a
        # medical device — gate it behind explicit operator confirmation.
        fcnts = [f["fcnt"] for f in frames if f["fcnt"] is not None]
        repeated_fcnt = len(fcnts) != len(set(fcnts)) and len(fcnts) > 1
        replay_ok = None
        if repeated_fcnt:
            replay_ok = True
        else:
            ans = self._prompt(
                "Frame-counter replay test. Replaying a captured uplink to the LoRaWAN "
                "network is an ACTIVE test that could disrupt a live device/network — "
                "only proceed with authorization. Was a previously-captured uplink "
                "(same or lower FCnt) ACCEPTED by the network server when replayed?",
                options=["Yes — replayed frame was accepted (no FCnt check)",
                         "No — replay rejected (FCnt validation enforced)",
                         "Skip — do not perform an active replay"],
                prompt_type="choice", skippable=True)
            a = (ans or "").lower()
            if a.startswith("yes"):
                replay_ok = True
            elif a.startswith("no"):
                replay_ok = False
        if replay_ok:
            self._f(self.T_FCNT_REPLAY,
                    "The network accepted a LoRaWAN uplink whose frame counter was equal to "
                    "or lower than a previously-seen value (observed as a repeated FCnt in "
                    "the capture, or confirmed by an authorized replay). Without strict "
                    "monotonic frame-counter validation an attacker can replay captured "
                    "uplinks — re-triggering actions or masking live telemetry with stale "
                    "readings.",
                    "High", tool="lora", output_file=evid,
                    force_classification="Validated" if repeated_fcnt else "",
                    remediation="Enforce strict monotonic frame-counter checks at the "
                    "network server (reject any FCnt <= last seen), enable 32-bit frame "
                    "counters, and alert on counter resets or rollovers.")

        # --- Cleartext application payload (LoRaWAN, no app-layer crypto) ----
        if cleartext_frames and (is_abp or is_otaa or saw_data):
            appq = self._prompt(
                "The captured FRMPayload decodes to printable/structured data. Does the "
                "application rely SOLELY on LoRaWAN's FRMPayload encryption with no "
                "additional end-to-end application-layer encryption (so the network "
                "server / any key-holder sees the data in the clear)?",
                options=["Yes — LoRaWAN encryption only, no app-layer E2E",
                         "No — payload is additionally app-layer encrypted",
                         "Unknown"],
                prompt_type="choice", skippable=True)
            if not (appq or "").lower().startswith("no"):
                self._f(self.T_CLEARTEXT,
                        "The application payload is protected only by LoRaWAN's session-key "
                        "FRMPayload encryption, with no independent end-to-end application-"
                        "layer encryption. Any holder of the session keys — the network "
                        "server, a compromised join server, or an attacker who recovered a "
                        "weak/default key — reads the plaintext, and for raw or "
                        "misconfigured payloads a passive listener may read it directly.",
                        "Medium", tool="lora", output_file=evid,
                        remediation="Add end-to-end application-layer encryption/"
                        "authentication (e.g. AES-GCM with a key held only by the device and "
                        "the application server) so LoRaWAN network operators cannot read or "
                        "forge sensitive payloads.")


# ---------------------------------------------------------------------------
# DB9 / Serial + CAN Modules
# ---------------------------------------------------------------------------
# Dynamic imports of helper scripts (same directory as gearbox.py).
# _SD_AVAILABLE  = serial_detect.py loaded successfully (requires pyserial)
# _CD_AVAILABLE  = can_detect.py loaded successfully (requires iproute2/candump)
# ---------------------------------------------------------------------------

def _db9_load_helpers():
    """Load serial_detect and can_detect modules from the gearbox directory."""
    import importlib.util as _iu
    _dir = Path(__file__).parent

    sd_mod, sd_ok = None, False
    try:
        _sp = _dir / "serial_detect.py"
        _ss = _iu.spec_from_file_location("serial_detect", _sp)
        sd_mod = _iu.module_from_spec(_ss)
        _ss.loader.exec_module(sd_mod)
        sd_ok = True
    except Exception:
        pass

    cd_mod, cd_ok = None, False
    try:
        _cp = _dir / "can_detect.py"
        _cs = _iu.spec_from_file_location("can_detect", _cp)
        cd_mod = _iu.module_from_spec(_cs)
        _cs.loader.exec_module(cd_mod)
        cd_ok = True
    except Exception:
        pass

    return sd_mod, sd_ok, cd_mod, cd_ok


_SD_MOD, _SD_AVAILABLE, _CD_MOD, _CD_AVAILABLE = _db9_load_helpers()


# ── DB9 serial helper functions ───────────────────────────────────────────────

_DB9_RS232_DEVS = ["rs232"]
_DB9_RS485_DEVS = ["rs485"]


def _db9_find_serial_devs() -> tuple:
    """
    Return (path_232, path_485) or (None, None) if either is absent.
    Case-insensitive search in /dev.
    """
    try:
        entries = {e.lower(): e for e in os.listdir("/dev")}
    except Exception:
        return None, None
    p232 = os.path.join("/dev", entries["rs232"]) if "rs232" in entries else None
    p485 = os.path.join("/dev", entries["rs485"]) if "rs485" in entries else None
    return p232, p485


def _db9_serial_sniff(port_path: str, baudrate: int, duration_s: int) -> bytes:
    """
    Read from *port_path* at *baudrate* for *duration_s* seconds using pyserial.
    Returns all bytes collected (may be empty if pyserial unavailable).
    """
    try:
        import serial as _serial  # pyserial — Chris Liechti (https://github.com/pyserial/pyserial) — DB9 serial port auto-detection and bitrate sniffing
        ser = _serial.Serial(
            port=port_path, baudrate=baudrate,
            bytesize=_serial.EIGHTBITS, parity=_serial.PARITY_NONE,
            stopbits=_serial.STOPBITS_ONE, timeout=0.5,
        )
        buf = b""
        deadline = time.monotonic() + duration_s
        while time.monotonic() < deadline:
            chunk = ser.read(256)
            if chunk:
                buf += chunk
        ser.close()
        return buf
    except Exception:
        return b""


def _db9_probe_commands(port_path: str, baudrate: int) -> bytes:
    """
    Send common shell/device commands on *port_path* and collect responses.
    Returns concatenated response bytes.
    """
    _CMDS = [
        b"\r\n", b"help\r\n", b"?\r\n", b"status\r\n", b"info\r\n",
        b"version\r\n", b"ls\r\n", b"dir\r\n", b"id\r\n", b"whoami\r\n",
        b"uname -a\r\n", b"ifconfig\r\n", b"cat /etc/passwd\r\n",
    ]
    try:
        import serial as _serial
        ser = _serial.Serial(
            port=port_path, baudrate=baudrate,
            bytesize=_serial.EIGHTBITS, parity=_serial.PARITY_NONE,
            stopbits=_serial.STOPBITS_ONE, timeout=1.5,
        )
        buf = b""
        for cmd in _CMDS:
            ser.write(cmd)
            time.sleep(0.3)
            waiting = ser.in_waiting
            if waiting:
                buf += ser.read(min(waiting, 2048))
        ser.close()
        return buf
    except Exception:
        return b""


def _db9_detect_heartbeats(candump_text: str) -> dict:
    """
    Detect CAN heartbeat sequences in timestamped candump output.

    Returns {can_id_hex: (avg_interval_ms, frame_count, sample_line)}
    for each CAN ID that fires at a consistent interval under 5 seconds.
    A candidate must appear at least 5 times with std-dev < 20% of the mean.
    """
    import re
    from collections import defaultdict

    # Match absolute-timestamp candump lines:
    #   (1234567890.123456) can0  7FF   [8]  01 02 03 …
    #   (1234567890.123456) can0  7FF#0102…
    ts_pat = re.compile(
        r'\((\d+\.\d+)\)\s+\S+\s+([0-9A-Fa-f]+)\s*[#\[]'
    )

    frames_by_id: dict = defaultdict(list)
    sample_lines: dict = {}

    for line in candump_text.splitlines():
        m = ts_pat.search(line)
        if not m:
            continue
        ts     = float(m.group(1))
        can_id = m.group(2).upper()
        frames_by_id[can_id].append(ts)
        if can_id not in sample_lines:
            sample_lines[can_id] = line.strip()

    heartbeats = {}
    for can_id, timestamps in frames_by_id.items():
        if len(timestamps) < 5:
            continue
        intervals  = [timestamps[i + 1] - timestamps[i]
                      for i in range(len(timestamps) - 1)]
        avg        = sum(intervals) / len(intervals)
        if avg > 5.0:
            continue   # too slow
        variance   = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        std_dev    = variance ** 0.5
        if avg > 0 and (std_dev / avg) < 0.20:
            heartbeats[can_id] = (avg * 1000, len(timestamps),
                                  sample_lines[can_id])

    return heartbeats


def _db9_strip_heartbeats(candump_text: str, heartbeat_ids: set) -> str:
    """Remove all frames matching *heartbeat_ids* from *candump_text*."""
    import re
    id_pat  = re.compile(r'\s+([0-9A-Fa-f]+)\s*[#\[]')
    kept    = []
    for line in candump_text.splitlines():
        m = id_pat.search(line)
        if m and m.group(1).upper() in heartbeat_ids:
            continue
        kept.append(line)
    return "\n".join(kept)


def _db9_replay_frames(stripped_text: str, iface: str, ctx) -> int:
    """
    Replay CAN frames from stripped candump text using cansend.
    Returns the number of frames sent.
    """
    import re
    # Match: optional timestamp + iface + CAN_ID + [len] + bytes
    frame_pat = re.compile(
        r'([0-9A-Fa-f]+)\s+\[(\d+)\]\s+((?:[0-9A-Fa-f]{2}\s*)*)'
    )
    count = 0
    for line in stripped_text.splitlines():
        m = frame_pat.search(line)
        if not m:
            continue
        can_id   = m.group(1)
        data_hex = m.group(3).strip().replace(" ", "")
        frame    = f"{can_id}#{data_hex}" if data_hex else f"{can_id}#"
        run_tool(["cansend", iface, frame], ctx,
                 tool_name="cansend", timeout=5)
        count += 1
        time.sleep(0.001)
    return count


# ── SerialDetectModule ────────────────────────────────────────────────────────

class SerialDetectModule(BaseModule):
    """
    Steps 3-9: Auto-detect serial protocol/baudrate on DB9 port, test for
    command responses, attempt data exfiltration if responsive, and sniff
    traffic at device shutdown, boot, and steady-state runtime.

    Writes a result file (serial_result.txt) consumed by CanAssessModule
    so the CAN workflow is skipped when serial is successfully detected.
    """
    name        = "SerialDetect"
    description = "Auto-detect serial baudrate and sniff RS-232/RS-422/RS-485 traffic"

    # ── result-file helpers ──────────────────────────────────────────────────

    def _result_file(self) -> Path:
        d = self.ctx.instance_dir / "SerialDetect"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{self.ctx.file_prefix}_serial_result.txt"

    def _write_result(self, found: bool, baudrate: int = 0,
                      protocol: str = "", port: str = "") -> None:
        self._result_file().write_text(
            f"found={found}\nbaudrate={baudrate}\n"
            f"protocol={protocol}\nport={port}\n"
        )

    # ── sniff helper with countdown ──────────────────────────────────────────

    def _sniff_with_countdown(self, port_path: str, baudrate: int,
                              duration_s: int, label: str) -> bytes:
        """Sniff serial traffic for duration_s seconds, logging progress."""
        self.ctx.logger.info(
            f"Sniffing {label} for {duration_s}s on {port_path} @ {baudrate} bps …",
            tool=self.name)
        for remaining in range(duration_s, 0, -30):
            if remaining < duration_s:
                self.ctx.logger.info(
                    f"  {label}: {remaining}s remaining …", tool=self.name)
            time.sleep(min(30, remaining))
        data = _db9_serial_sniff(port_path, baudrate, duration_s)
        self.ctx.logger.info(
            f"  {label}: captured {len(data)} bytes.", tool=self.name)
        return data

    # ── run ─────────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._mark_running()
        out_dir = self.ctx.instance_dir / "SerialDetect"
        out_dir.mkdir(parents=True, exist_ok=True)

        if not _SD_AVAILABLE:
            self._write_result(found=False)
            self._mark_skipped(
                "serial_detect unavailable (pyserial not installed)")
            return

        # ── Step 3: cable connection prompt + device check (3 attempts) ──────
        p232, p485 = None, None
        _serial_photo_done = False
        for attempt in range(3):
            self._prompt(
                f"Connect a DB9 cable between the testing device and the "
                f"DB9-1 port at [{self.ctx.instance_loc}].\n"
                f"Both /dev/rs232 and /dev/rs485 adapters must be attached.",
                options=["Connected — ready to detect"],
                prompt_type="choice")
            p232, p485 = _db9_find_serial_devs()
            if p232 and p485:
                self.ctx.logger.info(
                    f"Serial devices found: {p232}, {p485}", tool=self.name)
                if not _serial_photo_done:
                    self._prompt_connected_photo(
                        f"DB9 cable connected to [{self.ctx.instance_loc}]")
                    _serial_photo_done = True
                break
            missing = []
            if not p232:
                missing.append("/dev/rs232")
            if not p485:
                missing.append("/dev/rs485")
            self.ctx.logger.warn(
                f"Device(s) not found: {', '.join(missing)}. "
                f"Attempt {attempt + 1}/3.", tool=self.name)
        else:
            self._write_result(found=False)
            self._mark_skipped(
                "Serial devices /dev/rs232 and/or /dev/rs485 not detected "
                "after 3 attempts")
            self._mark_connected_photo_na("Serial devices not detected after 3 attempts")
            return

        # ── Steps 3-4: scan baudrates (retry on user request) ────────────────
        rs232_bauds = _SD_MOD.ordered_baudrates(
            _SD_MOD.RS232_BAUDRATES, _SD_MOD.RS232_PRIORITY)
        rs485_bauds = _SD_MOD.ordered_baudrates(
            _SD_MOD.RS422_RS485_BAUDRATES, _SD_MOD.RS485_PRIORITY)

        serial_result = None
        while True:
            dummy_counts: dict = {}
            self.ctx.logger.info("Scanning RS-232 baudrates …", tool=self.name)
            serial_result = _SD_MOD.scan_pass(
                p232, "RS-232", rs232_bauds, 1, dummy_counts)

            if not serial_result:
                self.ctx.logger.info(
                    "No match on RS-232.  Scanning RS-422/RS-485 …",
                    tool=self.name)
                serial_result = _SD_MOD.scan_pass(
                    p485, "RS-422/RS-485", rs485_bauds, 2, dummy_counts)

            if serial_result:
                break

            answer = self._prompt(
                "No baudrate detected on either port.  What would you like to do?",
                options=["Scan again", "Skip serial testing",
                         "Assume non-serial (proceed to CAN testing)"],
                prompt_type="choice")
            if "3" in answer or "assume" in answer.lower() or "non-serial" in answer.lower():
                # Assessor has confirmed this port does not carry a serial protocol.
                # Record explicit completion markers for RS-232 and RS-485 phases
                # so the evidence log shows they were actively ruled out, then let
                # CanAssessModule run normally.
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_rs232_result", "non_serial_assumed")
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "_rs485_result", "non_serial_assumed")
                self._write_result(found=False, protocol="assumed_non_serial")
                self._mark_complete(
                    "RS-232 and RS-485 confirmed non-serial by assessor — "
                    "proceeding to CAN assessment")
                return
            if "2" in answer or "skip" in answer.lower():
                break

        if not serial_result:
            self._write_result(found=False)
            self._mark_complete("No serial baudrate detected — no serial protocol on this port")
            return

        score, baudrate, init_data, protocol = serial_result
        port_path = p232 if "RS-232" in protocol else p485

        self.ctx.logger.info(
            f"Serial detected: {protocol} @ {baudrate} bps  "
            f"(score={score:.3f})", tool=self.name)

        # Save initial detection data
        det_file = out_dir / f"{self.ctx.file_prefix}_detection.txt"
        try:
            det_file.write_bytes(init_data)
        except Exception:
            pass

        # ── Step 5: probe for command responses ──────────────────────────────
        self.ctx.logger.info(
            f"Probing for command responses on {port_path} @ {baudrate} bps …",
            tool=self.name)
        response_data = _db9_probe_commands(port_path, baudrate)

        # ── Step 6: exfiltration if responsive ───────────────────────────────
        if response_data:
            resp_score = _SD_MOD.score_english(response_data)
            if resp_score >= _SD_MOD.ENGLISH_THRESHOLD:
                exfil_file = out_dir / f"{self.ctx.file_prefix}_exfil.txt"
                try:
                    exfil_file.write_bytes(response_data)
                except Exception:
                    pass
                self._observe(
                    title=f"Serial Port Responds to Commands — "
                          f"{self.ctx.instance_key}",
                    description=(
                        f"DB9 port [{self.ctx.instance_loc}] ({protocol}) "
                        f"returned readable data in response to probe commands "
                        f"at {baudrate} bps, indicating an interactive serial "
                        f"console or device interface is accessible."
                    ),
                    tool="serial_detect",
                    output_file=str(exfil_file),
                    output_text=response_data[:500].decode("ascii", errors="replace"),
                    risk="High",
                )
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="Serial Port Allows Remote Access",
                    description=(
                        f"The DB9 port [{self.ctx.instance_loc}] ({protocol}) "
                        f"responded to serial commands at {baudrate} bps, "
                        f"exposing a potentially interactive console or device "
                        f"management interface without authentication."
                    ),
                    tool="serial_detect",
                    raw_output=exfil_file.read_text(errors="replace"),
                    source_type="primary", force_risk="High",
                    ip="", output_file=str(exfil_file),
                )

        # ── Step 7: sniff device shutdown ─────────────────────────────────────
        self._prompt(
            f"Power OFF the target device connected to "
            f"[{self.ctx.instance_loc}].",
            options=["Device is now powered off"],
            prompt_type="choice")
        shutdown_data = _db9_serial_sniff(port_path, baudrate, 30)
        if shutdown_data:
            sf = out_dir / f"{self.ctx.file_prefix}_shutdown.txt"
            sf.write_bytes(shutdown_data)
            self.ctx.findings.create(
                ctx=self.ctx,
                title="Data Leakage: Serial Traffic Sniffable",
                description=(
                    f"Serial traffic was captured on DB9 port "
                    f"[{self.ctx.instance_loc}] ({protocol} @ {baudrate} bps) "
                    f"during device shutdown, indicating unencrypted data "
                    f"transmission on an accessible physical interface."
                ),
                tool="serial_detect",
                raw_output=shutdown_data[:500].decode("ascii", errors="replace"),
                source_type="primary", force_risk="Low",
                ip="", output_file=str(sf),
            )
            self.ctx.logger.info(
                f"Shutdown sniff: {len(shutdown_data)} bytes captured.",
                tool=self.name)

        # ── Step 8: sniff device boot ─────────────────────────────────────────
        self._prompt(
            f"Power ON the target device at [{self.ctx.instance_loc}].\n"
            f"Wait until it has fully booted, then confirm.",
            options=["Device has finished booting"],
            prompt_type="choice")
        boot_data = _db9_serial_sniff(port_path, baudrate, 60)
        if boot_data:
            bf = out_dir / f"{self.ctx.file_prefix}_boot.txt"
            bf.write_bytes(boot_data)
            self.ctx.findings.create(
                ctx=self.ctx,
                title="Data Leakage: Serial Traffic Sniffable",
                description=(
                    f"Serial traffic was captured on DB9 port "
                    f"[{self.ctx.instance_loc}] ({protocol} @ {baudrate} bps) "
                    f"during device boot."
                ),
                tool="serial_detect",
                raw_output=boot_data[:500].decode("ascii", errors="replace"),
                source_type="primary", force_risk="Low",
                ip="", output_file=str(bf),
            )
            self.ctx.logger.info(
                f"Boot sniff: {len(boot_data)} bytes captured.", tool=self.name)

        # ── Step 9: sniff 5-minute running capture ────────────────────────────
        self.ctx.logger.info(
            "Capturing running traffic for 5 minutes …", tool=self.name)
        running_data = b""
        for chunk_num in range(10):
            running_data += _db9_serial_sniff(port_path, baudrate, 30)
            remaining = (9 - chunk_num) * 30
            if remaining > 0:
                self.ctx.logger.info(
                    f"  Running sniff: ~{remaining}s remaining …",
                    tool=self.name)

        if running_data:
            rf = out_dir / f"{self.ctx.file_prefix}_running.txt"
            rf.write_bytes(running_data)
            self.ctx.findings.create(
                ctx=self.ctx,
                title="Data Leakage: Serial Traffic Sniffable",
                description=(
                    f"Serial traffic was captured on DB9 port "
                    f"[{self.ctx.instance_loc}] ({protocol} @ {baudrate} bps) "
                    f"during normal device operation."
                ),
                tool="serial_detect",
                raw_output=running_data[:500].decode("ascii", errors="replace"),
                source_type="primary", force_risk="Low",
                ip="", output_file=str(rf),
            )

        # Ask if the user wants an extended capture
        ext = self._prompt(
            "5-minute running capture complete.  Extend by another 5 minutes?",
            options=["Yes, extend", "No, continue"],
            prompt_type="choice")
        if "1" in ext or "yes" in ext.lower() or "extend" in ext.lower():
            self.ctx.logger.info(
                "Extending running capture by 5 minutes …", tool=self.name)
            extra = b""
            for _ in range(10):
                extra += _db9_serial_sniff(port_path, baudrate, 30)
            if extra:
                rf2 = out_dir / f"{self.ctx.file_prefix}_running_ext.txt"
                rf2.write_bytes(extra)
                self.ctx.logger.info(
                    f"Extended capture: {len(extra)} bytes saved.",
                    tool=self.name)

        self._write_result(found=True, baudrate=baudrate,
                           protocol=protocol, port=port_path)
        self._mark_complete(
            f"Serial protocol detected: {protocol} @ {baudrate} bps")


# ── CanAssessModule ───────────────────────────────────────────────────────────

class CanAssessModule(BaseModule):
    """
    Steps 10-15: CAN bus detection, 5-minute traffic capture, heartbeat
    pattern analysis, heartbeat stripping, and CAN replay attack.

    Skipped automatically when SerialDetectModule found a serial protocol.
    If all CAN tests also fail, the DB9 port is marked as dead (no active
    protocol detected on this physical connector).
    """
    name        = "CanAssess"
    description = "CAN bus bitrate detection, traffic capture, heartbeat analysis, and replay"

    def _serial_result(self) -> dict:
        """Read the result file written by SerialDetectModule."""
        rf = self.ctx.instance_dir / "SerialDetect" / \
             f"{self.ctx.file_prefix}_serial_result.txt"
        result = {"found": False, "baudrate": 0, "protocol": "", "port": ""}
        if not rf.exists():
            return result
        try:
            for line in rf.read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k == "found":
                        result["found"] = v.strip().lower() == "true"
                    elif k == "baudrate":
                        result["baudrate"] = int(v.strip() or "0")
                    elif k in ("protocol", "port"):
                        result[k] = v.strip()
        except Exception:
            pass
        return result

    def run(self) -> None:
        self._mark_running()
        out_dir = self.ctx.instance_dir / "CanAssess"
        out_dir.mkdir(parents=True, exist_ok=True)

        # ── Check serial result ───────────────────────────────────────────────
        ser_res = self._serial_result()
        if ser_res["found"]:
            self._mark_skipped(
                f"Serial protocol detected ({ser_res['protocol']} @ "
                f"{ser_res['baudrate']} bps) — CAN assessment skipped")
            self._mark_connected_photo_na("Serial protocol detected — CAN skipped")
            return

        if not _CD_AVAILABLE:
            self._mark_skipped("can_detect unavailable")
            self._mark_connected_photo_na("can_detect unavailable")
            return

        # ── Step 10: locate CAN interface (3 attempts) ───────────────────────
        iface = None
        _can_photo_done = False
        for attempt in range(3):
            self._prompt(
                f"Connect a CAN-to-USB adapter to the DB9 port at "
                f"[{self.ctx.instance_loc}].\n"
                f"Supported adapters:\n"
                f"  • SocketCAN (e.g. PEAK PCAN-USB): kernel module loads automatically\n"
                f"    or manually: sudo modprobe peak_usb\n"
                f"  • Serial SLCAN adapter: ensure it appears as /dev/can\n"
                f"    (slcand and can-utils must be installed)",
                options=["Adapter connected — ready to detect CAN"],
                prompt_type="choice")
            interfaces = _CD_MOD.find_can_interfaces()
            if interfaces:
                iface = interfaces[0]
                self.ctx.logger.info(
                    f"CAN interface found: {iface}", tool=self.name)
                if not _can_photo_done:
                    self._prompt_connected_photo(
                        f"CAN-to-USB adapter connected to [{self.ctx.instance_loc}]")
                    _can_photo_done = True
                break
            self.ctx.logger.warn(
                f"No CAN interface found.  Attempt {attempt + 1}/3.",
                tool=self.name)
        else:
            # All serial and CAN tests failed — port is dead
            dead_file = out_dir / f"{self.ctx.file_prefix}_port_dead.txt"
            dead_file.write_text(
                f"DB9 port [{self.ctx.instance_loc}]: no active serial or "
                f"CAN protocol detected after full test suite.\n")
            self._observe(
                title=f"DB9 Port: No Active Protocol Detected — "
                      f"{self.ctx.instance_key}",
                description=(
                    f"Neither serial (RS-232/RS-422/RS-485) nor CAN bus "
                    f"traffic was found on DB9 port [{self.ctx.instance_loc}].  "
                    f"The port may be unpopulated, used for a proprietary "
                    f"protocol, or currently inactive."
                ),
                tool="serial_detect / can_detect",
                output_file=str(dead_file),
                risk="Informational",
            )
            self._mark_complete("DB9 port dead — no active protocol")
            self._mark_connected_photo_na("No CAN interface detected after 3 attempts")
            return

        # ── Run CAN bitrate detection ─────────────────────────────────────────
        self.ctx.logger.info(
            f"Detecting CAN bitrate on {iface} …", tool=self.name)
        can_result = _CD_MOD.detect_bitrate(iface)

        if not can_result:
            dead_file = out_dir / f"{self.ctx.file_prefix}_port_dead.txt"
            dead_file.write_text(
                f"DB9 port [{self.ctx.instance_loc}]: CAN interface {iface} "
                f"found but no traffic detected at any standard bitrate.\n")
            self._observe(
                title=f"DB9 Port: No Active Protocol Detected — "
                      f"{self.ctx.instance_key}",
                description=(
                    f"CAN interface {iface} is present but no traffic was "
                    f"received at any standard bitrate on "
                    f"[{self.ctx.instance_loc}].  The CAN bus may be "
                    f"inactive, terminated incorrectly, or using a "
                    f"non-standard bitrate."
                ),
                tool="can_detect",
                output_file=str(dead_file),
                risk="Informational",
            )
            self._mark_complete("CAN interface present but no traffic — port dead")
            return

        bitrate, sample_frames = can_result
        self.ctx.logger.info(
            f"CAN bitrate detected: {bitrate} bps on {iface}", tool=self.name)

        # ── Step 11: 5-minute candump capture ─────────────────────────────────
        self._prompt(
            f"CAN bus detected at {bitrate} bps on {iface}.\n"
            f"About to capture traffic for 5 minutes.",
            options=["Start capture"],
            prompt_type="choice")

        can_file = out_dir / f"{self.ctx.file_prefix}_can.txt"
        self.ctx.logger.info(
            f"Capturing CAN traffic for 300s on {iface} @ {bitrate} bps …",
            tool=self.name)

        # Log countdown while capture runs
        from threading import Thread as _Thread
        import threading as _threading
        capture_done = _threading.Event()

        def _countdown():
            for remaining in range(270, 0, -30):
                if capture_done.is_set():
                    break
                self.ctx.logger.info(
                    f"  CAN capture: ~{remaining}s remaining …",
                    tool=self.name)
                time.sleep(30)

        _t = _Thread(target=_countdown, daemon=True)
        _t.start()

        can_text = _CD_MOD.capture(
            iface, bitrate, duration_s=300, out_path=str(can_file))
        capture_done.set()
        _t.join(timeout=2)

        # Offer extension
        ext_ans = self._prompt(
            "5-minute CAN capture complete.  Extend by another 5 minutes?",
            options=["Yes, extend", "No, continue"],
            prompt_type="choice")
        if "1" in ext_ans or "yes" in ext_ans.lower():
            self.ctx.logger.info(
                "Extending CAN capture by 5 minutes …", tool=self.name)
            extra_text = _CD_MOD.capture(iface, bitrate, duration_s=300)
            if extra_text:
                can_text += "\n" + extra_text
                try:
                    with open(str(can_file), "a", encoding="utf-8") as f:
                        f.write("\n" + extra_text)
                except Exception:
                    pass

        can_line_count = can_text.count("\n") if can_text else 0

        if can_text and can_line_count > 0:
            self.ctx.findings.create(
                ctx=self.ctx,
                title="Plaintext CAN Traffic Captured",
                description=(
                    f"CAN bus traffic ({can_line_count} frames) was captured "
                    f"in plaintext on DB9 port [{self.ctx.instance_loc}] "
                    f"at {bitrate} bps.  An attacker with physical access can "
                    f"passively monitor all CAN communications."
                ),
                tool="candump",
                raw_output=can_text[:1000],
                source_type="primary", force_risk="Low",
                ip="", output_file=str(can_file),
            )
        else:
            self.ctx.logger.warn(
                "CAN capture produced no frames.", tool=self.name)
            self._mark_complete("CAN detected but capture empty")
            return

        # ── Step 12: Heartbeat detection ──────────────────────────────────────
        heartbeats = _db9_detect_heartbeats(can_text)
        hb_file = out_dir / f"{self.ctx.file_prefix}_heartbeat.txt"
        if heartbeats:
            lines = [
                f"Detected {len(heartbeats)} heartbeat CAN ID(s):\n"
            ]
            for can_id, (avg_ms, count, sample) in sorted(heartbeats.items()):
                lines.append(
                    f"  ID {can_id}: {count} frames, avg interval "
                    f"{avg_ms:.1f} ms\n    Sample: {sample}\n")
            hb_file.write_text("".join(lines))
            self.ctx.logger.info(
                f"Heartbeat IDs: {', '.join(sorted(heartbeats.keys()))}",
                tool=self.name)
        else:
            hb_file.write_text("No heartbeat sequences detected.\n")
            self.ctx.logger.info(
                "No heartbeat sequences detected.", tool=self.name)

        # ── Step 13: Strip heartbeats ─────────────────────────────────────────
        stripped_text = _db9_strip_heartbeats(
            can_text, set(heartbeats.keys()) if heartbeats else set())
        stripped_file = out_dir / f"{self.ctx.file_prefix}_can_stripped.txt"
        stripped_file.write_text(stripped_text)
        stripped_line_count = stripped_text.count("\n")
        self.ctx.logger.info(
            f"Heartbeat-stripped capture: {stripped_line_count} frames.",
            tool=self.name)

        # ── Step 14: CAN replay attack ────────────────────────────────────────
        if not tool_available("cansend"):
            self.ctx.logger.warn(
                "cansend not available — skipping replay attack.",
                tool=self.name)
            self._mark_complete(
                f"CAN assessment complete — {bitrate} bps on {iface} "
                f"(replay skipped: cansend missing)")
            return

        self._prompt(
            f"CAN Replay Attack — {self.ctx.instance_key}\n\n"
            f"About to replay {stripped_line_count} non-heartbeat CAN frames "
            f"onto {iface}.\n\n"
            f"IMPORTANT: Start a video recording of the target device NOW "
            f"to document any observable effects (LEDs, actuators, displays, "
            f"unexpected behaviour).",
            options=["Video recording started — begin replay"],
            prompt_type="choice")

        replay_log = out_dir / f"{self.ctx.file_prefix}_can_replay_log.txt"
        sent = _db9_replay_frames(stripped_text, iface, self.ctx)
        replay_log.write_text(
            f"CAN replay on {iface} @ {bitrate} bps: {sent} frame(s) sent.\n"
            f"Source: {stripped_file.name}\n")

        self.ctx.findings.create(
            ctx=self.ctx,
            title="CAN Replay Attack",
            description=(
                f"CAN bus frames captured from DB9 port "
                f"[{self.ctx.instance_loc}] were successfully replayed onto "
                f"the bus ({sent} frames sent via cansend).  Replay attacks "
                f"can trigger unintended device behaviour including actuator "
                f"commands, mode changes, or safety system bypasses."
            ),
            tool="cansend",
            raw_output=replay_log.read_text(),
            source_type="primary", force_risk="High",
            ip="", output_file=str(replay_log),
        )

        self._mark_complete(
            f"CAN assessment complete — {bitrate} bps on {iface}, "
            f"{sent} frames replayed")


# ---------------------------------------------------------------------------
# RFID Modules
# ---------------------------------------------------------------------------

def _rfid_chameleon_cli() -> Optional[str]:
    """Locate a Chameleon Ultra CLI (alternate HF/LF reader/emulator to Proxmark3).
    Checks the common command names shipped by RfidResearchGroup/ChameleonUltra."""
    for name in ("chameleon_cli", "chameleon_ultra", "cu"):
        p = shutil.which(name)
        if p:
            return p
    for cand in ("/opt/ChameleonUltra/software/script/chameleon_cli_main.py",
                 str(Path.home() / "ChameleonUltra/software/script/chameleon_cli_main.py")):
        if os.path.exists(cand):
            return cand
    return None


class RFIDSniffModule(BaseModule):
    name        = "RFIDSniff"
    description = "Capture RFID/NFC card data using Proxmark or similar"

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "RFIDSniff"
            out_dir.mkdir(parents=True, exist_ok=True)
            answer = self._prompt(
                f"Connect an RFID/NFC reader near port [{self.ctx.instance_loc}] — "
                f"Proxmark3 (pm3) or Chameleon Ultra. Place the test card in range. "
                f"Press Enter to begin.",
                options=["Ready", "Skip"], prompt_type="choice", skippable=True)
            if "skip" in answer.lower() or answer == "2":
                self._mark_skipped("Skipped by user")
                self._mark_connected_photo_na("RFID test skipped")
                return
            self._prompt_connected_photo(
                f"RFID reader (Proxmark3 / Chameleon Ultra) positioned at [{self.ctx.instance_loc}]")

            out_file = out_dir / f"{self.ctx.file_prefix}_rfid_sniff.txt"
            if tool_available("pm3"):
                run_tool(
                    ["pm3", "--script", "hf_search"],
                    self.ctx, tool_name="proxmark3",
                    output_file=out_file, timeout=60)
                if out_file.exists() and out_file.stat().st_size > 0:
                    content = out_file.read_text(errors="replace")
                    self._observe(
                        title=f"RFID Scan Results — {self.ctx.instance_key}",
                        description=f"Proxmark3 HF search results for [{self.ctx.instance_loc}].",
                        tool="proxmark3",
                        output_file=str(out_file),
                        output_text=content[:1500],
                        risk="Informational",
                    )
            elif _rfid_chameleon_cli():
                # Chameleon Ultra fallback. Its CLI (RfidResearchGroup/ChameleonUltra
                # chameleon_cli) mirrors Proxmark HF/LF search verbs; command names may
                # vary by CLI version, so this is best-effort and the raw output is
                # preserved for the operator.
                cli = _rfid_chameleon_cli()
                run_tool([cli, "hf", "14a", "scan"], self.ctx, tool_name="chameleon_ultra",
                         output_file=out_file, timeout=60)
                if out_file.exists() and out_file.stat().st_size > 0:
                    self._observe(
                        title=f"RFID Scan Results — {self.ctx.instance_key}",
                        description=f"Chameleon Ultra HF scan for [{self.ctx.instance_loc}].",
                        tool="chameleon_ultra", output_file=str(out_file),
                        output_text=out_file.read_text(errors="replace")[:1500],
                        risk="Informational")
            else:
                out_file.write_text(
                    "No RFID reader CLI available. RFID sniff requires a Proxmark3 (pm3) "
                    "or a Chameleon Ultra (chameleon_cli) on PATH.\n")
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="RFID testing SKIPPED — no RFID reader available",
                    description=("Gearbox found no RFID reader CLI on PATH (Proxmark3 'pm3' "
                                 "or Chameleon Ultra 'chameleon_cli'). RFID/NFC was NOT tested. "
                                 "Attach a supported reader and re-run the module."),
                    tool="rfid-sniff", source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
            self._mark_complete("RFID sniff done")
        except Exception as e:
            self._mark_error(str(e))


class RFIDReplayModule(BaseModule):
    name        = "RFIDReplay"
    description = "Replay captured RFID credentials"

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir  = self.ctx.instance_dir / "RFIDReplay"
            out_dir.mkdir(parents=True, exist_ok=True)
            sniff_dir = self.ctx.instance_dir / "RFIDSniff"
            captures  = list(sniff_dir.glob("*.txt")) if sniff_dir.exists() else []

            if not captures or not tool_available("pm3"):
                with open(str(out_dir / f"{self.ctx.file_prefix}_rfid_replay.txt"), "w") as f:
                    f.write("No data captured to replay or pm3 not available.\n")
                self._mark_skipped("No data captured to replay")
                return

            answer = self._prompt(
                f"Attempt to replay captured RFID credentials against "
                f"[{self.ctx.instance_loc}]. Was replay successful?",
                options=["Yes — replayed successfully", "No — replay failed",
                         "No data captured to replay"],
                prompt_type="choice", skippable=True)

            out_file = out_dir / f"{self.ctx.file_prefix}_rfid_replay.txt"
            out_file.write_text(f"Replay result: {answer}\n")

            if "successfully" in answer.lower():
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"RFID Credential Replay Successful — {self.ctx.instance_key}",
                    description=(
                        f"Captured RFID credentials were successfully replayed against "
                        f"the reader at [{self.ctx.instance_loc}]."
                    ),
                    tool="proxmark3", raw_output=answer,
                    source_type="primary", force_risk="Critical",
                    force_classification="Validated",
                    ip="",
                    output_file="",
                )
            self._mark_complete(f"RFID replay: {answer}")
        except Exception as e:
            self._mark_error(str(e))

# ---------------------------------------------------------------------------
# 2026-06-11 review round 4: embedded-hardware extension modules.
#
# Each module:
#   * uses shutil.which() to probe for its required binary
#   * runs the tool with a generous subprocess timeout via the shared
#     pr0t31n_timeouts catalogue when available
#   * emits an honest "SKIPPED — tool not installed" INFO finding when
#     the binary is absent (so the operator is NOT misled into thinking
#     the test ran)
#   * persists raw stdout/stderr to <project_dir>/<module>/<file>.txt
#
# Coverage:
#   JtagDetectModule    — openocd JTAG/SWD chain probe
#   SpiFlashDumpModule  — flashrom SPI flash dump
#   FirmwareAnalysisModule — binwalk on extracted firmware
#   SerialConsoleLoginModule — minicom-based console enumeration
#     + default-credential probe and boot-interrupt detection
#   RFIDDeepReadModule  — mfoc / mfcuk / nfc-list extended RFID enumeration
# ---------------------------------------------------------------------------


def _gb_resolve_timeout(tool_key: str, default: int = 3600) -> int:
    """Generous timeout from shared catalogue with graceful fallback."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_timeouts as _to   # type: ignore
        return _to.resolve(tool_key)
    except Exception:
        return default


class JtagDetectModule(BaseModule):
    name        = "JtagDetect"
    description = "Probe for JTAG/SWD chain via openocd"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            self._prompt("Connect a JTAG/SWD probe — ST-Link V2, J-Link, Bus Pirate 5, "
                          "or Olimex — to the target's debug pads. "
                          + f"Testing port: [{self.ctx.instance_loc}]. Press Enter to begin.",
                          options=["Ready"], prompt_type="choice")
            self._prompt_connected_photo(f"JTAG/SWD probe connected at [{self.ctx.instance_loc}]")
            out_dir = self.ctx.instance_dir / "JtagDetect"
            out_dir.mkdir(parents=True, exist_ok=True)
            openocd = _shu.which("openocd")
            if not openocd:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="JTAG/SWD testing SKIPPED — openocd not installed",
                    description=("Gearbox attempted to probe for a JTAG/SWD chain "
                                  "but openocd is not on PATH. JTAG/SWD was NOT tested. "
                                  "Install openocd (apt install openocd) and re-run."),
                    tool="openocd", raw_output="no openocd binary",
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
                self._mark_complete("JTAG/SWD SKIPPED — openocd not installed")
                return
            # Try a chain probe with a couple of common interface scripts.
            # ST-Link V2 is tried first (openocd interface/stlink.cfg); Bus Pirate
            # and J-Link/Olimex follow.
            interface_scripts = ["interface/stlink.cfg", "interface/jlink.cfg",
                                  "interface/buspirate.cfg",
                                  "interface/ftdi/olimex-arm-usb-tiny-h.cfg"]
            timeout = _gb_resolve_timeout("openocd", 3 * 3600)
            for iface in interface_scripts:
                out_file = out_dir / f"openocd_chain_{Path(iface).stem}.txt"
                cmd = [openocd, "-f", iface, "-c", "init;scan_chain;exit"]
                try:
                    res = _sp.run(cmd, capture_output=True, text=True, timeout=180)
                    out_file.write_text(
                        f"$ {' '.join(cmd)}\n\n── stdout ──\n{res.stdout}\n\n── stderr ──\n{res.stderr}\n",
                        encoding="utf-8")
                    # Detection markers in openocd output
                    if re.search(r"Cortex-[MAR]|IDCODE", res.stdout, re.IGNORECASE):
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title=f"Debug Port Reachable: JTAG/SWD chain detected via {iface}",
                            description=("openocd identified at least one tap on the JTAG/SWD "
                                          "chain. Unprotected debug access allows firmware extraction, "
                                          "secure-boot bypass, and memory write. Disable JTAG/SWD in "
                                          "production by blowing the SoC's debug-disable e-fuse, "
                                          "removing the header, or filling the pads with conformal "
                                          "coating."),
                            tool="openocd", raw_output=res.stdout[:4000],
                            source_type="primary", force_risk="High",
                            ip="", port=str(self.ctx.instance_loc))
                        break
                except _sp.TimeoutExpired:
                    out_file.write_text(f"$ {' '.join(cmd)}\n[TIMEOUT after 180s]\n",
                                          encoding="utf-8")
                except Exception as exc:
                    out_file.write_text(f"$ {' '.join(cmd)}\n[ERROR: {exc}]\n",
                                          encoding="utf-8")
            self._mark_complete("JTAG/SWD probe complete")
        except Exception as e:
            self._mark_error(str(e))


class SpiFlashDumpModule(BaseModule):
    name        = "SpiFlashDump"
    description = "Dump SPI flash chip via flashrom + USB programmer"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            self._prompt("Connect a flashrom-supported programmer to the SPI flash — "
                          "CH341A, Bus Pirate 5, or FT2232 — using a SOP8/SOP16 SOIC "
                          "test clip for an in-circuit read (no desolder). "
                          + f"Testing port: [{self.ctx.instance_loc}]. Press Enter to begin.",
                          options=["Ready"], prompt_type="choice")
            self._prompt_connected_photo(
                f"SPI programmer + SOIC clip connected at [{self.ctx.instance_loc}]")
            out_dir = self.ctx.instance_dir / "SpiFlashDump"
            out_dir.mkdir(parents=True, exist_ok=True)
            flashrom = _shu.which("flashrom")
            if not flashrom:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="SPI flash dump SKIPPED — flashrom not installed",
                    description=("Gearbox attempted to dump the SPI flash but flashrom is "
                                  "not on PATH. SPI flash extraction was NOT performed. "
                                  "Install flashrom (apt install flashrom) and re-run."),
                    tool="flashrom", raw_output="no flashrom binary",
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
                self._mark_complete("SPI flash dump SKIPPED — flashrom not installed")
                return
            # Try a few common programmers; let the operator-photo confirm hardware.
            # buspirate_spi (Bus Pirate 5) requires an explicit serial dev= path, so
            # resolve the first likely Bus Pirate CDC port and append it.
            _bp_port = next((p for p in ("/dev/ttyUSB0", "/dev/ttyACM0",
                                         "/dev/ttyUSB1", "/dev/ttyACM1")
                             if os.path.exists(p)), None)
            programmers = ["ch341a_spi", "ft2232_spi"]
            if _bp_port:
                programmers.insert(1, f"buspirate_spi:dev={_bp_port}")
            else:
                programmers.insert(1, "buspirate_spi")
            timeout = _gb_resolve_timeout("flashrom", 4 * 3600)
            for prog in programmers:
                slug = re.sub(r"[^A-Za-z0-9]+", "_", prog).strip("_")
                out_file = out_dir / f"flashrom_dump_{slug}.bin"
                log_file = out_dir / f"flashrom_log_{slug}.txt"
                cmd = [flashrom, "-p", prog, "-r", str(out_file)]
                try:
                    res = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
                    log_file.write_text(
                        f"$ {' '.join(cmd)}\n\n── stdout ──\n{res.stdout}\n\n── stderr ──\n{res.stderr}\n",
                        encoding="utf-8")
                    if res.returncode == 0 and out_file.exists() and out_file.stat().st_size > 1024:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title=f"SPI Flash Extracted via {prog} ({out_file.stat().st_size:,} bytes)",
                            description=("SPI flash dumped. The dumped image likely contains "
                                          "firmware, configuration data, secrets, and bootloader "
                                          "code. Run binwalk to extract embedded filesystems and "
                                          "search for hardcoded credentials, private keys, and "
                                          "certificates."),
                            tool="flashrom", raw_output=res.stdout[:2000],
                            source_type="primary", force_risk="High",
                            ip="", port=str(self.ctx.instance_loc),
                            output_file=str(out_file))
                        break
                except _sp.TimeoutExpired:
                    log_file.write_text(f"$ {' '.join(cmd)}\n[TIMEOUT after {timeout}s]\n",
                                          encoding="utf-8")
                except Exception as exc:
                    log_file.write_text(f"$ {' '.join(cmd)}\n[ERROR: {exc}]\n",
                                          encoding="utf-8")
            self._mark_complete("SPI flash dump complete")
        except Exception as e:
            self._mark_error(str(e))


class FirmwareAnalysisModule(BaseModule):
    name        = "FirmwareAnalysis"
    description = "Run binwalk on previously dumped firmware images"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            out_dir = self.ctx.instance_dir / "FirmwareAnalysis"
            out_dir.mkdir(parents=True, exist_ok=True)
            binwalk = _shu.which("binwalk")
            if not binwalk:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="Firmware analysis SKIPPED — binwalk not installed",
                    description=("Gearbox attempted to run binwalk on previously dumped "
                                  "firmware but binwalk is not on PATH. Install binwalk "
                                  "(apt install binwalk) and re-run."),
                    tool="binwalk", raw_output="no binwalk binary",
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
                self._mark_complete("Firmware analysis SKIPPED — binwalk not installed")
                return
            # Find any .bin files dumped earlier in this project
            bin_files = list(self.ctx.project_dir.rglob("*.bin"))
            if not bin_files:
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="Firmware analysis SKIPPED — no .bin files in project",
                    description=("binwalk is installed but no .bin files were found in "
                                  "the project directory. Run SpiFlashDump (or import a "
                                  "firmware image) first."),
                    tool="binwalk", raw_output="no .bin files",
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
                self._mark_complete("Firmware analysis SKIPPED — no .bin files")
                return
            timeout = _gb_resolve_timeout("binwalk", 2 * 3600)
            for bf in bin_files[:5]:
                bw_out = out_dir / f"binwalk_{bf.stem}.txt"
                bw_extract_dir = out_dir / f"extracted_{bf.stem}"
                # First: signature pass
                try:
                    res = _sp.run([binwalk, str(bf)], capture_output=True,
                                    text=True, timeout=timeout)
                    bw_out.write_text(
                        f"$ binwalk {bf}\n\n── stdout ──\n{res.stdout}\n\n── stderr ──\n{res.stderr}\n",
                        encoding="utf-8")
                except _sp.TimeoutExpired:
                    bw_out.write_text(f"$ binwalk {bf}\n[TIMEOUT after {timeout}s]\n",
                                       encoding="utf-8")
                    continue
                except Exception as exc:
                    bw_out.write_text(f"$ binwalk {bf}\n[ERROR: {exc}]\n",
                                       encoding="utf-8")
                    continue
                # Second: extraction pass
                try:
                    _sp.run([binwalk, "-e", "-M",
                              "--directory", str(bw_extract_dir), str(bf)],
                              capture_output=True, text=True, timeout=timeout)
                except (_sp.TimeoutExpired, Exception):
                    pass
                # Look for high-value markers in the binwalk signature pass
                hot = []
                for needle in ("squashfs", "JFFS2", "U-Boot", "Linux kernel",
                                 "encrypted", "private key", "SSL certificate"):
                    if needle.lower() in res.stdout.lower():
                        hot.append(needle)
                if hot:
                    self.ctx.findings.create(
                        ctx=self.ctx,
                        title=f"Firmware Components Identified: {', '.join(hot)}",
                        description=("binwalk identified embedded components in the "
                                      f"dumped firmware ({bf.name}): {', '.join(hot)}. "
                                      "Examine extracted filesystem under "
                                      f"{bw_extract_dir.name}/ for hardcoded "
                                      "credentials, hardcoded keys, and known-vulnerable "
                                      "binaries."),
                        tool="binwalk", raw_output=res.stdout[:4000],
                        source_type="primary", force_risk="Medium",
                        ip="", port=str(self.ctx.instance_loc),
                        output_file=str(bw_out))
            self._mark_complete("Firmware analysis complete")
        except Exception as e:
            self._mark_error(str(e))


class SerialConsoleLoginModule(BaseModule):
    name        = "SerialConsoleLogin"
    description = "Probe serial console for default credentials and boot interrupt"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            ans = self._prompt(
                f"Probe the serial console at [{self.ctx.instance_loc}] for default "
                + "credentials and U-Boot/grub boot-interrupt access. "
                + "Did the operator observe any of the following?",
                options=["Default credentials accepted (e.g. root:root, admin:admin)",
                          "Boot interrupt allowed access to U-Boot/grub",
                          "Both default credentials and boot interrupt",
                          "Console requires authentication; no interrupt",
                          "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "SerialConsoleLogin"
            out_dir.mkdir(parents=True, exist_ok=True)
            obs_file = out_dir / f"{self.ctx.file_prefix}_observations.txt"
            obs_file.write_text(f"Operator observation: {ans}\n", encoding="utf-8")
            if "default credentials" in ans.lower() and "both" in ans.lower():
                _risk = "Critical"
                _title = "Serial Console: Default Credentials AND Boot Interrupt"
            elif "default credentials" in ans.lower():
                _risk = "High"
                _title = "Serial Console: Default Credentials Accepted"
            elif "boot interrupt" in ans.lower():
                _risk = "High"
                _title = "Serial Console: Boot Interrupt Allows U-Boot/Grub Access"
            else:
                self._mark_complete(f"Serial console: {ans}")
                return
            self.ctx.findings.create(
                ctx=self.ctx,
                title=_title,
                description=("Serial console is exploitable. " + ans),
                tool="serial-console-probe", raw_output=ans,
                source_type="primary", force_risk=_risk,
                ip="", port=str(self.ctx.instance_loc),
                output_file=str(obs_file))
            self._mark_complete(f"Serial console: {ans}")
        except Exception as e:
            self._mark_error(str(e))


class RFIDDeepReadModule(BaseModule):
    name        = "RFIDDeepRead"
    description = "Extended RFID enumeration via mfoc / mfcuk / nfc-list"

    def run(self) -> None:
        self._mark_running()
        try:
            import shutil as _shu, subprocess as _sp
            self._prompt(f"Place an RFID/NFC tag on the reader. Tool will attempt full "
                          + "key recovery via mfoc (timing attack). Press Enter to begin.",
                          options=["Ready"], prompt_type="choice")
            out_dir = self.ctx.instance_dir / "RFIDDeepRead"
            out_dir.mkdir(parents=True, exist_ok=True)
            mfoc    = _shu.which("mfoc")
            mfcuk   = _shu.which("mfcuk")
            nfclist = _shu.which("nfc-list")
            if not any((mfoc, mfcuk, nfclist)):
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="RFID deep read SKIPPED — no mfoc/mfcuk/nfc-list installed",
                    description=("Gearbox attempted extended RFID enumeration but none "
                                  "of mfoc, mfcuk, or nfc-list is installed. Install "
                                  "libnfc-bin + mfoc + mfcuk and re-run."),
                    tool="mfoc/mfcuk/nfc-list",
                    raw_output="no RFID tools present",
                    source_type="primary", force_risk="Informational",
                    ip="", port=str(self.ctx.instance_loc))
                self._mark_complete("RFID deep read SKIPPED — no tools installed")
                return
            timeout = _gb_resolve_timeout("proxmark", 1800)
            results = []
            # Step 1: nfc-list to enumerate the tag
            if nfclist:
                out_file = out_dir / "nfc_list.txt"
                try:
                    res = _sp.run([nfclist], capture_output=True, text=True, timeout=60)
                    out_file.write_text(f"$ nfc-list\n\n{res.stdout}\n", encoding="utf-8")
                    if "Type" in res.stdout: results.append("nfc-list: tag identified")
                except Exception: pass
            # Step 2: mfoc darkside attack (only succeeds on MIFARE Classic w/ at least one known key)
            if mfoc:
                out_file = out_dir / "mfoc_keys.txt"
                try:
                    res = _sp.run([mfoc, "-O", str(out_file)],
                                    capture_output=True, text=True, timeout=timeout)
                    if res.returncode == 0:
                        self.ctx.findings.create(
                            ctx=self.ctx,
                            title="RFID Card Keys Recovered (mfoc — MIFARE Classic)",
                            description=("mfoc successfully recovered all sector keys for the "
                                          "presented MIFARE Classic card. The card can be "
                                          "cloned, modified, or used to enumerate the access "
                                          "control system's key universe."),
                            tool="mfoc", raw_output=res.stdout[:2000],
                            source_type="primary", force_risk="High",
                            ip="", port=str(self.ctx.instance_loc),
                            output_file=str(out_file))
                        results.append("mfoc: keys recovered")
                except Exception: pass
            self._mark_complete("RFID deep read: " + (", ".join(results) if results else "no results"))
        except Exception as e:
            self._mark_error(str(e))


# ---------------------------------------------------------------------------
# Module Registry  (name → class)
# ---------------------------------------------------------------------------

_MODULE_REGISTRY: dict[str, type] = {
    "Photo":            PhotoModule,
    "EthernetIface":    EthernetIfaceModule,
    "Ethtool":          EthtoolModule,
    "ConfigDiscovery":  ConfigDiscoveryModule,
    "TrafficCollector": TrafficCollectorModule,
    "DhcpServer":       DhcpServerModule,
    "NmapLive":         NmapLiveModule,
    "Nessus":           NessusModule,
    "Responder":        ResponderModule,
    "NmapPort":         NmapPortModule,
    "BannerGrab":       BannerGrabModule,
    "Web":              WebModule,
    "Nuclei":           NucleiModule,
    "SSL":              SSLModule,
    "SSH":              SSHModule,
    "SMB":              SMBModule,
    "NFS":              NFSModule,
    "FTP":              FTPModule,
    "UsbPower":         UsbPowerModule,
    "Keyboard":         KeyboardModule,
    "KeyCombos":        KeyCombosModule,
    "Mouse":            MouseModule,
    "BashBunny":        BashBunnyModule,
    "UsbMassStorage":   UsbMassStorageModule,
    "UsbEthernetAdapter": UsbEthernetAdapterModule,
    "Tcpdump_running":  TcpdumpRunningModule,
    "Tcpdump_boot":     TcpdumpBootModule,
    "Tcpdump_shutdown": TcpdumpShutdownModule,
    "PortType":         PortTypeModule,
    "Input":            VideoInputModule,
    "Output":           VideoOutputModule,
    "EDID":             EDIDModule,
    "HdmiDDC":          HdmiDDCModule,
    "HdmiHDCP":         HdmiHDCPModule,
    "HdmiCEC":          HdmiCECModule,
    "Sniff":            ZigbeeSniffModule,
    "Flood":            ZigbeeFloodModule,
    "Bluetooth":        BluetoothModule,
    "SerialDetect":     SerialDetectModule,
    "CanAssess":        CanAssessModule,
    "RFIDSniff":        RFIDSniffModule,
    "RFIDReplay":       RFIDReplayModule,
    # 2026-06-11 review round 4 — embedded hardware extension modules.
    "JtagDetect":          JtagDetectModule,
    "SpiFlashDump":        SpiFlashDumpModule,
    "FirmwareAnalysis":    FirmwareAnalysisModule,
    "SerialConsoleLogin":  SerialConsoleLoginModule,
    "RFIDDeepRead":        RFIDDeepReadModule,
    # 2026-08-13 — wireless / RF / smart-card interface modules
    "WiFi":             WiFiModule,
    "SubGHz":           SubGHzModule,
    "UWB":              UWBModule,
    "SmartCard":        SmartCardModule,
    "ZWave":            ZWaveModule,
    "LoRa":             LoRaModule,
    "EthernetCleanup":  EthernetCleanupModule,
}


# ---------------------------------------------------------------------------
# IpTracker singleton helper
# ---------------------------------------------------------------------------

_ip_tracker_cache: Optional[IpTracker] = None

def _get_ip_tracker(project_dir: Path) -> IpTracker:
    global _ip_tracker_cache
    if _ip_tracker_cache is None:
        _ip_tracker_cache = IpTracker(project_dir)
    return _ip_tracker_cache


# ---------------------------------------------------------------------------
# InstanceOrchestrator
# ---------------------------------------------------------------------------

class InstanceOrchestrator:
    """Runs all modules for a single (interface, instance) pair."""

    def __init__(self, ctx: ModuleContext,
                 worker_semaphore: threading.Semaphore) -> None:
        self.ctx          = ctx
        self._semaphore   = worker_semaphore

    def run(self) -> None:
        interface    = self.ctx.interface
        module_names = INTERFACE_MODULES.get(interface, [])
        registry     = _MODULE_REGISTRY

        console.log(
            f"=== Instance: {self.ctx.subdevice_key}/{interface}/"
            f"{self.ctx.instance_key} ({len(module_names)} modules) ===",
            "INFO")

        # Kill leftover Responder process if one was started by a previous run
        pid_str = self.ctx.progress.get_module_status(
            self.ctx.subdevice_key, interface, self.ctx.instance_key,
            "_responder_pid")
        if pid_str and pid_str.isdigit():
            try:
                os.kill(int(pid_str), signal.SIGTERM)
                console.log(f"Responder (pid={pid_str}) terminated", "INFO")
            except Exception:
                pass

        if interface == "Ethernet":
            self._run_ethernet_modules(module_names, registry)
        else:
            self._run_sequential(module_names, registry)

    def _run_sequential(self, module_names: list[str],
                        registry: dict[str, type]) -> None:
        for mod_name in module_names:
            _check_pause()
            if self.ctx.progress.is_module_complete(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, mod_name):
                console.log(f"  [SKIP] {mod_name} — already complete", "INFO")
                continue
            cls = registry.get(mod_name)
            if cls is None:
                console.log(f"  [WARN] No implementation for {mod_name}", "WARNING")
                continue
            try:
                module = cls(self.ctx)
                module.run()
            except SystemExit:
                raise
            except Exception as e:
                console.log(
                    f"Module {mod_name} raised unhandled exception: {e}",
                    "ERROR")

    def _run_ethernet_modules(self, module_names: list[str],
                               registry: dict[str, type]) -> None:
        """
        Ethernet module execution order:

          Sequential:  Photo → Ethtool → ConfigDiscovery → TrafficCollector
          Background:  Nessus    (non-blocking, joins before instance complete)
          Sequential:  NmapLive
          Background:  Responder (non-blocking, killed after phase 2 completes)
          Sequential:  NmapPort  (dispatches per-host assessments internally,
                                  waits for all of them before returning)
          Safety-net:  _run_concurrent(phase2_concurrent) — skips modules
                       already completed by per-host dispatch; handles any
                       hosts that were in the DB before this run started.
          Wait:        Nessus (Responder stays alive during Nessus scan)
          Kill:        Responder stop event signalled (after Nessus done)
          Wait:        Responder future joined
        """
        sequential_pre  = ["Photo", "EthernetIface", "Ethtool", "ConfigDiscovery",
                           "TrafficCollector", "DhcpServer"]
        phase2_concurrent = ["BannerGrab", "Web", "Nuclei", "SSL", "SSH", "FTP", "SMB", "NFS"]

        # Register ctx so _ethernet_shutdown_cleanup() can reach Responder/Nessus
        # if a SIGINT, SIGTERM, or "Cancel" fires mid-assessment.
        _active_ethernet_ctxs.append(self.ctx)
        try:
            self._run_ethernet_body(
                sequential_pre, phase2_concurrent, registry)
        finally:
            try:
                _active_ethernet_ctxs.remove(self.ctx)
            except ValueError:
                pass

    def _run_ethernet_body(
            self,
            sequential_pre: list[str],
            phase2_concurrent: list[str],
            registry: dict[str, type]) -> None:
        """Inner body of _run_ethernet_modules — separated so the outer method
        can wrap it with the shutdown-cleanup registry try/finally."""

        # ── Restore test_interface from progress (handles session resume) ──────
        # EthernetIfaceModule persists the chosen interface as _test_interface.
        # On resume it is skipped as already-complete, so we must restore the
        # value here before any module reads ctx.config["test_interface"].
        saved_iface = self.ctx.progress.get_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, "_test_interface")
        if saved_iface and saved_iface not in ("pending", "skipped", ""):
            self.ctx.config["test_interface"] = saved_iface
            console.log(
                f"  [EthernetIface] Restored test_interface={saved_iface} "
                f"from progress (session resume)",
                "INFO")
        else:
            # No saved selection yet — check for test_direct now so that even
            # if EthernetIfaceModule itself hasn't run yet the value is correct
            # for any module that needs it before EthernetIface executes.
            import subprocess as _sp_iface
            try:
                r = _sp_iface.run(["ip", "link", "show", "test_direct"],
                                  capture_output=True, timeout=3)
                if r.returncode == 0:
                    self.ctx.config["test_interface"] = "test_direct"
            except Exception:
                pass

        # ── Pre-instance sanity check: ensure interface is clean ──────────────
        # If a previous instance's EthernetCleanup failed or was interrupted,
        # the test interface may still carry the DHCP-server static address.
        # Detect and revert before running any modules for this instance.
        pre_check_iface = self.ctx.config.get("test_interface", "eth0")
        flag_set        = bool(self.ctx.config.get("_dhcp_server_ran"))
        iface_dirty     = _interface_has_dhcp_server_ip(pre_check_iface)
        if flag_set or iface_dirty:
            console.log(
                f"  [EthernetCleanup] WARNING — stale DHCP-server config detected "
                f"on {pre_check_iface} before instance {self.ctx.instance_key} "
                f"starts (flag={flag_set}, dirty={iface_dirty}). Reverting now.",
                "WARNING")
            pid = self.ctx.config.get("_dhcp_proc_pid")
            _revert_test_iface(pre_check_iface, pid=pid)
            self.ctx.config.pop("_dhcp_server_ran",   None)
            self.ctx.config.pop("_dhcp_server_iface", None)
            self.ctx.config.pop("_dhcp_proc_pid",     None)

        # ── Pre-sequential: Photo, EthernetIface, Ethtool, ConfigDiscovery,
        #                   TrafficCollector, DhcpServer ───────────────────────
        self._run_sequential(sequential_pre, registry)

        # ── Dead-port check ───────────────────────────────────────────────────
        all_remaining = ["NmapLive", "Nessus", "Responder", "NmapPort"] + phase2_concurrent
        link_alive = self.ctx.progress.get_module_status(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key, "_link_alive")

        if link_alive == "no":
            console.log(
                f"  [N/A] Port dead — skipping all post-Ethtool modules "
                f"for {self.ctx.instance_key}",
                "INFO")
            for mod_name in (all_remaining + ["EthernetCleanup"]):
                cls = registry.get(mod_name)
                if cls is None:
                    continue
                try:
                    mod_obj = cls(self.ctx)
                    mod_obj._mark_na("Port dead — no link detected by ethtool")
                except Exception:
                    pass
            self.ctx.progress.mark_instance_complete(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key)
            return

        # ── NmapLive (must complete before Nessus/Responder/NmapPort) ──────────
        _check_pause()
        self._run_sequential(["NmapLive"], registry)

        # ── Check for live hosts — gate all remaining target-dependent modules ─
        # ctx._live_ips is set in-memory by NmapLive immediately after it runs.
        # If empty, there are no targets for any subsequent module to act on;
        # mark them all N/A rather than running them and getting vacuous results.
        live_ips_after_nmap: list = list(getattr(self.ctx, '_live_ips', None) or [])
        if not live_ips_after_nmap:
            raw_ips = self.ctx.progress.get_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "_live_ips")
            if raw_ips and raw_ips not in ("pending", "skipped", ""):
                try:
                    live_ips_after_nmap = json.loads(raw_ips)
                except Exception:
                    pass

        if not live_ips_after_nmap:
            console.log(
                f"  [N/A] No live hosts discovered — skipping all target-dependent "
                f"modules for {self.ctx.instance_key}",
                "INFO")
            for mod_name in (["Nessus", "Responder", "NmapPort"] + phase2_concurrent):
                cls = registry.get(mod_name)
                if cls is None:
                    continue
                try:
                    cls(self.ctx)._mark_na("No live hosts discovered")
                except Exception:
                    pass
            self._run_sequential(["EthernetCleanup"], registry)
            self.ctx.progress.mark_instance_complete(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key)
            return

        _check_pause()

        # ── Launch Nessus in a background thread ─────────────────────────────
        # Nessus can take 30+ minutes; we must not block the rest of the pipeline.
        # NmapLive has already confirmed live hosts exist, so pre-marking "running"
        # is accurate. IMPORTANT: read _network_configured from in-memory state
        # RIGHT NOW, before any concurrent _reload_from_disk() call can delete it.
        nessus_future: Future = None
        nessus_cls = registry.get("Nessus")
        if nessus_cls and not self.ctx.progress.is_module_complete(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "Nessus"):
            # Snapshot IP now — use _state directly (no disk reload)
            net_cfg_key = (f"{self.ctx.subdevice_key}.{self.ctx.interface}"
                           f".{self.ctx.instance_key}._network_configured")
            net_ip = (self.ctx.progress._state
                      .get("module_status", {})
                      .get(net_cfg_key, {})
                      .get("status", ""))
            if not net_ip or net_ip in ("pending", "skipped"):
                # Also try reading directly from the network interface as fallback
                try:
                    import subprocess as _sp, re as _re
                    TEST_INTERFACE = self.ctx.config.get("test_interface", "eth0")
                    r = _sp.run(["ip", "-4", "addr", "show", str(TEST_INTERFACE)],
                                capture_output=True, text=True, timeout=5)
                    m = _re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                    if m:
                        net_ip = m.group(1)
                except Exception:
                    pass

            if net_ip and net_ip not in ("pending", "skipped"):
                # Inject IP onto context so NessusModule reads it without touching progress
                self.ctx._nessus_net_cfg = net_ip
                # Pre-mark running so the Evidence tab shows "running" immediately.
                # Live hosts are confirmed above, so this status is accurate.
                self.ctx.progress.set_module_status(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "Nessus", "running",
                )
                console.status_update(
                    self.ctx.subdevice_key, self.ctx.interface,
                    self.ctx.instance_key, "Nessus", "running",
                )
                executor = ThreadPoolExecutor(max_workers=1,
                                              thread_name_prefix="nessus-bg")
                nessus_future = executor.submit(self._run_one, "Nessus", registry)
                console.log(
                    f"  [Nessus] Background scan started for "
                    f"{self.ctx.instance_key} (target network: {net_ip}) "
                    f"— pipeline continues.",
                    "INFO")
            else:
                # No IP available — mark Nessus as N/A (network never configured)
                console.log(
                    f"  [Nessus] N/A — no network configuration for "
                    f"{self.ctx.instance_key}", "WARNING")
                nessus_cls(self.ctx)._mark_na("No network configuration established")

        # ── Launch Responder in a background thread ───────────────────────────
        # Responder poisons LLMNR/NBT-NS while the rest of the scan runs.
        # It is killed after Phase 2 completes by signalling _responder_stop_event.
        responder_future = None
        responder_executor = None
        responder_cls = registry.get("Responder")
        if responder_cls and not self.ctx.progress.is_module_complete(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "Responder"):
            stop_event = threading.Event()
            self.ctx._responder_stop_event = stop_event
            # Pre-mark running NOW so Evidence tab shows "running" immediately.
            self.ctx.progress.set_module_status(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "Responder", "running",
            )
            console.status_update(
                self.ctx.subdevice_key, self.ctx.interface,
                self.ctx.instance_key, "Responder", "running",
            )
            responder_executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="responder-bg")
            responder_future = responder_executor.submit(
                self._run_one, "Responder", registry)
            console.log(
                f"  [Responder] Background poisoner started for "
                f"{self.ctx.instance_key} — pipeline continues.",
                "INFO")

        # ── NmapPort ──────────────────────────────────────────────────────────
        _check_pause()
        self._run_sequential(["NmapPort"], registry)

        # ── Phase 2: concurrent assessment modules ───────────────────────────
        # Runs after NmapPort is fully complete. Every module in phase2_concurrent
        # has a _source_module_done("NmapPort") loop — on entry here that returns
        # True immediately so they proceed to assess all discovered hosts/ports.
        _check_pause()
        self._run_concurrent(phase2_concurrent, registry)

        # ── Wait for Nessus FIRST — Responder stays alive while Nessus runs ─
        # Responder passively captures credentials during the entire scan window
        # including Nessus, so it must not be killed until Nessus is complete.
        if nessus_future is not None:
            try:
                console.log(
                    f"  [Nessus] Waiting for background scan to complete "
                    f"({self.ctx.instance_key})…",
                    "INFO")
                nessus_future.result(timeout=10800)  # 3-hour hard ceiling
            except TimeoutError:
                console.log(
                    "  [Nessus] Scan exceeded 3-hour limit — "
                    "abandoning wait. Thread will self-terminate.",
                    "WARNING")
            except Exception as e:
                console.log(f"  [Nessus] Background scan error: {e}", "ERROR")
            finally:
                executor.shutdown(wait=False)

        # ── NOW signal Responder to stop (after Nessus + all phase2 done) ────
        if getattr(self.ctx, '_responder_stop_event', None):
            self.ctx.logger.info(
                "Signalling Responder to stop (all modules complete)…",
                tool="responder")
            self.ctx._responder_stop_event.set()

        if responder_future is not None:
            try:
                responder_future.result(timeout=30)
            except Exception as e:
                console.log(f"  [Responder] Background thread error: {e}", "WARNING")
            finally:
                if responder_executor:
                    responder_executor.shutdown(wait=False)

        # ── Ethernet cleanup (revert interface if DHCP server was used) ──────────
        self._run_sequential(["EthernetCleanup"], registry)

        # ── Mark instance complete ─────────────────────────────────────────────
        self.ctx.progress.mark_instance_complete(
            self.ctx.subdevice_key, self.ctx.interface,
            self.ctx.instance_key)

    def _run_one(self, mod_name: str, registry: dict[str, type]) -> None:
        cls = registry.get(mod_name)
        if cls is None:
            console.log(f"  [WARN] No implementation for {mod_name}", "WARNING")
            return
        try:
            module = cls(self.ctx)
            module.run()
        except Exception as e:
            console.log(
                f"Module {mod_name} raised unhandled exception: {e}",
                "ERROR")

    def _run_concurrent(self, mod_names: list[str],
                        registry: dict[str, type]) -> None:
        eligible = [m for m in mod_names if not
                    self.ctx.progress.is_module_complete(
                        self.ctx.subdevice_key, self.ctx.interface,
                        self.ctx.instance_key, m)]
        if not eligible:
            return
        with ThreadPoolExecutor(max_workers=_PHASE_SEMAPHORE_COUNT) as pool:
            futures = {}
            for mod_name in eligible:
                cls = registry.get(mod_name)
                if cls is None:
                    continue
                mod = cls(self.ctx)
                if mod.concurrent_safe:
                    futures[pool.submit(mod.run)] = mod_name
                else:
                    self._run_one(mod_name, registry)
            for fut in as_completed(futures):
                _check_pause()
                mod_name = futures[fut]
                try:
                    fut.result()
                except SystemExit:
                    raise
                except Exception as e:
                    console.log(
                        f"Concurrent module {mod_name} failed: {e}",
                        "ERROR")


# ---------------------------------------------------------------------------
# ProjectOrchestrator
# ---------------------------------------------------------------------------

class ProjectOrchestrator:
    """Top-level orchestrator: iterates all instances across all subdevices."""

    def __init__(
        self,
        config:      dict,
        config_path: str,
        project_dir: Path,
        progress:    ProgressManager,
        logger:      GearboxLogger,
        db:          DatabaseManager,
        findings:    FindingManager,
        skip_nessus: bool = False,
        risk_map:    dict = None,
    ) -> None:
        self.config       = config
        self.config_path  = config_path
        self.project_dir  = project_dir
        self.progress     = progress
        self.logger       = logger
        self.db           = db
        self.findings     = findings
        self.skip_nessus  = skip_nessus
        self.risk_map     = risk_map or {}
        self.ip_tracker   = _get_ip_tracker(project_dir)

    def _run_preflight_photos(self, all_instances: list) -> None:
        """Run all photo requirements before module selection.

        Phase 1 — subdevice photos: FRONT / BACK / INTERFACES for every
                   subdevice, matching the virtual _photos_ instances shown
                   in Gauntlet's evidence tab.
        Phase 2 — per-instance photos: PhotoModule for every regular instance
                   whose Photo module is not yet complete.
        """
        # ── Phase 1: subdevice FRONT / BACK / INTERFACES photos ───────────────
        join_interfaces = self.config.get("join_interfaces") or []
        join_url        = join_interfaces[0]["url"] if join_interfaces else ""

        short  = (self.config.get("client_short") or "proj").strip().replace(" ", "_").upper()
        device = (self.config.get("device") or "device").strip().replace(" ", "_").replace("/", "-")

        seen_sds: dict = {}
        for inst in all_instances:
            sd_key = inst["sd_key"]
            if sd_key not in seen_sds:
                seen_sds[sd_key] = {"sd_name": inst["sd_name"], "sd_dir": inst["sd_dir"]}

        for sd_key, info in seen_sds.items():
            sd_name = info["sd_name"]
            sd_dir  = info["sd_dir"]
            if not sd_dir:
                continue
            _SUBDEV_PHOTO_LABELS = {
                "FRONT":        "front view",
                "BACK":         "back view",
                "INTERFACES":   "interface panel",
                "VERSION_INFO": "version / device info screen",
            }
            for photo_type in ("FRONT", "BACK", "INTERFACES", "VERSION_INFO"):
                inst_key    = photo_type.lower()
                module_name = f"PHOTO-{sd_dir}-{photo_type}"
                if self.progress.is_module_complete(sd_key, "_photos_", inst_key, module_name):
                    continue
                photo_dir   = (self.project_dir / short / device
                               / sd_dir / "_Photos" / inst_key / "Photo")
                file_prefix = f"{short}_{device}_{sd_dir}_photos_{inst_key}"
                photo_dir.mkdir(parents=True, exist_ok=True)
                label = _SUBDEV_PHOTO_LABELS.get(photo_type, photo_type.title())
                answer = console.prompt(
                    f"Upload a photo of the {label} of subdevice '{sd_name}'.",
                    prompt_type="file",
                    skippable=True,
                    join_url=join_url,
                    join_interfaces=join_interfaces,
                )
                if answer and answer.lower() not in ("skip", "") and os.path.exists(answer):
                    shutil.copy2(answer, str(photo_dir / f"{file_prefix}_photo_1.jpg"))
                    self.progress.set_module_status(
                        sd_key, "_photos_", inst_key, module_name,
                        "complete", "Photo captured")
                else:
                    self.progress.set_module_status(
                        sd_key, "_photos_", inst_key, module_name,
                        "skipped", "Skipped by user")

        # ── Phase 2: per-instance photos ──────────────────────────────────────
        for inst in all_instances:
            if "Photo" not in INTERFACE_MODULES.get(inst["interface"], []):
                continue
            if self.progress.is_module_complete(
                    inst["sd_key"], inst["interface"], inst["inst_key"], "Photo"):
                continue
            ctx = ModuleContext(
                config         = self.config,
                subdevice_key  = inst["sd_key"],
                subdevice_name = inst["sd_name"],
                interface      = inst["interface"],
                instance_key   = inst["inst_key"],
                instance_loc   = inst["inst_loc"],
                instance_dir   = inst["inst_dir"],
                file_prefix    = inst["file_prefix"],
                db             = self.db,
                findings       = self.findings,
                progress       = self.progress,
                logger         = self.logger,
                ip_tracker     = self.ip_tracker,
                net            = NetworkUtils(self.logger),
                skip_nessus    = self.skip_nessus,
            )
            PhotoModule(ctx).run()

    def _run_postflight_photos(self, all_instances: list) -> None:
        """Collect tool evidence photos and re-prompt for any skipped preflight photos.

        Two categories are collected here:
          TOOL_EVIDENCE — always new (never asked during preflight); photos of the
                          physical test equipment/tools connected to each subdevice
                          as evidence that testing was performed.
          FRONT / BACK / INTERFACES / VERSION_INFO — re-prompted only if they were
                          skipped during the preflight phase.
        """
        # TOOL_EVIDENCE is postflight-only — never asked during preflight.
        # The other types are only collected here if they were skipped earlier.
        _POSTFLIGHT_LABELS = {
            "TOOL_EVIDENCE": "test tools and equipment used during testing",
            "FRONT":         "front view",
            "BACK":          "back view",
            "INTERFACES":    "interface panel",
            "VERSION_INFO":  "version / device info screen",
        }

        join_interfaces = self.config.get("join_interfaces") or []
        join_url        = join_interfaces[0]["url"] if join_interfaces else ""

        short  = (self.config.get("client_short") or "proj").strip().replace(" ", "_").upper()
        device = (self.config.get("device") or "device").strip().replace(" ", "_").replace("/", "-")

        seen_sds: dict = {}
        for inst in all_instances:
            sd_key = inst["sd_key"]
            if sd_key not in seen_sds:
                seen_sds[sd_key] = {"sd_name": inst["sd_name"], "sd_dir": inst["sd_dir"]}

        pending = []
        for sd_key, info in seen_sds.items():
            sd_dir = info["sd_dir"]
            if not sd_dir:
                continue
            for photo_type in _POSTFLIGHT_LABELS:
                inst_key    = photo_type.lower()
                module_name = f"PHOTO-{sd_dir}-{photo_type}"
                status = self.progress.get_module_status(
                    sd_key, "_photos_", inst_key, module_name)
                if status != "complete":
                    pending.append({
                        "sd_key": sd_key, "sd_name": info["sd_name"],
                        "sd_dir": sd_dir, "photo_type": photo_type,
                        "inst_key": inst_key, "module_name": module_name,
                    })

        if not pending:
            return

        console.log(
            f"Final evidence collection: {len(pending)} photo(s) required.",
            "INFO")

        for p in pending:
            sd_key      = p["sd_key"]
            sd_name     = p["sd_name"]
            sd_dir      = p["sd_dir"]
            photo_type  = p["photo_type"]
            inst_key    = p["inst_key"]
            module_name = p["module_name"]
            label       = _POSTFLIGHT_LABELS[photo_type]

            photo_dir   = (self.project_dir / short / device
                           / sd_dir / "_Photos" / inst_key / "Photo")
            file_prefix = f"{short}_{device}_{sd_dir}_photos_{inst_key}"
            photo_dir.mkdir(parents=True, exist_ok=True)

            answer = console.prompt(
                f"[Evidence required — testing complete] "
                f"Upload a photo of the {label} for subdevice '{sd_name}'.",
                prompt_type="file",
                skippable=True,
                join_url=join_url,
                join_interfaces=join_interfaces,
            )
            if answer and answer.lower() not in ("skip", "") and os.path.exists(answer):
                shutil.copy2(answer, str(photo_dir / f"{file_prefix}_photo_1.jpg"))
                self.progress.set_module_status(
                    sd_key, "_photos_", inst_key, module_name,
                    "complete", "Photo captured (postflight)")
            else:
                self.progress.set_module_status(
                    sd_key, "_photos_", inst_key, module_name,
                    "skipped", "Skipped by user (postflight)")

    def run(self) -> None:
        """Main project execution loop."""
        all_instances = self._collect_instances()
        if not all_instances:
            console.log("No instances found in configuration file.", "ERROR")
            return

        console.log(
            f"Project has {len(all_instances)} total instance(s) to test.",
            "INFO")

        # Collect all photo requirements upfront before instance selection
        self._run_preflight_photos(all_instances)

        # Filter to incomplete instances
        remaining = [
            inst for inst in all_instances
            if not self.progress.is_instance_complete(
                inst["sd_key"], inst["interface"], inst["inst_key"])
        ]

        if not remaining:
            console.log("All instances already complete.", "INFO")
        else:
            if len(remaining) < len(all_instances):
                console.log(
                    f"{len(all_instances) - len(remaining)} instance(s) "
                    f"already complete — resuming from checkpoint.",
                    "INFO")

        # Let user choose which instance to run next
        while remaining:
            _check_pause()
            options = [
                f"{r['sd_name']} / {r['interface']} / "
                f"{r['inst_data'].get('name') or r['inst_data'].get('id') or r['inst_key']}"
                for r in remaining
            ]
            options.append("Exit / stop for now")
            options.append("Cancel")

            choice = console.prompt(
                f"Select the next instance to test "
                f"({len(remaining)} remaining):",
                options=options,
                prompt_type="choice",
            )

            # Resolve choice to index
            idx = None
            for i, opt in enumerate(options):
                if choice == str(i + 1) or choice == opt:
                    idx = i
                    break
            if idx is None:
                try:
                    idx = int(choice) - 1
                except Exception:
                    idx = 0

            # "Cancel" — terminate the process cleanly
            cancel_idx = len(options) - 1
            if idx == cancel_idx or (isinstance(choice, str) and
                                     choice.strip().lower() == "cancel"):
                console.log("Cancelled by user — stopping Responder/Nessus and terminating.", "INFO")
                _ethernet_shutdown_cleanup()
                sys.exit(0)

            # "Exit / stop for now" — finish this session but keep progress resumable
            if idx == cancel_idx - 1:
                console.log("Stopping at user request.", "INFO")
                break

            instance = remaining.pop(idx)
            self._run_instance(instance)

        # Collect any outstanding photo evidence now that all testing is complete
        self._run_postflight_photos(all_instances)

    def _run_instance(self, inst: dict) -> None:
        """Build context and run all modules for a single instance."""
        ctx = ModuleContext(
            config         = self.config,
            subdevice_key  = inst["sd_key"],
            subdevice_name = inst["sd_name"],
            interface      = inst["interface"],
            instance_key   = inst["inst_key"],
            instance_loc   = inst["inst_loc"],
            instance_dir   = inst["inst_dir"],
            file_prefix    = inst["file_prefix"],
            db             = self.db,
            findings       = self.findings,
            progress       = self.progress,
            logger         = self.logger,
            ip_tracker     = self.ip_tracker,
            net            = NetworkUtils(self.logger),
            skip_nessus    = self.skip_nessus,
        )
        orch = InstanceOrchestrator(
            ctx, threading.Semaphore(_PHASE_SEMAPHORE_COUNT))
        try:
            orch.run()
        except Exception as e:
            console.log(
                f"Instance {inst['sd_key']}/{inst['interface']}/"
                f"{inst['inst_key']} failed: {e}",
                "ERROR")

    def _collect_instances(self) -> list[dict]:
        """Build a flat list of all instance descriptors from YAML config."""

        # ── Shared path builder ───────────────────────────────────────────────
        def _process_ifaces(ifaces_raw, sd_key, sd_name, sd_dir,
                            out_list, project_dir, short, device, component=""):
            """
            Resolve ifaces_raw → list of instance dicts, appending to out_list.
            sd_dir: cleaned sd_name suitable for use in a filesystem path.
            """
            _STRUCTURAL_KEYS = {"instances", "ports", "connectors",
                                 "id", "name", "location", "loc",
                                 "_component", "description", "notes"}

            # Normalise to {iface_type: iface_data} dict
            if isinstance(ifaces_raw, dict):
                iface_items = list(ifaces_raw.items())
            elif isinstance(ifaces_raw, list):
                iface_items = []
                for entry in ifaces_raw:
                    if isinstance(entry, str):
                        iface_items.append((entry, {}))
                    elif isinstance(entry, dict):
                        itype = entry.get("type") or entry.get("name")
                        if itype:
                            iface_items.append((itype, entry))
                        else:
                            for k, v in entry.items():
                                if k not in ("type", "name", "id", "location"):
                                    iface_items.append((k, v if isinstance(v, (dict, list)) else {}))
            elif isinstance(ifaces_raw, str):
                iface_items = [(ifaces_raw, {})]
            else:
                return

            console.log(
                f"  Subdevice '{sd_name}': interface types: "
                f"{[i for i, _ in iface_items]}", "DEBUG")

            for interface, iface_data in iface_items:
                # ── Locate instances ──────────────────────────────────────────
                if isinstance(iface_data, dict):
                    inst_list = (iface_data.get("instances")
                                 or iface_data.get("ports")
                                 or iface_data.get("connectors"))
                    if inst_list is None:
                        if any(k in iface_data for k in
                               ("id", "name", "location", "loc")):
                            inst_list = [iface_data]
                        else:
                            non_struct = {k: v for k, v in iface_data.items()
                                          if k not in _STRUCTURAL_KEYS}
                            if non_struct:
                                inst_list = []
                                for iname, idata in non_struct.items():
                                    entry = dict(idata) if isinstance(idata, dict) else {}
                                    entry.setdefault("name", iname)
                                    entry.setdefault("location", iname)
                                    inst_list.append(entry)
                            else:
                                inst_list = [{}]
                elif isinstance(iface_data, list):
                    inst_list = iface_data
                elif iface_data is None:
                    inst_list = [{}]
                else:
                    inst_list = [{}]

                for inst_dict in inst_list:
                    if isinstance(inst_dict, str):
                        inst_dict = {"location": inst_dict}
                    if not isinstance(inst_dict, dict):
                        inst_dict = {}

                    inst_key = (
                        inst_dict.get("id") or
                        inst_dict.get("name") or
                        inst_dict.get("location") or
                        inst_dict.get("loc") or
                        f"inst{len(out_list)+1}"
                    )
                    inst_key = str(inst_key).lower().replace(" ", "_")
                    inst_loc = (inst_dict.get("location") or
                                inst_dict.get("loc") or inst_key)

                    # Build directory path — matches app.py _instance_dir:
                    # project_dir / CLIENT_SHORT / device / sd_dir / interface / inst_key
                    if sd_dir:
                        inst_dir    = project_dir / short / device / sd_dir / interface / inst_key
                        file_prefix = f"{short}_{device}_{sd_dir}_{interface}_{inst_key}"
                    else:
                        inst_dir    = project_dir / short / device / interface / inst_key
                        file_prefix = f"{short}_{device}_{interface}_{inst_key}"
                    inst_dir.mkdir(parents=True, exist_ok=True)

                    out_list.append({
                        "sd_key":      sd_key,
                        "sd_name":     sd_name,
                        "sd_dir":      sd_dir,
                        "interface":   interface,
                        "inst_key":    inst_key,
                        "inst_loc":    inst_loc,
                        "inst_dir":    inst_dir,
                        "file_prefix": file_prefix,
                        "inst_data":   inst_dict,
                    })

        # ─────────────────────────────────────────────────────────────────────

        instances = []
        # Match app.py's path structure exactly:
        #   project_dir / CLIENT_SHORT / device / sd_name / interface / inst_key
        short  = (self.config.get("client_short") or "proj").strip().replace(" ", "_").upper()
        device = (self.config.get("device") or "device").strip().replace(" ", "_").replace("/", "-")

        # ── Log the raw config keys so layout is visible in the console ──────
        console.log(
            f"Config top-level keys: {list(self.config.keys())}", "DEBUG")

        # ── Locate the subdevices list ────────────────────────────────────────
        # Try every common nesting pattern
        def _find_subdevices(cfg: dict) -> list:
            raw = cfg.get("subdevices") or cfg.get("device", {})
            if not raw:
                return []

            # subdevices: [{name: X, interfaces: {...}}, ...]  — list of dicts
            if isinstance(raw, list):
                return raw

            # subdevices: {central_unit: {...}, hand_unit: {...}}  — name-keyed dict
            if isinstance(raw, dict):
                # If any value is a dict that itself contains known interface keys
                # or an 'interfaces' key, treat each top-level key as a subdevice name
                known_ifaces = set(INTERFACE_MODULES.keys())
                result = []
                for sd_name, sd_body in raw.items():
                    if isinstance(sd_body, dict):
                        entry = dict(sd_body)
                        entry.setdefault("name", sd_name)
                        result.append(entry)
                    else:
                        result.append({"name": sd_name})
                return result

            return []

        # Check inside 'proj' wrapper first, then top-level
        if "proj" in self.config and isinstance(self.config["proj"], dict):
            subdevices = _find_subdevices(self.config["proj"])
            if not subdevices:
                # Maybe interfaces are directly under proj
                subdevices = [self.config["proj"]]
        else:
            subdevices = _find_subdevices(self.config)

        # Last resort: if there are known interface-type keys at top level,
        # treat the whole config as a single unnamed subdevice
        if not subdevices:
            known_ifaces = set(INTERFACE_MODULES.keys())
            if any(k in known_ifaces for k in self.config):
                subdevices = [self.config]
                console.log(
                    "No 'subdevices' key found — treating top-level config "
                    "as a single subdevice.", "DEBUG")

        console.log(f"Subdevices found: {len(subdevices)}", "DEBUG")

        for sd in subdevices:
            # Tolerate bare strings
            if isinstance(sd, str):
                sd = {"name": sd}
            if not isinstance(sd, dict):
                console.log(f"Skipping non-dict subdevice entry: {sd!r}", "DEBUG")
                continue

            sd_key  = sd.get("name", "unknown").lower().replace(" ", "_")
            sd_name = sd.get("name", "Unknown")

            # ── Locate interfaces ─────────────────────────────────────────────
            interfaces_raw = sd.get("interfaces") or sd.get("interface")

            if interfaces_raw is None:
                known_ifaces = set(INTERFACE_MODULES.keys())
                direct = {k: v for k, v in sd.items() if k in known_ifaces}
                if direct:
                    interfaces_raw = direct
                else:
                    # Keys may be component names whose values contain interface keys.
                    # Each component is treated as its own named sub-subdevice,
                    # giving it its own directory path.
                    skip_keys = {"name", "id", "description", "location",
                                 "model", "serial", "firmware"}
                    components = {}  # comp_key -> {itype: idata}
                    for comp_key, comp_val in sd.items():
                        if comp_key in skip_keys:
                            continue
                        if isinstance(comp_val, dict):
                            comp_ifaces = {k: v for k, v in comp_val.items()
                                           if k in known_ifaces}
                            if comp_ifaces:
                                components[comp_key] = comp_ifaces
                    if components:
                        # Recurse: process each component as its own subdevice
                        for comp_key, comp_ifaces in components.items():
                            comp_sd_name = comp_key.replace("_", " ").title()
                            comp_sd_key  = comp_key.lower().replace(" ", "_")
                            comp_sd_dir  = comp_sd_name.strip().replace(" ", "_").replace("/", "-")
                            _process_ifaces(
                                comp_ifaces, comp_sd_key, comp_sd_name, comp_sd_dir,
                                instances, self.project_dir, short, device,
                                comp_key,
                            )
                        continue   # handled via _process_ifaces
                    else:
                        console.log(
                            f"Subdevice '{sd_name}' has no 'interfaces' key — "
                            f"keys present: {list(sd.keys())}", "DEBUG")
                        continue

            # ── interfaces_raw is resolved — delegate to helper ───────────────
            sd_dir = sd_name.strip().replace(" ", "_").replace("/", "-") if sd_name else ""
            console.log(
                f"  Subdevice '{sd_name}' (dir={sd_dir}): "
                f"interfaces type={type(interfaces_raw).__name__}", "DEBUG")
            _process_ifaces(
                interfaces_raw, sd_key, sd_name, sd_dir,
                instances, self.project_dir, short, device,
            )

        console.log(f"Total instances collected: {len(instances)}", "DEBUG")
        for inst in instances:
            console.log(
                f"  {inst['sd_name']} / {inst['interface']} / "
                f"{inst['inst_key']} @ {inst['inst_loc']}  →  {inst['inst_dir']}",
                "DEBUG")

        return instances


# ---------------------------------------------------------------------------
# load_risk_map
# ---------------------------------------------------------------------------

def load_risk_map(path: str) -> dict[str, str]:
    """Load a CSV file mapping finding titles to risk levels."""
    risk_map: dict[str, str] = {}
    if not path or not os.path.exists(path):
        return risk_map
    try:
        with open(path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                title = row.get("finding_title") or row.get("title", "")
                risk  = row.get("risk", "Unknown")
                if title:
                    risk_map[title.strip().lower()] = risk.strip()
    except Exception as e:
        console.log(f"Could not load risk map from {path}: {e}", "WARNING")
    return risk_map


# ---------------------------------------------------------------------------
# check_environment
# ---------------------------------------------------------------------------

def check_environment(skip_nessus: bool = False) -> bool:
    """
    Load Nessus credentials from ~/.config/gearbox/config.yaml.
    If the file does not exist or credentials are absent, prompt the user,
    then save to config.yaml with the password encrypted via Fernet.
    Always returns True — missing creds disable Nessus rather than halting.
    """
    if skip_nessus:
        return True

    user, pwd = NessusConfig.load()

    if user and pwd:
        console.log(
            f"Nessus credentials loaded from {NessusConfig._CONFIG_FILE}.",
            "INFO")
        os.environ["nessus_user"] = user
        os.environ["nessus_pass"] = pwd
        return True

    # Config file absent or incomplete — prompt and save
    console.log(
        f"Nessus credentials not found in {NessusConfig._CONFIG_FILE}. "
        "Prompting for input.",
        "WARNING")
    user = console.prompt(
        "Enter Nessus username (or type 'skip' to disable Nessus for this run):",
        prompt_type="text",
        skippable=True,
    )
    if not user or user.lower() == "skip":
        return True

    pwd = console.prompt(
        "Enter Nessus password:",
        prompt_type="password",
    )
    if not pwd:
        return True

    # Persist for future runs
    NessusConfig.save(user, pwd)
    os.environ["nessus_user"] = user
    os.environ["nessus_pass"] = pwd
    return True


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------

def _update_tools() -> None:
    """
    Update security tool definitions at gearbox startup.
    Runs non-interactively; failures are warnings only — never block execution.
    """
    console.log("Updating tool definitions before scan…", "INFO")

    # nuclei — update templates (runs whether nuclei was pre-installed or just installed)
    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin and tool_available("nuclei"):
        nuclei_bin = "nuclei"
    if nuclei_bin:
        console.log("  Updating nuclei templates…", "INFO")
        try:
            result = subprocess.run(
                [nuclei_bin, "-update-templates", "-duc"],
                capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                console.log("  nuclei templates updated.", "INFO")
            else:
                # -update-templates may exit non-zero if already up to date
                out = (result.stdout + result.stderr).strip()
                console.log(f"  nuclei template update: {out[:120] or 'already up to date'}",
                            "INFO")
        except subprocess.TimeoutExpired:
            console.log("  nuclei template update timed out (180s) — continuing.",
                        "WARNING")
        except Exception as e:
            console.log(f"  nuclei template update skipped: {e}", "WARNING")
    else:
        console.log("  nuclei not found — templates will be updated after install.", "INFO")

    # nmap — update scripts db
    if tool_available("nmap"):
        console.log("  Updating nmap script database…", "INFO")
        try:
            subprocess.run(
                ["nmap", "--script-updatedb"],
                capture_output=True, text=True, timeout=60)
            console.log("  nmap script db updated.", "INFO")
        except Exception as e:
            console.log(f"  nmap script update skipped: {e}", "WARNING")

    # testssl.sh — git pull if cloned
    testssl_clone = Path.home() / "testssl.sh"
    if testssl_clone.is_dir() and shutil.which("git"):
        console.log("  Updating testssl.sh via git pull…", "INFO")
        try:
            subprocess.run(
                ["git", "pull", "--ff-only"],
                capture_output=True, text=True, timeout=60,
                cwd=str(testssl_clone))
            console.log("  testssl.sh updated.", "INFO")
        except Exception as e:
            console.log(f"  testssl.sh update skipped: {e}", "WARNING")

    # bettercap — update caplets
    bettercap_bin = shutil.which("bettercap")
    if bettercap_bin:
        console.log("  Updating bettercap caplets…", "INFO")
        try:
            subprocess.run(
                [bettercap_bin, "-eval", "caplets.update; quit"],
                capture_output=True, text=True, timeout=120)
            console.log("  bettercap caplets updated.", "INFO")
        except subprocess.TimeoutExpired:
            console.log("  bettercap caplets update timed out (120s) — continuing.",
                        "WARNING")
        except Exception as e:
            console.log(f"  bettercap caplets update skipped: {e}", "WARNING")

    console.log("Tool update complete.", "INFO")



    parser = argparse.ArgumentParser(
        prog="gearbox",
        description="GearBox — Device Security Assessment Orchestration Tool",
    )
    parser.add_argument(
        "config",
        metavar="CONFIG_YAML",
        help="Path to the project YAML configuration file",
    )
    parser.add_argument(
        "--skip-nessus",
        action="store_true",
        default=False,
        help="Skip Nessus vulnerability scanning for this run",
    )
    parser.add_argument(
        "--risk-map",
        metavar="CSV",
        default="",
        help="Optional CSV file mapping finding titles to risk levels",
    )
    parser.add_argument(
        "--project-dir",
        metavar="DIR",
        default="",
        help="Override the project output directory (default: <config_stem>_output/)",
    )
    parser.add_argument(
        "--interface",
        metavar="IFACE",
        default="",
        help="Network interface to use for scanning (overrides test_interface in YAML)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume from saved progress (default: auto-detect from progress file)",
    )
    parser.add_argument(
        "--join-url",
        metavar="URL",
        default="",
        help="(legacy) Single LAN join URL — use --join-interfaces instead",
    )
    parser.add_argument(
        "--join-interfaces",
        metavar="JSON",
        default="",
        help='JSON array [{name,ip,url}] of all interfaces — passed by the Flask app',
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gearbox",
        description="GearBox — Device Security Assessment Orchestration Tool",
    )
    parser.add_argument(
        "config",
        metavar="CONFIG_YAML",
        help="Path to the project YAML configuration file",
    )
    parser.add_argument(
        "--skip-nessus",
        action="store_true",
        default=False,
        help="Skip Nessus vulnerability scanning for this run",
    )
    parser.add_argument(
        "--risk-map",
        metavar="CSV",
        default="",
        help="Optional CSV file mapping finding titles to risk levels",
    )
    parser.add_argument(
        "--project-dir",
        metavar="DIR",
        default="",
        help="Override the project output directory (default: directory of CONFIG_YAML)",
    )
    parser.add_argument(
        "--interface",
        metavar="IFACE",
        default="",
        help="Network interface to use for scanning (overrides test_interface in YAML)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume from saved progress (default: auto-detect from progress file)",
    )
    parser.add_argument(
        "--join-url",
        metavar="URL",
        default="",
        help="(legacy) Single LAN join URL — use --join-interfaces instead",
    )
    parser.add_argument(
        "--join-interfaces",
        metavar="JSON",
        default="",
        help='JSON array [{name,ip,url}] of all interfaces — passed by the Flask app',
    )
    parser.add_argument(
        "--nessus-user",
        metavar="USER",
        default="",
        help="Nessus username — injected into os.environ at startup",
    )
    parser.add_argument(
        "--nessus-pass",
        metavar="PASS",
        default="",
        help="Nessus password — injected into os.environ at startup",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Inject Nessus credentials from CLI args into os.environ FIRST — before
    # check_environment() or any module runs.  This bypasses sudo's env_reset
    # entirely: app.py passes them as --nessus-user / --nessus-pass arguments
    # so they never need to cross the sudo environment boundary.
    if args.nessus_user:
        os.environ["nessus_user"] = args.nessus_user
        os.environ["NESSUS_USER"] = args.nessus_user
    if args.nessus_pass:
        os.environ["nessus_pass"] = args.nessus_pass
        os.environ["NESSUS_PASS"] = args.nessus_pass

    # ----- Load YAML config ------------------------------------------------
    config_path = args.config
    if not os.path.exists(config_path):
        console.log(f"FATAL: Config file not found: {config_path}", "ERROR")
        sys.exit(1)
    try:
        _load_optional_imports()
        if yaml is None:
            console.log("FATAL: PyYAML is required but not installed.", "ERROR")
            sys.exit(1)
        with open(config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        console.log(f"FATAL: Failed to parse YAML config: {e}", "ERROR")
        sys.exit(1)

    # Inject CLI overrides into config
    if args.interface:
        config["test_interface"] = args.interface
    if args.join_url:
        config["join_url"] = args.join_url
    if args.join_interfaces:
        try:
            config["join_interfaces"] = json.loads(args.join_interfaces)
        except Exception:
            pass
    # Fall back: build interfaces list from join_url if --join-interfaces wasn't given
    if not config.get("join_interfaces") and config.get("join_url"):
        config["join_interfaces"] = [{"name": "eth0", "ip": "", "url": config["join_url"]}]
    if not config.get("join_interfaces"):
        flask_port = 5700
        config["join_interfaces"] = [
            {"name": iface["name"], "ip": iface["ip"],
             "url": f"https://{iface['ip']}:{flask_port}/join/{config.get('project_id', '')}"}
            for iface in get_all_interfaces()
        ]

    # ----- Project directory -----------------------------------------------
    # Priority:
    #   1. Explicit --project-dir CLI arg
    #   2. Structured path from YAML config fields client_short + start_date
    #   3. Fallback: clients_base / YAML filename stem
    if args.project_dir:
        project_dir = Path(args.project_dir).resolve()
    else:
        _cs = (config.get("client_short") or "").strip()
        _sd = (config.get("start_date") or "").strip()
        if _cs:
            project_dir = _build_project_dir(_cs, _sd, "gearbox")
        else:
            project_dir = _clients_base() / Path(config_path).resolve().stem
            project_dir.mkdir(parents=True, exist_ok=True)
    _write_project_meta(
        project_dir,
        tool="gearbox",
        client_short=(config.get("client_short") or ""),
        year=((config.get("start_date") or "")[:4] or datetime.now().strftime("%Y")),
        version=VERSION,
    )
    # Dual-write universal meta.json (schema 1.0) for Prometheus UniversalParser.
    _u_dual_write_meta(
        project_dir,
        tool="gearbox", version=VERSION,
        client_short=(config.get("client_short") or ""),
        client_name=(config.get("client_name") or ""),
        engagement_name=(config.get("engagement_name") or ""),
        target=(config.get("targets") or config.get("target") or
                ", ".join(sd.get("name", "?") if isinstance(sd, dict) else str(sd)
                          for sd in (config.get("subdevices") or []))[:200]),
    )
    # §13b/§14j/§14k: bring up the on-disk audit log now that the run dir exists.
    console.attach_run_dir(project_dir)
    console.log(f"Project output directory: {project_dir}", "INFO")

    # Expose local IP for QR / join URL generation
    local_ip = get_local_ip()
    config.setdefault("local_ip", local_ip)
    if local_ip and local_ip != "127.0.0.1":
        console.log(f"Local IP: {local_ip}", "INFO")

    # ----- Pre-flight checks -----------------------------------------------
    # Collect all interface types needed
    interfaces_in_scope: list[str] = []
    for sd in (config.get("subdevices") or
               config.get("proj", {}).get("subdevices", []) or []):
        if isinstance(sd, str):
            continue  # bare string subdevice name — no interfaces to enumerate
        ifaces = sd.get("interfaces", {})
        if isinstance(ifaces, dict):
            interfaces_in_scope.extend(ifaces.keys())
        elif isinstance(ifaces, list):
            interfaces_in_scope.extend(ifaces)

    console.start()

    if not check_and_install_packages():
        console.log("FATAL: Required package installation failed.", "ERROR")
        sys.exit(1)
    _load_optional_imports()

    if not check_and_install_tools(list(set(interfaces_in_scope))):
        console.log("FATAL: Required tool installation failed.", "ERROR")
        sys.exit(1)

    # Ensure Go toolchain is available before update/scan (needed for nuclei, gowitness)
    _go_avail, _go_bin = _ensure_go()
    if _go_avail:
        console.log(f"Go toolchain: {_go_bin}", "INFO")
        # Make sure GOPATH/bin is in PATH so go-installed tools are found
        _gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
        _gobin  = os.path.join(_gopath, "bin")
        if _gobin not in os.environ.get("PATH", "").split(os.pathsep):
            os.environ["PATH"] = _gobin + os.pathsep + os.environ["PATH"]
    else:
        console.log("Go toolchain not available — go-based tools (nuclei, gowitness) "
                    "will be skipped.", "WARNING")

    _update_tools()

    check_environment(skip_nessus=args.skip_nessus)
    _start_oom_watchdog()

    # ----- Risk map --------------------------------------------------------
    risk_map     = load_risk_map(args.risk_map)
    if risk_map:
        _RISK_MAP.update(risk_map)

    # ----- Shared services -------------------------------------------------
    stem          = Path(config_path).stem
    progress_file = str(project_dir / "progress.json")
    db_path       = str(project_dir / f"{stem}.db")

    db       = DatabaseManager(db_path)
    progress = ProgressManager(progress_file)

    # ----- Pause manager init -------------------------------------------------
    global _pause
    if PauseManager is not None:
        _pause = PauseManager(project_dir, "gearbox")
        _pause.start_watcher(
            checkpoint_callback=progress._save,
            grace_period=30,
        )
        prev_stop = _pause.read_stop_reason()
        if prev_stop.get("action") in ("paused_user", "paused_engagement_hours",
                                        "paused_scheduled", "paused_crucible"):
            _pause.cleanup_incomplete()
            console.log(f"Gearbox RESUMED from checkpoint (prev: {prev_stop.get('action')})", "INFO")
        else:
            console.log(f"Gearbox started (NEW RUN) — pause manager active", "INFO")

    # GearboxLogger needs a context — use a stub for the top-level logger
    _stub_ctx = type("_Stub", (), {
        "subdevice_key": "project",
        "interface":     "all",
        "instance_key":  "main",
        "findings":      None,
    })()
    logger   = GearboxLogger(_stub_ctx)  # type: ignore
    findings = FindingManager(db, config_path)

    # ----- Signal handler for clean shutdown --------------------------------
    def _sighandler(sig, frame):
        console.log("\nInterrupted — stopping Responder/Nessus and exiting.", "INFO")
        _ethernet_shutdown_cleanup()
        if _pause:
            _pause.write_stop_reason("killed_user", detail="SIGINT/SIGTERM")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    # ----- Run project ------------------------------------------------------
    orchestrator = ProjectOrchestrator(
        config       = config,
        config_path  = config_path,
        project_dir  = project_dir,
        progress     = progress,
        logger       = logger,
        db           = db,
        findings     = findings,
        skip_nessus  = args.skip_nessus,
        risk_map     = risk_map,
    )
    orchestrator.run()

    if _pause:
        _pause.write_stop_reason("completed", "all_instances_done")

    # Synthesise universal findings.json + summary.json from findings.jsonl.
    _u_synthesize_outputs(project_dir, tool="gearbox", version=VERSION,
                           config=config)

    console.log("GearBox run complete.", "INFO")


def _u_synthesize_outputs(project_dir, *, tool: str, version: str,
                          config: dict) -> None:
    """Read findings.jsonl, emit universal findings.json + summary.json."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return
    try:
        from pathlib import Path as _P
        jsonl = _P(project_dir) / "findings.jsonl"
        if not jsonl.exists():
            return
        raw_findings = []
        for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            # Map Gearbox native schema to universal field names.
            mapped = dict(obj)
            if "affected_host" in mapped and not mapped.get("ip"):
                mapped["ip"] = mapped.pop("affected_host")
            if "affected_port" in mapped and not mapped.get("port"):
                try:
                    mapped["port"] = int(mapped.pop("affected_port") or 0)
                except (ValueError, TypeError):
                    mapped["port"] = 0
            if "severity" in mapped and not mapped.get("risk"):
                mapped["risk"] = mapped.pop("severity")
            mapped.setdefault("sources", "gearbox")
            mapped.setdefault("description", mapped.get("title", ""))
            mapped.setdefault("remediation", "See module documentation for remediation guidance.")
            # v1.1 enrichment — Gearbox knows these natively in its Finding
            # dataclass; bubble them up rather than dropping them on the floor.
            #   classification, subdevice, interface, instance — already in
            #   the source dict if present, just keep them as-is (they're
            #   v1.1 optional fields so they pass through).
            # cvss_score: ensure float type when present
            if "cvss_score" in mapped:
                try:
                    mapped["cvss_score"] = float(mapped["cvss_score"]) if mapped["cvss_score"] else None
                except (ValueError, TypeError):
                    mapped["cvss_score"] = None
            # cve_ids (list) → cves (comma-string) for v1.1 baseline compat,
            # but keep the list around too via cve_examples
            if isinstance(mapped.get("cve_ids"), list) and not mapped.get("cves"):
                mapped["cves"] = ",".join(mapped["cve_ids"])
            # tools_used list → source_tools (v1.1 catalogue lineage field)
            if isinstance(mapped.get("tools_used"), list):
                mapped["source_tools"] = mapped["tools_used"]
            raw_findings.append(mapped)

        # G2 fix (2026-06-11 review): pr0t31n_schema.make_finding uppercases
        # "Informational" → "INFORMATIONAL" which is NOT in RISK_LEVELS, so
        # findings.json carried off-enum risk values and summary.json INFO
        # count was always 0. Fold every "Informational" / "INFORMATIONAL"
        # → "INFO" BEFORE the universal write so both consumers see the
        # canonical value.
        def _gb_canon_risk(r):
            rs = str(r or "").strip()
            ru = rs.upper()
            if ru in ("INFORMATIONAL", "INFO", "INFORMATION"): return "INFO"
            if ru in ("CRITICAL","HIGH","MEDIUM","LOW"): return ru
            if rs in ("Critical","High","Medium","Low","Informational"):
                return {"Critical":"CRITICAL","High":"HIGH","Medium":"MEDIUM",
                        "Low":"LOW","Informational":"INFO"}[rs]
            return "INFO"
        for f in raw_findings:
            f["risk"] = _gb_canon_risk(f.get("risk"))

        n = _us.write_universal_findings(
            project_dir, raw_findings,
            tool=tool, scope=None, phase="",
        )

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in raw_findings:
            r = _gb_canon_risk(f.get("risk"))
            if r in risk_counts:
                risk_counts[r] += 1
        from datetime import datetime as _dt, timezone as _tz
        now = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _us.write_summary(project_dir, _us.make_summary(
            tool=tool, version=version,
            scan_start=now, scan_end=now,
            target=(config.get("targets") or config.get("target") or ""),
            success=True, total_findings=n, risk_counts=risk_counts,
        ))
    except Exception as e:
        try:
            console.log(f"universal output synthesis failed: {e}", "WARNING")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()