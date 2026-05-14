#!/usr/bin/env python3
# =============================================================================
# GearBox — Device Security Assessment Orchestration Tool
# =============================================================================
# Usage:
#   Standalone : python3 gearbox.py <project.yaml> [options]
#   Flask mode : launched automatically by app.py
# =============================================================================

from __future__ import annotations

VERSION = "1.3.1"

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
]

# ---------------------------------------------------------------------------
# Interface → Module mapping
# ---------------------------------------------------------------------------
INTERFACE_MODULES: dict[str, list[str]] = {
    "Ethernet":     ["Photo", "EthernetIface", "Ethtool", "ConfigDiscovery",
                     "TrafficCollector", "DhcpServer", "NmapLive", "Nessus", "Responder",
                     "NmapPort", "BannerGrab", "Web", "Nuclei", "SSL", "SSH", "FTP", "SMB", "NFS",
                     "EthernetCleanup"],
    "USB":          ["Photo", "UsbPower", "Keyboard", "KeyCombos", "Mouse", "BashBunny"],
    "Ethernet_tap": ["Photo", "Tcpdump_running", "Tcpdump_boot", "Tcpdump_shutdown"],
    "HDMI":         ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC", "HdmiHDCP", "HdmiCEC"],
    "Dvi":          ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC"],
    "sdi":          ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC", "HdmiHDCP", "HdmiCEC"],
    "Dp":           ["Photo", "PortType", "Input", "Output", "EDID", "HdmiDDC", "HdmiHDCP", "HdmiCEC"],
    "Rca":          ["Photo", "Input", "Output"],
    "Aux":          ["Photo", "Input", "Output"],
    "Zigbee":       ["Photo", "Sniff", "Flood"],
    "DB9":          ["Photo", "SerialDetect", "CanAssess"],
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

    def start(self) -> None:
        """Initialise the display. Call once at script start."""
        if not self._tty:
            console.log(f"GearBox v{VERSION} — starting in subprocess mode", "INFO")
            return
        self._render_banner()

    def log(self, message: str, level: str = "INFO") -> None:
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
    "Web Server Version Disclosure":         "Header Data Leakage: Server",
    "Web — Server Version Disclosure":       "Header Data Leakage: Server",
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

    def set_static_ip(self, interface: str, ip: str, prefix: int,
                      gateway: str, ctx: ModuleContext) -> bool:
        """
        Configure a static IP via netplan. Backs up existing config.
        Stores working config in project directory.
        """
        config_file = self.NETPLAN_DIR / f"99-gearbox-{interface}.yaml"
        backup_file = config_file.with_suffix(self.NETPLAN_BACKUP_SUFFIX)
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
                ctx.db.store_network_config(ip, gateway, f"{ip}/{prefix}", "", str(config_file), ctx)
                self._logger.info(f"Static IP {ip}/{prefix} configured via netplan")
                return True
        except Exception as e:
            self._logger.error(f"set_static_ip failed: {e}")
        return False

    def revert_netplan(self, interface: str) -> None:
        """Restore netplan configuration from backup."""
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
    """
    cmd_str  = " ".join(cmd)
    ctx.logger.cmd(cmd, tool=tool_name)
    # Log tool version on first use (cached after first call)
    if tool_name:
        _tv = get_tool_version(tool_name)
        if _tv:
            ctx.logger.info(f"{tool_name} version: {_tv}", tool=tool_name)

    proc_env = {**os.environ, **(env or {})}
    _subproc_sem.acquire()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=proc_env,
        )
        stdout  = result.stdout or ""
        stderr  = result.stderr or ""

        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(str(output_file), "w", encoding="utf-8") as f:
                f.write(stdout)
                if stderr:
                    f.write("\n--- STDERR ---\n")
                    f.write(stderr)

        return result.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        ctx.logger.warn(f"{tool_name} timed out after {timeout}s", tool=tool_name)
        return -1, "", f"{tool_name} timed out"
    except FileNotFoundError:
        return -1, "", f"{tool_name} not found"
    except Exception as e:
        ctx.logger.error(f"{tool_name} execution failed: {e}", exc=e, tool=tool_name)
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
                    flask_port = 5000
                    project_id = self.ctx.config.get("project_id", "")
                    join_interfaces = [
                        {"name": iface["name"], "ip": iface["ip"],
                         "url": f"http://{iface['ip']}:{flask_port}/join/{project_id}"}
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
                return

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
            )
            self.ctx.config["_dhcp_proc_pid"] = proc.pid

            self.ctx.logger.info(
                f"dnsmasq started (pid={proc.pid}); waiting up to "
                f"{self._LEASE_WAIT_S}s for DHCP leases…", tool="dnsmasq")

            # ── Wait for lease(s) ─────────────────────────────────────────────
            waited    = 0
            leased_ips: list = []
            while waited < self._LEASE_WAIT_S:
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
                )
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

    def _probe_port(self, ip: str, port: int) -> Optional[str]:
        """Quick HTTP probe — returns URL if port responds to HTTP or HTTPS."""
        for scheme in ("https", "http"):
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
                            title="Header Data Leakage: Server",
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
                            source_type="primary", force_risk="High",
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
                        source_type="primary", force_risk="Medium",
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
            if "password" in content.lower() and "ssh-auth-methods" in content.lower():
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title="SSH Weak Configuration (Ciphers / Legacy Protocol / Credential Auth)",
                    description="The SSH service is configured with one or more weaknesses including weak ciphers/MACs, SSHv1 support, permitted root login, or password-based authentication, increasing exposure to brute-force and protocol-level attacks.",
                    remediation="Harden sshd_config to disable SSHv1, restrict ciphers and MACs to strong algorithms, disable root login, disable password authentication, and require public-key authentication only.",
                    tool="nmap-ssh",
                    raw_output=content[:500],
                    source_type="primary",
                    force_risk="Medium",
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
                force_risk="Medium",
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
                force_risk="Medium",
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
                force_risk="Medium",
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
            (r'forward.secrecy|PFS',             "No Forward Secrecy",                              ""),
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
            title=f"NFS Enumeration — {ip}",
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
            answer = self._prompt(
                f"Connect a USB power measurement device to the USB port: "
                f"[{self.ctx.instance_loc}]. Record the voltage and current readings below.",
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
            answer = self._prompt(
                f"Connect a USB keyboard to [{self.ctx.instance_loc}]. "
                f"Test if keystrokes are registered. Was HID keyboard detected?",
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
            answer = self._prompt(
                f"Test the following key combinations on [{self.ctx.instance_loc}]:\n"
                + "\n".join(f"  • {c}" for c in combos)
                + "\n  Which combinations produced a result?",
                prompt_type="text", skippable=True)
            out_dir = self.ctx.instance_dir / "KeyCombos"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{self.ctx.file_prefix}_keycombos.txt").write_text(
                f"Effective combos: {answer}\n")
            if answer and answer.lower() not in ("skip", "none", ""):
                self.ctx.findings.create(
                    ctx=self.ctx,
                    title=f"Keyboard Shortcut Access — {self.ctx.instance_key}",
                    description=f"Key combinations produced responses: {answer}",
                    tool="manual", raw_output=answer,
                    source_type="primary", force_risk="Medium",
                    ip="",
                    output_file="",
                )
            self._mark_complete("KeyCombos tested")
        except Exception as e:
            self._mark_error(str(e))


class MouseModule(BaseModule):
    name        = "Mouse"
    description = "Test USB HID Mouse functionality"

    def run(self) -> None:
        self._mark_running()
        try:
            answer = self._prompt(
                f"Connect a USB mouse to [{self.ctx.instance_loc}]. "
                f"Was HID mouse detected and functional?",
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
            answer = self._prompt(
                f"Insert a Bash Bunny (or HID attack device) into "
                f"[{self.ctx.instance_loc}]. Was the device accepted / did payloads execute?",
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
                return

            answer = self._prompt(
                f"Connect a video source to the {iface} INPUT port "
                f"[{self.ctx.instance_loc}]. Was the input signal detected and accepted?",
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
                return

            answer = self._prompt(
                f"Connect a video display/sink to the {iface} OUTPUT port "
                f"[{self.ctx.instance_loc}]. Was an output signal detected or displayed?",
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
            r = subprocess.run(["get-edid"], capture_output=True, timeout=15)
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
            r = subprocess.run(
                ["edid-decode", str(bin_path)],
                capture_output=True, text=True, timeout=15)
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
            r = subprocess.run(
                ["cec-client", "-l"],
                capture_output=True, text=True, timeout=10)
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

            reader.join(timeout=5)

        except Exception as e:
            self.ctx.logger.warn(f"CEC session error: {e}", tool="cec-client")
            if proc:
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
                return

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
                title=f"CEC Devices Enumerated — {self.ctx.instance_key}",
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
            answer = self._prompt(
                f"Connect a Zigbee sniffer dongle (e.g., ApiMote, RZUSBSTICK, CC2531). "
                f"Testing port: [{self.ctx.instance_loc}]. Press Enter to begin capture.",
                options=["Ready"], prompt_type="choice")
            out_dir = self.ctx.instance_dir / "Sniff"
            out_dir.mkdir(parents=True, exist_ok=True)
            # Zigbee capture tooling will be added in a future release.
            with open(str(out_dir / f"{self.ctx.file_prefix}_zigbee_note.txt"), "w") as f:
                f.write(
                    "Zigbee capture tool not yet configured.\n"
                    "Install an appropriate Zigbee testing tool and re-run.\n")
            self._mark_complete("Zigbee sniff placeholder — tool TBD")
        except Exception as e:
            self._mark_error(str(e))


class ZigbeeFloodModule(BaseModule):
    name        = "Flood"
    description = "Test Zigbee network resilience against flooding attacks"

    def run(self) -> None:
        self._mark_running()
        try:
            ans = self._prompt(
                f"Perform a Zigbee flood test against [{self.ctx.instance_loc}]. "
                f"Use an appropriate Zigbee testing tool. "
                f"Did the device respond abnormally?",
                options=["Yes — abnormal response / crash", "No — unaffected", "Skip"],
                prompt_type="choice", skippable=True)
            out_dir = self.ctx.instance_dir / "Flood"
            out_dir.mkdir(parents=True, exist_ok=True)
            with open(str(out_dir / f"{self.ctx.file_prefix}_zigbee_flood_note.txt"), "w") as f:
                f.write("Zigbee flood tool not yet configured. "
                        "Results recorded from manual observation.\n")
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
            return

        if not _CD_AVAILABLE:
            self._mark_skipped("can_detect unavailable")
            return

        # ── Step 10: locate CAN interface (3 attempts) ───────────────────────
        iface = None
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

class RFIDSniffModule(BaseModule):
    name        = "RFIDSniff"
    description = "Capture RFID/NFC card data using Proxmark or similar"

    def run(self) -> None:
        self._mark_running()
        try:
            out_dir = self.ctx.instance_dir / "RFIDSniff"
            out_dir.mkdir(parents=True, exist_ok=True)
            answer = self._prompt(
                f"Connect Proxmark3 (or similar) RFID reader near port "
                f"[{self.ctx.instance_loc}]. Place test RFID card in range. "
                f"Press Enter to begin.",
                options=["Ready", "Skip"], prompt_type="choice", skippable=True)
            if "skip" in answer.lower() or answer == "2":
                self._mark_skipped("Skipped by user")
                return

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
            else:
                out_file.write_text(
                    "proxmark3 (pm3) not available. RFID sniff requires Proxmark3 hardware.\n")
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
    "SerialDetect":     SerialDetectModule,
    "CanAssess":        CanAssessModule,
    "RFIDSniff":        RFIDSniffModule,
    "RFIDReplay":       RFIDReplayModule,
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
        self._run_sequential(["NmapPort"], registry)

        # ── Phase 2: concurrent assessment modules ───────────────────────────
        # Runs after NmapPort is fully complete. Every module in phase2_concurrent
        # has a _source_module_done("NmapPort") loop — on entry here that returns
        # True immediately so they proceed to assess all discovered hosts/ports.
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
                mod_name = futures[fut]
                try:
                    fut.result()
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

    def run(self) -> None:
        """Main project execution loop."""
        all_instances = self._collect_instances()
        if not all_instances:
            console.log("No instances found in configuration file.", "ERROR")
            return

        console.log(
            f"Project has {len(all_instances)} total instance(s) to test.",
            "INFO")

        # Filter to incomplete instances
        remaining = [
            inst for inst in all_instances
            if not self.progress.is_instance_complete(
                inst["sd_key"], inst["interface"], inst["inst_key"])
        ]

        if not remaining:
            console.log("All instances already complete.", "INFO")
            return

        if len(remaining) < len(all_instances):
            console.log(
                f"{len(all_instances) - len(remaining)} instance(s) "
                f"already complete — resuming from checkpoint.",
                "INFO")

        # Let user choose which instance to run next
        while remaining:
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
        flask_port = 5000
        config["join_interfaces"] = [
            {"name": iface["name"], "ip": iface["ip"],
             "url": f"http://{iface['ip']}:{flask_port}/join/{config.get('project_id', '')}"}
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

    console.log("GearBox run complete.", "INFO")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()