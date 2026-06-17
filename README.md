# Gearbox

**Device security assessment orchestrator** — multi-interface hardware testing from photo capture through Nessus vulnerability scanning, in a single structured pipeline.

Gearbox automates security assessments of physical devices across Ethernet, USB, HDMI, serial, RFID, Zigbee, and CAN bus interfaces. It reads a YAML project file defining device subcomponents and interface instances, then runs a phased pipeline of 40+ testing modules against each instance: network discovery and DHCP server setup, Nessus scanning, LLMNR/NBT-NS poisoning, per-host port scanning, banner grabbing, TLS/SSL analysis, SSH hardening, SMB enumeration, web vulnerability scanning, and interface-specific hardware tests. All findings are deduplicated, CVE-enriched, and written to structured JSONL and SQLite output. When launched by [Gauntlet](../gauntlet/), Gearbox switches to protocol token mode for live streaming to the web UI.

---

## Features

- **Multi-interface pipeline** — Ethernet, USB, HDMI, Serial/CAN, RFID, Zigbee, and network tap interfaces each get their own module set
- **Per-instance orchestration** — YAML defines subdevices, interfaces, and individual port instances; each instance runs the full pipeline independently with its own output directory and findings context
- **Background parallelism** — Nessus and Responder run as background threads through phases 1 and 2; per-host service checks (SSL, SSH, SMB, web, NFS, FTP, banner grab) run concurrently (6 workers)
- **Checkpoint resume** — `progress.json` tracks every completed module; `--resume` skips already-finished work across sessions
- **CVE enrichment** — banner and version strings looked up against NVD and OSV.dev; CVSS score mapped to risk level automatically
- **Finding deduplication** — composite key `(instance, title, ip, port)` deduplicates across tools; overlapping findings merge `output_files`, `tools_used`, and `cve_ids`
- **Nessus API integration** — launches, polls, and cleanly stops local Nessus scans; credentials stored encrypted via Fernet
- **Network self-configuration** — writes a `192.168.4.x/24` DHCP server on the test interface using dnsmasq + netplan; reverts to original config on exit
- **Graceful shutdown** — SIGINT/SIGTERM stops Responder, stops running Nessus scan via API, reverts interface, and saves checkpoint before exit
- **Gauntlet integration** — `SPECTRE_MANAGED` / subprocess mode emits typed protocol tokens; TTY mode prints coloured human-readable output
- **Tool auto-install** — detects missing tools and offers to install via apt/brew/go/git at startup; Go toolchain bootstrapped automatically if absent

---

## Requirements

### Python
- Python 3.9+
- `pyyaml` — required (YAML config parsing)
- `requests` — recommended (Nessus API, NVD/OSV CVE lookups)
- `qrcode[pil]` — recommended (QR codes for photo upload prompts)
- `pyserial` — optional (DB9 serial auto-detection)
- `cryptography` — optional (Fernet encryption for Nessus password; falls back to base64)

```bash
pip install pyyaml requests "qrcode[pil]" pyserial cryptography
```

### External tools

Required:

| Tool | Purpose | Install |
|------|---------|---------|
| `nmap` | Host discovery + port scanning | `apt install nmap` / `brew install nmap` |
| `tcpdump` | Packet capture | `apt install tcpdump` / `brew install tcpdump` |
| `ethtool` | Link status detection | `apt install ethtool` / build from source (macOS) |

Recommended:

| Tool | Purpose | Install |
|------|---------|---------|
| `sslscan` | TLS cipher + certificate analysis | `apt install sslscan` |
| `testssl.sh` | Comprehensive TLS testing | `apt install testssl.sh` / git clone |
| `nuclei` | Template-based vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `gowitness` | Web screenshots | `go install github.com/sensepost/gowitness/v3/cmd/gowitness@latest` |
| `ssh-audit` | SSH algorithm enumeration | `apt install ssh-audit` |
| `responder` | LLMNR/NBT-NS credential capture | `apt install responder` |
| `dnsmasq` | DHCP server for test interface | `apt install dnsmasq` |
| `smbmap` | SMB share enumeration | `apt install smbmap` |

Optional (interface-specific):

| Tool | Interface | Install |
|------|-----------|---------|
| `cec-client` | HDMI CEC | `apt install cec-utils` |
| `ddcutil` | HDMI DDC-CI | `apt install ddcutil` |
| `get-edid`, `edid-decode` | HDMI EDID | `apt install read-edid edid-decode` |
| `candump`, `cansend`, `canplayer` | CAN bus | `apt install can-utils` |
| `minicom` | Serial | `apt install minicom` |
| `proxmark3` (`pm3`) | RFID/NFC | Build from source |

Go 1.18+ is required for nuclei and gowitness. Gearbox will detect and offer to install it automatically.

---

## Installation

No installation required. Run directly:

```bash
git clone https://github.com/yourorg/gearbox
cd gearbox
pip install pyyaml requests "qrcode[pil]"
sudo python3 gearbox.py project.yaml
```

Missing Python packages and system tools are detected at startup and offered for auto-install.

---

## Usage

```bash
# Basic run — prompts for interface, photo, and Nessus credentials interactively
sudo python3 gearbox.py project.yaml

# Skip Nessus scanning
sudo python3 gearbox.py project.yaml --skip-nessus

# Resume a previous session from checkpoint
sudo python3 gearbox.py project.yaml --resume

# Specify interface and output directory
sudo python3 gearbox.py project.yaml --interface eth1 --project-dir /opt/assessments/client_2026

# Pass Nessus credentials directly (used by Gauntlet)
sudo python3 gearbox.py project.yaml --nessus-user admin --nessus-pass secret

# Apply custom risk level overrides from a CSV
sudo python3 gearbox.py project.yaml --risk-map overrides.csv
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `config` | *(required)* | Path to YAML project configuration file |
| `--skip-nessus` | off | Disable Nessus vulnerability scanning |
| `--resume` | off | Resume from `progress.json` checkpoint |
| `--project-dir DIR` | YAML parent directory | Override output directory for all findings |
| `--interface IFACE` | auto / prompts user | Network interface to use for Ethernet testing |
| `--nessus-user USER` | from `~/.config/gearbox/config.yaml` | Nessus username |
| `--nessus-pass PASS` | from `~/.config/gearbox/config.yaml` | Nessus password |
| `--risk-map FILE` | none | CSV mapping finding titles to risk levels |
| `--join-interfaces JSON` | none | JSON array of `{name, ip, url}` objects for photo QR codes (set by Gauntlet) |

---

## Project YAML Format

Gearbox accepts four YAML structures — all are auto-detected:

```yaml
# Multiple subdevices with named interface instances
client_short: ACME           # used in output path (default: proj)
device: "Industrial PLC"     # device name

subdevices:
  cpu_board:
    name: "CPU Board"
    interfaces:
      Ethernet:
        instances:
          - id: eth_primary
            location: "RJ45 Port 1"
          - id: eth_secondary
            location: "RJ45 Port 2"
      USB:
        instances:
          - id: usb_a
            location: "USB-A Front Panel"

  io_module:
    name: "I/O Module"
    interfaces:
      Ethernet:
        instances:
          - location: "Management Port"
      Serial:
        instances:
          - location: "DB9 Console Port"
```

Supported interface types: `Ethernet`, `USB`, `HDMI`, `Serial`, `Zigbee`, `RFID`, `Ethernet_tap`

Each instance gets its own output directory, findings database, and module completion state.

---

## Testing Modules

### Ethernet

| Module | Phase | Description | Tools |
|--------|-------|-------------|-------|
| **Photo** | 0 | Photo capture prompt (QR/join URL for mobile upload) | qrcode |
| **EthernetIface** | 0 | Detect/select test network interface | ip, ethtool |
| **Ethtool** | 0 | Verify physical link carrier signal | ethtool |
| **ConfigDiscovery** | 1 | Passive ARP/DHCP/DNS sniff to identify network config | tcpdump |
| **TrafficCollector** | 1 | Background packet capture throughout assessment | tcpdump |
| **DhcpServer** | 1 | Stand up 192.168.4.x/24 DHCP server on test interface | dnsmasq, netplan |
| **NmapLive** | 1 | Ping sweep + ARP scan to discover live hosts | nmap |
| **Nessus** | 1 (bg) | Authenticated vulnerability scan via local Nessus API | Nessus Professional |
| **Responder** | 1 (bg) | LLMNR/NBT-NS poisoning for credential capture | responder |
| **NmapPort** | 2 | TCP/UDP port scan + service/version detection per host | nmap |
| **BannerGrab** | 2 | TCP socket banner collection on all open ports | socket, curl |
| **Web** | 2 | HTTP/HTTPS screenshots, directory enumeration, template scanning | gowitness, nuclei, curl |
| **Nuclei** | 2 | ProjectDiscovery template-based CVE/misconfiguration scanning | nuclei |
| **SSL** | 2 | TLS cipher suite, certificate chain, and protocol analysis | sslscan, testssl.sh, openssl |
| **SSH** | 2 | SSH banner, algorithm enumeration, weak cipher detection | ssh-audit |
| **SMB** | 2 | SMB signing, null session, anonymous share enumeration | smbmap, nmap |
| **NFS** | 2 | NFS export enumeration, world-writable mount detection | showmount |
| **FTP** | 2 | Anonymous FTP, version banner, deprecated auth checks | nmap, ftp |
| **EthernetCleanup** | 3 | Revert interface to DHCP client, restore netplan config | dhclient, netplan |

### USB

| Module | Description | Tools |
|--------|-------------|-------|
| **Photo** | Photo capture of USB port | qrcode |
| **UsbPower** | Measure USB power draw; detect rogue peripheral indicators | usbmon |
| **Keyboard** | HID keyboard injection; test debounce and rate-limiting | hid-tools |
| **KeyCombos** | Attempt predefined key sequences (Ctrl+C, Ctrl+Alt+Del, etc.) | hid-tools |
| **Mouse** | HID mouse movement injection; test authentication bypass | hid-tools |
| **BashBunny** | Deploy Bash Bunny HID payload; document execution results | bash-bunny |

### HDMI

| Module | Description | Tools |
|--------|-------------|-------|
| **Photo** | Photo capture of HDMI port | qrcode |
| **PortType** | Detect HDMI variant (1.4/2.0/2.1, DVI, DisplayPort, SDI) | v4l2-ctl |
| **Input** | EDID reads + input availability | get-edid |
| **Output** | Detect available video outputs; DDC-CI availability | ddcutil |
| **EDID** | Extract and analyse Extended Display Identification Data | get-edid, edid-decode |
| **HdmiDDC** | DDC-CI monitor control (brightness/contrast/OSD); test unauthorized control | ddcutil |
| **HdmiHDCP** | HDCP version detection and copy-protection bypass assessment | v4l2-ctl |
| **HdmiCEC** | HDMI CEC command injection; test device control via CEC bus | cec-client |

### Serial / CAN

| Module | Description | Tools |
|--------|-------------|-------|
| **Photo** | Photo capture of serial port | qrcode |
| **SerialDetect** | Auto-detect serial port and bitrate | pyserial, minicom |
| **CanAssess** | CAN bus frame capture, heartbeat detection, replay attack | candump, cansend, canplayer |

### RFID

| Module | Description | Tools |
|--------|-------------|-------|
| **Photo** | Photo capture of RFID reader | qrcode |
| **RFIDSniff** | Capture RFID/NFC card data (HF search, LF read) | proxmark3 (pm3) |
| **RFIDReplay** | Replay captured credentials; test reader authentication | proxmark3 (pm3) |

### Zigbee

| Module | Description | Tools |
|--------|-------------|-------|
| **Photo** | Photo capture of Zigbee antenna/port | qrcode |
| **Sniff** | Capture Zigbee frames (requires hardware sniffer) | wireshark, scapy |
| **Flood** | Zigbee packet injection and flooding | scapy |

### Network Tap (`Ethernet_tap`)

| Module | Description | Tools |
|--------|-------------|-------|
| **Tcpdump_running** | Capture packets during active testing | tcpdump |
| **Tcpdump_boot** | Capture device bootup traffic sequence | tcpdump |
| **Tcpdump_shutdown** | Capture device shutdown/power-down traffic | tcpdump |

---

## Execution Pipeline

```
Phase 0 — Setup (sequential)
  Photo → EthernetIface → Ethtool

Phase 1 — Discovery (sequential)
  ConfigDiscovery → TrafficCollector → DhcpServer → NmapLive
       ↓ (after live hosts found)
  Nessus ──────────────────────────────────────────── (background thread, up to 3h)
  Responder ───────────────────────────────────────── (background thread, until Phase 2 done)

Phase 2 — Assessment (NmapPort sequential, then 6 concurrent workers)
  NmapPort → [BannerGrab, Web, Nuclei, SSL, SSH, SMB, NFS, FTP]

Phase 3 — Cleanup (sequential)
  Wait for Nessus → signal Responder stop → EthernetCleanup
```

**Conditional execution:**
- Nessus only runs if live hosts are found, credentials are available, and `--skip-nessus` is not set
- Responder is kept alive until both Nessus and Phase 2 complete, maximising credential capture window
- Service modules (SSL, SSH, SMB, etc.) auto-mark as N/A if no relevant ports are found
- All instances run sequentially; the user is prompted to proceed to each next instance

---

## Output Structure

```
<project_dir>/
├── meta.json                              ← tool identity + version (§13b)
├── scan.log / scan.log.json               ← timestamped audit log: own version +
│                                             phase EVENTs + all messages (§13b/§14j/§14k)
├── errors.log / errors.log.json           ← ERROR-level + TOOL_ERROR entries
└── CLIENT_SHORT/
    └── device/
        └── <subdevice>/
            └── <Interface>/
                └── <instance>/
                    ├── findings.jsonl              ← security findings (one JSON per line)
                    ├── findings.db                 ← SQLite database
                    ├── progress.json               ← module checkpoint state
                    ├── summary.json                ← curl commands + screenshot refs
                    ├── observed_ranges.txt         ← discovered /24 CIDR ranges
                    ├── observed_ips.csv            ← discovered IP:port inventory
                    ├── *_photo.jpg                 ← interface photo
                    ├── *_nmap_live.xml             ← host discovery results
                    ├── *_nmap_port_<ip>.xml        ← per-host port scan
                    ├── *_nessus.nessus             ← Nessus export file
                    ├── *_responder.txt             ← captured credentials
                    ├── *_tcpdump.pcap              ← packet capture
                    ├── *_ssl_<ip>_<port>.txt       ← TLS analysis
                    ├── *_ssh_<ip>.txt              ← SSH audit
                    ├── *_banner_<ip>_<port>.txt    ← service banners
                    ├── *_nuclei.txt                ← nuclei findings
                    ├── *_web_<ip>_<port>.txt       ← web vulnerability output
                    ├── *_smb_<ip>.txt              ← SMB enumeration
                    ├── Web/screenshots/            ← gowitness PNG screenshots
                    └── *_netplan.yaml              ← network config backup
```

### `findings.jsonl` schema

```json
{
  "id":                 "uuid",
  "title":              "SSH: Weak MAC Algorithm Enabled",
  "description":        "The SSH server accepts hmac-md5...",
  "risk":               "High",
  "classification":     "Confirmed",
  "subdevice":          "cpu_board",
  "interface":          "Ethernet",
  "instance":           "eth_primary",
  "ip":                 "192.168.4.52",
  "port":               "22",
  "cve_ids":            ["CVE-2023-38408"],
  "cvss_score":         9.8,
  "affected_component": "OpenSSH",
  "affected_version":   "8.2p1",
  "remediation":        "Disable hmac-md5 in sshd_config",
  "tools_used":         ["ssh-audit"],
  "commands_used":      ["ssh-audit 192.168.4.52"],
  "output_file":        "/path/to/ssh_192.168.4.52.txt",
  "output_files":       ["/path/to/ssh_192.168.4.52.txt"],
  "affected":           [],
  "timestamp":          "2026-04-06T09:14:22"
}
```

Risk values: `Critical`, `High`, `Medium`, `Low`, `Informational`, `Unknown`
Classification values: `Unconfirmed`, `Confirmed`, `Validated`

### `progress.json` schema

```json
{
  "version": 1,
  "started": "2026-04-06T09:00:00",
  "completed_instances": ["cpu_board.Ethernet.eth_primary"],
  "module_status": {
    "cpu_board.Ethernet.eth_primary.NmapPort": {
      "status": "complete",
      "detail": "Found 6 open ports on 192.168.4.52",
      "timestamp": "2026-04-06T09:22:10"
    }
  }
}
```

Module status values: `complete`, `running`, `error`, `skipped`, `pending`, `waiting`, `na`

---

## Finding Deduplication & Risk Resolution

**Deduplication key:** `instance::title_lowercased::ip::port`

When a duplicate key is detected:
- `output_files` and `tools_used` are merged into the existing finding
- Cross-tool findings for the same `ip:port` with similar titles are merged
- Post-create rules apply: CVE title normalisation, LFI false-positive filtering, acronym uppercasing

**Risk resolution priority:**
1. Hardcoded patterns (e.g., `telnet` → Critical, `anonymous FTP` → High)
2. User-supplied `--risk-map` CSV overrides
3. Tool-provided risk (e.g., nuclei severity tag)
4. NVD CVSS score mapping (≥9.0 Critical, ≥7.0 High, ≥5.0 Medium, <5.0 Low)
5. Default: `Unknown`

---

## Nessus Integration

Gearbox integrates with a locally installed Nessus Professional instance at `https://127.0.0.1:8834`.

**Credential storage** (`~/.config/gearbox/config.yaml`):
```yaml
nessus:
  username: "admin"
  password_enc: "gAAAAABl..."   # Fernet-encrypted; key at ~/.config/gearbox/.nessus_key
```

Credentials can also be passed via `--nessus-user` / `--nessus-pass` CLI flags (used by Gauntlet to avoid sudo environment stripping) or via `NESSUS_USER` / `NESSUS_PASS` environment variables.

**Scan lifecycle:**
1. Target CIDR derived from discovered live hosts after NmapLive
2. Scan launched via POST `/scans/{template_uuid}/launch`
3. Status polled via GET `/scans/{scan_id}` every 30 seconds (up to 3-hour ceiling)
4. Findings extracted and converted to Gearbox finding objects with CVE IDs and CVSS scores
5. On SIGINT/SIGTERM: POST `/scans/{scan_id}/stop` called before exit

---

## Gauntlet Protocol

When launched by [Gauntlet](../gauntlet/) as a subprocess, Gearbox emits structured tokens to stdout. All other output (raw console logs) is passed through as plain text.

| Token | Payload | Purpose |
|-------|---------|---------|
| `__GB_LOG__:` | `[LEVEL] message` | Log line forwarded to Gauntlet console buffer |
| `__GB_STATUS__:` | JSON | Module progress update for Gauntlet Evidence tab |
| `__GB_FINDING__:` | JSON finding object | New finding emitted in real time |
| `__GB_PROMPT__:` | JSON prompt descriptor | Interactive prompt (renders modal in UI) |
| `__GB_OBSERVATION__:` | JSON | Informational observation (non-finding) |

### `__GB_STATUS__` payload

```json
{
  "subdevice":  "cpu_board",
  "interface":  "Ethernet",
  "instance":   "eth_primary",
  "module":     "SSL",
  "status":     "running",
  "detail":     "Scanning 192.168.4.52:443"
}
```

### `__GB_PROMPT__` payload

```json
{
  "id":        "uuid",
  "question":  "Select the test interface:",
  "type":      "choice",
  "options":   ["eth0", "eth1", "eth2"],
  "skippable": false
}
```

Prompt responses are written back to gearbox's stdin by Gauntlet after the user answers the modal dialog.

---

## Network Setup and Cleanup

**Setup (DhcpServer module):**
1. Backs up existing netplan configuration files to `.gb_backup` copies
2. Writes `/etc/netplan/99-gearbox-<iface>.yaml` with static IP `192.168.4.1/24`
3. Runs `netplan apply`
4. Launches dnsmasq with DHCP range `192.168.4.50–192.168.4.254`

**Cleanup (EthernetCleanup module + SIGINT/SIGTERM handler):**
1. Terminates dnsmasq
2. Flushes all IPs: `ip addr flush dev <iface>`
3. Requests a fresh DHCP lease: `dhclient <iface>`
4. Removes gearbox netplan file, restores backups
5. Runs `netplan apply`

Cleanup is guaranteed on clean exit, SIGINT, SIGTERM, and via the `atexit` handler. The `cleanup.py` utility can also be run independently to force cleanup of any orphaned processes.

---

## `cleanup.py`

Standalone utility for cleaning up after an interrupted session. Can be invoked directly or via Gauntlet's `/api/system_cleanup` endpoint.

```bash
sudo python3 cleanup.py
```

Performs:
- Terminates any running `gearbox.py` process (SIGTERM → SIGKILL)
- Terminates any running `responder` process
- Stops all running Nessus scans via API (reads and decrypts stored credentials)
- Reverts the `test_direct` interface from DHCP-server mode back to DHCP client

Returns a structured results dict indicating success/failure for each action.

---

## Cross-Platform Notes

| Feature | Linux / Kali | macOS |
|---------|-------------|-------|
| Full Ethernet pipeline | ✓ | ✓ (limited netplan) |
| DHCP server (dnsmasq) | ✓ | Partial |
| Responder | ✓ | ✗ |
| HDMI CEC | ✓ | ✗ |
| DDC-CI (HDMI) | ✓ (`/dev/i2c-*`) | ✓ (IORegistry) |
| CAN bus | ✓ | ✗ |
| USB enumeration | ✓ (`lsusb`) | ✓ (`system_profiler`) |
| Tool install | apt → go → git → pip | brew → go → git → pip |

Kali Linux is the primary target platform. On Kali, most tools are available via `apt` and the tool auto-installer prefers Kali repositories.

---

## Project Structure

```
gearbox/
├── gearbox.py     Main orchestrator (13,000+ lines)
│                  ├── Module classes (40+ testing modules)
│                  ├── ProjectOrchestrator / InstanceOrchestrator
│                  ├── FindingManager (dedup, CVE enrichment, JSONL/SQLite)
│                  ├── NessusModule (API integration)
│                  ├── NetworkManager (dnsmasq, netplan, iptables)
│                  ├── GearboxConsole (TTY + protocol token output)
│                  └── Tool installer (apt/brew/go/git)
└── cleanup.py     Emergency cleanup utility (800 lines)
                   ├── Process termination (gearbox, responder)
                   ├── Nessus scan stopper (self-contained API client)
                   └── Interface revert (dhclient, netplan)
```

---

## Contributors

Gearbox integrates the following open-source tools and Python libraries. Credit to their authors:

### Python Libraries

| Library | Author / Maintainer | Link |
|---------|-------------------|------|
| **PyYAML** | Kirill Simonov & PyYAML team | https://pyyaml.org |
| **requests** | Python Requests / Kenneth Reitz | https://docs.python-requests.org |
| **qrcode** | Lincoln Loop | https://github.com/lincolnloop/python-qrcode |
| **Pillow** | Pillow contributors (fork of PIL by Fredrik Lundh) | https://github.com/python-pillow/Pillow |
| **pyserial** | Chris Liechti | https://github.com/pyserial/pyserial |
| **cryptography** | PyCA team | https://cryptography.io |

### External Tools

| Tool | Author / Maintainer | Link |
|------|-------------------|------|
| **nmap** | Gordon Lyon @Fyodor | https://nmap.org |
| **Nessus** | Tenable Inc. | https://www.tenable.com |
| **sslscan** | rbsec | https://github.com/rbsec/sslscan |
| **testssl.sh** | Dirk Wetter @drwetter | https://github.com/drwetter/testssl.sh |
| **nuclei** | ProjectDiscovery @projectdiscovery | https://github.com/projectdiscovery/nuclei |
| **gowitness** | SensePost @sensepost | https://github.com/sensepost/gowitness |
| **ssh-audit** | Joe Testa @jtesta | https://github.com/jtesta/ssh-audit |
| **Responder** | Laurent Gaffié @lgandx | https://github.com/lgandx/Responder |
| **smbmap** | ShawnDEvans | https://github.com/ShawnDEvans/smbmap |
| **shcheck** | santoru | https://github.com/santoru/shcheck |
| **tcpdump / libpcap** | tcpdump team | https://www.tcpdump.org |
| **dnsmasq** | Simon Kelley | https://www.thekelleys.org.uk/dnsmasq |
| **curl** | Daniel Stenberg @bagder | https://curl.se |
| **OpenSSL** | OpenSSL project | https://openssl.org |
| **ethtool** | Jeff Garzik & kernel.org / sigma-1 | https://github.com/sigma-1/ethtool |
| **proxmark3 / pm3** | RfidResearchGroup | https://github.com/RfidResearchGroup/proxmark3 |
| **cec-client** | Pulse-Eight | https://github.com/Pulse-Eight/libcec |
| **ddcutil** | Sanford Rockowitz | https://www.ddcutil.com |
| **get-edid / read-edid** | Matthew Kern / read-edid project | https://github.com/groeck/read-edid |
| **edid-decode** | Hans Verkuil | https://git.linuxtv.org/edid-decode.git |
| **can-utils** (candump, cansend, canplayer) | SocketCAN / linux-can team | https://github.com/linux-can/can-utils |
| **minicom** | Miquel van Smoorenburg / Adam Lackorzynski | https://salsa.debian.org/minicom-team/minicom |
