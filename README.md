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
netifaces
```

### Setup

```bash
git clone https://github.com/CobblePot59/flask-evil-ssdp.git
cd flask-evil-ssdp
pip install -r requirements.txt
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
lands in on the victim's machine — in Windows Explorer's **Network** view, a
`Printer:1` shows up under *Printers* while an `InternetGatewayDevice:1` shows up
under *Network Infrastructure*. Pick the one that matches the story your
`friendlyName` tells. 

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
| Printer | `urn:schemas-upnp-org:device:Printer:1` | Printers |
| Scanner | `urn:schemas-upnp-org:device:Scanner:1` | Printers |
| Camera | `urn:schemas-upnp-org:device:DigitalSecurityCamera:1` | Other Devices |
| Light | `urn:schemas-upnp-org:device:BinaryLight:1` | Other Devices |
| Dimmable light | `urn:schemas-upnp-org:device:DimmableLight:1` | Other Devices |

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

## References

- [Valerchk - O365 Phishing Page](https://github.com/Valerchk/Microsoft-Page-tester)
