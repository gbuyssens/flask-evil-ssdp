#!/usr/bin/env python3
"""Offline unit tests for the packet builders / parsers in app.py.

No root, sockets or third-party deps required: flask is stubbed and the
listener message builders are exercised on instances created without binding.
Run with:  python3 tests/test_app.py
"""
import os
import sys
import types
import socket
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Stub flask so `import app` needs no third-party dependency.
_fl = types.ModuleType('flask')
for _nm in ('Flask', 'render_template_string', 'request', 'redirect', 'abort', 'send_from_directory'):
    setattr(_fl, _nm, object)
sys.modules['flask'] = _fl

sys.path.insert(0, ROOT)
import app  # noqa: E402

IP = '10.0.0.5'


class FakeSock:
    def __init__(self):
        self.sent = []

    def sendto(self, b, a):
        self.sent.append((b, a))


def enc16(name):
    n = (name.upper() + ' ' * 15)[:15] + '\x00'
    out = b''
    for ch in n:
        c = ord(ch)
        out += bytes([0x41 + (c >> 4), 0x41 + (c & 0xf)])
    return out


def test_dns_helpers():
    q = b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x04wpad\x00' + b'\x00\x01\x00\x01'
    assert app.dns_qname(q, 12) == 'wpad'
    assert app.dns_qname_end(q, 12) == 18
    assert app.dns_encode_name('foo.local') == b'\x03foo\x05local\x00'


def test_netbios_decode():
    e = enc16('WPAD')
    assert len(e) == 32 and app.netbios_decode(e) == 'WPAD'


def test_ssdp_notify():
    s = object.__new__(app.SSDPListener)
    s.local_ip, s.local_port = IP, 8888
    s.templates_config = [{'name': 'scanner', 'session_usn': 'uuid:abcd',
                           'device_type': 'urn:schemas-upnp-org:device:Scanner:1'}]
    s.sock = FakeSock()
    s._notify('ssdp:alive')
    blob = b''.join(b for b, a in s.sock.sent)
    assert b'NOTIFY * HTTP/1.1' in blob and b'NTS: ssdp:alive' in blob
    assert b'LOCATION: http://10.0.0.5:8888/ssdp/0/device-desc.xml' in blob
    assert b'USN: uuid:abcd::upnp:rootdevice' in blob
    assert b'USN: uuid:abcd\r\n' in blob
    assert b'USN: uuid:abcd::urn:schemas-upnp-org:device:Scanner:1' in blob
    s.sock = FakeSock()
    s._notify('ssdp:byebye')
    assert b'NTS: ssdp:byebye' in b''.join(b for b, a in s.sock.sent)


def test_llmnr():
    q = b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x04wpad\x00' + b'\x00\x01\x00\x01'
    l = object.__new__(app.LLMNRListener)
    l.local_ip, l.analyze, l.respond_to = IP, False, None
    l.sock = FakeSock()
    l.process_packet(q, ('10.0.0.9', 5355))
    assert l.sock.sent, 'no LLMNR reply'
    r = l.sock.sent[0][0]
    assert r[0:2] == b'\x12\x34' and r[6:8] == b'\x00\x01'
    assert b'\xc0\x0c' in r and socket.inet_aton(IP) in r
    # allowlist should suppress non-matching names
    l.sock = FakeSock()
    l.respond_to = {'other'}
    l.process_packet(q, ('10.0.0.9', 5355))
    assert not l.sock.sent, 'respond_to filter failed'


def test_mdns():
    m = object.__new__(app.MDNSListener)
    m.local_ip, m.analyze, m.respond_to = IP, False, None
    m.sock = FakeSock()
    mq = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x08wpad-foo\x05local\x00' + b'\x00\x01\x00\x01'
    m.process_packet(mq, ('10.0.0.9', 5353))
    assert m.sock.sent
    r = m.sock.sent[0][0]
    assert r[2:4] == b'\x84\x00' and socket.inet_aton(IP) in r


def test_nbtns():
    nb = (b'\xAB\xCD\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00'
          + b'\x20' + enc16('WPAD') + b'\x00' + b'\x00\x20\x00\x01')
    assert len(nb) == 50
    n = object.__new__(app.NBTNSListener)
    n.local_ip, n.analyze, n.respond_to = IP, False, None
    n.sock = FakeSock()
    n.process_packet(nb, ('10.0.0.9', 137))
    assert n.sock.sent
    r = n.sock.sent[0][0]
    assert r[0:2] == b'\xAB\xCD' and r[6:8] == b'\x00\x01'
    assert b'\x00\x20\x00\x01' in r and socket.inet_aton(IP) in r


def test_wsd_envelopes():
    cfg = {'name': 'scanner', 'session_usn': 'uuid:dead-beef', 'local_ip': IP, 'local_port': 8888,
           'device_type': 'urn:schemas-upnp-org:device:Scanner:1', 'device_friendly': 'Corporate Scanner',
           'device_manufacturer': 'Xerox', 'device_model': 'SM5000'}
    for doc in (app.wsd_build_hello(cfg, 0), app.wsd_build_hello(cfg, 0, bye=True),
                app.wsd_build_match(cfg, 0, 'urn:uuid:req'),
                app.wsd_build_match(cfg, 0, 'urn:uuid:req', resolve=True),
                app.wsd_build_metadata(cfg, 'urn:uuid:req')):
        ET.fromstring(doc)  # raises on malformed XML
    assert app.wsd_epr(cfg) == 'urn:uuid:dead-beef'
    assert b'http://10.0.0.5:8888/wsd/0/metadata.xml' in app.wsd_build_match(cfg, 0, 'x')
    assert app.wsd_extract_msgid(b'<a:MessageID>urn:uuid:xyz</a:MessageID>') == 'urn:uuid:xyz'


def test_parse_device_meta():
    meta = app.parse_device_meta(os.path.join(ROOT, 'templates', 'scanner', 'device.xml'))
    assert meta['device_type'] == 'urn:schemas-upnp-org:device:Scanner:1'
    assert meta['device_friendly'].startswith('Corporate Scanner')


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_') and callable(v)]
    for t in tests:
        t()
        print(f"[ok] {t.__name__}")
    print(f"\nALL {len(tests)} TESTS PASSED")


if __name__ == '__main__':
    main()
