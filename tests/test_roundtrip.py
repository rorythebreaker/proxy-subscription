"""Offline XHTTP/TLS integration: real Xray server/client, trusted HTTPS, DoH and speed."""
import base64
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, StreamEnded
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import subscription as c
import update_protocols as u
from incy import profile
from vless import canonical
from test_vless import xhttp


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def handle(self):
        if self.connection.selected_alpn_protocol() != 'h2':
            return super().handle()
        conn = H2Connection(config=H2Configuration(client_side=False))
        conn.initiate_connection()
        self.connection.sendall(conn.data_to_send())
        queries = {}
        while True:
            data = self.connection.recv(65535)
            if not data: return
            for event in conn.receive_data(data):
                if isinstance(event, DataReceived):
                    queries.setdefault(event.stream_id, bytearray()).extend(event.data)
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    body = self.dns_answer(bytes(queries.pop(event.stream_id)))
                    conn.send_headers(event.stream_id, [(':status', '200'), ('content-type', 'application/dns-message'), ('content-length', str(len(body)))])
                    conn.send_data(event.stream_id, body, end_stream=True)
            self.connection.sendall(conn.data_to_send())
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == '/generate_204':
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
        elif path.path == '/__down':
            self.respond(b'x' * int(parse_qs(path.query)['bytes'][0]), 'application/octet-stream')
        elif path.path == '/dns-query':
            query = parse_qs(path.query)['dns'][0]
            self.dns(base64.urlsafe_b64decode(query + '=' * (-len(query) % 4)))
        else:
            self.send_error(404)
    def do_POST(self):
        query = self.rfile.read(int(self.headers['Content-Length']))
        self.dns(query)
    def dns(self, query):
        self.respond(self.dns_answer(query), 'application/dns-message')
    def dns_answer(self, query):
        end = 12
        while query[end]: end += query[end] + 1
        question = query[12:end + 5]
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x08\x08\x08\x08'
        return query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + answer
    def respond(self, body, mime):
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(shutil.which('xray') and shutil.which('openssl'), 'Xray/openssl not installed')
class Roundtrip(unittest.TestCase):
    def test_full_profile_reaches_https_dns_and_measured_speed_through_xhttp_tls(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', str(key), '-out', str(cert), '-subj', '/CN=example.org',
                '-addext', 'subjectAltName=DNS:example.org,DNS:www.gstatic.com,DNS:cp.cloudflare.com,DNS:cloudflare-dns.com,DNS:speed.cloudflare.com'], check=True, capture_output=True)
            app = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            context.set_alpn_protocols(['http/1.1'])
            doh_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            doh_context.load_cert_chain(cert, key)
            doh_context.set_alpn_protocols(['h2'])
            def select_context(sock, name, initial):
                if name == 'cloudflare-dns.com': sock.context = doh_context
            context.set_servername_callback(select_context)
            app.socket = context.wrap_socket(app.socket, server_side=True)
            thread = threading.Thread(target=app.serve_forever, daemon=True)
            thread.start()
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                server_port = s.getsockname()[1]
            server = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': server_port,
                'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': [{'id': '00000000-0000-4000-8000-000000000000'}]},
                'streamSettings': {'network': 'xhttp', 'security': 'tls',
                    'tlsSettings': {'alpn': ['h2', 'http/1.1'], 'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]},
                    'xhttpSettings': {'path': '/upload/', 'mode': 'auto'}}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {'redirect': f'127.0.0.1:{app.server_port}', 'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1']}]}}]}
            path = root / 'server.json'
            path.write_text(json.dumps(server))
            serverlog = (root / 'server.log').open('wb')
            process = subprocess.Popen(['xray', 'run', '-config', str(path)], stdout=serverlog, stderr=serverlog)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', server_port), timeout=0.1): break
                    except OSError: time.sleep(0.02)
                # Only the server endpoint is redirected into this isolated test fixture.
                def local_profile(uri):
                    value = profile(uri)
                    value['log']['loglevel'] = 'debug'
                    remote = value['outbounds'][0]['settings']['vnext'][0]
                    remote.update(address='127.0.0.1', port=server_port)
                    value['outbounds'][0]['streamSettings']['tlsSettings']['certificates'] = [{'certificateFile': str(cert), 'usage': 'verify'}]
                    return value
                errors = []
                log = (root / 'client.log').open('wb')
                original_popen = subprocess.Popen
                def traced_popen(*args, **kwargs):
                    if args[0][0] == 'xray' and '-test' not in args[0]:
                        kwargs.update(stdout=log, stderr=log)
                    return original_popen(*args, **kwargs)
                original_curl = c.curl
                def traced_curl(*args, **kwargs):
                    result = original_curl(*args, **kwargs)
                    if result.returncode: errors.append(result.stderr.decode())
                    return result
                env = {'SSL_CERT_FILE': str(cert), 'CURL_CA_BUNDLE': str(cert)}
                with patch.dict(os.environ, env), patch.object(u, 'profile', side_effect=local_profile), patch.object(c, 'curl', side_effect=traced_curl), patch.object(u.subprocess, 'Popen', side_effect=traced_popen):
                    result = u.verify({'uri': canonical(xhttp()), 'transport': 'xhttp_tls'}, time.monotonic() + 70, threading.BoundedSemaphore(1))
                log.close()
                self.assertEqual(result['status'], 'passed', result['status'] + str(errors) + (root / 'client.log').read_text()[-3000:] + (root / 'server.log').read_text()[-5000:])
                self.assertTrue(result['dns_ok'])
                self.assertGreaterEqual(len(result['speed_samples_mbps']), 2)
            finally:
                process.terminate()
                process.wait(timeout=5)
                serverlog.close()
                app.shutdown()
                app.server_close()
                thread.join(timeout=2)
