"""Exercise stored/password-protected shares and a relay larger than its queue."""
import concurrent.futures
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


class ShareSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='lan-share-test-')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cls.base = f'http://127.0.0.1:{port}/share/'
        env = dict(os.environ, LAN_SHARE_DATA_DIR=cls.temp.name, LAN_SHARE_PORT=str(port))
        cls.process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'server.py')],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            if cls.process.poll() is not None:
                break
            try:
                if cls.request('', timeout=0.2)[0] == 200:
                    return
            except OSError:
                time.sleep(0.1)
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.temp.cleanup()
        raise RuntimeError('LAN Share did not start')

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.temp.cleanup()

    @classmethod
    def request(cls, route, data=None, headers=None, timeout=15):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            headers = dict(headers or {}, **{'Content-Type': 'application/json'})
        req = urllib.request.Request(cls.base + route, data=data, headers=headers or {})
        try:
            response = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            if 'application/json' in response.headers.get('Content-Type', ''):
                body = json.loads(body)
            return response.status, body

    def test_stored_share_and_password(self):
        password = secrets.token_urlsafe(20)
        status, created = self.request('api/create', {'text': 'Private test note', 'expiry': 3600, 'password': password})
        self.assertEqual(status, 201)
        status, listing = self.request('api/items')
        self.assertEqual(status, 200)
        self.assertNotIn('Private test note', json.dumps(listing))
        self.assertEqual(self.request('api/unlock', {'id': created['id'], 'password': 'incorrect'})[0], 403)
        status, unlocked = self.request('api/unlock', {'id': created['id'], 'password': password})
        self.assertEqual(status, 200)
        self.assertIn('Private test note', json.dumps(unlocked))
        for name in ['manifest.webmanifest', 'sw.js', 'icon.svg', 'icon-192.png', 'qrcode.min.js']:
            self.assertEqual(self.request('static/' + name)[0], 200)
        status, uploaded = self.request('api/create', {'text': 'Attachment test', 'file_count': 1})
        self.assertEqual(status, 201)
        route = f"api/upload?id={uploaded['id']}&token={uploaded['upload_token']}"
        status, _ = self.request(route, b'sample file content', {'X-File-Name': 'sample.txt', 'Content-Type': 'text/plain'})
        self.assertIn(status, (200, 201))

    def test_direct_relay(self):
        payload = secrets.token_bytes(3 * 1024 * 1024)
        status, transfer = self.request('api/direct/create', {
            'name': 'sample.bin', 'size': len(payload), 'mime': 'application/octet-stream',
            'sender_name': 'Demo sender', 'client_id': 'smoke-test',
        })
        self.assertEqual(status, 201)
        status, accepted = self.request('api/direct/accept', {'id': transfer['id'], 'receiver_name': 'Demo receiver'})
        self.assertEqual(status, 200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            receiving = pool.submit(self.request, accepted['receive_url'])
            route = f"direct/send/{transfer['id']}?token={transfer['sender_token']}"
            status, _ = self.request(route, payload, {'Content-Type': 'application/octet-stream'})
            self.assertEqual(status, 200)
            received_status, received = receiving.result(timeout=20)
            self.assertEqual(received_status, 200)
            self.assertEqual(received, payload)
        self.assertFalse(any((Path(self.temp.name) / 'uploads').glob('*')))


if __name__ == '__main__':
    unittest.main()
