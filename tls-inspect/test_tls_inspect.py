import contextlib
import io
import json
import ssl
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from tls_inspect import certificate_report, inspect, main, normalize_host

CERT = {'subject': ((('commonName', 'example.test'),),), 'issuer': ((('commonName', 'Test CA'),),),
        'notBefore': 'Jan 01 00:00:00 2026 GMT', 'notAfter': 'Jan 31 00:00:00 2026 GMT',
        'subjectAltName': (('DNS', 'example.test'),)}


class TLSInspectTests(unittest.TestCase):
    def test_domain_and_ip_normalization(self):
        self.assertEqual(normalize_host('EXAMPLE.com.'), 'example.com')
        self.assertEqual(normalize_host('127.0.0.1'), '127.0.0.1')
        self.assertEqual(normalize_host('::1'), '::1')
        self.assertEqual(normalize_host('café.example'), 'xn--caf-dma.example')

    def test_invalid_hosts(self):
        for host in ('https://example.com', 'example.com:443', 'a b', '-test.com', 'a..com', 'user@example.com'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                normalize_host(host)

    def test_expiry_boundaries(self):
        cases = [(1, 10, 'dentro do prazo'), (21, 10, 'vence em breve'), (31, 10, 'expirado')]
        for day, warn, expected in cases:
            report = certificate_report('example.test', 443, CERT, 'TLSv1.3', 'cipher', warn, datetime(2026, 1, day, tzinfo=timezone.utc))
            self.assertEqual(report['validity'], expected)

    def test_not_yet_valid(self):
        result = certificate_report('example.test', 443, CERT, 'TLSv1.3', 'cipher', now=datetime(2025, 12, 1, tzinfo=timezone.utc))
        self.assertEqual(result['validity'], 'ainda não válido')

    def test_connection_uses_verifying_context_and_sni(self):
        raw = MagicMock()
        context = MagicMock()
        secure = context.wrap_socket.return_value.__enter__.return_value
        secure.getpeercert.return_value = CERT
        secure.version.return_value = 'TLSv1.3'
        secure.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        with patch('tls_inspect.socket.create_connection', return_value=raw) as connect, patch('tls_inspect.ssl.create_default_context', return_value=context):
            inspect('EXAMPLE.test', 443, 5)
        connect.assert_called_once_with(('example.test', 443), timeout=5)
        context.wrap_socket.assert_called_once_with(raw.__enter__.return_value, server_hostname='example.test')
        self.assertEqual(ssl.create_default_context().verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ssl.create_default_context().check_hostname)

    def test_certificate_failure_returns_error(self):
        with patch('tls_inspect.inspect', side_effect=ssl.SSLCertVerificationError(1, 'certificate verify failed')), contextlib.redirect_stderr(io.StringIO()):
            # verify_message é fornecido pelo OpenSSL; simula sua presença.
            error = ssl.SSLCertVerificationError(1, 'certificate verify failed')
            error.verify_message = 'hostname mismatch'
            with patch('tls_inspect.inspect', side_effect=error):
                self.assertEqual(main(['example.test']), 2)

    def test_demo_json_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--demo', '--json', str(path)]), 1)
                self.assertEqual(main(['--demo', '--json', str(path)]), 2)
            result = json.loads(path.read_text(encoding='utf-8'))
            self.assertTrue(result['demo'])
            self.assertEqual(result['validation'], 'simulada')
            self.assertEqual(result['days_remaining'], 14)


if __name__ == '__main__':
    unittest.main()
