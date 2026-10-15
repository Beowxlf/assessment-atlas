"""Real TLS handshakes under Python 3.13's stricter RFC 5280 policy.

Explicitly enable the same strict flag on earlier supported Python versions, so
nonconforming interception certificates cannot hide behind older TLS defaults.
"""
import datetime as dt
import importlib.util
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from atlas.web_proxy import LocalCertificates


@unittest.skipUnless(importlib.util.find_spec('cryptography') and hasattr(ssl, 'VERIFY_X509_STRICT'),
                     'Install requirements-web.txt and use OpenSSL with strict X.509 verification')
class StrictCertificates(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / 'work' / 'test-temp'
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.certificates = LocalCertificates()

    def strict_client(self):
        context = ssl.create_default_context(cadata=self.certificates.pem)
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        return context

    def exchange(self, server_context, client_context, server_name):
        """One owned loopback handshake, including server thread completion."""
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        errors = []
        def serve():
            try:
                raw, _ = listener.accept()
                raw.settimeout(5)
                with server_context.wrap_socket(raw, server_side=True) as connection:
                    connection.sendall(b'SYNTHETIC_STRICT_TLS')
            except ssl.SSLError:
                pass  # A rejecting client deliberately sends a fatal TLS alert.
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                with client_context.wrap_socket(raw, server_hostname=server_name) as connection:
                    certificate = connection.getpeercert(binary_form=True)
                    self.assertEqual(connection.recv(64), b'SYNTHETIC_STRICT_TLS')
                    return self.certificates.x509.load_der_x509_certificate(certificate)
        finally:
            thread.join(6)
            listener.close()
            self.assertFalse(thread.is_alive(), 'Owned strict TLS peer did not stop')
            self.assertEqual(errors, [])

    def test_generated_ca_and_ip_dns_leafs_validate_strictly_and_keep_private_keys_transient(self):
        x509 = self.certificates.x509
        ca = self.certificates.ca
        ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        self.assertEqual(ca.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier, ca_ski)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).critical)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.KeyUsage).critical)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
        for hostname in ('127.0.0.1', 'localhost'):
            with self.subTest(hostname=hostname):
                leaf = self.exchange(self.certificates.context(hostname, self.folder), self.strict_client(), hostname)
                self.assertEqual(leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier, ca_ski)
                self.assertTrue(leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
                self.assertTrue(leaf.extensions.get_extension_for_class(x509.BasicConstraints).critical)
                self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
                usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
                self.assertTrue(usage.critical)
                self.assertTrue(usage.value.digital_signature)
                self.assertFalse(usage.value.key_cert_sign)
                self.assertIn(self.certificates.ExtendedKeyUsageOID.SERVER_AUTH,
                              leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
                self.assertEqual(list(self.folder.iterdir()), [], 'Issued leaf private keys must be removed after SSLContext loading')
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.exchange(self.certificates.context('localhost', self.folder), self.strict_client(), 'other-host.invalid')

    def test_strict_policy_still_rejects_a_signed_leaf_missing_authority_key_identifier(self):
        x509 = self.certificates.x509
        key = self.certificates.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        instant = dt.datetime.now(dt.timezone.utc)
        # A synthetic deliberately malformed leaf proves the stricter policy is
        # active; the production builder must never issue this incomplete shape.
        malformed = (x509.CertificateBuilder()
                     .subject_name(x509.Name([x509.NameAttribute(self.certificates.NameOID.COMMON_NAME, 'localhost')]))
                     .issuer_name(self.certificates.ca.subject).public_key(key.public_key())
                     .serial_number(x509.random_serial_number())
                     .not_valid_before(instant - dt.timedelta(minutes=1)).not_valid_after(instant + dt.timedelta(hours=1))
                     .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                                 crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                     .sign(self.certificates.key, self.certificates.hashes.SHA256()))
        serialization = self.certificates.serialization
        path = self.folder / 'synthetic-malformed-leaf.pem'
        try:
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption())
                             + malformed.public_bytes(serialization.Encoding.PEM))
            path.chmod(0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(path)
        finally:
            path.unlink(missing_ok=True)
        with self.assertRaises(ssl.SSLCertVerificationError) as rejected:
            self.exchange(context, self.strict_client(), 'localhost')
        self.assertIn('authority key identifier', rejected.exception.verify_message.lower())
        self.assertEqual(list(self.folder.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
