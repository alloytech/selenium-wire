import contextlib
import datetime
import ipaddress
import os
import ssl
import typing

import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from seleniumwire.thirdparty.mitmproxy.coretypes import serializable

# Default expiry must not be too long: https://github.com/mitmproxy/mitmproxy/issues/815
DEFAULT_EXP = 94608000  # = 60 * 60 * 24 * 365 * 3 = 3 years
DEFAULT_EXP_DUMMY_CERT = 31536000  # = 60 * 60 * 24 * 365 = 1 year

# Generated with "openssl dhparam". It's too slow to generate this on startup.
DEFAULT_DHPARAM = b"""
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAyT6LzpwVFS3gryIo29J5icvgxCnCebcdSe/NHMkD8dKJf8suFCg3
O2+dguLakSVif/t6dhImxInJk230HmfC8q93hdcg/j8rLGJYDKu3ik6H//BAHKIv
j5O9yjU3rXCfmVJQic2Nne39sg3CreAepEts2TvYHhVv3TEAzEqCtOuTjgDv0ntJ
Gwpj+BJBRQGG9NvprX1YGJ7WOFBP/hWU7d6tgvE6Xa7T/u9QIKpYHMIkcN/l3ZFB
chZEqVlyrcngtSXCROTPcDOQ6Q8QzhaBJS+Z6rcsd7X+haiQqvoFcmaJ08Ks6LQC
ZIL2EtYJw8V8z7C0igVEBIADZBI6OTbuuhDwRw//zU1uq52Oc48CIZlGxTYG/Evq
o9EWAXUYVzWkDSTeBH1r4z/qLPE2cnhtMxbFxuvK53jGB0emy2y1Ei6IhKshJ5qX
IB/aE7SSHyQ3MDHHkCmQJCsOd4Mo26YX61NZ+n501XjqpCBQ2+DfZCBh8Va2wDyv
A2Ryg9SUz8j0AXViRNMJgJrr446yro/FuJZwnQcO3WQnXeqSBnURqKjmqkeFP+d8
6mk2tqJaY507lRNqtGlLnj7f5RNoBFJDCLBNurVgfvq9TCVWKDIFD4vZRjCrnl6I
rD693XKIHUCWOjMh1if6omGXKHH40QuME2gNa50+YPn1iYDl88uDbbMCAQI=
-----END DH PARAMETERS-----
"""


def create_ca(organization, cn, exp, key_size):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .not_valid_before(now - datetime.timedelta(hours=48))
        .not_valid_after(now + datetime.timedelta(seconds=exp))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return (
        OpenSSL.crypto.PKey.from_cryptography_key(key),
        OpenSSL.crypto.X509.from_cryptography(cert),
    )


def dummy_cert(privkey, cacert, commonname, sans, organization):
    """
        Generates a dummy certificate.

        privkey: CA private key
        cacert: CA certificate
        commonname: Common name for the generated certificate.
        sans: A list of Subject Alternate Names.
        organization: Organization name for the generated certificate.

        Returns cert if operation succeeded, None if not.
    """
    ck_privkey = privkey.to_cryptography_key()
    ck_cacert = cacert.to_cryptography()

    altnames: typing.List[x509.GeneralName] = []
    for i in sans:
        name = i.decode("ascii")
        try:
            altnames.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            altnames.append(x509.DNSName(name))

    is_valid_commonname = commonname is not None and len(commonname) < 64
    subject = []
    if is_valid_commonname:
        subject.append(x509.NameAttribute(NameOID.COMMON_NAME, commonname.decode("utf-8")))
    if organization is not None:
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization.decode("utf-8")))

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .subject_name(x509.Name(subject))
        .issuer_name(ck_cacert.subject)
        .public_key(ck_cacert.public_key())
        .not_valid_before(now - datetime.timedelta(hours=48))
        .not_valid_after(now + datetime.timedelta(seconds=DEFAULT_EXP_DUMMY_CERT))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )
    if altnames:
        # RFC 5280 §4.2.1.6: subjectAltName is critical if subject is empty.
        builder = builder.add_extension(x509.SubjectAlternativeName(altnames), critical=not is_valid_commonname)
    cert = builder.sign(private_key=ck_privkey, algorithm=hashes.SHA256())
    return Cert(OpenSSL.crypto.X509.from_cryptography(cert))


class CertStoreEntry:

    def __init__(self, cert, privatekey, chain_file):
        self.cert = cert
        self.privatekey = privatekey
        self.chain_file = chain_file


TCustomCertId = bytes  # manually provided certs (e.g. mitmproxy's --certs)
TGeneratedCertId = typing.Tuple[typing.Optional[bytes], typing.Tuple[bytes, ...]]  # (common_name, sans)
TCertId = typing.Union[TCustomCertId, TGeneratedCertId]


class CertStore:

    """
        Implements an in-memory certificate store.
    """
    STORE_CAP = 100

    def __init__(
            self,
            default_privatekey,
            default_ca,
            default_chain_file,
            dhparams):
        self.default_privatekey = default_privatekey
        self.default_ca = default_ca
        self.default_chain_file = default_chain_file
        self.dhparams = dhparams
        self.certs: typing.Dict[TCertId, CertStoreEntry] = {}
        self.expire_queue = []

    def expire(self, entry):
        self.expire_queue.append(entry)
        if len(self.expire_queue) > self.STORE_CAP:
            d = self.expire_queue.pop(0)
            self.certs = {k: v for k, v in self.certs.items() if v != d}

    @staticmethod
    def load_dhparam(path):

        # mitmproxy<=0.10 doesn't generate a dhparam file.
        # Create it now if necessary.
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(DEFAULT_DHPARAM)

        # Custom DH parameters are not configured on the TLS context; modern
        # cipher suites negotiate key exchange over ECDHE instead.
        return None

    @classmethod
    def from_store(cls, path, basename, key_size, passphrase: typing.Optional[bytes] = None):
        ca_path = os.path.join(path, basename + "-ca.pem")
        if not os.path.exists(ca_path):
            key, ca = cls.create_store(path, basename, key_size)
        else:
            with open(ca_path, "rb") as f:
                raw = f.read()
            ca = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                raw)
            key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                raw,
                passphrase)
        dh_path = os.path.join(path, basename + "-dhparam.pem")
        dh = cls.load_dhparam(dh_path)
        return cls(key, ca, ca_path, dh)

    @staticmethod
    @contextlib.contextmanager
    def umask_secret():
        """
            Context to temporarily set umask to its original value bitor 0o77.
            Useful when writing private keys to disk so that only the owner
            will be able to read them.
        """
        original_umask = os.umask(0)
        os.umask(original_umask | 0o77)
        try:
            yield
        finally:
            os.umask(original_umask)

    @staticmethod
    def create_store(path, basename, key_size, organization=None, cn=None, expiry=DEFAULT_EXP):
        if not os.path.exists(path):
            os.makedirs(path)

        organization = organization or basename
        cn = cn or basename

        key, ca = create_ca(organization=organization, cn=cn, exp=expiry, key_size=key_size)
        # Dump the CA plus private key
        with CertStore.umask_secret(), open(os.path.join(path, basename + "-ca.pem"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM,
                    key))
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))

        # Dump the certificate in PEM format
        with open(os.path.join(path, basename + "-ca-cert.pem"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))

        # Create a .cer file with the same contents for Android
        with open(os.path.join(path, basename + "-ca-cert.cer"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))

        # Dump the certificate in PKCS12 format for Windows devices
        with open(os.path.join(path, basename + "-ca-cert.p12"), "wb") as f:
            f.write(
                pkcs12.serialize_key_and_certificates(
                    name=basename.encode(),
                    key=None,
                    cert=ca.to_cryptography(),
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

        # Dump the certificate and key in a PKCS12 format for Windows devices
        with CertStore.umask_secret(), open(os.path.join(path, basename + "-ca.p12"), "wb") as f:
            f.write(
                pkcs12.serialize_key_and_certificates(
                    name=basename.encode(),
                    key=key.to_cryptography_key(),
                    cert=ca.to_cryptography(),
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

        with open(os.path.join(path, basename + "-dhparam.pem"), "wb") as f:
            f.write(DEFAULT_DHPARAM)

        return key, ca

    def add_cert_file(self, spec: str, path: str, passphrase: typing.Optional[bytes] = None) -> None:
        with open(path, "rb") as f:
            raw = f.read()
        cert = Cert(
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                raw))
        try:
            privatekey = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                raw,
                passphrase)
        except Exception:
            privatekey = self.default_privatekey
        self.add_cert(
            CertStoreEntry(cert, privatekey, path),
            spec.encode("idna")
        )

    def add_cert(self, entry: CertStoreEntry, *names: bytes):
        """
            Adds a cert to the certstore. We register the CN in the cert plus
            any SANs, and also the list of names provided as an argument.
        """
        if entry.cert.cn:
            self.certs[entry.cert.cn] = entry
        for i in entry.cert.altnames:
            self.certs[i] = entry
        for i in names:
            self.certs[i] = entry

    @staticmethod
    def asterisk_forms(dn: bytes) -> typing.List[bytes]:
        """
        Return all asterisk forms for a domain. For example, for www.example.com this will return
        [b"www.example.com", b"*.example.com", b"*.com"]. The single wildcard "*" is omitted.
        """
        parts = dn.split(b".")
        ret = [dn]
        for i in range(1, len(parts)):
            ret.append(b"*." + b".".join(parts[i:]))
        return ret

    def get_cert(
            self,
            commonname: typing.Optional[bytes],
            sans: typing.List[bytes],
            organization: typing.Optional[bytes] = None
    ) -> typing.Tuple["Cert", OpenSSL.SSL.PKey, str]:
        """
            Returns an (cert, privkey, cert_chain) tuple.

            commonname: Common name for the generated certificate. Must be a
            valid, plain-ASCII, IDNA-encoded domain name.

            sans: A list of Subject Alternate Names.

            organization: Organization name for the generated certificate.
        """

        potential_keys: typing.List[TCertId] = []
        if commonname:
            potential_keys.extend(self.asterisk_forms(commonname))
        for s in sans:
            potential_keys.extend(self.asterisk_forms(s))
        potential_keys.append(b"*")
        potential_keys.append((commonname, tuple(sans)))

        name = next(
            filter(lambda key: key in self.certs, potential_keys),
            None
        )
        if name:
            entry = self.certs[name]
        else:
            entry = CertStoreEntry(
                cert=dummy_cert(
                    self.default_privatekey,
                    self.default_ca,
                    commonname,
                    sans,
                    organization),
                privatekey=self.default_privatekey,
                chain_file=self.default_chain_file)
            self.certs[(commonname, tuple(sans))] = entry
            self.expire(entry)

        return entry.cert, entry.privatekey, entry.chain_file


class Cert(serializable.Serializable):

    def __init__(self, cert):
        """
            Returns a (common name, [subject alternative names]) tuple.
        """
        self.x509 = cert

    def __eq__(self, other):
        return self.digest("sha256") == other.digest("sha256")

    def get_state(self):
        return self.to_pem()

    def set_state(self, state):
        self.x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, state)

    @classmethod
    def from_state(cls, state):
        return cls.from_pem(state)

    @classmethod
    def from_pem(cls, txt):
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, txt)
        return cls(x509)

    @classmethod
    def from_der(cls, der):
        pem = ssl.DER_cert_to_PEM_cert(der)
        return cls.from_pem(pem)

    def to_pem(self):
        return OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            self.x509)

    def digest(self, name):
        return self.x509.digest(name)

    @property
    def issuer(self):
        return self.x509.get_issuer().get_components()

    @property
    def notbefore(self):
        t = self.x509.get_notBefore()
        return datetime.datetime.strptime(t.decode("ascii"), "%Y%m%d%H%M%SZ")

    @property
    def notafter(self):
        t = self.x509.get_notAfter()
        return datetime.datetime.strptime(t.decode("ascii"), "%Y%m%d%H%M%SZ")

    @property
    def has_expired(self):
        return self.x509.has_expired()

    @property
    def subject(self):
        return self.x509.get_subject().get_components()

    @property
    def serial(self):
        return self.x509.get_serial_number()

    @property
    def keyinfo(self):
        pk = self.x509.get_pubkey()
        types = {
            OpenSSL.crypto.TYPE_RSA: "RSA",
            OpenSSL.crypto.TYPE_DSA: "DSA",
        }
        return (
            types.get(pk.type(), "UNKNOWN"),
            pk.bits()
        )

    @property
    def cn(self):
        c = None
        for i in self.subject:
            if i[0] == b"CN":
                c = i[1]
        return c

    @property
    def organization(self):
        c = None
        for i in self.subject:
            if i[0] == b"O":
                c = i[1]
        return c

    @property
    def altnames(self):
        """
        Returns:
            All DNS altnames.
        """
        # tcp.TCPClient.convert_to_tls assumes that this property only contains DNS altnames for hostname verification.
        try:
            ext = self.x509.to_cryptography().extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            return []

        return [name.encode("ascii") for name in ext.value.get_values_for_type(x509.DNSName)]
