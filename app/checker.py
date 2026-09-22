"""Core SSL/TLS inspection logic.

Connects to a ``host:port`` over TLS and returns a structured breakdown of
everything the handshake reveals: negotiated protocol, cipher suite, and a
full parse of the certificate chain (subject, issuer, SANs, validity, key,
fingerprint, verification status, ...).

The connection is made twice:
  1. A *verified* attempt (system trust store) — determines whether the
     chain actually validates.
  2. If (and only if) that fails on verification, an *unverified* attempt so
     we can still report the certificate details for self-signed / expired /
     misconfigured servers instead of just returning an error.
"""

from __future__ import annotations

import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

#: Certificates expiring within this many days are flagged "expiring_soon".
EXPIRY_WARNING_DAYS = 14


_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


def _chain_via_openssl(host: str, port: int, timeout: float) -> list[x509.Certificate] | None:
    """Fallback chain extraction via the openssl CLI (for Python < 3.13).

    ``SSLSocket.get_verified_chain`` / ``get_unverified_chain`` only landed in
    Python 3.13, so on older interpreters we shell out to ``openssl s_client
    -showcerts`` to grab the full server-sent chain. Returns ``None`` if
    openssl is missing or the run fails, so callers degrade to leaf-only.
    """
    try:
        proc = subprocess.run(
            [
                "openssl", "s_client", "-connect", f"{host}:{port}",
                "-servername", host, "-showcerts",
            ],
            input=b"", capture_output=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None

    out = proc.stdout.decode("utf-8", errors="ignore")
    certs: list[x509.Certificate] = []
    for pem in _CERT_RE.findall(out):
        try:
            certs.append(x509.load_pem_x509_certificate(pem.encode()))
        except ValueError:
            continue
    return certs or None


def _oid_name(oid: Any) -> str:
    """Best-effort human name for an OID (falls back to dotted string)."""
    return getattr(oid, "_name", oid.dotted_string)


def _dt_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    """Flatten an x509 Name into {label: value} using common short labels."""
    labels = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
    }
    out: dict[str, str] = {}
    for attr in name:
        label = labels.get(attr.oid, _oid_name(attr.oid))
        out[label] = str(attr.value)
    return out


def _key_info(cert: x509.Certificate) -> dict[str, Any]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "bits": pub.key_size}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"algorithm": "EC", "curve": pub.curve.name, "bits": pub.curve.key_size}
    if isinstance(pub, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "bits": pub.key_size}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "bits": 256}
    if isinstance(pub, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "bits": 448}
    return {"algorithm": type(pub).__name__, "bits": 0}


def _san(cert: x509.Certificate) -> dict[str, list[str]]:
    dns: list[str] = []
    ips: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                dns.append(name.value)
            elif isinstance(name, x509.IPAddress):
                ips.append(str(name.ip))
    except x509.ExtensionNotFound:
        pass
    return {"dns": dns, "ip": ips}


def _cert_dict(cert: x509.Certificate) -> dict[str, Any]:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    if now < not_before:
        status = "not_yet_valid"
    elif now > not_after:
        status = "expired"
    elif days_left <= EXPIRY_WARNING_DAYS:
        status = "expiring_soon"
    else:
        status = "valid"

    return {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial_number": format(cert.serial_number, "X"),
        "signature_algorithm": _oid_name(cert.signature_algorithm_oid),
        "not_before": _dt_iso(not_before),
        "not_after": _dt_iso(not_after),
        "days_remaining": days_left,
        "validity_status": status,
        "san": _san(cert),
        "public_key": _key_info(cert),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "version": cert.version.name,
    }


def _connect(host: str, port: int, timeout: float, verify: bool) -> dict[str, Any]:
    """Open a TLS connection and harvest everything the handshake reveals."""
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    data: dict[str, Any] = {
        "connected": False,
        "tls_negotiated": False,
    }

    with socket.create_connection((host, port), timeout=timeout) as sock:
        data["connected"] = True
        data["ip_address"] = sock.getpeername()[0]
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            data["tls_negotiated"] = True
            data["tls_version"] = tls.version()

            cipher = tls.cipher()
            if cipher:
                data["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}

            leaf_der = tls.getpeercert(binary_form=True)

            # Full chain is only exposed on Python 3.13+; otherwise report leaf.
            chain_der: list[bytes] = []
            if verify and hasattr(tls, "get_verified_chain"):
                chain_der = list(tls.get_verified_chain())
            elif hasattr(tls, "get_unverified_chain"):
                chain_der = list(tls.get_unverified_chain())

            if chain_der:
                certs = [x509.load_der_x509_certificate(der) for der in chain_der]
            else:
                # Python < 3.13: enrich the chain via openssl if available.
                certs = (
                    _chain_via_openssl(host, port, timeout)
                    or [x509.load_der_x509_certificate(leaf_der)]
                )

            data["certificates"] = [_cert_dict(c) for c in certs]
            data["certificate"] = data["certificates"][0]

    return data


def _friendly_error(exc: BaseException, timeout: float) -> str:
    if isinstance(exc, socket.timeout):
        return f"Connection timed out after {timeout:g}s"
    if isinstance(exc, socket.gaierror):
        return f"Could not resolve host: {exc}"
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused (nothing listening on that port?)"
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc}"
    return f"{type(exc).__name__}: {exc}"


def check(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    """Inspect the SSL/TLS state of ``host:port`` and return a full report."""
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "checked_at": _dt_iso(datetime.now(timezone.utc)),
        "connected": False,
        "tls_negotiated": False,
        "verified": False,
        "verify_error": None,
        "error": None,
    }

    try:
        # 1) Verified connection — also yields chain + verification status.
        result.update(_connect(host, port, timeout, verify=True))
        result["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        # Cert exists but the chain doesn't validate — still grab the details.
        result["verified"] = False
        result["verify_error"] = str(exc)
        try:
            result.update(_connect(host, port, timeout, verify=False))
        except Exception as exc2:  # noqa: BLE001
            result["error"] = _friendly_error(exc2, timeout)
    except ssl.SSLError as exc:
        result["connected"] = True
        result["error"] = f"TLS error: {exc}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        result["error"] = _friendly_error(exc, timeout)
    except Exception as exc:  # noqa: BLE001
        result["error"] = _friendly_error(exc, timeout)

    return result
