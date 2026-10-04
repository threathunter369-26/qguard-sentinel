"""TLS and certificate assessment.

An **active** engine: it completes TLS handshakes against the target, so it runs
only when an approved authorization covers it.

Three things are assessed, and the distinction matters when reading the output:

* **The certificate** — validity window, key strength, signature algorithm,
  name coverage, self-signing. These are properties of the certificate itself.
* **The negotiated connection** — protocol version, cipher suite, key-exchange
  group. These are properties of the *server's configuration*, and a target may
  present a perfect certificate over a badly configured connection.
* **Post-quantum posture** — whether the key exchange is classical, hybrid or
  post-quantum, and which signature algorithm the certificate uses. Recorded
  with the same strict taxonomy the crypto engine uses.

Handshakes are attempted per protocol version to establish what the server
*accepts*, which is the question that matters — a server that merely prefers
TLS 1.3 while still accepting TLS 1.0 is vulnerable to a downgrade.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from qguard_scanner.rules.crypto_catalog import (
    TLS_VERSIONS,
    PQCategory,
    QuantumRisk,
    is_hybrid,
    lookup,
    rsa_security_bits,
    weak_tls_reason,
)
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import Evidence, NetworkLocation, ScanFinding
from qguard_scanner.sdk.netguard import parse_target
from qguard_scanner.sdk.registry import register_engine

#: Protocol versions to probe individually, so what the server *accepts* is
#: established rather than only what it prefers.
PROBE_VERSIONS: tuple[tuple[str, int, int], ...] = (
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ("TLSv1", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
)

#: A certificate expiring sooner than this is reported, because renewal needs
#: lead time and an expired certificate is an outage as well as a security gap.
EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7


@dataclass(slots=True)
class HandshakeResult:
    version: str
    accepted: bool
    cipher: str | None = None
    cipher_bits: int | None = None
    error: str | None = None


@dataclass(slots=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    key_size: int | None
    curve: str | None
    signature_algorithm: str
    san: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_ca: bool = False
    fingerprint_sha256: str = ""
    chain_length: int = 1


@dataclass(slots=True)
class _Issue:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe: str
    remediation: str
    evidence_summary: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    discriminator: str | None = None


@register_engine
class CertificateEngine(SecurityEngine):
    """TLS configuration, certificate and post-quantum posture assessment."""

    metadata = EngineMetadata(
        key="certificate",
        name="TLS and Certificate Assessment",
        description=(
            "Completes TLS handshakes to establish which protocol versions and cipher "
            "suites a target accepts, inspects the presented certificate's validity, "
            "key strength and name coverage, and records the key exchange's "
            "post-quantum posture."
        ),
        version="1.0.0",
        target_kinds=("url", "host", "web_application", "api", "certificate"),
        capabilities=frozenset({EngineCapability.NETWORK}),
        categories=(
            "certificate_issue",
            "cryptographic_failure",
            "insecure_communication",
            "quantum_vulnerable_cryptography",
        ),
    )

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        info = parse_target(ctx.target.value, default_scheme="https")
        host = info.host
        port = info.port or 443

        await ctx.report_progress(10, f"probing TLS on {host}:{port}")
        handshakes: list[HandshakeResult] = []
        for name, minimum, maximum in PROBE_VERSIONS:
            if ctx.is_cancelled():
                break
            result = await asyncio.to_thread(
                self._probe_version,
                host,
                port,
                name,
                minimum,
                maximum,
                ctx.http_timeout_seconds,
            )
            handshakes.append(result)
            await ctx.report_progress(
                10 + 15 * len(handshakes), f"{name}: {'accepted' if result.accepted else 'refused'}"
            )

        accepted = [h for h in handshakes if h.accepted]
        if not accepted:
            reasons = "; ".join(f"{h.version}: {h.error}" for h in handshakes if h.error)
            return EngineResult.failed(
                self.key,
                (
                    f"No TLS handshake succeeded against {host}:{port}, so neither the "
                    f"certificate nor the configuration could be assessed. Attempts: "
                    f"{reasons or 'all refused with no detail'}."
                ),
                stats={"host": host, "port": port, "handshakes": [h.__dict__ for h in handshakes]},
                requests_sent=len(handshakes),
            )

        await ctx.report_progress(70, "retrieving the certificate chain")
        certificate, cert_error, pq_detail = await asyncio.to_thread(
            self._fetch_certificate, host, port, ctx.http_timeout_seconds
        )

        issues: list[_Issue] = []
        issues.extend(self._assess_versions(handshakes, host, port))
        issues.extend(self._assess_ciphers(accepted, host, port))
        if certificate is not None:
            issues.extend(self._assess_certificate(certificate, host))
            issues.extend(self._assess_pq_posture(certificate, pq_detail, host))

        findings = [self._to_finding(i, host, port, ctx) for i in issues]
        stats: dict[str, Any] = {
            "host": host,
            "port": port,
            "versions_accepted": [h.version for h in accepted],
            "versions_refused": [h.version for h in handshakes if not h.accepted],
            "negotiated_ciphers": {h.version: h.cipher for h in accepted if h.cipher},
            "pq_key_exchange": pq_detail,
            "certificate": (
                {
                    "subject": certificate.subject,
                    "issuer": certificate.issuer,
                    "not_after": certificate.not_after.isoformat(),
                    "key_algorithm": certificate.key_algorithm,
                    "key_size": certificate.key_size,
                    "curve": certificate.curve,
                    "signature_algorithm": certificate.signature_algorithm,
                    "san": certificate.san[:50],
                    "self_signed": certificate.is_self_signed,
                    "fingerprint_sha256": certificate.fingerprint_sha256,
                }
                if certificate
                else None
            ),
        }

        if certificate is None:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    f"TLS handshakes succeeded against {host}:{port} and the protocol and "
                    f"cipher configuration was assessed, but the certificate could not be "
                    f"retrieved ({cert_error}). Certificate validity, key strength and "
                    "name coverage are therefore unassessed."
                ),
                stats=stats,
                items_examined=len(handshakes),
                checks_executed=len(handshakes) + 2,
                requests_sent=len(handshakes) + 1,
            )

        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=len(handshakes) + 1,
            checks_executed=len(handshakes) + 10,
            requests_sent=len(handshakes) + 1,
        )

    # ------------------------------------------------------------ handshakes
    @staticmethod
    def _probe_version(
        host: str, port: int, name: str, minimum: int, maximum: int, timeout: float
    ) -> HandshakeResult:
        """Attempt a handshake restricted to one protocol version."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Verification is intentionally off for the probe: the question here is
        # which versions the server *accepts*. Certificate validity is assessed
        # separately and reported on its own.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = ssl.TLSVersion(minimum)
            context.maximum_version = ssl.TLSVersion(maximum)
        except (ValueError, OSError) as exc:
            return HandshakeResult(
                version=name,
                accepted=False,
                error=(
                    f"the local OpenSSL build does not permit restricting to {name} "
                    f"({exc}), so acceptance of this version is unknown"
                ),
            )
        if name in ("TLSv1", "TLSv1.1"):
            # Modern OpenSSL refuses the legacy ciphers these versions need
            # unless security level 0 is requested explicitly.
            with contextlib.suppress(ssl.SSLError):
                context.set_ciphers("ALL:@SECLEVEL=0")

        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                context.wrap_socket(raw, server_hostname=host) as tls,
            ):
                cipher = tls.cipher()
                return HandshakeResult(
                    version=name,
                    accepted=True,
                    cipher=cipher[0] if cipher else None,
                    cipher_bits=cipher[2] if cipher and len(cipher) > 2 else None,
                )
        except ssl.SSLError as exc:
            return HandshakeResult(
                version=name, accepted=False, error=f"refused: {exc.reason or exc}"
            )
        except TimeoutError as exc:
            return HandshakeResult(version=name, accepted=False, error=f"timed out: {exc}")
        except OSError as exc:
            return HandshakeResult(
                version=name, accepted=False, error=f"{type(exc).__name__}: {exc}"
            )

    @staticmethod
    def _fetch_certificate(
        host: str, port: int, timeout: float
    ) -> tuple[CertificateInfo | None, str | None, dict[str, Any]]:
        """Retrieve and parse the presented certificate."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        pq_detail: dict[str, Any] = {}
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                context.wrap_socket(raw, server_hostname=host) as tls,
            ):
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                pq_detail = {
                    "negotiated_version": tls.version(),
                    "negotiated_cipher": cipher[0] if cipher else None,
                    # The negotiated group is what reveals whether key
                    # exchange is classical, hybrid or post-quantum.
                    # ``SSLSocket.group()`` exists only on Python 3.13+ with a
                    # new enough OpenSSL; absent it, the group is unknown and
                    # reported as such rather than guessed.
                    "negotiated_group": tls.group() if hasattr(tls, "group") else None,
                }
                if der is None:
                    return None, "the server presented no certificate", pq_detail
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}", pq_detail

        try:
            certificate = x509.load_der_x509_certificate(der)
        except Exception as exc:
            return None, f"the certificate could not be parsed ({exc})", pq_detail

        public_key = certificate.public_key()
        key_algorithm = "unknown"
        key_size: int | None = None
        curve: str | None = None
        if isinstance(public_key, rsa.RSAPublicKey):
            key_algorithm, key_size = "RSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_algorithm = "ECDSA"
            key_size = public_key.curve.key_size
            curve = public_key.curve.name
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            key_algorithm, key_size = "Ed25519", 256
        elif isinstance(public_key, ed448.Ed448PublicKey):
            key_algorithm, key_size = "Ed448", 448
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_algorithm, key_size = "DSA", public_key.key_size

        # ``get_extension_for_oid`` is typed as returning the base extension,
        # so each value is narrowed to its concrete class before its own
        # accessors are used.
        san: list[str] = []
        try:
            extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            san = []
        else:
            san = [str(n) for n in extension.value.get_values_for_type(x509.DNSName)]
            san += [str(n) for n in extension.value.get_values_for_type(x509.IPAddress)]

        is_ca = False
        try:
            basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            is_ca = False
        else:
            is_ca = bool(basic.value.ca)

        return (
            CertificateInfo(
                subject=certificate.subject.rfc4514_string(),
                issuer=certificate.issuer.rfc4514_string(),
                serial=format(certificate.serial_number, "x"),
                not_before=certificate.not_valid_before_utc,
                not_after=certificate.not_valid_after_utc,
                key_algorithm=key_algorithm,
                key_size=key_size,
                curve=curve,
                signature_algorithm=(
                    certificate.signature_algorithm_oid._name
                    if hasattr(certificate.signature_algorithm_oid, "_name")
                    else str(certificate.signature_algorithm_oid)
                ),
                san=san,
                is_self_signed=certificate.subject == certificate.issuer,
                is_ca=is_ca,
                fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            ),
            None,
            pq_detail,
        )

    # -------------------------------------------------------------- assessment
    @staticmethod
    def _assess_versions(handshakes: list[HandshakeResult], host: str, port: int) -> list[_Issue]:
        issues: list[_Issue] = []
        accepted = {h.version for h in handshakes if h.accepted}

        for version in sorted(accepted):
            spec = TLS_VERSIONS.get(version, {})
            if spec.get("acceptable", True):
                continue
            issues.append(
                _Issue(
                    rule_id=f"tls.deprecated-version.{version.lower().replace('.', '')}",
                    title=f"{version} is accepted",
                    description=(
                        f"The server completed a handshake restricted to {version}. "
                        f"{spec.get('reason', '')} Accepting a deprecated version means a "
                        "client can be downgraded to it even when both sides support "
                        "something better."
                    ),
                    severity=str(spec.get("severity", "high")),
                    confidence="high",
                    category="insecure_communication",
                    cwe="CWE-327",
                    remediation=(
                        f"Disable {version} at the server or terminator and require "
                        "TLS 1.2 as a minimum, TLS 1.3 preferably."
                    ),
                    evidence_summary=f"A {version}-only handshake succeeded on {host}:{port}",
                    artifacts={"version": version, "accepted_versions": sorted(accepted)},
                    discriminator=f"tls-version:{version}",
                )
            )

        if "TLSv1.3" not in accepted:
            issues.append(
                _Issue(
                    rule_id="tls.no-tls13",
                    title="TLS 1.3 is not accepted",
                    description=(
                        "A TLS 1.3 handshake was refused, so the server offers at best "
                        "TLS 1.2. Beyond the handshake improvements, TLS 1.3 is the only "
                        "version that carries hybrid post-quantum key exchange — so no "
                        "post-quantum migration is possible without it."
                    ),
                    severity="low",
                    confidence="high",
                    category="insecure_communication",
                    cwe="CWE-327",
                    remediation=(
                        "Enable TLS 1.3. It is a prerequisite for adopting hybrid "
                        "post-quantum key exchange."
                    ),
                    evidence_summary=f"TLS 1.3 refused on {host}:{port}",
                    artifacts={"accepted_versions": sorted(accepted)},
                    discriminator="no-tls13",
                )
            )
        return issues

    @staticmethod
    def _assess_ciphers(accepted: list[HandshakeResult], host: str, port: int) -> list[_Issue]:
        issues: list[_Issue] = []
        for handshake in accepted:
            if not handshake.cipher:
                continue
            reason = weak_tls_reason(handshake.cipher)
            if reason is None:
                continue
            issues.append(
                _Issue(
                    rule_id="tls.weak-cipher-suite",
                    title=f"Weak cipher suite negotiated under {handshake.version}",
                    description=(
                        f"The server negotiated {handshake.cipher} for a "
                        f"{handshake.version} connection. {reason}"
                    ),
                    severity="high" if "NULL" in handshake.cipher.upper() else "medium",
                    confidence="high",
                    category="cryptographic_failure",
                    cwe="CWE-327",
                    remediation=(
                        "Restrict the cipher list to AEAD suites with forward secrecy: "
                        "ECDHE with AES-GCM or ChaCha20-Poly1305."
                    ),
                    evidence_summary=(
                        f"{handshake.version} negotiated {handshake.cipher} "
                        f"({handshake.cipher_bits} bits)"
                    ),
                    artifacts={
                        "version": handshake.version,
                        "cipher": handshake.cipher,
                        "bits": handshake.cipher_bits,
                    },
                    discriminator=f"weak-cipher:{handshake.cipher}",
                )
            )
        return issues

    @staticmethod
    def _assess_certificate(certificate: CertificateInfo, host: str) -> list[_Issue]:
        issues: list[_Issue] = []
        now = datetime.now(UTC)
        remaining = certificate.not_after - now
        days_left = remaining.days
        # ``timedelta.days`` truncates toward zero, so a certificate with eight
        # hours left reports 0 days. Phrase that as hours rather than printing
        # "expires in 0 days", which reads as a bug.
        horizon = (
            f"{days_left} day(s)"
            if days_left >= 1
            else f"{max(0, int(remaining.total_seconds() // 3600))} hour(s)"
        )

        if days_left < 0:
            issues.append(
                _Issue(
                    rule_id="tls.certificate-expired",
                    title="Certificate has expired",
                    description=(
                        f"The certificate expired {abs(days_left)} day(s) ago, on "
                        f"{certificate.not_after.date()}. Clients will refuse the "
                        "connection or, worse, users will be trained to click through the "
                        "warning — which removes the protection TLS provides."
                    ),
                    severity="critical",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-298",
                    remediation="Renew the certificate and automate renewal so this cannot recur.",
                    evidence_summary=f"notAfter {certificate.not_after.isoformat()}",
                    artifacts={"not_after": certificate.not_after.isoformat(), "days": days_left},
                    discriminator="cert-expired",
                )
            )
        elif days_left <= EXPIRY_WARNING_DAYS:
            issues.append(
                _Issue(
                    rule_id="tls.certificate-expiring",
                    title=f"Certificate expires in {horizon}",
                    description=(
                        f"The certificate is valid until "
                        f"{certificate.not_after.isoformat()}, {horizon} away. Renewal "
                        "needs lead time, and an expired certificate is an outage as well "
                        "as a security gap."
                    ),
                    severity="high" if days_left <= EXPIRY_CRITICAL_DAYS else "medium",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-298",
                    remediation="Renew now and automate renewal with monitoring on the "
                    "expiry date.",
                    evidence_summary=f"notAfter {certificate.not_after.isoformat()}",
                    artifacts={
                        "not_after": certificate.not_after.isoformat(),
                        "days": days_left,
                        "seconds_remaining": int(remaining.total_seconds()),
                    },
                    discriminator="cert-expiring",
                )
            )

        if certificate.not_before > now:
            issues.append(
                _Issue(
                    rule_id="tls.certificate-not-yet-valid",
                    title="Certificate is not yet valid",
                    description=(
                        f"The certificate's validity begins {certificate.not_before.date()}, "
                        "which is in the future. Clients will reject it."
                    ),
                    severity="high",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-298",
                    remediation="Check the issuing process and the server's clock.",
                    evidence_summary=f"notBefore {certificate.not_before.isoformat()}",
                    discriminator="cert-not-yet-valid",
                )
            )

        # The certificate assessed here is the leaf the server presents, so
        # subject == issuer means it is self-signed whatever its basic
        # constraints say. A self-signed certificate that is *also* marked as a
        # CA is a separate and worse defect, reported alongside rather than
        # treated as an exemption.
        if certificate.is_self_signed:
            issues.append(
                _Issue(
                    rule_id="tls.self-signed-certificate",
                    title="Certificate is self-signed",
                    description=(
                        "The certificate's subject and issuer are identical, so no "
                        "certificate authority vouches for it. Clients cannot distinguish "
                        "it from a certificate an attacker generated, so the connection is "
                        "encrypted but not authenticated. Where clients have been configured "
                        "to accept it, they will equally accept an attacker's substitute "
                        "unless they pin this exact certificate."
                    ),
                    severity="medium",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-295",
                    remediation=(
                        "Issue the certificate from a CA the clients trust. For internal "
                        "services, run an internal CA and distribute its root rather than "
                        "using self-signed leaf certificates."
                    ),
                    evidence_summary=f"subject == issuer ({certificate.subject[:120]})",
                    artifacts={"subject": certificate.subject, "issuer": certificate.issuer},
                    discriminator="self-signed",
                )
            )

        if certificate.is_ca:
            issues.append(
                _Issue(
                    rule_id="tls.ca-certificate-as-leaf",
                    title="A CA certificate is being used to terminate TLS",
                    description=(
                        "The certificate presented for this connection has "
                        "`basicConstraints: CA:TRUE`, so it is a certificate authority "
                        "certificate being used directly as a server certificate. Its "
                        "private key therefore lives on an internet-facing host rather "
                        "than offline, and because the key can sign certificates, "
                        "compromising that host yields the ability to issue certificates "
                        "for any name within whatever trust this CA has been given."
                    ),
                    severity="high",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-295",
                    remediation=(
                        "Issue a leaf certificate with `CA:FALSE` for the service, keep the "
                        "CA key offline or in an HSM, and replace the certificate on this "
                        "host. Treat the current CA key as compromised if the host has been "
                        "internet-facing."
                    ),
                    evidence_summary=(
                        f"basicConstraints CA:TRUE on the leaf presented by the server "
                        f"({certificate.subject[:100]})"
                    ),
                    artifacts={
                        "subject": certificate.subject,
                        "is_ca": True,
                        "self_signed": certificate.is_self_signed,
                    },
                    discriminator="ca-as-leaf",
                )
            )

        # Name coverage: a certificate that does not cover the host it is served
        # on produces a browser warning and defeats authentication.
        names = {n.lower() for n in certificate.san}
        covered = any(
            host == name or (name.startswith("*.") and host.endswith(name[1:]) and host != name[2:])
            for name in names
        )
        if names and not covered:
            issues.append(
                _Issue(
                    rule_id="tls.hostname-mismatch",
                    title=f"Certificate does not cover {host}",
                    description=(
                        f"The certificate's subject alternative names do not include "
                        f"{host!r}. Names present: {', '.join(sorted(names)[:8])}. Clients "
                        "will reject the connection, and users who click through are no "
                        "longer authenticating the server at all."
                    ),
                    severity="high",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-297",
                    remediation=f"Reissue the certificate including {host} in its SANs.",
                    evidence_summary=f"{host} not in SAN list of {len(names)} name(s)",
                    artifacts={"host": host, "san": sorted(names)[:50]},
                    discriminator="hostname-mismatch",
                )
            )
        elif not names:
            issues.append(
                _Issue(
                    rule_id="tls.no-san",
                    title="Certificate has no subject alternative names",
                    description=(
                        "The certificate carries no SAN extension. Modern clients ignore "
                        "the common name entirely and will reject it."
                    ),
                    severity="medium",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-295",
                    remediation="Reissue with a SAN extension listing every name served.",
                    evidence_summary="No subjectAltName extension present",
                    discriminator="no-san",
                )
            )

        signature = certificate.signature_algorithm.lower()
        if "md5" in signature or "sha1" in signature:
            issues.append(
                _Issue(
                    rule_id="tls.weak-certificate-signature",
                    title=f"Certificate signed with {certificate.signature_algorithm}",
                    description=(
                        f"The certificate is signed with {certificate.signature_algorithm}. "
                        "Practical chosen-prefix collisions exist for both MD5 and SHA-1, "
                        "which means a forged certificate with a colliding signature is "
                        "feasible."
                    ),
                    severity="high",
                    confidence="high",
                    category="cryptographic_failure",
                    cwe="CWE-327",
                    remediation="Reissue the certificate with a SHA-256 or stronger signature.",
                    evidence_summary=f"signatureAlgorithm {certificate.signature_algorithm}",
                    artifacts={"signature_algorithm": certificate.signature_algorithm},
                    discriminator="weak-cert-signature",
                )
            )

        if certificate.key_algorithm == "RSA" and certificate.key_size:
            bits = rsa_security_bits(certificate.key_size)
            if certificate.key_size < 2048:
                issues.append(
                    _Issue(
                        rule_id="tls.weak-key-size",
                        title=f"RSA key is only {certificate.key_size} bits",
                        description=(
                            f"The certificate uses a {certificate.key_size}-bit RSA key, "
                            f"giving roughly {bits} bits of classical security. NIST "
                            "disallows RSA below 2048 bits."
                        ),
                        severity="high",
                        confidence="high",
                        category="cryptographic_failure",
                        cwe="CWE-326",
                        remediation="Reissue with at least a 2048-bit RSA key, or move to "
                        "ECDSA P-256.",
                        evidence_summary=f"RSA {certificate.key_size} bits",
                        artifacts={"key_size": certificate.key_size, "security_bits": bits},
                        discriminator="weak-key-size",
                    )
                )

        validity_days = (certificate.not_after - certificate.not_before).days
        if validity_days > 400:
            issues.append(
                _Issue(
                    rule_id="tls.excessive-validity",
                    title=f"Certificate validity spans {validity_days} days",
                    description=(
                        f"The certificate is valid for {validity_days} days. A long "
                        "validity period extends the window in which a compromised key "
                        "stays trusted, and public CAs have been limited to ~398 days "
                        "since 2020 for exactly that reason."
                    ),
                    severity="low",
                    confidence="high",
                    category="certificate_issue",
                    cwe="CWE-324",
                    remediation="Issue shorter-lived certificates and automate renewal.",
                    evidence_summary=f"Validity {validity_days} days",
                    artifacts={"validity_days": validity_days},
                    discriminator="excessive-validity",
                )
            )
        return issues

    @staticmethod
    def _assess_pq_posture(
        certificate: CertificateInfo, pq_detail: dict[str, Any], host: str
    ) -> list[_Issue]:
        """Record the connection's post-quantum posture.

        Reported as one finding describing both halves — key exchange and
        signature — because migrating only one leaves the other Shor-breakable
        and that is the mistake worth naming explicitly.
        """
        group = str(pq_detail.get("negotiated_group") or "")
        hybrid, components = is_hybrid(group) if group else (False, ())
        signature_spec = lookup(certificate.key_algorithm)
        signature_broken = (
            signature_spec is not None and signature_spec.quantum_risk is QuantumRisk.BROKEN
        )

        if hybrid and not signature_broken:
            return []  # both halves addressed

        group_unknown = not group

        kex_state = (
            f"hybrid ({' + '.join(components)})"
            if hybrid
            else f"classical ({group})"
            if group
            else "classical (the negotiated group could not be read)"
        )
        return [
            _Issue(
                rule_id=(
                    "tls.quantum-posture-unverified"
                    if group_unknown
                    else "tls.quantum-vulnerable-connection"
                ),
                title=(
                    "Post-quantum protection of the TLS key exchange could not be verified"
                    if group_unknown
                    else "TLS connection is not post-quantum protected"
                ),
                description=(
                    "The negotiated key-exchange group could not be read from this "
                    "connection, so whether key exchange is classical, hybrid or "
                    "post-quantum was not established. Reading it requires Python 3.13 "
                    "or later built against an OpenSSL that exposes the group; this "
                    "scanner is running on an older combination. What *was* "
                    f"established is the certificate's signature algorithm: "
                    f"{certificate.key_algorithm}"
                    + (
                        ", which is Shor-breakable. "
                        if signature_broken
                        else ", which is post-quantum. "
                    )
                    + "Confirm the key-exchange group directly on the TLS terminator — "
                    "`openssl s_client -connect <host>:<port>` reports the negotiated "
                    "group — before treating this connection as migrated."
                    if group_unknown
                    else f"Key exchange is {kex_state} and the certificate signs with "
                    f"{certificate.key_algorithm}"
                    + (
                        ", which is Shor-breakable."
                        if signature_broken
                        else ", which is post-quantum."
                    )
                    + (
                        " Key exchange is the urgent half: traffic recorded today can "
                        "be decrypted once the exchange is broken, so the exposure is "
                        "retroactive. A signature only needs to resist forgery while "
                        "it is still trusted."
                        if not hybrid
                        else " Key exchange is already hybrid, so recorded traffic is "
                        "protected; the signature remains to migrate, which is the "
                        "less urgent half."
                    )
                ),
                severity=("low" if group_unknown or hybrid else "medium"),
                confidence="low" if group_unknown else "high",
                category="quantum_vulnerable_cryptography",
                cwe="CWE-327",
                remediation=(
                    (
                        "Verify the negotiated key-exchange group on the terminator, then "
                        "enable the X25519MLKEM768 hybrid group if it is not already in "
                        "use. "
                        if group_unknown
                        else "Enable the X25519MLKEM768 hybrid key-exchange group on the "
                        "TLS terminator. This requires TLS 1.3 and is supported by current "
                        "OpenSSL, BoringSSL and the major CDNs. "
                        if not hybrid
                        else ""
                    )
                    + (
                        "For signatures, plan migration to ML-DSA certificates as CA "
                        "support becomes available; hybrid certificates allow this "
                        "without breaking verifiers that do not yet understand ML-DSA."
                        if signature_broken
                        else ""
                    )
                ),
                evidence_summary=(
                    f"group={group or 'unknown'} signature={certificate.key_algorithm} "
                    f"version={pq_detail.get('negotiated_version')}"
                ),
                artifacts={
                    "negotiated_group": group or None,
                    "key_exchange_hybrid": hybrid,
                    "hybrid_components": list(components),
                    "certificate_key_algorithm": certificate.key_algorithm,
                    # The classification is recorded with the same strict
                    # taxonomy the crypto engine uses: a signature algorithm is
                    # never described as key establishment.
                    "certificate_pq_category": (
                        signature_spec.pq_category.value
                        if signature_spec
                        else PQCategory.UNKNOWN.value
                    ),
                    "negotiated_version": pq_detail.get("negotiated_version"),
                    "key_exchange_established": not group_unknown,
                },
                discriminator="pq-connection",
            )
        ]

    # --------------------------------------------------------------- findings
    @staticmethod
    def _to_finding(issue: _Issue, host: str, port: int, ctx: EngineContext) -> ScanFinding:
        return ScanFinding(
            engine="certificate",
            rule_id=issue.rule_id,
            category=issue.category,
            title=issue.title,
            description=issue.description,
            severity=issue.severity,
            confidence=issue.confidence,
            cwe=issue.cwe,
            owasp_top10="A02:2021",
            owasp_asvs=["V9.1.2", "V9.2.1"],
            remediation=issue.remediation,
            reproduction=(
                f"Inspect the TLS configuration of {host}:{port}, for example with "
                f"`openssl s_client -connect {host}:{port} -servername {host}`."
            ),
            evidence=Evidence(
                summary=issue.evidence_summary,
                command=f"openssl s_client -connect {host}:{port} -servername {host}",
                artifacts=issue.artifacts,
            ),
            network_location=NetworkLocation(host=host, port=port, scheme="https", protocol="tls"),
            correlation_discriminator=issue.discriminator,
            target=ctx.target,
            references=[
                "https://www.rfc-editor.org/rfc/rfc8996.html",
                f"https://cwe.mitre.org/data/definitions/{issue.cwe.split('-')[-1]}.html",
            ],
            raw={"rule_id": issue.rule_id, **issue.artifacts},
        )
