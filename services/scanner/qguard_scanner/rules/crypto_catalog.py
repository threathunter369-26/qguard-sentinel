"""Cryptographic algorithm catalogue and post-quantum classification.

The taxonomy here is strict, because conflating primitive classes is the most
common error in post-quantum readiness work and it produces migration plans
that cannot work:

====================  ==========================================================
Key encapsulation     ML-KEM (FIPS 203). Establishes a shared secret. **Not** a
                      signature scheme and cannot authenticate anything.
Digital signature     ML-DSA (FIPS 204), SLH-DSA (FIPS 205). Authenticate data.
                      **Not** KEMs and cannot establish a shared secret.
Key agreement         ECDH, X25519, DH. Shor-breakable.
Symmetric encryption  AES, ChaCha20. Grover-reduced, not broken.
Hash                  SHA-2, SHA-3. Grover-reduced, not broken.
====================  ==========================================================

Two consequences follow and are encoded below rather than left to prose:

* A quantum-safe deployment needs **both** a PQ KEM and a PQ signature scheme.
  Deploying ML-KEM alone protects confidentiality in transit while leaving
  authentication Shor-breakable; deploying ML-DSA alone does the reverse.
* Symmetric and hash primitives are *reduced* by Grover, not broken. AES-256
  retains roughly 128 bits of security against a quantum adversary, which is
  adequate. Replacing AES-256 is not part of a PQ migration, and a tool that
  reports it as quantum-vulnerable sends teams to do unnecessary work.

Store-now-decrypt-later is why key establishment is the migration priority:
traffic captured today can be decrypted once a capable quantum computer
exists, whereas a signature only needs to resist forgery while it is still
trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class PQCategory(StrEnum):
    """Primitive class. Mirrors the platform's database enum exactly."""

    KEY_ENCAPSULATION = "key_encapsulation"
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_AGREEMENT = "key_agreement"
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    UNKNOWN = "unknown"


class QuantumRisk(StrEnum):
    BROKEN = "broken"
    """Shor-breakable: the primitive provides no security against a capable
    quantum adversary. RSA, ECC, DH, DSA."""
    REDUCED = "reduced"
    """Grover-reduced: effective security is roughly halved in bits but the
    primitive is not broken. Adequate at 256-bit symmetric strength."""
    QUANTUM_SAFE = "quantum_safe"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AlgorithmSpec:
    name: str
    pq_category: PQCategory
    quantum_risk: QuantumRisk
    description: str
    #: Classical security in bits at the stated key size.
    classical_bits: int | None = None
    #: Effective security in bits against a quantum adversary. ``0`` for a
    #: Shor-breakable primitive.
    quantum_bits: int | None = None
    #: NIST PQC security category 1-5, for standardised PQ algorithms only.
    nist_category: int | None = None
    standard: str | None = None
    is_deprecated: bool = False
    deprecation_reason: str | None = None
    migration: str | None = None
    #: Minimum key size still considered acceptable, where applicable.
    min_acceptable_bits: int | None = None
    aliases: tuple[str, ...] = ()


SHOR_BROKEN_NOTE = (
    "Shor's algorithm solves integer factorisation and discrete logarithms in "
    "polynomial time, so this primitive offers no security against a "
    "cryptographically relevant quantum computer regardless of key size. "
    "Increasing the key size does not help."
)

GROVER_NOTE = (
    "Grover's algorithm gives at best a quadratic speed-up against a symmetric "
    "primitive, which halves its effective security in bits. It does not break "
    "the primitive."
)

# ---------------------------------------------------------------------------
# Post-quantum standards (NIST, 2024)
# ---------------------------------------------------------------------------
PQ_ALGORITHMS: tuple[AlgorithmSpec, ...] = (
    # --- Key encapsulation: ML-KEM only. Never a signature scheme. ---------
    AlgorithmSpec(
        name="ML-KEM-512",
        pq_category=PQCategory.KEY_ENCAPSULATION,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "Module-Lattice Key Encapsulation Mechanism, NIST FIPS 203. Establishes a "
            "shared secret. It is not a signature scheme and cannot authenticate a peer."
        ),
        nist_category=1,
        quantum_bits=128,
        standard="FIPS 203",
        aliases=("Kyber512", "KYBER-512", "ml_kem_512"),
    ),
    AlgorithmSpec(
        name="ML-KEM-768",
        pq_category=PQCategory.KEY_ENCAPSULATION,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "Module-Lattice KEM, FIPS 203, NIST category 3. The usual choice for TLS "
            "key establishment and the level CNSA 2.0 expects."
        ),
        nist_category=3,
        quantum_bits=192,
        standard="FIPS 203",
        aliases=("Kyber768", "KYBER-768", "ml_kem_768"),
    ),
    AlgorithmSpec(
        name="ML-KEM-1024",
        pq_category=PQCategory.KEY_ENCAPSULATION,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description="Module-Lattice KEM, FIPS 203, NIST category 5.",
        nist_category=5,
        quantum_bits=256,
        standard="FIPS 203",
        aliases=("Kyber1024", "KYBER-1024", "ml_kem_1024"),
    ),
    # --- Digital signatures: ML-DSA and SLH-DSA. Never KEMs. ---------------
    AlgorithmSpec(
        name="ML-DSA-44",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "Module-Lattice Digital Signature Algorithm, NIST FIPS 204. A signature "
            "scheme: it authenticates data and cannot establish a shared secret."
        ),
        nist_category=2,
        quantum_bits=128,
        standard="FIPS 204",
        aliases=("Dilithium2", "DILITHIUM2", "ml_dsa_44"),
    ),
    AlgorithmSpec(
        name="ML-DSA-65",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description="Module-Lattice signature scheme, FIPS 204, NIST category 3.",
        nist_category=3,
        quantum_bits=192,
        standard="FIPS 204",
        aliases=("Dilithium3", "DILITHIUM3", "ml_dsa_65"),
    ),
    AlgorithmSpec(
        name="ML-DSA-87",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description="Module-Lattice signature scheme, FIPS 204, NIST category 5.",
        nist_category=5,
        quantum_bits=256,
        standard="FIPS 204",
        aliases=("Dilithium5", "DILITHIUM5", "ml_dsa_87"),
    ),
    AlgorithmSpec(
        name="SLH-DSA-SHA2-128s",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "Stateless Hash-Based Digital Signature Algorithm, NIST FIPS 205. Its "
            "security rests only on the hash function, which makes it the conservative "
            "choice for long-lived roots of trust such as firmware signing. A signature "
            "scheme, never a KEM."
        ),
        nist_category=1,
        quantum_bits=128,
        standard="FIPS 205",
        aliases=("SPHINCS+-SHA2-128s", "sphincsplus128s", "slh_dsa_sha2_128s"),
    ),
    AlgorithmSpec(
        name="SLH-DSA-SHA2-192s",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description="Hash-based signature scheme, FIPS 205, NIST category 3.",
        nist_category=3,
        quantum_bits=192,
        standard="FIPS 205",
        aliases=("SPHINCS+-SHA2-192s",),
    ),
    AlgorithmSpec(
        name="SLH-DSA-SHA2-256s",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description="Hash-based signature scheme, FIPS 205, NIST category 5.",
        nist_category=5,
        quantum_bits=256,
        standard="FIPS 205",
        aliases=("SPHINCS+-SHA2-256s",),
    ),
    AlgorithmSpec(
        name="FN-DSA-512",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "FFT over NTRU-Lattice Digital Signature Algorithm (Falcon), selected by "
            "NIST and awaiting final publication as FIPS 206. Compact signatures."
        ),
        nist_category=1,
        quantum_bits=128,
        standard="FIPS 206 (draft)",
        aliases=("Falcon-512", "falcon512"),
    ),
    AlgorithmSpec(
        name="LMS",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "Leighton-Micali Signatures, RFC 8554, approved by NIST SP 800-208 for "
            "firmware and software signing. Stateful: reusing a one-time key index "
            "destroys security, so key state management is a hard requirement."
        ),
        standard="NIST SP 800-208",
        aliases=("HSS", "LMS/HSS"),
    ),
    AlgorithmSpec(
        name="XMSS",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.QUANTUM_SAFE,
        description=(
            "eXtended Merkle Signature Scheme, RFC 8391, approved by NIST SP 800-208. "
            "Stateful, with the same key-state requirement as LMS."
        ),
        standard="NIST SP 800-208",
        aliases=("XMSS-MT", "XMSSMT"),
    ),
)

# ---------------------------------------------------------------------------
# Classical algorithms
# ---------------------------------------------------------------------------
CLASSICAL_ALGORITHMS: tuple[AlgorithmSpec, ...] = (
    AlgorithmSpec(
        name="RSA",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Rivest-Shamir-Adleman, used for signatures and key transport. " + SHOR_BROKEN_NOTE
        ),
        classical_bits=112,
        quantum_bits=0,
        min_acceptable_bits=2048,
        migration=(
            "Replace signing with ML-DSA (FIPS 204), or SLH-DSA where a long-lived root "
            "of trust needs the most conservative assumptions. Replace RSA key transport "
            "with ML-KEM — not with an ML-DSA variant, which cannot establish a secret."
        ),
    ),
    AlgorithmSpec(
        name="ECDSA",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.BROKEN,
        description="Elliptic Curve Digital Signature Algorithm. " + SHOR_BROKEN_NOTE,
        classical_bits=128,
        quantum_bits=0,
        min_acceptable_bits=256,
        migration=(
            "Replace with ML-DSA (FIPS 204). A hybrid certificate carrying both ECDSA "
            "and ML-DSA signatures allows migration without breaking verifiers that do "
            "not yet understand ML-DSA."
        ),
    ),
    AlgorithmSpec(
        name="Ed25519",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "EdDSA over Curve25519. Excellent classically — fast, misuse-resistant, no "
            "nonce reuse hazard — but it is an elliptic-curve scheme and therefore "
            "Shor-breakable. " + SHOR_BROKEN_NOTE
        ),
        classical_bits=128,
        quantum_bits=0,
        migration="Replace with ML-DSA, or deploy a hybrid Ed25519+ML-DSA signature.",
    ),
    AlgorithmSpec(
        name="Ed448",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.BROKEN,
        description="EdDSA over Curve448. " + SHOR_BROKEN_NOTE,
        classical_bits=224,
        quantum_bits=0,
        migration="Replace with ML-DSA-87 for an equivalent conservative level.",
    ),
    AlgorithmSpec(
        name="DSA",
        pq_category=PQCategory.DIGITAL_SIGNATURE,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Digital Signature Algorithm over finite fields. Withdrawn for new use by "
            "NIST, and fragile in practice because a repeated or biased nonce discloses "
            "the private key. " + SHOR_BROKEN_NOTE
        ),
        classical_bits=112,
        quantum_bits=0,
        is_deprecated=True,
        deprecation_reason=(
            "Withdrawn by NIST FIPS 186-5 for new signatures, and historically a source "
            "of catastrophic nonce-reuse failures."
        ),
        migration="Replace with ML-DSA. Do not migrate to ECDSA as an interim step.",
    ),
    AlgorithmSpec(
        name="DH",
        pq_category=PQCategory.KEY_AGREEMENT,
        quantum_risk=QuantumRisk.BROKEN,
        description="Finite-field Diffie-Hellman key agreement. " + SHOR_BROKEN_NOTE,
        classical_bits=112,
        quantum_bits=0,
        min_acceptable_bits=2048,
        migration=(
            "Replace with ML-KEM, ideally as a hybrid with X25519 so classical security "
            "is retained if a weakness is found in the lattice assumption."
        ),
        aliases=("DHE", "Diffie-Hellman"),
    ),
    AlgorithmSpec(
        name="ECDH",
        pq_category=PQCategory.KEY_AGREEMENT,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Elliptic Curve Diffie-Hellman key agreement. "
            + SHOR_BROKEN_NOTE
            + " This is the highest-priority primitive to migrate: traffic captured "
            "today can be decrypted later once the key exchange is broken."
        ),
        classical_bits=128,
        quantum_bits=0,
        migration=(
            "Adopt X25519MLKEM768 hybrid key exchange, which is widely deployed in "
            "TLS 1.3 and retains classical security alongside the PQ guarantee."
        ),
        aliases=("ECDHE",),
    ),
    AlgorithmSpec(
        name="X25519",
        pq_category=PQCategory.KEY_AGREEMENT,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Curve25519 key agreement. The best classical choice available, and still "
            "Shor-breakable. " + SHOR_BROKEN_NOTE
        ),
        classical_bits=128,
        quantum_bits=0,
        migration=(
            "Move to the X25519MLKEM768 hybrid group. Keeping X25519 as the classical "
            "half of a hybrid is the recommended path, not a problem to remove."
        ),
    ),
    # --- Symmetric: reduced by Grover, not broken -------------------------
    AlgorithmSpec(
        name="AES-128-GCM",
        pq_category=PQCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRisk.REDUCED,
        description=("AES-128 in Galois/Counter Mode. Authenticated encryption. " + GROVER_NOTE),
        classical_bits=128,
        quantum_bits=64,
        migration=(
            "Move to AES-256-GCM for data that must stay confidential beyond the next "
            "decade. 64 bits of quantum-reduced strength is the margin that is thin "
            "here, not the mode."
        ),
        aliases=("AES128-GCM", "AES_128_GCM"),
    ),
    AlgorithmSpec(
        name="AES-256-GCM",
        pq_category=PQCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRisk.REDUCED,
        description=(
            "AES-256 in Galois/Counter Mode. " + GROVER_NOTE + " At 256 bits the "
            "remaining ~128 bits of quantum-reduced strength is considered adequate, so "
            "this is NOT a migration target and replacing it is unnecessary work."
        ),
        classical_bits=256,
        quantum_bits=128,
        aliases=("AES256-GCM", "AES_256_GCM"),
    ),
    AlgorithmSpec(
        name="ChaCha20-Poly1305",
        pq_category=PQCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRisk.REDUCED,
        description=(
            "256-bit stream cipher with a Poly1305 authenticator. "
            + GROVER_NOTE
            + " Adequate against a quantum adversary; not a migration target."
        ),
        classical_bits=256,
        quantum_bits=128,
        aliases=("CHACHA20-POLY1305",),
    ),
    AlgorithmSpec(
        name="3DES",
        pq_category=PQCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRisk.REDUCED,
        description=(
            "Triple DES. Already inadequate classically: its 64-bit block makes it "
            "vulnerable to the Sweet32 birthday attack, and NIST disallowed it after "
            "2023. The quantum question is irrelevant — it needs replacing now."
        ),
        classical_bits=112,
        quantum_bits=56,
        is_deprecated=True,
        deprecation_reason="Disallowed by NIST SP 800-131A after 2023; Sweet32 (CVE-2016-2183).",
        migration="Replace with AES-256-GCM.",
        aliases=("DES-EDE3", "TripleDES", "DESede"),
    ),
    AlgorithmSpec(
        name="DES",
        pq_category=PQCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Single DES with a 56-bit key, exhaustively searchable on commodity "
            "hardware. Broken classically, with or without a quantum computer."
        ),
        classical_bits=56,
        quantum_bits=28,
        is_deprecated=True,
        deprecation_reason="A 56-bit key can be brute-forced in hours.",
        migration="Replace with AES-256-GCM immediately.",
    ),
    AlgorithmSpec(
        name="RC4",
        pq_category=PQCategory.SYMMETRIC_ENCRYPTION,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Stream cipher with statistical biases in its keystream that permit "
            "plaintext recovery. Prohibited in TLS by RFC 7465."
        ),
        classical_bits=0,
        quantum_bits=0,
        is_deprecated=True,
        deprecation_reason="Prohibited in TLS by RFC 7465; keystream biases are exploitable.",
        migration="Replace with AES-256-GCM or ChaCha20-Poly1305.",
        aliases=("ARCFOUR", "ARC4"),
    ),
    # --- Hashes: reduced by Grover, not broken ---------------------------
    AlgorithmSpec(
        name="SHA-256",
        pq_category=PQCategory.HASH,
        quantum_risk=QuantumRisk.REDUCED,
        description=(
            "SHA-2 family, 256-bit output. " + GROVER_NOTE + " Collision resistance "
            "drops to roughly 128 bits, which remains adequate. Not a PQ migration "
            "target."
        ),
        classical_bits=128,
        quantum_bits=128,
        aliases=("SHA256", "sha2-256"),
    ),
    AlgorithmSpec(
        name="SHA-384",
        pq_category=PQCategory.HASH,
        quantum_risk=QuantumRisk.REDUCED,
        description="SHA-2, 384-bit output. Adequate against a quantum adversary.",
        classical_bits=192,
        quantum_bits=192,
        aliases=("SHA384",),
    ),
    AlgorithmSpec(
        name="SHA-512",
        pq_category=PQCategory.HASH,
        quantum_risk=QuantumRisk.REDUCED,
        description="SHA-2, 512-bit output. Adequate against a quantum adversary.",
        classical_bits=256,
        quantum_bits=256,
        aliases=("SHA512",),
    ),
    AlgorithmSpec(
        name="SHA3-256",
        pq_category=PQCategory.HASH,
        quantum_risk=QuantumRisk.REDUCED,
        description=(
            "SHA-3 (Keccak), 256-bit output. Different internal construction from "
            "SHA-2, which is useful for algorithm diversity. Adequate against a "
            "quantum adversary."
        ),
        classical_bits=128,
        quantum_bits=128,
        aliases=("SHA3_256",),
    ),
    AlgorithmSpec(
        name="SHA-1",
        pq_category=PQCategory.HASH,
        quantum_risk=QuantumRisk.BROKEN,
        description=(
            "Practical chosen-prefix collisions exist (SHA-1 is a Shambles, 2020), so it "
            "is broken classically for any use that depends on collision resistance."
        ),
        classical_bits=0,
        quantum_bits=0,
        is_deprecated=True,
        deprecation_reason="Chosen-prefix collisions demonstrated in 2020; disallowed by NIST.",
        migration="Replace with SHA-256 or SHA3-256.",
        aliases=("SHA1",),
    ),
    AlgorithmSpec(
        name="MD5",
        pq_category=PQCategory.HASH,
        quantum_risk=QuantumRisk.BROKEN,
        description=("Collisions are computable in seconds. Broken for every security purpose."),
        classical_bits=0,
        quantum_bits=0,
        is_deprecated=True,
        deprecation_reason="Collisions computable in seconds since 2004.",
        migration="Replace with SHA-256.",
    ),
)

# ---------------------------------------------------------------------------
# Hybrid key exchange groups
# ---------------------------------------------------------------------------
HYBRID_GROUPS: dict[str, tuple[str, ...]] = {
    "X25519MLKEM768": ("X25519", "ML-KEM-768"),
    "x25519_kyber768": ("X25519", "ML-KEM-768"),
    "X25519Kyber768Draft00": ("X25519", "ML-KEM-768"),
    "SecP256r1MLKEM768": ("ECDH", "ML-KEM-768"),
    "p256_kyber768": ("ECDH", "ML-KEM-768"),
    "SecP384r1MLKEM1024": ("ECDH", "ML-KEM-1024"),
    "p384_kyber1024": ("ECDH", "ML-KEM-1024"),
}

#: Weak TLS cipher-suite markers. Each entry is the reason it is weak, which is
#: what a report needs rather than a bare "weak cipher" label.
WEAK_TLS_MARKERS: dict[str, str] = {
    "NULL": "No encryption at all; the data is sent in the clear.",
    "EXPORT": "Deliberately weakened 1990s export-grade key sizes (FREAK, Logjam).",
    "anon": "Anonymous key exchange performs no server authentication.",
    "ADH": "Anonymous Diffie-Hellman performs no server authentication.",
    "AECDH": "Anonymous ECDH performs no server authentication.",
    "RC4": "RC4 keystream biases permit plaintext recovery (RFC 7465 prohibits it).",
    "DES-CBC3": "3DES has a 64-bit block and is vulnerable to Sweet32 (CVE-2016-2183).",
    "DES-CBC": "Single DES has a brute-forceable 56-bit key.",
    "MD5": "MD5 integrity offers no collision resistance.",
    "RC2": "RC2 is obsolete and cryptographically weak.",
    "SEED": "SEED is obsolete outside legacy Korean deployments.",
    "IDEA": "IDEA is obsolete and has a small 64-bit block.",
    "PSK": "A pre-shared key suite without certificates provides no PKI authentication.",
    "SRP": "SRP suites are rarely reviewed and seldom correctly configured.",
    "CAMELLIA": "Not broken, but outside the modern recommended set.",
}

#: TLS protocol versions and whether they are acceptable.
TLS_VERSIONS: dict[str, dict[str, object]] = {
    "SSLv2": {
        "acceptable": False,
        "severity": "critical",
        "reason": (
            "SSL 2.0 has fundamental design flaws including an unprotected handshake. "
            "Prohibited by RFC 6176."
        ),
    },
    "SSLv3": {
        "acceptable": False,
        "severity": "critical",
        "reason": "SSL 3.0 is broken by POODLE (CVE-2014-3566). Prohibited by RFC 7568.",
    },
    "TLSv1": {
        "acceptable": False,
        "severity": "high",
        "reason": (
            "TLS 1.0 relies on SHA-1 and MD5 in the handshake and is vulnerable to BEAST. "
            "Deprecated by RFC 8996; browsers removed support in 2020."
        ),
    },
    "TLSv1.1": {
        "acceptable": False,
        "severity": "high",
        "reason": "TLS 1.1 is deprecated by RFC 8996 and offers no modern AEAD suites.",
    },
    "TLSv1.2": {
        "acceptable": True,
        "severity": "info",
        "reason": (
            "Acceptable when restricted to AEAD suites with forward secrecy. TLS 1.3 is "
            "preferred, and PQ hybrid key exchange requires TLS 1.3."
        ),
    },
    "TLSv1.3": {
        "acceptable": True,
        "severity": "info",
        "reason": (
            "Current best practice. Forward secrecy and AEAD are mandatory, and it is "
            "the only version that carries hybrid post-quantum key exchange."
        ),
    },
}

#: Source-code markers for cryptographic use, so code can be inventoried
#: alongside live TLS configuration.
CODE_CRYPTO_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\bML[-_]?KEM[-_]?(512|768|1024)\b", re.I), "ML-KEM-{0}", "code"),
    (re.compile(r"\bKyber[-_]?(512|768|1024)\b", re.I), "ML-KEM-{0}", "code"),
    (re.compile(r"\bML[-_]?DSA[-_]?(44|65|87)\b", re.I), "ML-DSA-{0}", "code"),
    (re.compile(r"\bDilithium[-_]?([2-5])\b", re.I), "ML-DSA", "code"),
    (re.compile(r"\bSLH[-_]?DSA\b", re.I), "SLH-DSA-SHA2-128s", "code"),
    (re.compile(r"\bSPHINCS\+?", re.I), "SLH-DSA-SHA2-128s", "code"),
    (re.compile(r"\bX25519MLKEM768\b", re.I), "X25519MLKEM768", "code"),
    (
        re.compile(r"\b(?:rsa|RSA)\.generate_private_key|generateKeyPair\s*\(\s*[\"']RSA"),
        "RSA",
        "code",
    ),
    (re.compile(r"\bRSA[-_/]?(1024|2048|3072|4096)\b"), "RSA", "code"),
    (re.compile(r"\bec\.(?:SECP256R1|SECP384R1|SECP521R1)\b"), "ECDSA", "code"),
    (re.compile(r"\bECDSA\b"), "ECDSA", "code"),
    (re.compile(r"\bEd25519\b", re.I), "Ed25519", "code"),
    (re.compile(r"\bEd448\b", re.I), "Ed448", "code"),
    (re.compile(r"\bX25519\b"), "X25519", "code"),
    (re.compile(r"\bECDHE?\b"), "ECDH", "code"),
    (re.compile(r"\bAES[-_]?256[-_]?GCM\b", re.I), "AES-256-GCM", "code"),
    (re.compile(r"\bAES[-_]?128[-_]?GCM\b", re.I), "AES-128-GCM", "code"),
    (re.compile(r"\bChaCha20", re.I), "ChaCha20-Poly1305", "code"),
    (re.compile(r"\b3DES\b|\bDESede\b|\bTripleDES\b", re.I), "3DES", "code"),
    (re.compile(r"\bRC4\b|\bARC4\b", re.I), "RC4", "code"),
    (re.compile(r"\bMD5\b", re.I), "MD5", "code"),
    (re.compile(r"\bSHA[-_]?1\b", re.I), "SHA-1", "code"),
    (re.compile(r"\bSHA[-_]?256\b", re.I), "SHA-256", "code"),
    (re.compile(r"\bSHA3[-_]?256\b", re.I), "SHA3-256", "code"),
)

# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------
ALL_ALGORITHMS: tuple[AlgorithmSpec, ...] = (*PQ_ALGORITHMS, *CLASSICAL_ALGORITHMS)

_INDEX: dict[str, AlgorithmSpec] = {}
for _spec in ALL_ALGORITHMS:
    _INDEX[_spec.name.upper()] = _spec
    for _alias in _spec.aliases:
        _INDEX[_alias.upper()] = _spec


def lookup(name: str) -> AlgorithmSpec | None:
    """Resolve an algorithm name or alias to its specification."""
    if not name:
        return None
    key = name.strip().upper()
    if key in _INDEX:
        return _INDEX[key]
    # Normalise common separator variations before giving up.
    for candidate in (
        key.replace("_", "-"),
        key.replace("-", ""),
        key.replace("_", ""),
        key.replace(" ", "-"),
    ):
        if candidate in _INDEX:
            return _INDEX[candidate]
    return None


def classify(name: str) -> tuple[PQCategory, QuantumRisk]:
    """Classify an algorithm, defaulting to unknown rather than guessing.

    An unrecognised algorithm is reported as unknown. Guessing a category would
    be worse than admitting ignorance: a KEM recorded as a signature scheme
    produces a migration plan that cannot work.
    """
    spec = lookup(name)
    if spec is not None:
        return spec.pq_category, spec.quantum_risk
    return PQCategory.UNKNOWN, QuantumRisk.UNKNOWN


def is_hybrid(group_name: str) -> tuple[bool, tuple[str, ...]]:
    """Whether a named key-exchange group is a classical+PQ hybrid."""
    for name, components in HYBRID_GROUPS.items():
        if name.upper() == group_name.strip().upper():
            return True, components
    return False, ()


def rsa_security_bits(key_size: int) -> int:
    """Approximate classical security of an RSA key, per NIST SP 800-57."""
    if key_size >= 15360:
        return 256
    if key_size >= 7680:
        return 192
    if key_size >= 3072:
        return 128
    if key_size >= 2048:
        return 112
    if key_size >= 1024:
        return 80
    return 0


def weak_tls_reason(cipher_name: str) -> str | None:
    """Why a cipher suite is weak, or ``None`` if it is acceptable."""
    upper = cipher_name.upper()
    for marker, reason in WEAK_TLS_MARKERS.items():
        if marker.upper() in upper:
            return reason
    if "CBC" in upper and "TLS_" not in upper:
        return (
            "CBC-mode suites in TLS 1.2 and earlier use MAC-then-encrypt and have a "
            "history of padding-oracle attacks (Lucky13). Prefer an AEAD suite."
        )
    if not any(aead in upper for aead in ("GCM", "CHACHA20", "CCM")):
        return "The suite does not use authenticated encryption (AEAD)."
    return None
