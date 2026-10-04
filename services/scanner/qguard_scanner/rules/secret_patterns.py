"""Secret detection patterns.

Each rule pairs a regular expression with the metadata needed to act on a hit:
how severe an exposure of that credential type is, whether the match is
specific enough to trust on its own, and how to remediate it.

Two detection strategies are combined:

* **Provider patterns** match credentials with a recognisable structure (an AWS
  access key id, a GitHub token, a Stripe key). These are high-confidence
  because the shape is distinctive, so they fire without an entropy check.

* **Entropy screening** catches credentials with no fixed shape — a random
  password or an in-house token — by looking for a high-entropy string
  assigned to a secret-sounding name. This is lower confidence by nature, so
  the rules require both signals and the finding says so.

Patterns are deliberately conservative. A false positive in secret detection
costs an engineer a rotation they did not need, and enough of them train people
to ignore the whole category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "high", "medium", "low", "tentative"]
    secret_type: str
    remediation: str
    #: The capture group holding the credential itself. 0 means the whole match.
    secret_group: int = 0
    #: Minimum Shannon entropy (bits/char) the captured value must have.
    min_entropy: float = 0.0
    #: Whether the credential can be checked for validity without using it.
    verifiable: bool = False
    references: tuple[str, ...] = ()


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE if pattern.startswith("(?i)") else 0)


ROTATE_FIRST = (
    "Treat this credential as compromised and rotate it now. Anything in a "
    "repository, build artifact or application package should be assumed to have "
    "been read. Rotating first and cleaning history second is the right order: "
    "removing the file does not invalidate the credential."
)

#: High-confidence provider credentials.
PROVIDER_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        rule_id="secrets.aws-access-key-id",
        name="AWS access key ID",
        pattern=_c(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        severity="critical",
        confidence="high",
        secret_type="aws_access_key_id",
        secret_group=1,
        verifiable=True,
        remediation=(
            "Deactivate and delete this access key in IAM, then replace it with a short-lived "
            "role credential. A long-lived key in source is the single most common cause of "
            "cloud account compromise. " + ROTATE_FIRST
        ),
        references=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        ),
    ),
    SecretRule(
        rule_id="secrets.aws-secret-access-key",
        name="AWS secret access key",
        pattern=_c(
            r"(?i)aws(?:.{0,20})?(?:secret|sk)(?:.{0,20})?['\"]?\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9/+=]{40})"
        ),
        severity="critical",
        confidence="high",
        secret_type="aws_secret_access_key",
        secret_group=1,
        min_entropy=4.0,
        remediation="Deactivate the key pair in IAM and move to role-based credentials. "
        + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.github-token",
        name="GitHub token",
        pattern=_c(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
        severity="critical",
        confidence="high",
        secret_type="github_token",
        secret_group=1,
        verifiable=True,
        remediation=(
            "Revoke the token in GitHub settings and issue a replacement with the narrowest "
            "scopes that work. " + ROTATE_FIRST
        ),
    ),
    SecretRule(
        rule_id="secrets.github-pat-fine-grained",
        name="GitHub fine-grained personal access token",
        pattern=_c(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"),
        severity="critical",
        confidence="high",
        secret_type="github_token",
        secret_group=1,
        verifiable=True,
        remediation="Revoke the token in GitHub settings. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.gitlab-token",
        name="GitLab personal access token",
        pattern=_c(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
        severity="critical",
        confidence="high",
        secret_type="gitlab_token",
        secret_group=1,
        remediation="Revoke the token in GitLab and reissue with minimal scopes. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.slack-token",
        name="Slack token",
        pattern=_c(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,})\b"),
        severity="high",
        confidence="high",
        secret_type="slack_token",
        secret_group=1,
        remediation="Revoke the token in the Slack app configuration. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.slack-webhook",
        name="Slack incoming webhook",
        pattern=_c(
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"
        ),
        severity="medium",
        confidence="high",
        secret_type="slack_webhook",
        secret_group=1,
        remediation=(
            "Delete the webhook in Slack and create a new one. A webhook URL is a bearer "
            "credential: anyone holding it can post as the integration."
        ),
    ),
    SecretRule(
        rule_id="secrets.stripe-secret-key",
        name="Stripe secret key",
        pattern=_c(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b"),
        severity="critical",
        confidence="high",
        secret_type="stripe_key",
        secret_group=1,
        remediation=(
            "Roll the key in the Stripe dashboard. A live secret key permits charges and "
            "refunds against the account. " + ROTATE_FIRST
        ),
    ),
    SecretRule(
        rule_id="secrets.google-api-key",
        name="Google API key",
        pattern=_c(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        severity="high",
        confidence="high",
        secret_type="google_api_key",
        secret_group=1,
        remediation=(
            "Delete the key in the Google Cloud console and create a replacement with API "
            "and referrer restrictions applied. " + ROTATE_FIRST
        ),
    ),
    SecretRule(
        rule_id="secrets.gcp-service-account",
        name="Google Cloud service account key",
        pattern=_c(r'"type"\s*:\s*"service_account"'),
        severity="critical",
        confidence="high",
        secret_type="gcp_service_account_key",
        remediation=(
            "Delete this service account key and adopt workload identity federation so no "
            "long-lived key file exists. " + ROTATE_FIRST
        ),
    ),
    SecretRule(
        rule_id="secrets.azure-storage-key",
        name="Azure storage account key",
        pattern=_c(r"(?i)(?:AccountKey|storage[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{86}==)"),
        severity="critical",
        confidence="high",
        secret_type="azure_storage_key",
        secret_group=1,
        remediation="Rotate the key in the Azure portal and prefer SAS tokens or managed "
        "identity. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.private-key",
        name="Private key material",
        pattern=_c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        severity="critical",
        confidence="confirmed",
        secret_type="private_key",
        remediation=(
            "Generate a new key pair and retire this one everywhere it is trusted. A private "
            "key in source must be assumed compromised: possession is the whole secret."
        ),
    ),
    SecretRule(
        rule_id="secrets.jwt-token",
        name="JSON Web Token",
        pattern=_c(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
        severity="medium",
        confidence="medium",
        secret_type="jwt",
        secret_group=1,
        remediation=(
            "Check what this token grants and whether it has expired. If it is a long-lived "
            "service token, revoke it and shorten the lifetime. A JWT in source is often a "
            "test fixture, so confirm before treating it as live."
        ),
    ),
    SecretRule(
        rule_id="secrets.npm-token",
        name="npm access token",
        pattern=_c(r"\b(npm_[A-Za-z0-9]{36})\b"),
        severity="high",
        confidence="high",
        secret_type="npm_token",
        secret_group=1,
        remediation=(
            "Revoke the token on npmjs.com. A publish-scoped token allows pushing a malicious "
            "version of your package, which is a supply-chain compromise. " + ROTATE_FIRST
        ),
    ),
    SecretRule(
        rule_id="secrets.pypi-token",
        name="PyPI API token",
        pattern=_c(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"),
        severity="high",
        confidence="high",
        secret_type="pypi_token",
        secret_group=1,
        remediation="Revoke the token on PyPI and scope the replacement to one project. "
        + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.openai-key",
        name="OpenAI API key",
        pattern=_c(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"),
        severity="high",
        confidence="medium",
        secret_type="llm_api_key",
        secret_group=1,
        min_entropy=3.5,
        remediation="Revoke the key with the provider and store the replacement in a secrets "
        "manager. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.anthropic-key",
        name="Anthropic API key",
        pattern=_c(r"\b(sk-ant-[A-Za-z0-9_\-]{32,})\b"),
        severity="high",
        confidence="high",
        secret_type="llm_api_key",
        secret_group=1,
        remediation="Revoke the key in the provider console. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.sendgrid-key",
        name="SendGrid API key",
        pattern=_c(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b"),
        severity="high",
        confidence="high",
        secret_type="sendgrid_key",
        secret_group=1,
        remediation="Delete the key in SendGrid. A mail-sending key enables phishing from "
        "your domain. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.twilio-key",
        name="Twilio API credential",
        pattern=_c(r"\b(SK[0-9a-fA-F]{32})\b"),
        severity="high",
        confidence="medium",
        secret_type="twilio_key",
        secret_group=1,
        remediation="Delete the API key in the Twilio console. " + ROTATE_FIRST,
    ),
    SecretRule(
        rule_id="secrets.database-url",
        name="Database connection string with embedded password",
        pattern=_c(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|"
            r"clickhouse|mariadb)://[^:@/\s]+:([^@\s'\"]{4,})@[^\s'\"<>]+)"
        ),
        severity="critical",
        confidence="high",
        secret_type="database_credentials",
        secret_group=1,
        remediation=(
            "Rotate the database password and move the connection string to configuration "
            "injected at runtime. Embedding the password in a URL puts it in logs, error "
            "messages and process listings as well as source."
        ),
    ),
    SecretRule(
        rule_id="secrets.basic-auth-url",
        name="URL with embedded credentials",
        pattern=_c(r"\b(https?://[^:@/\s]+:([^@\s'\"]{4,})@[^\s'\"<>]+)"),
        severity="high",
        confidence="medium",
        secret_type="basic_auth_credentials",
        secret_group=1,
        remediation=(
            "Remove the credentials from the URL and send them in an Authorization header or "
            "inject them from configuration. Credentials in a URL leak through referrers, "
            "logs and browser history."
        ),
    ),
)

#: Names that indicate the assigned value is a credential. Combined with an
#: entropy threshold so a secret with no recognisable shape is still found.
SECRET_NAME_PATTERN = _c(
    r"(?i)\b((?:api|access|secret|private|auth|session|encryption|signing|master|"
    r"client|refresh|bearer|webhook|slack|stripe|twilio|sendgrid|db|database|"
    r"redis|mongo|postgres|mysql|jwt|hmac|crypto)?[_\-\.]?"
    r"(?:key|token|secret|password|passwd|pwd|credential|credentials|passphrase|"
    r"apikey|api_key|auth|signature))\b\s*[:=]\s*"
    r"['\"]([^'\"\s]{12,256})['\"]"
)

GENERIC_RULE = SecretRule(
    rule_id="secrets.high-entropy-assignment",
    name="High-entropy value assigned to a credential-named field",
    pattern=SECRET_NAME_PATTERN,
    severity="medium",
    confidence="low",
    secret_type="generic_credential",
    secret_group=2,
    # 3.4 bits/char filters English words and short identifiers while still
    # catching base64 and hex credentials. Tuned to keep false positives low:
    # too many and the whole category gets ignored.
    min_entropy=3.4,
    remediation=(
        "Confirm whether this value is a live credential. If it is, rotate it and move it "
        "into a secrets manager or runtime-injected configuration. Detected by entropy "
        "rather than a known provider format, so verify before acting."
    ),
)

#: Values that look like credentials but are placeholders. Checked before a
#: finding is raised, because reporting these is what makes engineers stop
#: reading secret findings.
PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "changeme",
        "change_me",
        "change-me",
        "placeholder",
        "example",
        "test",
        "testing",
        "dummy",
        "sample",
        "yourkeyhere",
        "your_key_here",
        "xxx",
        "todo",
        "fixme",
        "none",
        "null",
        "nil",
        "undefined",
        "redacted",
        "insertkeyhere",
        "replaceme",
        "notasecret",
        "fake",
        "mock",
        "secret",
        "password",
        "mypassword",
        "s3cret",
        "abc123",
        "foobar",
        "lorem",
    }
)

PLACEHOLDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    _c(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$"),  # ${VAR} / $VAR
    _c(r"^\{\{.*\}\}$"),  # {{ template }}
    _c(r"^<[^>]+>$"),  # <your-key>
    _c(r"^%[A-Za-z_]+%$"),  # %VAR%
    _c(r"(?i)^(?:x{6,}|y{6,}|z{6,}|a{6,}|0{6,}|1{6,}|\*{6,}|\.{3,})$"),
    _c(r"(?i)^(?:your|my|the|example|sample|test|dummy|fake|placeholder)[_\-]"),
    _c(r"(?i)(?:example|placeholder|redacted|removed|sanitized)\.(?:com|org|net|local)"),
    _c(r"^(?:[A-Za-z]+_){2,}[A-Za-z]+$"),  # Mixed_Case_Identifier
    # A pure lowercase snake_case token is an identifier, not a credential:
    # generated secrets are not spelled in words joined by underscores. This
    # is what stops a keyword argument such as ``key="known_exploited"`` from
    # being reported as a high-entropy secret.
    _c(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$"),
    # Variable and bind-parameter references: the value is supplied elsewhere,
    # so the literal here is a name, not a secret.
    _c(r"^:'[A-Za-z_][A-Za-z0-9_]*'$"),  # psql :'var'
    _c(r"^:[A-Za-z_][A-Za-z0-9_]*$"),  # :bind_param
    _c(r"^%\([A-Za-z_][A-Za-z0-9_]*\)s$"),  # %(name)s
    _c(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$"),  # {name}
    _c(r"(?i)^(?:true|false|none|null|enabled|disabled|localhost|127\.0\.0\.1)$"),
)

#: Paths that are examples or fixtures by convention. Findings there are
#: reported at reduced severity rather than suppressed, since a real credential
#: does sometimes get committed to a test fixture.
EXAMPLE_PATH_PATTERN = _c(
    r"(?i)(?:^|/)(?:test|tests|spec|specs|fixtures?|examples?|samples?|mocks?|"
    r"__tests__|__mocks__|testdata|docs?|documentation)(?:/|$)"
    r"|(?:\.example|\.sample|\.template|\.dist)(?:\.|$)"
    r"|(?:^|/)(?:\.env\.example|\.env\.sample|\.env\.template)$"
)

#: Files never worth scanning for secrets: binary, compiled, or vendored.
SKIP_FILE_PATTERN = _c(
    r"(?i)\.(?:png|jpe?g|gif|bmp|ico|svg|webp|tiff?|mp[34]|wav|ogg|avi|mov|mkv|"
    r"woff2?|ttf|eot|otf|pdf|zip|gz|bz2|xz|7z|rar|tar|jar|war|ear|class|pyc|pyo|"
    r"so|dylib|dll|exe|bin|dat|db|sqlite3?|lock|min\.js|min\.css|map)$"
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "target",
        ".next",
        ".nuxt",
        ".gradle",
        ".idea",
        ".vscode",
        "site-packages",
        "bower_components",
        ".terraform",
        "coverage",
        ".tox",
        ".eggs",
        "htmlcov",
    }
)

ALL_RULES: tuple[SecretRule, ...] = (*PROVIDER_RULES, GENERIC_RULE)
RULES_BY_ID: dict[str, SecretRule] = {r.rule_id: r for r in ALL_RULES}


def is_placeholder(value: str) -> bool:
    """Whether a captured value is evidently not a real credential."""
    stripped = value.strip().strip("\"'")
    if not stripped or len(stripped) < 8:
        return True
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    # A value made only of one repeated character carries no entropy.
    if len(set(stripped)) <= 2:
        return True
    return any(pattern.search(stripped) for pattern in PLACEHOLDER_PATTERNS)


def is_example_path(path: str) -> bool:
    return bool(EXAMPLE_PATH_PATTERN.search(path))


def should_skip_file(path: str) -> bool:
    return bool(SKIP_FILE_PATTERN.search(path))
