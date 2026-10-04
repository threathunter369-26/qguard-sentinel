"""Network service catalogue.

Maps TCP ports to the services conventionally found on them, and records what
exposure of each service actually means. The severity attached to a service is
the severity of *reachability* — an open PostgreSQL port is not itself a
vulnerability, but a datastore reachable from the scan origin is a finding
worth raising, and the catalogue states why rather than asserting a number.

Two properties drive most of the reasoning:

* ``is_cleartext`` — the protocol carries credentials or data without
  transport encryption, so exposure means interception is possible.
* ``is_administrative`` / ``is_datastore`` — the service grants management
  control or holds data directly, so exposure removes a layer of defence.

The catalogue is deliberately conservative: a service is only described as
identified when a banner or port convention supports it, and an unknown port
is reported as unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Exposure = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True, slots=True)
class ServiceDefinition:
    """What is conventionally served on a port, and what exposure means."""

    name: str
    """Short protocol or product name, e.g. ``postgresql``."""
    label: str
    """Human-readable name for the UI, e.g. ``PostgreSQL database``."""
    category: str
    """Grouping used for reporting: ``database``, ``remote_access``, ``web``…"""
    exposure_severity: Exposure
    """Severity of this service being reachable from outside its tier."""
    rationale: str
    """Why reachability matters. Shown verbatim in the finding."""
    remediation: str
    is_cleartext: bool = False
    is_administrative: bool = False
    is_datastore: bool = False
    expects_banner: bool = True
    """Whether the service greets the client. Used to read a silent socket honestly."""
    secure_alternative: str | None = None
    cwe: str | None = None
    references: tuple[str, ...] = ()


def _svc(
    port_names: str,
    label: str,
    category: str,
    exposure: Exposure,
    rationale: str,
    remediation: str,
    **kwargs: object,
) -> ServiceDefinition:
    return ServiceDefinition(
        name=port_names,
        label=label,
        category=category,
        exposure_severity=exposure,
        rationale=rationale,
        remediation=remediation,
        **kwargs,  # type: ignore[arg-type]
    )


#: Port → service. Only ports with a meaningful security reading are listed;
#: an unlisted open port is reported as an unidentified service rather than
#: being guessed at.
PORT_SERVICES: dict[int, ServiceDefinition] = {
    21: _svc(
        "ftp",
        "FTP",
        "file_transfer",
        "high",
        "FTP authenticates and transfers in cleartext, so any on-path observer "
        "recovers the credentials and the file contents. It also commonly allows "
        "anonymous access by default.",
        "Replace FTP with SFTP or FTPS and close port 21.",
        is_cleartext=True,
        secure_alternative="SFTP (port 22) or FTPS",
        cwe="CWE-319",
    ),
    22: _svc(
        "ssh",
        "SSH",
        "remote_access",
        "medium",
        "SSH grants interactive shell access. Exposure is normal for managed "
        "infrastructure but it is the single most credential-attacked service on "
        "the internet, so it belongs behind an allow-list or bastion.",
        "Restrict source addresses, disable password authentication in favour of "
        "keys or certificates, and front it with a bastion where possible.",
        is_administrative=True,
        cwe="CWE-284",
    ),
    23: _svc(
        "telnet",
        "Telnet",
        "remote_access",
        "critical",
        "Telnet carries the login and the entire session in cleartext and offers "
        "no host authentication, so an on-path attacker both reads and hijacks "
        "the session. There is no configuration that makes it safe.",
        "Disable Telnet entirely and use SSH.",
        is_cleartext=True,
        is_administrative=True,
        secure_alternative="SSH (port 22)",
        cwe="CWE-319",
    ),
    25: _svc(
        "smtp",
        "SMTP",
        "mail",
        "low",
        "An exposed SMTP service is expected on a mail gateway. It matters when "
        "it relays without authentication, which turns it into spam "
        "infrastructure and damages the domain's sending reputation.",
        "Confirm relaying is restricted to authenticated senders and that "
        "STARTTLS is offered and enforced for submission.",
        is_cleartext=True,
    ),
    53: _svc(
        "dns",
        "DNS",
        "infrastructure",
        "low",
        "An exposed resolver matters if it answers recursive queries for "
        "arbitrary clients, which makes it usable for amplification attacks.",
        "Restrict recursion to internal clients; serve authoritative zones only to the public.",
        expects_banner=False,
    ),
    110: _svc(
        "pop3",
        "POP3",
        "mail",
        "medium",
        "POP3 without TLS carries mailbox credentials in cleartext.",
        "Offer POP3S (995) only, or require STARTTLS before AUTH.",
        is_cleartext=True,
        secure_alternative="POP3S (port 995)",
        cwe="CWE-319",
    ),
    135: _svc(
        "msrpc",
        "Microsoft RPC endpoint mapper",
        "windows",
        "high",
        "The RPC endpoint mapper enumerates the services a Windows host offers "
        "and has a long history of remotely exploitable flaws. It is not "
        "intended to be reachable outside a trusted network.",
        "Block 135 at the network boundary; it has no legitimate internet-facing use.",
        expects_banner=False,
        cwe="CWE-668",
    ),
    139: _svc(
        "netbios-ssn",
        "NetBIOS session service",
        "windows",
        "high",
        "Legacy SMB over NetBIOS supports the obsolete SMBv1 dialect and leaks "
        "host and share information before authentication.",
        "Disable NetBIOS over TCP/IP and block 139 at the boundary.",
        expects_banner=False,
        cwe="CWE-668",
    ),
    143: _svc(
        "imap",
        "IMAP",
        "mail",
        "medium",
        "IMAP without TLS carries mailbox credentials and message contents in cleartext.",
        "Offer IMAPS (993) only, or require STARTTLS before AUTH.",
        is_cleartext=True,
        secure_alternative="IMAPS (port 993)",
        cwe="CWE-319",
    ),
    161: _svc(
        "snmp",
        "SNMP",
        "infrastructure",
        "high",
        "SNMP v1 and v2c authenticate with a community string sent in cleartext, "
        "and defaults such as 'public' are still widespread. Read access exposes "
        "the device's full configuration and interface inventory.",
        "Move to SNMPv3 with authPriv, change default community strings, and "
        "restrict source addresses.",
        is_cleartext=True,
        expects_banner=False,
        cwe="CWE-1392",
    ),
    389: _svc(
        "ldap",
        "LDAP",
        "directory",
        "high",
        "LDAP without TLS carries bind credentials in cleartext, and the "
        "directory it fronts is usually the organisation's identity source.",
        "Require LDAPS (636) or StartTLS, and refuse simple binds over cleartext.",
        is_cleartext=True,
        secure_alternative="LDAPS (port 636)",
        cwe="CWE-319",
    ),
    445: _svc(
        "smb",
        "SMB",
        "file_transfer",
        "critical",
        "Directly reachable SMB is the delivery path used by most "
        "network-propagating ransomware. Exposure also risks share enumeration "
        "and credential relay attacks.",
        "Block 445 at the network boundary without exception; reach file shares over a VPN.",
        expects_banner=False,
        cwe="CWE-668",
    ),
    512: _svc(
        "exec",
        "rexec",
        "remote_access",
        "critical",
        "The Berkeley r-services accept cleartext credentials and trust "
        "host-based authentication that is trivial to spoof.",
        "Remove rexec/rlogin/rsh and use SSH.",
        is_cleartext=True,
        is_administrative=True,
        secure_alternative="SSH (port 22)",
        cwe="CWE-319",
    ),
    513: _svc(
        "login",
        "rlogin",
        "remote_access",
        "critical",
        "The Berkeley r-services accept cleartext credentials and trust "
        "host-based authentication that is trivial to spoof.",
        "Remove rexec/rlogin/rsh and use SSH.",
        is_cleartext=True,
        is_administrative=True,
        secure_alternative="SSH (port 22)",
        cwe="CWE-319",
    ),
    514: _svc(
        "shell",
        "rsh",
        "remote_access",
        "critical",
        "The Berkeley r-services accept cleartext credentials and trust "
        "host-based authentication that is trivial to spoof.",
        "Remove rexec/rlogin/rsh and use SSH.",
        is_cleartext=True,
        is_administrative=True,
        secure_alternative="SSH (port 22)",
        cwe="CWE-319",
    ),
    623: _svc(
        "ipmi",
        "IPMI / BMC",
        "management",
        "critical",
        "A baseboard management controller has power and console control over the "
        "host, below the operating system. IPMI's cipher-zero and RAKP hash "
        "weaknesses make exposed BMCs reliably compromisable.",
        "Place BMCs on an isolated management network reachable only through a jump host.",
        is_administrative=True,
        expects_banner=False,
        cwe="CWE-668",
    ),
    873: _svc(
        "rsync",
        "rsync daemon",
        "file_transfer",
        "high",
        "An rsync daemon frequently runs without authentication, exposing whole "
        "module trees for read and sometimes write.",
        "Require authentication, or tunnel rsync over SSH and close 873.",
        cwe="CWE-306",
    ),
    1433: _svc(
        "mssql",
        "Microsoft SQL Server",
        "database",
        "critical",
        "A database reachable from outside its application tier removes the "
        "layer of defence the application provides, and exposes the instance to "
        "credential attacks against the data directly.",
        "Bind to the private network only, restrict by security group, and reach "
        "it through the application tier or a bastion.",
        is_datastore=True,
        expects_banner=False,
        cwe="CWE-668",
    ),
    1521: _svc(
        "oracle",
        "Oracle TNS listener",
        "database",
        "critical",
        "The TNS listener enumerates instances and service names before "
        "authentication, and the database behind it is reachable directly.",
        "Bind to the private network only and restrict by firewall.",
        is_datastore=True,
        cwe="CWE-668",
    ),
    2375: _svc(
        "docker",
        "Docker daemon (unencrypted)",
        "management",
        "critical",
        "The Docker API on 2375 is unauthenticated and unencrypted. Reachability "
        "is equivalent to root on the host: a container can be started with the "
        "host filesystem mounted.",
        "Never expose 2375. Use a local socket, or TLS client-certificate authentication on 2376.",
        is_administrative=True,
        expects_banner=False,
        cwe="CWE-306",
    ),
    2376: _svc(
        "docker-tls",
        "Docker daemon (TLS)",
        "management",
        "high",
        "The Docker API grants control equivalent to root on the host. TLS "
        "protects the channel but exposure still depends entirely on client "
        "certificate verification being enforced.",
        "Restrict source addresses and confirm `--tlsverify` is enabled.",
        is_administrative=True,
        expects_banner=False,
        cwe="CWE-668",
    ),
    2379: _svc(
        "etcd",
        "etcd client API",
        "database",
        "critical",
        "etcd holds the full cluster state of Kubernetes, including every "
        "Secret in plaintext. Read access to etcd is read access to all "
        "cluster credentials.",
        "Bind etcd to the control-plane network, require client certificates, "
        "and enable encryption at rest.",
        is_datastore=True,
        cwe="CWE-668",
    ),
    3000: _svc(
        "http-dev",
        "HTTP development server",
        "web",
        "medium",
        "Port 3000 conventionally carries a framework development server. Those "
        "servers enable verbose error pages, source maps and debug endpoints "
        "that are not intended to be reachable outside development.",
        "Serve production traffic from a production build behind a reverse "
        "proxy, and close the development port.",
        cwe="CWE-489",
    ),
    3306: _svc(
        "mysql",
        "MySQL / MariaDB",
        "database",
        "critical",
        "A database reachable from outside its application tier removes the "
        "layer of defence the application provides, and exposes the instance to "
        "credential attacks against the data directly.",
        "Bind to the private network only, restrict by security group, and reach "
        "it through the application tier or a bastion.",
        is_datastore=True,
        cwe="CWE-668",
    ),
    3389: _svc(
        "rdp",
        "Remote Desktop",
        "remote_access",
        "high",
        "Exposed RDP is among the most common initial access vectors for "
        "ransomware, through credential stuffing and through protocol flaws such "
        "as BlueKeep.",
        "Require a VPN or RD Gateway, enforce Network Level Authentication, and "
        "never expose 3389 directly.",
        is_administrative=True,
        expects_banner=False,
        cwe="CWE-284",
    ),
    4444: _svc(
        "unexpected",
        "Unregistered service on a commonly abused port",
        "suspicious",
        "high",
        "Port 4444 has no standard service but is the default listener for "
        "several exploitation frameworks. A listener here warrants investigation "
        "rather than assuming a benign cause.",
        "Identify the owning process. If it is not an understood application, "
        "treat the host as potentially compromised and begin an investigation.",
        cwe="CWE-506",
    ),
    5000: _svc(
        "http-alt",
        "HTTP application server",
        "web",
        "low",
        "Port 5000 conventionally carries an application server, often a development-mode one.",
        "Confirm the service is intended to be reachable and is running in "
        "production mode behind a reverse proxy.",
    ),
    5432: _svc(
        "postgresql",
        "PostgreSQL",
        "database",
        "critical",
        "A database reachable from outside its application tier removes the "
        "layer of defence the application provides, and exposes the instance to "
        "credential attacks against the data directly.",
        "Bind to the private network only, restrict by security group, and reach "
        "it through the application tier or a bastion.",
        is_datastore=True,
        expects_banner=False,
        cwe="CWE-668",
    ),
    5601: _svc(
        "kibana",
        "Kibana",
        "management",
        "high",
        "Kibana is a console over the search cluster's data and, when security "
        "is not enabled, grants unauthenticated read and write to every index.",
        "Enable authentication, put Kibana behind SSO, and restrict source addresses.",
        is_administrative=True,
        cwe="CWE-306",
    ),
    5900: _svc(
        "vnc",
        "VNC",
        "remote_access",
        "critical",
        "VNC's native authentication is an 8-character DES challenge and many "
        "deployments have none at all. Exposure gives direct console control of "
        "the desktop session.",
        "Tunnel VNC over SSH or a VPN and never expose 5900 directly.",
        is_administrative=True,
        cwe="CWE-284",
    ),
    6379: _svc(
        "redis",
        "Redis",
        "database",
        "critical",
        "Redis ships without authentication by default. An exposed instance "
        "yields all cached data, and CONFIG SET plus a crafted key can write "
        "files on the host, which is a routine path to remote code execution.",
        "Set `requirepass` or ACLs, bind to localhost or the private network, "
        "enable protected mode, and rename or disable CONFIG.",
        is_datastore=True,
        cwe="CWE-306",
    ),
    7474: _svc(
        "neo4j",
        "Neo4j HTTP",
        "database",
        "high",
        "The Neo4j HTTP endpoint accepts Cypher queries against the graph and "
        "has historically shipped with well-known default credentials.",
        "Change the default password, bind to the private network, and restrict source addresses.",
        is_datastore=True,
        cwe="CWE-1392",
    ),
    8080: _svc(
        "http-proxy",
        "HTTP (alternate port)",
        "web",
        "low",
        "Port 8080 commonly fronts an application server or proxy directly, "
        "bypassing the TLS termination and WAF applied to 443.",
        "Confirm the port is meant to be reachable; if it is an origin behind a "
        "proxy, restrict it to the proxy's addresses.",
    ),
    8086: _svc(
        "influxdb",
        "InfluxDB",
        "database",
        "high",
        "InfluxDB's HTTP API exposes query and write access to time-series data, "
        "and older versions default to no authentication.",
        "Enable authentication and bind to the private network.",
        is_datastore=True,
        cwe="CWE-306",
    ),
    8443: _svc(
        "https-alt",
        "HTTPS (alternate port)",
        "web",
        "low",
        "Port 8443 commonly fronts an application server or management console over TLS.",
        "Confirm the service is meant to be reachable and that its certificate "
        "and TLS configuration are assessed.",
    ),
    9000: _svc(
        "http-mgmt",
        "Management or application console",
        "management",
        "medium",
        "Port 9000 carries a range of management consoles (Portainer, SonarQube, "
        "MinIO) whose defaults frequently include unauthenticated setup pages.",
        "Identify the service, confirm authentication is enabled, and restrict source addresses.",
        is_administrative=True,
    ),
    9200: _svc(
        "elasticsearch",
        "Elasticsearch HTTP",
        "database",
        "critical",
        "Elasticsearch's REST API historically shipped without authentication. "
        "An exposed cluster yields every index for read and delete, which is the "
        "cause of a long series of mass data exposures.",
        "Enable the security plugin with authentication and TLS, and bind to the private network.",
        is_datastore=True,
        cwe="CWE-306",
    ),
    11211: _svc(
        "memcached",
        "Memcached",
        "database",
        "critical",
        "Memcached has no authentication. An exposed instance leaks all cached "
        "values — frequently session tokens — and its UDP counterpart is the "
        "largest known reflection amplifier.",
        "Bind to localhost or the private network, disable UDP, and restrict by firewall.",
        is_datastore=True,
        cwe="CWE-306",
    ),
    15672: _svc(
        "rabbitmq-mgmt",
        "RabbitMQ management console",
        "management",
        "high",
        "The RabbitMQ management plugin ships with the guest/guest account and "
        "grants full control over queues and messages.",
        "Delete the guest user, require strong credentials, and restrict the "
        "management port to the private network.",
        is_administrative=True,
        cwe="CWE-1392",
    ),
    27017: _svc(
        "mongodb",
        "MongoDB",
        "database",
        "critical",
        "MongoDB without authorization enabled grants full read and write to "
        "every database. Exposed instances are routinely found, wiped and held "
        "for ransom by automated scanners.",
        "Enable authorization, bind to the private network, and require TLS.",
        is_datastore=True,
        expects_banner=False,
        cwe="CWE-306",
    ),
    50070: _svc(
        "hadoop",
        "Hadoop NameNode web UI",
        "management",
        "high",
        "The NameNode UI exposes the HDFS namespace and, with WebHDFS enabled, "
        "read access to the data itself without authentication by default.",
        "Enable Kerberos authentication and restrict the UI to the cluster network.",
        is_administrative=True,
        cwe="CWE-306",
    ),
}

#: Ports treated as speaking HTTP, so a minimal HTTP probe identifies them
#: rather than waiting for a banner that will never arrive.
HTTP_PORTS: frozenset[int] = frozenset(
    {80, 81, 3000, 5000, 5601, 7474, 8000, 8008, 8080, 8086, 8088, 8443, 8888, 9000, 9200, 15672}
)

#: Ports where TLS is expected immediately, so a cleartext read yields nothing.
TLS_PORTS: frozenset[int] = frozenset({443, 465, 636, 993, 995, 2376, 8443, 9443})


#: Named port profiles. ``quick`` covers the services whose exposure is most
#: often a real finding; ``standard`` adds the rest of the catalogue; ``web``
#: covers HTTP-bearing ports only.
PORT_PROFILES: dict[str, tuple[int, ...]] = {
    "quick": (
        21,
        22,
        23,
        25,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        1433,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        9200,
        11211,
        27017,
    ),
    "standard": tuple(sorted(set(PORT_SERVICES) | {80, 443, 8000, 8888, 636, 993, 995, 465})),
    "web": tuple(sorted(HTTP_PORTS | TLS_PORTS)),
    "database": (1433, 1521, 2379, 3306, 5432, 6379, 7474, 8086, 9200, 11211, 27017),
    "remote_access": (22, 23, 512, 513, 514, 623, 3389, 5900),
}


@dataclass(frozen=True, slots=True)
class BannerSignature:
    """A pattern that identifies a product, and optionally its version."""

    pattern: re.Pattern[str]
    product: str
    note: str = ""
    version_group: str = "version"


#: Banner patterns. Version capture is what makes a banner a finding in its own
#: right: a precise version tells an attacker which exploits apply.
BANNER_SIGNATURES: tuple[BannerSignature, ...] = (
    BannerSignature(
        re.compile(r"^SSH-(?P<proto>[\d.]+)-OpenSSH[_-](?P<version>[\w.]+)", re.IGNORECASE),
        "OpenSSH",
    ),
    BannerSignature(
        re.compile(r"^SSH-(?P<proto>[\d.]+)-(?P<version>\S+)"),
        "SSH server",
    ),
    BannerSignature(
        re.compile(r"\bvsftpd\s+(?P<version>[\d.]+)", re.IGNORECASE),
        "vsftpd",
    ),
    BannerSignature(
        re.compile(r"\bProFTPD\s+(?P<version>[\d.]+)", re.IGNORECASE),
        "ProFTPD",
    ),
    BannerSignature(
        re.compile(r"\bPostfix\b.*?(?P<version>[\d.]+)?", re.IGNORECASE),
        "Postfix",
    ),
    BannerSignature(
        re.compile(r"\bExim\s+(?P<version>[\d.]+)", re.IGNORECASE),
        "Exim",
    ),
    BannerSignature(
        re.compile(r"\bSendmail\b[^\d]*(?P<version>[\d.]+)", re.IGNORECASE),
        "Sendmail",
    ),
    BannerSignature(
        re.compile(r"\bDovecot\b(?:\s+(?P<version>[\d.]+))?", re.IGNORECASE),
        "Dovecot",
    ),
    BannerSignature(
        re.compile(r"^\+OK\s+(?P<version>.*POP3.*)$", re.IGNORECASE),
        "POP3 service",
    ),
    BannerSignature(
        re.compile(r"\bMySQL\b.*?(?P<version>\d+\.\d+\.\d+)", re.IGNORECASE),
        "MySQL",
    ),
    BannerSignature(
        re.compile(r"(?P<version>\d+\.\d+\.\d+)[-\w]*-MariaDB", re.IGNORECASE),
        "MariaDB",
    ),
    BannerSignature(
        re.compile(r"-ERR\s+.*(?:unauthenticated|NOAUTH)", re.IGNORECASE),
        "Redis",
        note="Redis replied to an unauthenticated command, so the instance requires a password.",
    ),
    BannerSignature(
        re.compile(r"^\+PONG|^\+OK\r?$"),
        "Redis",
        note=(
            "Redis answered PING without authentication, so the instance accepts "
            "unauthenticated commands."
        ),
    ),
    BannerSignature(
        re.compile(r"\bRFB\s+(?P<version>\d+\.\d+)"),
        "VNC",
    ),
    BannerSignature(
        re.compile(r"\bServer:\s*nginx/(?P<version>[\d.]+)", re.IGNORECASE),
        "nginx",
    ),
    BannerSignature(
        re.compile(r"\bServer:\s*Apache/(?P<version>[\d.]+)", re.IGNORECASE),
        "Apache httpd",
    ),
    BannerSignature(
        re.compile(r"\bServer:\s*Microsoft-IIS/(?P<version>[\d.]+)", re.IGNORECASE),
        "Microsoft IIS",
    ),
    BannerSignature(
        re.compile(r"\bServer:\s*(?P<version>Werkzeug/[\d.]+)", re.IGNORECASE),
        "Werkzeug development server",
        note=(
            "Werkzeug's development server is serving requests directly. It is "
            "single-threaded, has no hardening, and may expose the interactive debugger."
        ),
    ),
    BannerSignature(
        re.compile(r"\bServer:\s*WEBrick/(?P<version>[\d.]+)", re.IGNORECASE),
        "WEBrick development server",
    ),
    BannerSignature(
        re.compile(r"\bX-Powered-By:\s*(?P<version>Express)", re.IGNORECASE),
        "Express",
    ),
    BannerSignature(
        re.compile(r"\bX-Powered-By:\s*PHP/(?P<version>[\d.]+)", re.IGNORECASE),
        "PHP",
    ),
    BannerSignature(
        re.compile(r'"cluster_name"\s*:\s*"(?P<version>[^"]+)"'),
        "Elasticsearch",
        note="The Elasticsearch REST API answered without credentials.",
    ),
    BannerSignature(
        re.compile(r"\bSTAT\s+version\s+(?P<version>[\d.]+)"),
        "Memcached",
        note="Memcached answered a stats command without authentication.",
    ),
)

#: Banner fragments that reveal the service accepted an unauthenticated command.
UNAUTHENTICATED_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^\+PONG", re.IGNORECASE),
        "Redis answered PING with no password set, so every command is available "
        "without authentication.",
    ),
    (
        re.compile(r'"cluster_name"\s*:', re.IGNORECASE),
        "The Elasticsearch cluster answered an unauthenticated API request, so "
        "indices are readable without credentials.",
    ),
    (
        re.compile(r"^STAT\s+", re.IGNORECASE),
        "Memcached answered a stats command without authentication, so cached "
        "values are readable without credentials.",
    ),
    (
        re.compile(r"\b220\b.*\bftp\b.*\banonymous\b", re.IGNORECASE),
        "The FTP greeting advertises anonymous access.",
    ),
)


@dataclass(slots=True)
class BannerIdentification:
    """What a banner revealed."""

    product: str | None = None
    version: str | None = None
    note: str = ""
    unauthenticated_reasons: list[str] = field(default_factory=list)

    @property
    def discloses_version(self) -> bool:
        return bool(self.version and any(ch.isdigit() for ch in self.version))

    @property
    def descriptor(self) -> str:
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.product or "unidentified service"


#: Service name → definition, so a service identified from its banner can be
#: classified even when it is listening on a non-standard port. A port number
#: is a convention; a banner is an observation, and the observation wins.
SERVICES_BY_NAME: dict[str, ServiceDefinition] = {
    service.name: service for service in PORT_SERVICES.values()
}

#: The conventional port for each catalogued service, used to report when a
#: service is found somewhere other than where it is expected.
DEFAULT_PORT_FOR_SERVICE: dict[str, int] = {}
for _port, _service in sorted(PORT_SERVICES.items()):
    DEFAULT_PORT_FOR_SERVICE.setdefault(_service.name, _port)
del _port, _service

#: Banner-identified product → catalogued service name. This is what lets an
#: SSH server on port 2222 be assessed as SSH rather than as an unknown
#: listener, which is the common real-world case for hardened hosts.
SERVICE_BY_PRODUCT: dict[str, str] = {
    "OpenSSH": "ssh",
    "SSH server": "ssh",
    "vsftpd": "ftp",
    "ProFTPD": "ftp",
    "Postfix": "smtp",
    "Exim": "smtp",
    "Sendmail": "smtp",
    "Dovecot": "imap",
    "POP3 service": "pop3",
    "MySQL": "mysql",
    "MariaDB": "mysql",
    "Redis": "redis",
    "VNC": "vnc",
    "Elasticsearch": "elasticsearch",
    "Memcached": "memcached",
    "nginx": "http-proxy",
    "Apache httpd": "http-proxy",
    "Microsoft IIS": "http-proxy",
    "Werkzeug development server": "http-dev",
    "WEBrick development server": "http-dev",
    "Express": "http-alt",
    "PHP": "http-proxy",
}

#: Read-only probes that make a silent service identify itself, by catalogued
#: service name. Every one of these is a status or version query: none writes,
#: authenticates, or changes state. A service with no safe probe is left alone
#: and reported as silent rather than guessed at.
SERVICE_PROBES: dict[str, bytes] = {
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
    "elasticsearch": (b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
}

#: The probe sent to a port with no catalogued service, after a passive read
#: returned nothing. ``HEAD`` retrieves headers without a body and changes no
#: state, and it identifies an HTTP service on any port — which is the single
#: most common thing found on an unregistered port.
GENERIC_HTTP_PROBE = (
    b"HEAD / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"User-Agent: QGuardSentinel/1.0 (authorized security assessment)\r\n"
    b"Accept: */*\r\n"
    b"Connection: close\r\n\r\n"
)


def lookup_service(name: str) -> ServiceDefinition | None:
    """A catalogued service by name, or ``None`` when the name is unknown."""
    return SERVICES_BY_NAME.get(name)


def service_for_product(product: str | None) -> ServiceDefinition | None:
    """The catalogued service a banner-identified product belongs to."""
    if not product:
        return None
    name = SERVICE_BY_PRODUCT.get(product)
    return SERVICES_BY_NAME.get(name) if name else None


def probe_for(service: ServiceDefinition | None, port: int) -> bytes:
    """The read-only probe to send to a silent port.

    Returns the catalogued service's own probe where one exists, an HTTP
    ``HEAD`` for a port conventionally carrying HTTP, and the generic HTTP
    probe otherwise — a service that does not speak HTTP simply does not
    answer it, which is itself informative.
    """
    if service is not None and service.name in SERVICE_PROBES:
        return SERVICE_PROBES[service.name]
    if port in HTTP_PORTS:
        return GENERIC_HTTP_PROBE
    return GENERIC_HTTP_PROBE


def lookup_port(port: int) -> ServiceDefinition | None:
    """The catalogued service for a port, or ``None`` when the port is unknown."""
    return PORT_SERVICES.get(port)


def profile_ports(name: str) -> tuple[int, ...]:
    """Ports for a named profile. Raises ``KeyError`` for an unknown profile."""
    return PORT_PROFILES[name]


def identify_banner(banner: str) -> BannerIdentification:
    """Identify a product and version from a service banner.

    Returns an identification with ``product`` unset when nothing matched: an
    unrecognised banner is reported as unrecognised, never guessed.
    """
    identification = BannerIdentification()
    cleaned = banner.strip()
    if not cleaned:
        return identification

    for signature in BANNER_SIGNATURES:
        match = signature.pattern.search(cleaned)
        if match is None:
            continue
        identification.product = signature.product
        groups = match.groupdict()
        version = groups.get(signature.version_group)
        if version:
            identification.version = version.strip()
        identification.note = signature.note
        break

    for pattern, reason in UNAUTHENTICATED_MARKERS:
        if pattern.search(cleaned):
            identification.unauthenticated_reasons.append(reason)

    return identification


__all__ = [
    "BANNER_SIGNATURES",
    "DEFAULT_PORT_FOR_SERVICE",
    "GENERIC_HTTP_PROBE",
    "HTTP_PORTS",
    "PORT_PROFILES",
    "PORT_SERVICES",
    "SERVICES_BY_NAME",
    "SERVICE_BY_PRODUCT",
    "SERVICE_PROBES",
    "TLS_PORTS",
    "BannerIdentification",
    "BannerSignature",
    "ServiceDefinition",
    "identify_banner",
    "lookup_port",
    "lookup_service",
    "probe_for",
    "profile_ports",
    "service_for_product",
]
