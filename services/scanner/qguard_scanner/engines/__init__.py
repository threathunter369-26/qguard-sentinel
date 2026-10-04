"""Security assessment engines.

Importing this package registers every engine with the SDK registry, which is
how the orchestrator discovers what a deployment can run. An engine that is
not imported here does not exist as far as the platform is concerned, so a new
engine is added by writing the module and adding it to this list.

The engines divide on one axis that matters operationally: whether they send
traffic to the target. A **passive** engine reads artifacts the platform
already holds — source trees, manifests, packages — and needs no permission
beyond access to those files. An **active** engine contacts the target, so the
SDK refuses to run it without an approved authorization covering that target.
"""

from qguard_scanner.engines import (
    api_security,
    certificate,
    container,
    crypto,
    kubernetes,
    mobile,
    network,
    sast,
    sca,
    secrets,
    web,
)

__all__ = [
    "api_security",
    "certificate",
    "container",
    "crypto",
    "kubernetes",
    "mobile",
    "network",
    "sast",
    "sca",
    "secrets",
    "web",
]
