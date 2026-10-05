"""Asset inventory: the things the platform assesses.

Every finding, scan and authorization points at an asset, so the inventory is
the spine of the data model rather than a convenience. Two properties follow
from that and are enforced here:

* **An asset has one identity.** The same host discovered by a network scan, a
  cloud inventory import and a manual entry is one asset, not three — findings
  about it must aggregate. Identity is the ``(asset_type, identifier)`` pair,
  unique per organization.
* **Business context is first-class.** Criticality, environment, data
  sensitivity and internet exposure are what turn a CVSS score into a risk
  score. They live on the asset because that is where someone who knows the
  system can set them.
"""

from __future__ import annotations

__all__: list[str] = []
