"""Binary format parsers for untrusted artifacts.

Everything in this package reads attacker-controlled input: an uploaded APK,
an IPA from an app store, a container layer. The parsers therefore share three
rules:

* **Nothing is executed.** No archive member is run, no code is loaded, no
  external tool is invoked on the artifact.
* **Every size is bounded.** A parser refuses input beyond its limit rather
  than allocating whatever a header claims.
* **A malformed artifact is reported, not swallowed.** Parsers raise with the
  real reason so the engine can report degraded coverage instead of an empty
  result that reads as "nothing found".
"""

from __future__ import annotations

__all__: list[str] = []
