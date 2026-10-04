"""OpenAPI / Swagger specification model.

Parses OpenAPI 3.x and Swagger 2.0 into one normalised shape so the API
security engine reasons about endpoints rather than about document versions.
The two formats differ in where security schemes live, how request bodies are
expressed and how servers are named; all of that is resolved here.

Parsing is deliberately tolerant. A real-world specification is frequently
incomplete or slightly invalid, and refusing to assess it would be worse than
assessing what can be read — but what could *not* be read is recorded in
``warnings`` so coverage is reported honestly instead of a partial parse
passing for a complete one.

Local ``$ref`` pointers are resolved with a depth limit and a visited set: a
specification is untrusted input, and a self-referencing schema must not take
the parser down with it. Remote refs are *not* fetched — following a URL out
of a specification would be a server-side request forgery primitive.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml

#: HTTP methods that appear as keys under a path item.
HTTP_METHODS: tuple[str, ...] = (
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
)

#: Methods that only read. The engine will send these during an authorized
#: assessment; anything else is never sent, because a scanner must not mutate
#: a production system's state.
SAFE_METHODS: frozenset[str] = frozenset({"get", "head", "options"})

#: Maximum ``$ref`` resolution depth. A specification is untrusted input.
MAX_REF_DEPTH = 12

#: Parameter names that conventionally carry an object identifier. An endpoint
#: keyed by one of these is where broken object-level authorization lives.
IDENTIFIER_HINTS: tuple[str, ...] = (
    "id",
    "uuid",
    "guid",
    "key",
    "ref",
    "number",
    "no",
    "code",
    "slug",
    "name",
    "email",
    "username",
    "user",
    "account",
    "customer",
    "order",
    "invoice",
    "document",
    "file",
    "tenant",
    "org",
    "organization",
    "organisation",
    "company",
    "project",
    "workspace",
)

#: Property names that must never be settable by a client. Accepting them in a
#: request body is the mass-assignment pattern.
PRIVILEGED_PROPERTIES: tuple[str, ...] = (
    "id",
    "role",
    "roles",
    "permission",
    "permissions",
    "scope",
    "scopes",
    "is_admin",
    "isadmin",
    "admin",
    "is_superuser",
    "issuperuser",
    "superuser",
    "is_staff",
    "is_active",
    "isactive",
    "is_verified",
    "isverified",
    "email_verified",
    "emailverified",
    "verified",
    "owner",
    "owner_id",
    "ownerid",
    "user_id",
    "userid",
    "tenant_id",
    "tenantid",
    "organization_id",
    "organizationid",
    "org_id",
    "orgid",
    "account_id",
    "accountid",
    "balance",
    "credit",
    "credits",
    "price",
    "amount",
    "status",
    "state",
    "created_at",
    "createdat",
    "updated_at",
    "updatedat",
    "deleted_at",
    "deletedat",
    "password_hash",
    "passwordhash",
    "api_key",
    "apikey",
    "secret",
    "token",
    "mfa_enabled",
    "mfaenabled",
    "plan",
    "tier",
    "quota",
    "limit",
)

#: Parameter names whose value should never appear in a URL. Query strings are
#: logged by proxies, load balancers and browser history.
SENSITIVE_PARAMETER_NAMES: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "idtoken",
    "api_key",
    "apikey",
    "apitoken",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "session_id",
    "jwt",
    "bearer",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "ssn",
    "social_security",
    "card_number",
    "cardnumber",
    "cvv",
    "pin",
    "otp",
    "mfa_code",
)


def _to_snake_case(name: str) -> str:
    """Normalise an identifier spelling to snake_case.

    ``accountId`` → ``account_id``, ``accountID`` → ``account_id``,
    ``account-id`` → ``account_id``. Handles the acronym boundary
    (``APIKey`` → ``api_key``) that a naive split gets wrong.
    """
    cleaned = name.strip().strip("{}").replace("-", "_").replace(".", "_")
    # Split a lower/digit followed by an upper: accountId -> account_Id
    cleaned = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", cleaned)
    # Split an acronym run followed by a word: APIKey -> API_Key
    cleaned = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", cleaned)
    return re.sub(r"_+", "_", cleaned).strip("_").lower()


#: Suffixes that mark a name as an object identifier regardless of its stem.
_IDENTIFIER_SUFFIXES = ("id", "uuid", "guid", "key", "ref", "slug", "number", "code")


def _is_identifier_name(name: str) -> bool:
    """Whether a parameter name denotes an object identifier."""
    normalised = _to_snake_case(name)
    if not normalised:
        return False
    if normalised in IDENTIFIER_HINTS:
        return True
    parts = normalised.split("_")
    if parts[-1] in _IDENTIFIER_SUFFIXES:
        return True
    # A compound of a known entity and an identifier suffix, e.g. "orderref".
    return any(
        normalised.endswith(suffix) and normalised[: -len(suffix)] in IDENTIFIER_HINTS
        for suffix in _IDENTIFIER_SUFFIXES
    )


class SpecParseError(ValueError):
    """The document is not a specification this parser can read."""


@dataclass(slots=True)
class SecurityScheme:
    """A declared authentication mechanism."""

    name: str
    type: str
    scheme: str | None = None
    location: str | None = None
    """``header``, ``query`` or ``cookie`` for an API key scheme."""
    parameter_name: str | None = None
    bearer_format: str | None = None
    flows: list[str] = field(default_factory=list)
    description: str = ""

    @property
    def is_basic(self) -> bool:
        return self.type == "http" and (self.scheme or "").lower() == "basic"

    @property
    def is_bearer(self) -> bool:
        return self.type == "http" and (self.scheme or "").lower() == "bearer"

    @property
    def is_api_key(self) -> bool:
        return self.type == "apiKey"

    @property
    def is_oauth2(self) -> bool:
        return self.type in ("oauth2", "openIdConnect")

    @property
    def carries_credential_in_url(self) -> bool:
        return self.is_api_key and (self.location or "").lower() == "query"

    def describe(self) -> str:
        if self.is_api_key:
            return (
                f"API key in {self.location or 'an unspecified location'} ({self.parameter_name})"
            )
        if self.type == "http":
            return f"HTTP {self.scheme or 'unspecified'} authentication"
        if self.is_oauth2:
            flows = ", ".join(self.flows) if self.flows else "no declared flow"
            return f"{self.type} ({flows})"
        return self.type


@dataclass(slots=True)
class Parameter:
    """One request parameter."""

    name: str
    location: str
    """``path``, ``query``, ``header``, ``cookie`` or ``body``."""
    required: bool = False
    schema_type: str | None = None
    description: str = ""

    @property
    def looks_like_identifier(self) -> bool:
        """Whether this parameter names an object identifier.

        Real specifications spell the same parameter ``accountId``,
        ``account_id``, ``account-id`` and ``accountID``, so the name is
        normalised to snake_case before matching. Matching only one spelling
        would silently skip the majority of real endpoints, and these are
        exactly the endpoints where broken object-level authorization lives.
        """
        return _is_identifier_name(self.name)

    @property
    def is_sensitive_name(self) -> bool:
        """Whether the name indicates a credential or personal identifier."""
        normalised = _to_snake_case(self.name)
        compact = normalised.replace("_", "")
        return any(
            normalised == candidate or compact == candidate.replace("_", "")
            for candidate in SENSITIVE_PARAMETER_NAMES
        )


@dataclass(slots=True)
class Endpoint:
    """One operation: a path plus a method."""

    path: str
    method: str
    operation_id: str | None = None
    summary: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False
    parameters: list[Parameter] = field(default_factory=list)
    #: Security requirements for this operation. ``None`` means the operation
    #: declared none of its own and inherits the document default; an empty
    #: list means it explicitly opted out of authentication.
    security: list[dict[str, list[str]]] | None = None
    response_codes: list[str] = field(default_factory=list)
    request_body_properties: dict[str, dict[str, Any]] = field(default_factory=dict)
    request_body_required: bool = False
    request_content_types: list[str] = field(default_factory=list)

    @property
    def identifier(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def is_safe_method(self) -> bool:
        return self.method.lower() in SAFE_METHODS

    @property
    def is_mutating(self) -> bool:
        return self.method.lower() in ("post", "put", "patch", "delete")

    @property
    def path_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def identifier_path_parameters(self) -> list[Parameter]:
        return [p for p in self.path_parameters if p.looks_like_identifier]

    def effective_security(
        self, document_default: list[dict[str, list[str]]]
    ) -> list[dict[str, list[str]]]:
        """Security requirements that actually apply, after inheritance."""
        if self.security is None:
            return document_default
        return self.security

    def is_unauthenticated(self, document_default: list[dict[str, list[str]]]) -> bool:
        """Whether the specification claims this operation needs no credential."""
        effective = self.effective_security(document_default)
        if not effective:
            return True
        # ``security: [{}]`` is the documented way to mark authentication
        # optional, and means the operation is reachable without a credential.
        return any(not requirement for requirement in effective)

    def privileged_body_properties(self) -> list[str]:
        """Request-body properties a client should not be able to set."""
        found: list[str] = []
        compact_privileged = {p.replace("_", "") for p in PRIVILEGED_PROPERTIES}
        for name, schema in self.request_body_properties.items():
            normalised = _to_snake_case(name)
            compact = normalised.replace("_", "")
            if normalised in PRIVILEGED_PROPERTIES or compact in compact_privileged:
                # A property the server declares read-only is documented as
                # not settable, so it is not a mass-assignment candidate.
                if schema.get("readOnly") is True:
                    continue
                found.append(name)
        return sorted(found)


@dataclass(slots=True)
class ApiSpecification:
    """A parsed specification, normalised across OpenAPI 3 and Swagger 2."""

    title: str
    version: str
    spec_version: str
    """The document's own version, e.g. ``3.0.3`` or ``2.0``."""
    servers: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    security_schemes: dict[str, SecurityScheme] = field(default_factory=dict)
    global_security: list[dict[str, list[str]]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def is_swagger_2(self) -> bool:
        return self.spec_version.startswith("2")

    def base_url(self, fallback: str | None = None) -> str | None:
        """The first absolute server URL, or ``fallback`` resolved against it."""
        for server in self.servers:
            parsed = urlparse(server)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                return server.rstrip("/")
        if fallback:
            return fallback.rstrip("/")
        return None

    def resolve_url(self, base: str, path: str) -> str:
        """Join a base URL and a specification path without losing a base prefix."""
        prefix = urlparse(base).path.rstrip("/")
        if prefix and not path.startswith(prefix):
            return urljoin(base + "/", (prefix + path).lstrip("/"))
        return urljoin(base + "/", path.lstrip("/"))

    def scheme_for(self, requirement: dict[str, list[str]]) -> list[SecurityScheme]:
        return [
            self.security_schemes[name] for name in requirement if name in self.security_schemes
        ]

    def stats(self) -> dict[str, Any]:
        unauthenticated = [
            e.identifier for e in self.endpoints if e.is_unauthenticated(self.global_security)
        ]
        return {
            "title": self.title,
            "api_version": self.version,
            "spec_version": self.spec_version,
            "servers": self.servers,
            "endpoint_count": len(self.endpoints),
            "method_counts": {
                method: sum(1 for e in self.endpoints if e.method == method)
                for method in sorted({e.method for e in self.endpoints})
            },
            "security_scheme_count": len(self.security_schemes),
            "security_schemes": {n: s.describe() for n, s in self.security_schemes.items()},
            "has_global_security": bool(self.global_security),
            "unauthenticated_endpoint_count": len(unauthenticated),
            "parse_warnings": self.warnings,
        }


# --------------------------------------------------------------------- parsing
def load_document(text: str) -> dict[str, Any]:
    """Parse a specification document from JSON or YAML text.

    YAML is loaded with ``safe_load``: a specification is untrusted input, and
    the full loader can instantiate arbitrary Python objects.
    """
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecParseError(f"the document is not valid JSON ({exc})") from exc
    else:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecParseError(f"the document is not valid YAML ({exc})") from exc

    if not isinstance(document, dict):
        raise SpecParseError(
            "the document parsed but is not a mapping, so it is not an OpenAPI or "
            "Swagger specification"
        )
    return document


class _RefResolver:
    """Resolves local ``$ref`` pointers with a depth and cycle limit."""

    def __init__(self, document: dict[str, Any]) -> None:
        self._document = document
        self.warnings: list[str] = []

    def resolve(self, node: Any, depth: int = 0, seen: frozenset[str] = frozenset()) -> Any:
        if depth > MAX_REF_DEPTH:
            self.warnings.append(
                f"A $ref chain exceeded {MAX_REF_DEPTH} levels and was not followed further, "
                "so part of a schema was not analysed."
            )
            return {}
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if not isinstance(ref, str):
            return node
        if not ref.startswith("#/"):
            # Remote refs are never fetched: following a URL out of an
            # untrusted document would be an SSRF primitive.
            self.warnings.append(
                f"The external reference {ref!r} was not followed, so the schema it "
                "points at was not analysed."
            )
            return {}
        if ref in seen:
            self.warnings.append(
                f"The reference {ref!r} is part of a cycle and was not followed again."
            )
            return {}

        target: Any = self._document
        for part in ref[2:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, dict) and key in target:
                target = target[key]
            elif isinstance(target, list) and key.isdigit() and int(key) < len(target):
                target = target[int(key)]
            else:
                self.warnings.append(
                    f"The reference {ref!r} does not resolve within the document, so the "
                    "schema it points at was not analysed."
                )
                return {}
        return self.resolve(target, depth + 1, seen | {ref})


def parse_specification(document: dict[str, Any], *, source: str = "") -> ApiSpecification:
    """Normalise an OpenAPI 3.x or Swagger 2.0 document."""
    if "openapi" in document:
        spec_version = str(document.get("openapi") or "3.0.0")
    elif "swagger" in document:
        spec_version = str(document.get("swagger") or "2.0")
    else:
        raise SpecParseError(
            "the document has neither an 'openapi' nor a 'swagger' version field, so it "
            "is not an API specification"
        )

    raw_info = document.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    resolver = _RefResolver(document)

    spec = ApiSpecification(
        title=str(info.get("title") or "Untitled API"),
        version=str(info.get("version") or "unspecified"),
        spec_version=spec_version,
        source=source,
    )

    spec.servers = _parse_servers(document, spec.is_swagger_2)
    spec.security_schemes = _parse_security_schemes(document, spec.is_swagger_2)
    spec.global_security = _parse_security_requirements(document.get("security"))

    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        spec.warnings.append(
            "The specification declares no paths, so no endpoint could be assessed."
        )
        spec.warnings.extend(resolver.warnings)
        return spec

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            spec.warnings.append(f"The path item for {path!r} is not a mapping and was skipped.")
            continue
        shared = _parse_parameters(path_item.get("parameters"), resolver, spec.is_swagger_2)
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            spec.endpoints.append(
                _parse_operation(
                    path=str(path),
                    method=method,
                    operation=operation,
                    shared_parameters=shared,
                    resolver=resolver,
                    is_swagger_2=spec.is_swagger_2,
                )
            )

    spec.warnings.extend(resolver.warnings)
    return spec


def _parse_servers(document: dict[str, Any], is_swagger_2: bool) -> list[str]:
    if is_swagger_2:
        host = document.get("host")
        base_path = str(document.get("basePath") or "")
        schemes = document.get("schemes")
        if not isinstance(schemes, list) or not schemes:
            schemes = ["https"]
        if not host:
            return []
        return [f"{str(scheme).lower()}://{host}{base_path}" for scheme in schemes]

    servers = document.get("servers")
    if not isinstance(servers, list):
        return []
    urls: list[str] = []
    for entry in servers:
        if isinstance(entry, dict) and isinstance(entry.get("url"), str):
            url = entry["url"]
            variables = entry.get("variables")
            if isinstance(variables, dict):
                # Substitute declared defaults so the URL is usable. A variable
                # with no default is left as-is and shows up in the findings.
                for name, definition in variables.items():
                    if isinstance(definition, dict) and "default" in definition:
                        url = url.replace(f"{{{name}}}", str(definition["default"]))
            urls.append(url)
    return urls


def _parse_security_schemes(
    document: dict[str, Any], is_swagger_2: bool
) -> dict[str, SecurityScheme]:
    if is_swagger_2:
        raw = document.get("securityDefinitions")
    else:
        components = document.get("components")
        raw = components.get("securitySchemes") if isinstance(components, dict) else None

    if not isinstance(raw, dict):
        return {}

    schemes: dict[str, SecurityScheme] = {}
    for name, definition in raw.items():
        if not isinstance(definition, dict):
            continue
        scheme_type = str(definition.get("type") or "unknown")
        # Swagger 2 spelt basic authentication as its own type.
        http_scheme: str | None
        if is_swagger_2 and scheme_type == "basic":
            scheme_type, http_scheme = "http", "basic"
        else:
            raw_scheme = definition.get("scheme")
            http_scheme = str(raw_scheme) if isinstance(raw_scheme, str) else None
        flows: list[str] = []
        if isinstance(definition.get("flows"), dict):
            flows = sorted(str(k) for k in definition["flows"])
        elif isinstance(definition.get("flow"), str):
            flows = [definition["flow"]]
        schemes[str(name)] = SecurityScheme(
            name=str(name),
            type=scheme_type,
            scheme=str(http_scheme) if http_scheme else None,
            location=str(definition["in"]) if isinstance(definition.get("in"), str) else None,
            parameter_name=(
                str(definition["name"]) if isinstance(definition.get("name"), str) else None
            ),
            bearer_format=(
                str(definition["bearerFormat"])
                if isinstance(definition.get("bearerFormat"), str)
                else None
            ),
            flows=flows,
            description=str(definition.get("description") or ""),
        )
    return schemes


def _parse_security_requirements(raw: Any) -> list[dict[str, list[str]]]:
    if not isinstance(raw, list):
        return []
    requirements: list[dict[str, list[str]]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        requirements.append(
            {
                str(name): [str(s) for s in scopes] if isinstance(scopes, list) else []
                for name, scopes in entry.items()
            }
        )
    return requirements


def _parse_parameters(raw: Any, resolver: _RefResolver, is_swagger_2: bool) -> list[Parameter]:
    if not isinstance(raw, list):
        return []
    parameters: list[Parameter] = []
    for entry in raw:
        resolved = resolver.resolve(entry)
        if not isinstance(resolved, dict) or not resolved.get("name"):
            continue
        location = str(resolved.get("in") or "query")
        if is_swagger_2 and location == "body":
            # Swagger 2 expressed the request body as a parameter; the caller
            # handles it separately so both formats look the same downstream.
            continue
        schema = resolver.resolve(resolved.get("schema")) if "schema" in resolved else {}
        schema_type = None
        if isinstance(schema, dict) and schema.get("type"):
            schema_type = str(schema["type"])
        elif resolved.get("type"):
            schema_type = str(resolved["type"])
        parameters.append(
            Parameter(
                name=str(resolved["name"]),
                location=location,
                required=bool(resolved.get("required", location == "path")),
                schema_type=schema_type,
                description=str(resolved.get("description") or ""),
            )
        )
    return parameters


def _flatten_properties(
    schema: Any, resolver: _RefResolver, depth: int = 0
) -> dict[str, dict[str, Any]]:
    """Collect a schema's own properties, following composition keywords."""
    if depth > MAX_REF_DEPTH or not isinstance(schema, dict):
        return {}
    schema = resolver.resolve(schema)
    if not isinstance(schema, dict):
        return {}

    properties: dict[str, dict[str, Any]] = {}
    raw_properties = schema.get("properties")
    if isinstance(raw_properties, dict):
        for name, definition in raw_properties.items():
            resolved = resolver.resolve(definition)
            properties[str(name)] = resolved if isinstance(resolved, dict) else {}

    for keyword in ("allOf", "anyOf", "oneOf"):
        composed = schema.get(keyword)
        if isinstance(composed, list):
            for member in composed:
                properties.update(_flatten_properties(member, resolver, depth + 1))

    items = schema.get("items")
    if items is not None:
        properties.update(_flatten_properties(items, resolver, depth + 1))

    return properties


def _parse_operation(
    *,
    path: str,
    method: str,
    operation: dict[str, Any],
    shared_parameters: list[Parameter],
    resolver: _RefResolver,
    is_swagger_2: bool,
) -> Endpoint:
    own = _parse_parameters(operation.get("parameters"), resolver, is_swagger_2)
    merged: dict[tuple[str, str], Parameter] = {
        (p.location, p.name): p for p in [*shared_parameters, *own]
    }

    # A path template may contain parameters the document never declares.
    for segment in path.split("/"):
        if segment.startswith("{") and segment.endswith("}") and len(segment) > 2:
            name = segment[1:-1]
            merged.setdefault(("path", name), Parameter(name=name, location="path", required=True))

    responses = operation.get("responses")
    response_codes = sorted(str(code) for code in responses) if isinstance(responses, dict) else []

    body_properties: dict[str, dict[str, Any]] = {}
    body_required = False
    content_types: list[str] = []

    if is_swagger_2:
        for entry in operation.get("parameters") or []:
            resolved = resolver.resolve(entry)
            if isinstance(resolved, dict) and resolved.get("in") == "body":
                body_required = bool(resolved.get("required"))
                body_properties = _flatten_properties(resolved.get("schema"), resolver)
                break
        consumes = operation.get("consumes")
        if isinstance(consumes, list):
            content_types = [str(c) for c in consumes]
    else:
        request_body = resolver.resolve(operation.get("requestBody"))
        if isinstance(request_body, dict):
            body_required = bool(request_body.get("required"))
            content = request_body.get("content")
            if isinstance(content, dict):
                content_types = [str(k) for k in content]
                for media in content.values():
                    if isinstance(media, dict):
                        body_properties.update(_flatten_properties(media.get("schema"), resolver))

    security = (
        _parse_security_requirements(operation["security"]) if "security" in operation else None
    )

    return Endpoint(
        path=path,
        method=method,
        operation_id=(
            str(operation["operationId"]) if isinstance(operation.get("operationId"), str) else None
        ),
        summary=str(operation.get("summary") or ""),
        description=str(operation.get("description") or ""),
        tags=[str(t) for t in operation.get("tags") or [] if isinstance(t, str)],
        deprecated=bool(operation.get("deprecated")),
        parameters=sorted(merged.values(), key=lambda p: (p.location, p.name)),
        security=security,
        response_codes=response_codes,
        request_body_properties=body_properties,
        request_body_required=body_required,
        request_content_types=content_types,
    )


__all__ = [
    "HTTP_METHODS",
    "IDENTIFIER_HINTS",
    "PRIVILEGED_PROPERTIES",
    "SAFE_METHODS",
    "SENSITIVE_PARAMETER_NAMES",
    "ApiSpecification",
    "Endpoint",
    "Parameter",
    "SecurityScheme",
    "SpecParseError",
    "load_document",
    "parse_specification",
]
