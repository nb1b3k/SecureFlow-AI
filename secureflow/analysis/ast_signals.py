"""Sensitive-file detection via regex / AST signals.

v1 ships the regex pre-filter only (no tree-sitter dependency yet). Even at
that level we beat filename keywords by reading the file content for route
decorators, auth-library imports, IAM resources, etc.

See `design/06_sensitive_detection_and_reachability.md` for the full design.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from secureflow.analysis.path_rules import is_under, matches_prefix_any

# ──────────────────────────────────────────────────────────── regex signals ──

_ROUTE_DECORATOR = re.compile(
    r"@(app|router|blueprint|bp|api)\.(route|get|post|put|patch|delete|head|options)\b",
    re.IGNORECASE,
)
_EXPRESS_ROUTE = re.compile(
    r"\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]/",
)
# Java: Spring MVC + JAX-RS + servlet annotations all flag the file as
# request-handling. WebServlet is the bare Java EE form; @Path is JAX-RS.
_SPRING_MAPPING = re.compile(
    r"@(Request|Get|Post|Put|Delete|Patch)Mapping\b"
    r"|@WebServlet\b"
    r"|@Path\s*\("
    r"|extends\s+HttpServlet\b",
)
_FASTAPI_DECORATOR = re.compile(r"@\w+\.(get|post|put|patch|delete)\s*\(")

# Go HTTP handlers: stdlib net/http, gorilla/mux, gin, echo, chi, fiber.
# The taint-source heuristic in #3 is what matters at the line level; this
# is the file-level "AI Discovery should look at this" signal.
_GO_HTTP_HANDLER = re.compile(
    r"\bhttp\.HandleFunc\s*\("
    r"|\bhttp\.Handle\s*\("
    r"|\b(mux|r|router)\.HandleFunc\s*\("
    r"|\bgin\.\w+\.(?:GET|POST|PUT|PATCH|DELETE)\s*\("
    r"|\b(?:GET|POST|PUT|PATCH|DELETE)\s*\(\s*\"/"  # gin-style group routing
    r"|\bnet/http\b"
    r"|\bgithub\.com/(?:gin-gonic/gin|labstack/echo|go-chi/chi|gofiber/fiber)\b",
)

# Ruby: Sinatra block routes, Rails controller actions/callbacks, Rack apps.
_RUBY_HTTP_HANDLER = re.compile(
    r"^\s*(get|post|put|patch|delete|options)\s+['\"]/"   # sinatra
    r"|\bclass\s+\w+Controller\s*<\s*ApplicationController\b"
    r"|\bbefore_action\b|\bskip_before_action\b"
    r"|\bRails\.application\.routes\b"
    r"|\brequire\s+['\"]sinatra['\"]",
    re.MULTILINE,
)

# PHP request superglobals are themselves the strongest "this file handles
# requests" signal in PHP — there's no decorator system.
_PHP_REQUEST_INPUT = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\b"
    r"|\bRoute::(get|post|put|patch|delete)\s*\("   # Laravel
    r"|\$request->(input|query|all|file)\(",         # Laravel/Symfony
)

# C# / ASP.NET: WebForms Page_Load, ASP.NET Core controller attributes,
# and the [HttpVerb] family.
_CSHARP_HTTP_HANDLER = re.compile(
    r"\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\b"
    r"|protected\s+void\s+Page_Load\s*\("
    r"|:\s*Controller\b|:\s*ControllerBase\b|:\s*Page\b"
    r"|\busing\s+System\.Web\b"
    r"|\busing\s+Microsoft\.AspNetCore\b",
)

_AUTH_IMPORTS = re.compile(
    r"\b(?:from|import)\s+("
    r"flask_login|flask\.session|flask\.sessions|"
    r"django\.contrib\.auth|django\.contrib\.sessions|"
    r"jose|jwt|pyjwt|"
    r"passlib|bcrypt|argon2|"
    r"werkzeug\.security|"
    r"oauth|oauthlib|authlib|"
    r"passport|express-session"
    r")\b",
    re.IGNORECASE,
)

# Anything that suggests the file is doing cryptography — high-level libs,
# low-level libs, and the stdlib `hashlib` / `secrets` / `hmac` / `ssl`
# modules. We want bare `import hashlib` to qualify even when no specific
# submodule is referenced, because AI Discovery should review crypto
# choices regardless of which symbol is used.
_CRYPTO_IMPORTS = re.compile(
    r"\b(?:from|import)\s+("
    r"cryptography|pycryptodome|Crypto|nacl|"
    r"hashlib|hmac|secrets|ssl|"
    r"jwt|pyjwt|jose|"
    r"OpenSSL|paramiko"
    r")\b",
    re.IGNORECASE,
)

# Patterns that suggest TLS / SSL is being configured insecurely on the
# wire-out side. requests `verify=False`, urllib3 disabled-warnings,
# ssl.CERT_NONE, etc. These often indicate a real security regression
# even when no cryptography library is imported.
_TLS_INSECURE = re.compile(
    r"\bverify\s*=\s*False\b"
    r"|\bssl\._create_unverified_context\b"
    r"|\bssl\.CERT_NONE\b"
    r"|\bdisable_warnings\s*\(\s*InsecureRequestWarning",
    re.IGNORECASE,
)

# Outbound-HTTP / SSRF-adjacent imports. Catches files that fetch URLs,
# which AI Discovery should review for SSRF / open-redirect / missing
# allowlists. Note we DO NOT flag the stdlib `urllib.parse` (parsing-only).
_NETWORK_CLIENT_IMPORTS = re.compile(
    r"\b(?:from|import)\s+("
    r"requests|httpx|aiohttp|urllib\.request|urllib3"
    r")\b",
    re.IGNORECASE,
)

# Embedded secret-shaped literals — a hardcoded private key block, an
# AKIA prefix, etc. These already match in `secret_masker`; we mirror a
# narrower set here so AI Discovery picks up files whose primary "code"
# IS the secret (e.g., a config.py with a private-key blob).
_EMBEDDED_SECRET_PATTERNS = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bsk_live_[A-Za-z0-9]{16,}\b",
)

_IAM_KEYWORDS = re.compile(
    r'("Effect"\s*:\s*"Allow"|resource\s+"aws_iam_|"Action"\s*:\s*"\*")',
    re.IGNORECASE,
)

_COOKIE_SESSION_WRITE = re.compile(
    r"\b(?:response|res|request|req)\.(?:cookies?|session)\b",
    re.IGNORECASE,
)

_SECRETS_MANAGER = re.compile(
    r"\b(secretsmanager|ssm\.get_parameter|secretmanager|hashicorp_vault|vault\.read)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SensitiveResult:
    sensitive: bool
    signals: list[str]


SENSITIVE_PATH_PREFIXES = [
    "auth/", "login/", "users/", "admin/", "payment/", "billing/",
    "iam/", "policy/", "session/",
]


def _is_excluded(path: str, exclusion_paths: Iterable[str]) -> bool:
    return matches_prefix_any(path, list(exclusion_paths))


def detect(
    *,
    file_path: str,
    content: str,
    sensitive_path_patterns: Iterable[str] = (),
    exclusion_paths: Iterable[str] = (),
) -> SensitiveResult:
    """Decide whether `file_path` is security-sensitive.

    AST-style content signals are authoritative. Path-based fallback only
    fires when no content signal does, and is suppressed inside `exclusion_paths`.
    """
    signals: list[str] = []
    if _ROUTE_DECORATOR.search(content):
        signals.append("route_decorator")
    if _EXPRESS_ROUTE.search(content):
        signals.append("express_route")
    if _SPRING_MAPPING.search(content):
        signals.append("spring_mapping")
    if _FASTAPI_DECORATOR.search(content):
        signals.append("fastapi_decorator")
    if _GO_HTTP_HANDLER.search(content):
        signals.append("go_http_handler")
    if _RUBY_HTTP_HANDLER.search(content):
        signals.append("ruby_http_handler")
    if _PHP_REQUEST_INPUT.search(content):
        signals.append("php_request_input")
    if _CSHARP_HTTP_HANDLER.search(content):
        signals.append("csharp_http_handler")
    if _AUTH_IMPORTS.search(content):
        signals.append("auth_import")
    if _CRYPTO_IMPORTS.search(content):
        signals.append("crypto_import")
    if _TLS_INSECURE.search(content):
        signals.append("tls_insecure_config")
    if _NETWORK_CLIENT_IMPORTS.search(content):
        signals.append("network_client_import")
    if _IAM_KEYWORDS.search(content):
        signals.append("iam_policy")
    if _COOKIE_SESSION_WRITE.search(content):
        signals.append("cookie_or_session")
    if _SECRETS_MANAGER.search(content):
        signals.append("secrets_manager")
    if _EMBEDDED_SECRET_PATTERNS.search(content):
        signals.append("embedded_secret")

    if signals:
        # AST signals override the exclusion list (a real route in tests/ still matters).
        return SensitiveResult(True, signals)

    # Path-based fallback.
    if _is_excluded(file_path, exclusion_paths):
        return SensitiveResult(False, [])

    # Match either built-in path prefixes or user-supplied keyword patterns.
    if matches_prefix_any(file_path, SENSITIVE_PATH_PREFIXES):
        return SensitiveResult(True, ["sensitive_path"])

    lowered = file_path.lower()
    for pattern in sensitive_path_patterns:
        if pattern.lower() in lowered:
            return SensitiveResult(True, [f"keyword:{pattern}"])

    return SensitiveResult(False, [])


def detect_path(
    repo_path: str | Path,
    file_path: str,
    *,
    sensitive_path_patterns: Iterable[str] = (),
    exclusion_paths: Iterable[str] = (),
    max_bytes: int = 200_000,
) -> SensitiveResult:
    """Convenience: read the file from disk and run `detect`.

    Bounded read so huge files don't blow up the budget.
    """
    full = Path(repo_path) / file_path
    if not full.exists() or not full.is_file():
        return detect(
            file_path=file_path,
            content="",
            sensitive_path_patterns=sensitive_path_patterns,
            exclusion_paths=exclusion_paths,
        )
    try:
        content = full.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError:
        content = ""
    return detect(
        file_path=file_path,
        content=content,
        sensitive_path_patterns=sensitive_path_patterns,
        exclusion_paths=exclusion_paths,
    )


def is_runtime_path(path: str, *, excluded: list[str], runtime: list[str]) -> str:
    """Classify a path for reachability: unreachable / likely_reachable / unknown."""
    if is_under(path, excluded):
        return "unreachable"
    if is_under(path, runtime):
        return "likely_reachable"
    return "unknown"
