import ipaddress
import re
from urllib.parse import unquote, urlparse

ALLOW_REDIRECT_HOSTS = {"app‑trust.example.com"}

_ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}
_IGNORED_CHARS = re.compile(r"[\x00-\x20\x7f]")
_MAX_DECODE_ROUNDS = 10


def _fully_decode(url: str) -> str:
    decoded = url
    for _ in range(_MAX_DECODE_ROUNDS):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    return decoded


def _loose_ipv4(host: str):
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for part in parts:
        if not part:
            return None
        try:
            if part.lower().startswith("0x"):
                num = int(part, 16)
            elif len(part) > 1 and part.startswith("0") and part.isdigit():
                num = int(part, 8)
            elif part.isdigit():
                num = int(part, 10)
            else:
                return None
        except ValueError:
            return None
        nums.append(num)
    if any(num > 0xFF for num in nums[:-1]):
        return None
    tail_bits = 8 * (4 - len(parts) + 1)
    if nums[-1] >= (1 << tail_bits):
        return None
    value = 0
    for num in nums[:-1]:
        value = (value << 8) | num
    value = (value << tail_bits) | nums[-1]
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def _to_ip_address(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return _loose_ipv4(host)


def _is_forbidden_ip(addr) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not addr.is_global:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _validate_authority(parsed, scheme: str) -> None:
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo (@) is not allowed in redirect urls")
    host = parsed.hostname
    if not host:
        raise ValueError("redirect url has no valid host")
    host = host.lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in redirect url: {exc}") from exc
    if port is not None:
        allowed = {_DEFAULT_PORTS[scheme]} if scheme in _DEFAULT_PORTS else {80, 443}
        if port not in allowed:
            raise ValueError(f"port {port} is not allowed in redirect urls")
    addr = _to_ip_address(host)
    if addr is not None and _is_forbidden_ip(addr):
        raise ValueError("redirect to private / intranet addresses is not allowed")
    if host not in ALLOW_REDIRECT_HOSTS:
        raise ValueError(f"host is not in the redirect whitelist: {host}")


def _validate(url: str) -> None:
    normalized = url.replace("\\", "/")
    try:
        parsed = urlparse(normalized)
    except ValueError as exc:
        raise ValueError(f"malformed redirect url: {exc}") from exc
    if parsed.fragment:
        raise ValueError("fragments are not allowed in redirect urls")
    scheme = parsed.scheme.lower()
    if scheme and scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"dangerous url scheme is not allowed: {scheme}")
    if parsed.netloc:
        _validate_authority(parsed, scheme)
    elif scheme:
        raise ValueError("absolute redirect url is missing a host")
    elif normalized.startswith("//") or parsed.path.startswith("//"):
        raise ValueError("ambiguous protocol-relative redirect url")


def sanitize_redirect_url(user_url: str) -> str:
    if not isinstance(user_url, str):
        raise ValueError("redirect url must be a string")
    stripped = user_url.strip()
    if not stripped:
        raise ValueError("redirect url must not be empty")
    cleaned = _IGNORED_CHARS.sub("", stripped)
    for candidate in dict.fromkeys((cleaned, _fully_decode(cleaned))):
        _validate(candidate)
    return stripped
