from urllib.parse import urlparse

SENSITIVE_WORDS = {
    "secure",
    "account",
    "login",
    "verify",
    "update",
    "bank",
    "payment",
    "password",
    "signin",
    "confirm",
}



def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url



def extract_features(url: str) -> dict[str, int]:
    """Extract lexical URL features used by the phishing model."""
    normalized_url = _normalize_url(url)
    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    subdomain_level = 0
    if hostname:
        parts = [p for p in hostname.split(".") if p]
        if len(parts) > 2:
            subdomain_level = len(parts) - 2

    path_level = len([segment for segment in path.split("/") if segment])

    lowered_url = normalized_url.lower()
    sensitive_count = sum(1 for word in SENSITIVE_WORDS if word in lowered_url)

    return {
        "UrlLength": len(normalized_url),
        "NumDots": normalized_url.count("."),
        "SubdomainLevel": subdomain_level,
        "PathLevel": path_level,
        "NumDash": normalized_url.count("-"),
        "AtSymbol": int("@" in normalized_url),
        "NumSensitiveWords": sensitive_count,
    }
