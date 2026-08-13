from __future__ import annotations

import ipaddress
import re
from pathlib import PurePath
from urllib.parse import urlparse

from .models import DetectionResult, Reason, severity_for

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.I)
SECRET_PATTERNS = [
    ("generic_api_key", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{24,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]


def _score(cfg: dict, key: str) -> int:
    return int(cfg.get("scoring", {}).get(key, 0))


def extract_urls(text: str) -> list[str]:
    return [m.group(0).rstrip(".,!?;:)]}\"'") for m in URL_RE.finditer(text or "")]


def hostname_for(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    try:
        return (urlparse(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _allowed(host: str, allowlist: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowlist)


def _registrable_guess(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def redact_secrets(text: str) -> tuple[str, list[Reason]]:
    redacted = text or ""
    reasons: list[Reason] = []
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(redacted):
            reasons.append(Reason("secret_leak", f"Possible {name} detected and redacted", 0))
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted, reasons


def evaluate_content(text: str, cfg: dict, *, outgoing: bool = False, attachment_names: list[str] | None = None, qr_urls: list[str] | None = None) -> DetectionResult:
    rules = cfg.get("rules", {})
    allowlist = {d.lower().lstrip(".") for d in rules.get("allow_domains", [])}
    denylist = {d.lower().lstrip(".") for d in rules.get("deny_domains", [])}
    suspicious_tlds = {x.lower().lstrip(".") for x in rules.get("suspicious_tlds", [])}
    keywords = [str(x).lower() for x in rules.get("suspicious_domain_keywords", [])]
    phrases = [str(x).lower() for x in rules.get("suspicious_phrases", [])]
    shorteners = {str(x).lower() for x in rules.get("url_shorteners", [])}
    brands = [str(x).lower() for x in rules.get("brand_keywords", [])]
    risky_exts = {str(x).lower().lstrip(".") for x in rules.get("risky_extensions", [])}

    reasons: list[Reason] = []
    urls = extract_urls(text)
    if qr_urls:
        urls.extend(qr_urls)
        reasons.append(Reason("qr_url", f"QR code contained {len(qr_urls)} URL(s)", _score(cfg, "qr_url")))
    domains: list[str] = []

    for url in dict.fromkeys(urls):
        candidate = url if "://" in url else f"https://{url}"
        try:
            parsed = urlparse(candidate)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            continue
        domains.append(host)
        if _allowed(host, allowlist):
            continue
        if host in denylist or any(host.endswith("." + d) for d in denylist):
            reasons.append(Reason("denylisted_domain", f"Denylisted domain: {host}", _score(cfg, "denylisted_domain")))
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in suspicious_tlds:
            reasons.append(Reason("suspicious_tld", f"Suspicious TLD .{tld}: {host}", _score(cfg, "suspicious_tld")))
        for keyword in keywords:
            if keyword in host:
                reasons.append(Reason("domain_keyword", f"Domain contains '{keyword}': {host}", _score(cfg, "domain_keyword")))
        if host in shorteners:
            reasons.append(Reason("shortener", f"URL shortener: {host}", _score(cfg, "shortener")))
        try:
            ipaddress.ip_address(host.strip("[]"))
            reasons.append(Reason("ip_url", f"Direct IP address URL: {host}", _score(cfg, "ip_url")))
        except ValueError:
            pass
        if "xn--" in host:
            reasons.append(Reason("punycode", f"Punycode/IDN hostname: {host}", _score(cfg, "punycode")))
        if parsed.username is not None or parsed.password is not None:
            reasons.append(Reason("url_userinfo", f"URL contains user-info section: {host}", _score(cfg, "url_userinfo")))
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port and port not in {80, 443}:
            reasons.append(Reason("unusual_port", f"URL uses unusual port {port}: {host}", _score(cfg, "unusual_port")))
        root = _registrable_guess(host)
        for brand in brands:
            if brand in host and brand not in root:
                reasons.append(Reason("brand_impersonation", f"Possible {brand} impersonation: {host}", _score(cfg, "brand_impersonation")))

    lower = (text or "").casefold()
    for phrase in phrases:
        if phrase.casefold() in lower:
            reasons.append(Reason("social_engineering_phrase", f"Social-engineering phrase: '{phrase}'", _score(cfg, "social_engineering_phrase")))

    for name in attachment_names or []:
        lower_name = name.lower()
        suffixes = [s.lstrip(".") for s in PurePath(lower_name).suffixes]
        if suffixes and suffixes[-1] in risky_exts:
            reasons.append(Reason("risky_attachment", f"Risky attachment type: {name}", _score(cfg, "risky_attachment")))
        if len(suffixes) >= 2 and suffixes[-1] in risky_exts:
            reasons.append(Reason("double_extension", f"Double-extension attachment: {name}", _score(cfg, "double_extension")))

    redacted, secret_reasons = redact_secrets(text)
    for reason in secret_reasons:
        reason.score = _score(cfg, "secret_leak")
        reasons.append(reason)

    unique: dict[tuple[str, str], Reason] = {}
    for reason in reasons:
        unique[(reason.code, reason.detail)] = reason
    reasons = list(unique.values())
    score = sum(r.score for r in reasons)
    if outgoing and score:
        score = round(score * float(cfg.get("scoring", {}).get("outgoing_multiplier", 1.0)))
    threshold = int(cfg.get("monitor", {}).get("alert_threshold", 35))
    return DetectionResult(
        suspicious=score >= threshold,
        score=score,
        severity=severity_for(score),
        reasons=reasons,
        urls=list(dict.fromkeys(urls)),
        domains=list(dict.fromkeys(domains)),
        redacted_text=redacted,
    )
