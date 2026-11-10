"""URL extraction, normalisation, IDN/punycode decoding, and domain parsing utilities.

Uses maintained libraries (`urllib.parse`, `idna`, `tldextract`, `ipaddress`) rather than
relying on regex alone for structural URL parsing.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import idna
import tldextract

from app.schemas.triage import ExtractedUrlFinding

# Offline Public Suffix List extractor (never makes live network requests during TLD parsing)
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Known URL shortener services
KNOWN_SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "ow.ly",
        "buff.ly",
        "tiny.cc",
        "rebrand.ly",
        "wa.link",
    }
)

# Tracking query parameters to strip during canonicalisation
_TRACKING_PARAMS: frozenset[str] = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "igshid",
        "mc_cid",
        "mc_eid",
    }
)

# Protected Nigerian electoral and civic institutions for lookalike/impersonation checks
PROTECTED_INSTITUTION_BRANDS: dict[str, tuple[str, ...]] = {
    "INEC": ("inecnigeria.org",),
    "NIMC": ("nimc.gov.ng",),
    "CBN": ("cbn.gov.ng",),
    "EFCC": ("efcc.gov.ng",),
    "NOA": ("noa.gov.ng",),
    "FGN": ("statehouse.gov.ng", "nigeria.gov.ng"),
    "NYSC": ("nysc.gov.ng", "nysc.org.ng"),
}

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF\u2060]")
_WHITESPACE_RE = re.compile(r"[ \t]+")

# Token finder to locate candidate URL-like tokens in free text before structural parsing
_CANDIDATE_TOKEN_RE = re.compile(
    r"""(?ix)
    (?:
        # Explicit scheme (standard or defanged)
        (?:h(?:tt|xx)ps?(?:\[:\]|:)//)[^\s<>\"'`]+
        |
        # www. prefixed URLs (standard or defanged)
        www(?:\[\.\]|\.)[^\s<>\"'`]+
        |
        # Bare domain with path or known TLD (including defanged brackets)
        (?<![@\w/])
        [a-z0-9\u00a1-\uffff-]+
        (?:(?:\[\.\]|\(\.\)|\[dot\]|\.)[a-z0-9\u00a1-\uffff-]+)+
        (?:/[^\s<>\"'`]*)?
    )
    """
)


def normalise_message_text(raw_text: str) -> str:
    """Clean and normalise user message text using Unicode NFKC and zero-width removal."""
    cleaned = _ZERO_WIDTH_RE.sub("", raw_text)
    normalised = unicodedata.normalize("NFKC", cleaned)
    normalised = _WHITESPACE_RE.sub(" ", normalised)
    return normalised.strip()


def refang_url_token(token: str) -> tuple[str, bool]:
    """Convert defanged URL notation (e.g., hxxps://example[.]com) into standard form."""
    original = token
    refanged = token

    scheme_patterns = [
        (re.compile(r"^hxxps\[:\]//", re.IGNORECASE), "https://"),
        (re.compile(r"^hxxp\[:\]//", re.IGNORECASE), "http://"),
        (re.compile(r"^https\[:\]//", re.IGNORECASE), "https://"),
        (re.compile(r"^http\[:\]//", re.IGNORECASE), "http://"),
        (re.compile(r"^hxxps://", re.IGNORECASE), "https://"),
        (re.compile(r"^hxxp://", re.IGNORECASE), "http://"),
    ]
    for pattern, replacement in scheme_patterns:
        if pattern.search(refanged):
            refanged = pattern.sub(replacement, refanged, count=1)

    for bracket_dot in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        if bracket_dot in refanged.lower():
            refanged = re.sub(re.escape(bracket_dot), ".", refanged, flags=re.IGNORECASE)

    was_defanged = refanged != original
    return refanged, was_defanged


def is_ip_blocked_or_reserved(ip_str: str) -> tuple[bool, str | None]:
    """Check if an IPv4 or IPv6 address is loopback, private, link-local, metadata, or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, None

    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if addr.is_unspecified:
        return True, "UNSPECIFIED_IP"
    if str(addr) == "169.254.169.254" or str(addr).startswith("169.254."):
        return True, "CLOUD_METADATA_OR_LINK_LOCAL_IP"
    if addr.is_loopback:
        return True, "LOOPBACK_IP"
    if addr.is_private:
        return True, "PRIVATE_NETWORK_IP"
    if addr.is_link_local:
        return True, "LINK_LOCAL_IP"
    if addr.is_multicast:
        return True, "MULTICAST_IP"
    if addr.is_reserved or not addr.is_global:
        return True, "RESERVED_NON_GLOBAL_IP"

    return False, None


def _has_mixed_scripts(unicode_host: str) -> bool:
    """Detect mixed Unicode scripts (e.g. Cyrillic + Latin homographs) within a single domain label."""
    for label in unicode_host.split("."):
        scripts: set[str] = set()
        for ch in label:
            if ch.isdigit() or ch == "-":
                continue
            try:
                char_name = unicodedata.name(ch)
            except ValueError:
                continue
            if "LATIN" in char_name:
                scripts.add("LATIN")
            elif "CYRILLIC" in char_name:
                scripts.add("CYRILLIC")
            elif "GREEK" in char_name:
                scripts.add("GREEK")
            else:
                scripts.add("OTHER")
        if len(scripts) > 1:
            return True
    return False


def parse_and_normalise_url(
    raw_token: str, *, require_valid_tld_if_schemeless: bool = True
) -> ExtractedUrlFinding | None:
    """Parse, validate, and canonicalise a single URL or domain token using urllib.parse, idna, and tldextract."""
    stripped = raw_token.strip().strip("<>\"'`").rstrip(".,;:!?)]}")
    if not stripped:
        return None

    refanged, was_defanged = refang_url_token(stripped)

    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", refanged))
    candidate_for_split = refanged if has_explicit_scheme else f"https://{refanged}"

    try:
        split_res = urlsplit(candidate_for_split)
    except ValueError as exc:
        return ExtractedUrlFinding(
            raw_url=stripped,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason=f"URL parse error: {exc}",
        )

    scheme = split_res.scheme.lower()
    if scheme not in {"http", "https"}:
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason=f"Unsupported URL scheme '{scheme}'.",
        )

    # Reject embedded credentials in URLs (e.g., https://inecnigeria.org@evil.com)
    if split_res.username is not None or split_res.password is not None:
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason="Embedded userinfo/credentials in URL authority are forbidden.",
        )

    raw_hostname = split_res.hostname
    if not raw_hostname:
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason="Missing hostname in URL.",
        )

    try:
        port = split_res.port
    except ValueError:
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason="Invalid port number in URL.",
        )

    # Check if hostname is an IP literal
    try:
        ip_obj = ipaddress.ip_address(raw_hostname)
        is_ip = True
        canonical_host = str(ip_obj)
        unicode_host = canonical_host
    except ValueError:
        is_ip = False
        canonical_host = ""
        unicode_host = ""

    if is_ip:
        is_blocked_ip, _ = is_ip_blocked_or_reserved(canonical_host)
        path = split_res.path or "/"
        netloc = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{netloc}:{port}"
        normalised_url = urlunsplit((scheme, netloc, path, split_res.query, ""))
        return ExtractedUrlFinding(
            raw_url=stripped,
            normalised_url=normalised_url,
            scheme=scheme,
            canonical_host=canonical_host,
            unicode_host=unicode_host,
            registered_domain=canonical_host,
            path=path,
            was_defanged=was_defanged,
            is_ip_literal=True,
            is_private_or_reserved_ip=is_blocked_ip,
        )

    # Handle domain names & IDN / Punycode conversion via `idna`
    lower_host = raw_hostname.strip(".").lower()
    if not lower_host or ".." in lower_host:
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason="Malformed domain label structure.",
        )

    try:
        ascii_host = idna.encode(lower_host, uts46=True).decode("ascii").lower()
        decoded_unicode_host = idna.decode(ascii_host)
    except idna.IDNAError as exc:
        if not has_explicit_scheme and not was_defanged:
            return None
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason=f"Invalid IDN/domain encoding: {exc}",
        )

    ext = _TLD_EXTRACTOR(ascii_host)
    if not ext.suffix or not ext.domain:
        if not has_explicit_scheme and not was_defanged and require_valid_tld_if_schemeless:
            return None
        return ExtractedUrlFinding(
            raw_url=stripped,
            scheme=scheme,
            canonical_host=ascii_host,
            unicode_host=decoded_unicode_host,
            was_defanged=was_defanged,
            is_malformed=True,
            malformed_reason="Unrecognised or missing top-level domain suffix.",
        )

    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    tld_suffix = ext.suffix.lower()

    is_idn = "xn--" in ascii_host or ascii_host != decoded_unicode_host
    has_mixed = _has_mixed_scripts(decoded_unicode_host) or is_idn
    is_shortened = (
        registered_domain in KNOWN_SHORTENER_DOMAINS
        or ascii_host in KNOWN_SHORTENER_DOMAINS
    )

    # Filter out tracking query parameters while preserving functional query parameters
    cleaned_query_pairs = [
        (k, v)
        for k, v in parse_qsl(split_res.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
    ]
    normalised_query = urlencode(cleaned_query_pairs, doseq=True)
    normalised_path = split_res.path if split_res.path else "/"

    netloc = ascii_host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{ascii_host}:{port}"

    normalised_url = urlunsplit((scheme, netloc, normalised_path, normalised_query, ""))

    return ExtractedUrlFinding(
        raw_url=stripped,
        normalised_url=normalised_url,
        scheme=scheme,
        canonical_host=ascii_host,
        unicode_host=decoded_unicode_host,
        registered_domain=registered_domain,
        subdomain=subdomain,
        tld_suffix=tld_suffix,
        path=normalised_path,
        was_defanged=was_defanged,
        is_idn_punycode=is_idn,
        has_mixed_script_or_confusable=has_mixed,
        is_shortened_url=is_shortened,
        is_ip_literal=False,
        is_private_or_reserved_ip=False,
        is_malformed=False,
    )


def extract_urls_from_text(text: str) -> list[ExtractedUrlFinding]:
    """Extract and normalise all URLs (standard, defanged, IDN, shortened, or malformed) from text."""
    cleaned_text = normalise_message_text(text)
    findings: list[ExtractedUrlFinding] = []
    seen_keys: set[str] = set()

    for match in _CANDIDATE_TOKEN_RE.finditer(cleaned_text):
        token = match.group(0)
        finding = parse_and_normalise_url(token, require_valid_tld_if_schemeless=True)
        if finding is None:
            continue
        dedup_key = finding.normalised_url or finding.raw_url
        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            findings.append(finding)

    return findings


def extract_basic_urls_compat(text: str) -> list[str]:
    """Return list of normalised URL strings for backward compatibility with Submission.extracted_urls."""
    findings = extract_urls_from_text(text)
    return [
        f.normalised_url if f.normalised_url else f.raw_url
        for f in findings
    ]


def extract_basic_urls(text: str) -> list[str]:
    """Extract normalised URL strings from text."""
    return extract_basic_urls_compat(text)


def detect_brand_impersonation(
    canonical_host: str, registered_domain: str
) -> tuple[str | None, str | None]:
    """Detect whether a non-official domain impersonates a protected Nigerian institution or .gov.ng."""
    host_lower = canonical_host.lower()
    reg_lower = registered_domain.lower()

    for institution, official_domains in PROTECTED_INSTITUTION_BRANDS.items():
        if reg_lower in official_domains or any(
            host_lower.endswith(f".{od}") for od in official_domains
        ):
            return None, None

        brand_token = institution.lower()
        if brand_token in host_lower:
            return (
                institution,
                f"Domain '{canonical_host}' contains protected institutional token '{brand_token}' "
                f"but is not an official {institution} domain ({', '.join(official_domains)}).",
            )

    # Check for fake 'gov' token used on commercial TLDs like .com.ng or .org
    if not host_lower.endswith(".gov.ng"):
        labels = re.split(r"[.-]", host_lower)
        if "gov" in labels or "govt" in labels:
            return (
                "FGN_GOVERNMENT",
                f"Domain '{canonical_host}' uses 'gov' label on a non-government TLD instead of '.gov.ng'.",
            )

    return None, None
