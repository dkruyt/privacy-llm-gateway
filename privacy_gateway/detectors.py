"""Rule-id-only sensitive-content detectors.

Detectors return a sorted, de-duplicated list of rule ids. They never return,
log or store the matched text. Every rule runs on each (normalised) string and
on its decoded variants (base64 runs, %-encoding), so trivial obfuscation does
not hide content from them.

Detectors are deliberately aggressive: a false positive only costs local inference.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import unquote

from .extract import normalize

PERSONAL_RULES = ("email", "phone_intl", "phone_nl", "iban", "credit_card", "nl_bsn", "private_ip")
CREDENTIAL_RULES = (
    "pem_private_key",
    "aws_access_key",
    "github_token",
    "openai_style_key",
    "slack_token",
    "google_api_key",
    "stripe_key",
    "jwt",
    "bearer_token",
    "credential_assignment",
    "url_with_credentials",
)
ORG_RULES = ("internal_domain", "confidential_marker")
MANIPULATION_RULES = ("classifier_manipulation",)
ALL_STATIC_RULES = PERSONAL_RULES + CREDENTIAL_RULES + ORG_RULES + MANIPULATION_RULES

MAX_DECODE_DEPTH = 2


# --------------------------------------------------------------------------- checksums


def iban_valid(candidate: str) -> bool:
    s = candidate.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_IIN = re.compile(
    r"^(?:4"  # Visa
    r"|5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720"  # Mastercard
    r"|3[47]"  # Amex
    r"|30[0-5]|3[689]"  # Diners
    r"|35(?:2[89]|[3-8]\d)"  # JCB
    r"|6011|64[4-9]|65"  # Discover
    r"|62"  # UnionPay
    r"|5[06-9]|6\d"  # Maestro
    r")"
)


def card_valid(digits: str) -> bool:
    return 13 <= len(digits) <= 19 and bool(_IIN.match(digits)) and luhn_valid(digits)


def bsn_valid(digits: str) -> bool:
    if len(digits) != 9 or not digits.isdigit() or digits == "000000000":
        return False
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    return sum(int(d) * w for d, w in zip(digits, weights)) % 11 == 0


_PRIVATE_V4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_ULA = ipaddress.ip_network("fc00::/7")


# --------------------------------------------------------------------------- regex rules

_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE_INTL = re.compile(r"(?<![\w+])\+[1-9]\d{0,2}(?:\s?\(0\))?(?:[\s.-]?\d){7,14}(?!\d)")
_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,34}")
_CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d])")
_BSN = re.compile(r"(?<![\w.,-])\d{9}(?![\w-]|[.,]\d)")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]|\.\d)")
_IPV6_ULA = re.compile(r"(?<![\w:])f[cd][0-9a-f]{0,2}:[0-9a-f:.]*[0-9a-f]", re.IGNORECASE)

_CREDENTIAL_REGEXES: dict[str, re.Pattern[str]] = {
    "pem_private_key": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    "aws_access_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "github_token": re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    "openai_style_key": re.compile(r"(?<![A-Za-z0-9_-])sk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{20,}"),
    "slack_token": re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}"),
    "stripe_key": re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    "jwt": re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    "bearer_token": re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    "credential_assignment": re.compile(
        r"(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|token|wachtwoord)(?![A-Za-z0-9])"
        r"[\"']?\s*[:=]\s*[\"']?[^\s\"',;}{\]\[]",
        re.IGNORECASE,
    ),
    "url_with_credentials": re.compile(
        r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s/]", re.IGNORECASE
    ),
}

_MANIPULATION = re.compile(
    r"|".join(
        [
            r"\bignore\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|preceding|former)\s+"
            r"(?:instructions?|prompts?|rules|directions|messages)",
            r"\b(?:disregard|forget)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier)\s+"
            r"(?:instructions?|prompts?|rules)",
            r"\b(?:classify|mark|route|label|treat|categori[sz]e|tag|flag|consider)\s+"
            r"(?:this|it|me|everything|the\s+(?:request|message|conversation|following|above))\s+as\s+"
            r"(?:public|safe|non[\s-]?sensitive|not\s+sensitive)",
            r"\b(?:this|it|the\s+following|everything\s+(?:here|below|above))\s+(?:is|contains|are)\s+"
            r"(?:only\s+|all\s+|purely\s+)?(?:public|non[\s-]?sensitive)\s+(?:information|data|knowledge|content)",
            r"[\"']verdict[\"']\s*:\s*[\"']public[\"']",
            r"\bthe\s+classifier\b",
            r"\bclef\b",
            r"\bprivacy[\s_-]*(?:gateway|filter|router)\b",
            r"\bnegeer\s+(?:alle\s+)?(?:vorige|eerdere|voorgaande)\s+(?:instructies|opdrachten)",
        ]
    ),
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- detect-secrets

# detect-secrets logs skipped secret values at INFO; never let that reach any handler.
_ds_log = logging.getLogger("detect-secrets")
_ds_log.handlers = [logging.NullHandler()]
_ds_log.propagate = False
_ds_log.setLevel(logging.CRITICAL + 1)

_DS_LOCK = threading.Lock()
_DS_ACTIVE: tuple[str, ...] | None = None


def detect_secrets_plugin_names() -> set[str]:
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    return {cls.__name__ for cls in get_mapping_from_secret_type_to_class().values()}


def _ds_silence() -> None:
    # get_logger() in detect-secrets resets handlers on import; re-apply after import.
    from detect_secrets.core import log as ds_log_mod

    ds_log_mod.log.handlers = [logging.NullHandler()]
    ds_log_mod.log.propagate = False
    ds_log_mod.log.setLevel(logging.CRITICAL + 1)
    ds_log_mod.log.disabled = True


def _ds_scan(text: str, plugins: tuple[str, ...]) -> set[str]:
    """detect-secrets line-based scan (with its built-in filters). Plugin class names."""
    global _DS_ACTIVE
    from detect_secrets.core.scan import _process_line_based_plugins
    from detect_secrets.settings import cache_bust, configure_settings_from_baseline, get_settings

    with _DS_LOCK:
        if _DS_ACTIVE != plugins:
            _ds_silence()
            cache_bust()
            get_settings().clear()
            configure_settings_from_baseline({"plugins_used": [{"name": p} for p in plugins]})
            _DS_ACTIVE = plugins
        from detect_secrets.settings import get_plugins

        type_to_name = {p.secret_type: type(p).__name__ for p in get_plugins()}
        lines = list(enumerate(text.splitlines() or [text], start=1))
        found: set[str] = set()
        for secret in _process_line_based_plugins(lines, filename="request.txt"):
            found.add(type_to_name.get(secret.type, "unknown"))
        return found


# --------------------------------------------------------------------------- variants

_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def _is_text(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    return printable / len(s) >= 0.95


def _b64_decode(run: str) -> str | None:
    core = run.rstrip("=")
    alt = b"-_" if ("-" in core or "_" in core) else None
    if alt and ("+" in core or "/" in core):
        return None
    padded = core + "=" * (-len(core) % 4)
    try:
        raw = base64.b64decode(padded, altchars=alt, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _is_text(text) else None


def decoded_variants(s: str, depth: int = MAX_DECODE_DEPTH) -> list[str]:
    """The string itself plus base64- and %-decoded variants (recursively)."""
    out = [s]
    if depth <= 0:
        return out
    children: list[str] = []
    for m in _B64_RUN.finditer(s):
        dec = _b64_decode(m.group(0))
        if dec:
            children.append(normalize(dec))
    if _PCT.search(s):
        try:
            dec = unquote(s, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            dec = unquote(s, encoding="utf-8", errors="replace")
        if dec != s:
            children.append(normalize(dec))
    for child in children:
        out.extend(decoded_variants(child, depth - 1))
    return out


# --------------------------------------------------------------------------- engine


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    match: Callable[[str], bool]


def _regex_rule(rule_id: str, rx: re.Pattern[str]) -> _Rule:
    return _Rule(rule_id, lambda s: rx.search(s) is not None)


def _any_valid(rx: re.Pattern[str], check: Callable[[str], bool]) -> Callable[[str], bool]:
    def run(s: str) -> bool:
        return any(check(m.group(0)) for m in rx.finditer(s))

    return run


def _iban_check(match: str) -> bool:
    compact = match.replace(" ", "").upper()
    # The run may swallow following text; try every prefix of plausible length.
    return any(iban_valid(compact[:n]) for n in range(min(len(compact), 34), 14, -1))


def _card_check(match: str) -> bool:
    return card_valid(re.sub(r"[ -]", "", match))


def _ipv4_check(match: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(match)
    except ValueError:
        return False
    return any(ip in n for n in _PRIVATE_V4)


def _ipv6_check(match: str) -> bool:
    for cand in (match, match.rstrip(":.")):
        try:
            if ipaddress.IPv6Address(cand) in _ULA:
                return True
        except ValueError:
            continue
    return False


class Detectors:
    """Compiled detector set for one policy. Immutable; rebuilt on config reload."""

    def __init__(self, policy) -> None:  # policy: config.DetectorPolicy
        disabled = set(policy.disabled)
        rules: list[_Rule] = []

        def add(rule: _Rule) -> None:
            if rule.rule_id not in disabled:
                rules.append(rule)

        add(_regex_rule("email", _EMAIL))
        add(_regex_rule("phone_intl", _PHONE_INTL))
        national = [re.compile(rx) for rx in policy.national_phone_patterns]
        add(_Rule("phone_nl", lambda s: any(rx.search(s) for rx in national)))
        add(_Rule("iban", _any_valid(_IBAN, _iban_check)))
        add(_Rule("credit_card", _any_valid(_CARD, _card_check)))
        add(_Rule("nl_bsn", _any_valid(_BSN, bsn_valid)))
        add(
            _Rule(
                "private_ip",
                lambda s: _any_valid(_IPV4, _ipv4_check)(s) or _any_valid(_IPV6_ULA, _ipv6_check)(s),
            )
        )
        for rid, rx in _CREDENTIAL_REGEXES.items():
            add(_regex_rule(rid, rx))
        if policy.internal_domains:
            alts = "|".join(re.escape(d) for d in sorted(policy.internal_domains, key=len, reverse=True))
            add(
                _regex_rule(
                    "internal_domain",
                    re.compile(
                        rf"(?<![\w.-])(?:[a-z0-9-]+\.)*(?:{alts})(?![\w-]|\.[a-z0-9-])", re.IGNORECASE
                    ),
                )
            )
        if policy.confidential_markers:
            alts = "|".join(
                r"\s+".join(re.escape(w) for w in m.split()) for m in policy.confidential_markers
            )
            add(_regex_rule("confidential_marker", re.compile(rf"(?<!\w)(?:{alts})(?!\w)", re.IGNORECASE)))
        for cid, rx in policy.custom_patterns.items():
            add(_regex_rule(f"custom:{cid}", re.compile(rx, re.IGNORECASE)))
        if policy.manipulation_patterns:
            add(_regex_rule("classifier_manipulation", _MANIPULATION))

        self._rules = tuple(rules)
        ds = policy.detect_secrets
        self._ds_plugins: tuple[str, ...] | None = None
        if ds.enabled and "detect_secrets" not in disabled:
            self._ds_plugins = tuple(sorted(ds.plugins or detect_secrets_plugin_names()))

    @property
    def rule_ids(self) -> list[str]:
        ids = [r.rule_id for r in self._rules]
        if self._ds_plugins:
            ids += [f"detect_secrets:{p}" for p in self._ds_plugins]
        return ids

    def scan(self, strings: Iterable[str]) -> list[str]:
        """Return sorted unique rule ids that fire on any string or decoded variant."""
        hits: set[str] = set()
        for s in strings:
            if not s:
                continue
            for variant in decoded_variants(s):
                for rule in self._rules:
                    if rule.rule_id not in hits and rule.match(variant):
                        hits.add(rule.rule_id)
                if self._ds_plugins:
                    hits.update(f"detect_secrets:{p}" for p in _ds_scan(variant, self._ds_plugins))
        return sorted(hits)
