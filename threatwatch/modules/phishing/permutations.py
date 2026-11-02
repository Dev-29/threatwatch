"""Look-alike domain generation (typosquatting, homoglyphs, bitsquatting, combosquatting, TLD swaps).

``generate("example.com")`` returns candidate domains tagged with the technique that produced them.
Every candidate is a syntactically valid hostname; IDN homoglyphs are returned in punycode with
their Unicode rendering available via :func:`threatwatch.core.domains.to_unicode`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.domains import is_valid_hostname, split, to_ascii

KEYBOARD = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7",
    "9": "0oi8", "0": "po9", "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6ygfr5",
    "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8", "o": "0plki9", "p": "lo0", "a": "qwsz", "s": "edxzaw",
    "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy", "j": "ikmnhu", "k": "olmji", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}

# ASCII look-alikes (stay ASCII, no IDN needed)
ASCII_GLYPHS = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "e": ["3"], "a": ["4"],
    "s": ["5"], "b": ["8", "6"], "g": ["9", "q"], "q": ["g"], "z": ["2"], "t": ["7"],
}
MULTI_GLYPHS = {"m": ["rn", "nn"], "rn": ["m"], "w": ["vv"], "vv": ["w"], "d": ["cl"], "cl": ["d"]}

# Unicode confusables (Cyrillic / Greek / Latin-extended) -> IDN homograph attacks
UNICODE_GLYPHS = {
    "a": ["а", "à", "á", "ä", "ạ"], "c": ["с", "ç"], "e": ["е", "é", "è", "ë", "ẹ"], "i": ["і", "í", "ì", "ï"],
    "o": ["о", "ó", "ò", "ö", "ọ", "ο"], "p": ["р"], "s": ["ѕ"], "x": ["х"], "y": ["у", "ý"], "k": ["κ"],
    "n": ["ń", "ñ"], "u": ["ú", "ü", "υ"], "h": ["һ"], "j": ["ј"], "l": ["ӏ"],
}

VOWELS = "aeiou"

TLDS = ["com", "net", "org", "co", "io", "info", "biz", "us", "app", "dev", "online", "site", "xyz", "top",
        "shop", "store", "live", "support", "services", "cloud", "tech", "help", "link", "click", "me", "cc",
        "eu", "uk", "co.uk", "in", "de", "ru", "cn", "vip", "work", "today", "email", "login", "secure"]

DICTIONARY = ["login", "signin", "secure", "account", "accounts", "verify", "verification", "update", "support",
              "help", "portal", "auth", "sso", "my", "online", "mail", "webmail", "service", "services", "pay",
              "billing", "invoice", "hr", "payroll", "vpn", "admin", "it", "helpdesk", "access", "id", "app",
              "security", "reset", "password", "team", "corp", "group", "official", "customer", "client"]


@dataclass(frozen=True)
class Candidate:
    domain: str
    technique: str


def _label_ok(label: str) -> bool:
    if not (0 < len(label) <= 63) or label.startswith("-") or label.endswith("-"):
        return False
    # "ab--" is reserved for IDNA A-labels; only genuine punycode (xn--) may use it
    return label[2:4] != "--" or label.startswith("xn--")


def _variants(label: str) -> dict[str, set[str]]:
    v: dict[str, set[str]] = {k: set() for k in (
        "addition", "bitsquatting", "homoglyph", "hyphenation", "insertion", "omission", "repetition",
        "replacement", "subdomain", "transposition", "vowel-swap", "idn-homograph")}
    n = len(label)
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
        v["addition"].add(label + ch)
        v["addition"].add(ch + label)
    for i, c in enumerate(label):
        # bit flips that stay within [a-z0-9-]
        for bit in range(8):
            f = chr(ord(c) ^ (1 << bit))
            if f.isascii() and (f.isalnum() or f == "-") and f.lower() == f:
                v["bitsquatting"].add(label[:i] + f + label[i + 1 :])
        for g in ASCII_GLYPHS.get(c, []):
            v["homoglyph"].add(label[:i] + g + label[i + 1 :])
        for g in UNICODE_GLYPHS.get(c, []):
            v["idn-homograph"].add(label[:i] + g + label[i + 1 :])
        if 0 < i < n:
            v["hyphenation"].add(label[:i] + "-" + label[i:])
            v["subdomain"].add(label[:i] + "." + label[i:])
        for k in KEYBOARD.get(c, ""):
            v["insertion"].add(label[:i] + k + c + label[i + 1 :])
            v["insertion"].add(label[:i] + c + k + label[i + 1 :])
            v["replacement"].add(label[:i] + k + label[i + 1 :])
        v["omission"].add(label[:i] + label[i + 1 :])
        v["repetition"].add(label[:i] + c + c + label[i + 1 :])
        if i < n - 1 and label[i] != label[i + 1]:
            v["transposition"].add(label[:i] + label[i + 1] + label[i] + label[i + 2 :])
        if c in VOWELS:
            for vw in VOWELS:
                if vw != c:
                    v["vowel-swap"].add(label[:i] + vw + label[i + 1 :])
    for src, dsts in MULTI_GLYPHS.items():
        start = label.find(src)
        while start != -1:
            for d in dsts:
                v["homoglyph"].add(label[:start] + d + label[start + len(src) :])
            start = label.find(src, start + 1)
    for k in v:
        v[k].discard(label)
    return v


def generate(domain: str, *, limit: int | None = None, include_tlds: bool = True,
             include_dictionary: bool = True) -> list[Candidate]:
    sub, label, suffix = split(domain)
    if not label or not suffix:
        raise ValueError(f"not a registrable domain: {domain}")
    original = f"{label}.{suffix}"
    seen: dict[str, str] = {}

    def add(name: str, technique: str) -> None:
        try:
            ascii_name = to_ascii(name)
        except UnicodeError:
            return
        if ascii_name == original or ascii_name in seen:
            return
        if not all(_label_ok(lbl) for lbl in ascii_name.split(".")) or not is_valid_hostname(ascii_name):
            return
        seen[ascii_name] = technique

    # Order matters when a limit applies: most dangerous techniques first.
    variants = _variants(label)
    priority = ["idn-homograph", "homoglyph", "transposition", "omission", "repetition", "replacement",
                "vowel-swap", "hyphenation", "insertion", "bitsquatting", "subdomain", "addition"]
    for tech in priority:
        for lbl in sorted(variants[tech]):
            add(f"{lbl}.{suffix}", tech)
    if include_tlds:
        for tld in TLDS:
            if tld != suffix:
                add(f"{label}.{tld}", "tld-swap")
        add(f"{label}{suffix.replace('.', '')}.com", "tld-concat")
        add(f"{label}-{suffix.replace('.', '-')}.com", "tld-concat")
    if include_dictionary:
        for w in DICTIONARY:
            for name in (f"{label}-{w}", f"{w}-{label}", f"{label}{w}", f"{w}{label}"):
                add(f"{name}.{suffix}", "combosquatting")
            if suffix != "com":
                add(f"{label}-{w}.com", "combosquatting")
    out = [Candidate(d, t) for d, t in seen.items()]
    return out[:limit] if limit else out


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (used by the URL analyser for brand similarity)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def skeleton(s: str) -> str:
    """Collapse visually-confusable characters so 'paypa1' and 'paypal' compare equal."""
    s = s.lower()
    for multi, single in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        s = s.replace(multi, single)
    table = {"0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s", "8": "b", "9": "g", "7": "t", "2": "z"}
    out = []
    for ch in s:
        for base, glyphs in UNICODE_GLYPHS.items():
            if ch in glyphs:
                ch = base
                break
        out.append(table.get(ch, ch))
    return "".join(out)
