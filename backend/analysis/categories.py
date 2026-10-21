"""Domain → service → category classification, local and rule based.

Rule layers, highest priority first:

1. `manual`  - rules entered in the web UI (stored in the settings table)
2. `local`   - `domain_categories.local.yaml` in the data directory
3. `builtin` - backend/data/domain_categories.yaml (shipped)
4. `ut1`     - optional import of the UT1 lists (python -m backend.dns_category_import)

Matching walks from the full name to ever shorter suffixes; at each length the
layers are asked in priority order. So the most specific rule wins, and among
equally specific rules the higher layer: a builtin `youtubei.googleapis.com`
beats a manual `googleapis.com`, a manual `youtube.com` beats the builtin one.

Every result says which rule and which layer decided it, and how sure that rule
is. "Unknown" means no rule matched - not that the domain is harmless.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

log = logging.getLogger(__name__)

BUILTIN_PATH = Path(__file__).resolve().parent.parent / "data" / "domain_categories.yaml"
LOCAL_FILE = "domain_categories.local.yaml"
UT1_FILE = "ut1_categories.tsv"
LAYERS = ("manual", "local", "builtin", "ut1")
CONFIDENCE = ("high", "medium", "low")
# Letters, digits, hyphen and underscore per label; also single labels like "lan".
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


def normalize_domain(name: str) -> str:
    return name.strip().lower().rstrip(".")


def valid_domain(name: str) -> bool:
    return bool(DOMAIN_RE.match(normalize_domain(name)))


@dataclass(frozen=True, slots=True)
class Rule:
    categories: tuple[str, ...]
    service: str | None
    service_name: str | None
    confidence: str


@dataclass(frozen=True, slots=True)
class Classification:
    categories: tuple[str, ...]
    service: str | None = None
    service_name: str | None = None
    source: str | None = None       # layer that decided, None = no rule matched
    rule: str | None = None         # matched pattern; "=name" for an exact rule
    confidence: str | None = None

    @property
    def primary(self) -> str:
        return self.categories[0] if self.categories else "unknown"

    def to_dict(self) -> dict:
        return {"categories": list(self.categories), "primary": self.primary, "service": self.service,
                "service_name": self.service_name, "source": self.source, "rule": self.rule,
                "confidence": self.confidence}


UNKNOWN = Classification(categories=("unknown",))


@dataclass
class RuleSet:
    source: str
    suffix: dict[str, Rule]
    exact: dict[str, Rule]

    def __len__(self) -> int:
        return len(self.suffix) + len(self.exact)


class RuleError(ValueError):
    pass


def _rule_set_from_data(data: dict, source: str, known: set[str] | None) -> tuple[RuleSet, dict[str, str]]:
    if not isinstance(data, dict):
        raise RuleError("top level must be a mapping")
    labels = {str(k): str(v) for k, v in (data.get("categories") or {}).items()}
    known = set(labels) | (known or set())
    rs = RuleSet(source, {}, {})
    shared = RuleSet(source, {}, {})

    def add(entry: dict, sid: str | None, into: RuleSet) -> None:
        cats = tuple(entry.get("categories") or ())
        if not cats:
            raise RuleError(f"{sid or 'shared'}: no categories")
        bad = [c for c in cats if c not in known]
        if bad:
            raise RuleError(f"{sid or 'shared'}: unknown categories {bad}")
        conf = entry.get("confidence") or ("low" if sid is None else "high")
        if conf not in CONFIDENCE:
            raise RuleError(f"{sid or 'shared'}: confidence must be one of {CONFIDENCE}")
        rule = Rule(cats, sid, entry.get("name"), conf)
        for key, target in (("domains", into.suffix), ("exact", into.exact)):
            for d in entry.get(key) or ():
                d = normalize_domain(str(d))
                if not valid_domain(d):
                    raise RuleError(f"{sid or 'shared'}: invalid domain {d!r}")
                target[d] = rule

    for sid, entry in (data.get("services") or {}).items():
        add(entry or {}, str(sid), rs)
    if data.get("shared"):
        add(data["shared"], None, shared)
    # A service entry for the same name is the more specific statement than
    # "shared infrastructure", so shared rules only fill gaps.
    for d, r in shared.suffix.items():
        rs.suffix.setdefault(d, r)
    for d, r in shared.exact.items():
        rs.exact.setdefault(d, r)
    return rs, labels


def load_yaml_rules(path: Path, source: str, known: set[str] | None = None) -> tuple[RuleSet, dict[str, str]]:
    with open(path, encoding="utf-8") as f:
        return _rule_set_from_data(yaml.safe_load(f) or {}, source, known)


def load_ut1(path: Path, known: set[str]) -> RuleSet:
    """Tab-separated `domain<TAB>category` as written by backend/dns_category_import.py."""
    rs = RuleSet("ut1", {}, {})
    rules: dict[str, Rule] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            dom, _, cat = line.rstrip("\n").partition("\t")
            if not dom or cat not in known:
                continue
            r = rules.get(cat)
            if r is None:
                r = rules[cat] = Rule((cat,), None, "UT1 list", "medium")
            rs.suffix[dom] = r
    return rs


def manual_rule_set(overrides: dict, known: set[str]) -> RuleSet:
    """`overrides`: {domain: {"categories": [...], "exact": bool, "service_name": str|None}}."""
    rs = RuleSet("manual", {}, {})
    for dom, o in (overrides or {}).items():
        cats = tuple(c for c in (o.get("categories") or ()) if c in known)
        if not cats or not valid_domain(dom):
            continue
        r = Rule(cats, None, o.get("service_name") or None, "high")
        (rs.exact if o.get("exact") else rs.suffix)[normalize_domain(dom)] = r
    return rs


class Classifier:
    def __init__(self, layers: Iterable[RuleSet], labels: dict[str, str], errors: list[str] | None = None,
                 cache_size: int = 50_000):
        order = {name: i for i, name in enumerate(LAYERS)}
        self.layers = sorted(layers, key=lambda rs: order.get(rs.source, len(order)))
        self.labels = labels
        self.errors = errors or []
        self._cache: dict[str, Classification] = {}
        self._cache_size = cache_size

    @classmethod
    def load(cls, data_dir: str | None = None, overrides: dict | None = None,
             builtin: Path = BUILTIN_PATH) -> "Classifier":
        errors: list[str] = []
        base, labels = load_yaml_rules(builtin, "builtin")    # shipped file: errors are bugs, let them raise
        known = set(labels)
        layers = [base]
        if data_dir:
            local = Path(data_dir) / LOCAL_FILE
            if local.exists():
                try:
                    rs, more = load_yaml_rules(local, "local", known)
                    labels = {**labels, **more}
                    known |= set(more)
                    layers.append(rs)
                except (OSError, yaml.YAMLError, RuleError) as e:
                    errors.append(f"{LOCAL_FILE} ignored: {e}")
                    log.error("Category rules %s ignored: %s", local, e)
            ut1 = Path(data_dir) / UT1_FILE
            if ut1.exists():
                try:
                    layers.append(load_ut1(ut1, known))
                except OSError as e:
                    errors.append(f"{UT1_FILE} ignored: {e}")
        layers.append(manual_rule_set(overrides or {}, known))
        return cls(layers, labels, errors)

    def classify(self, domain: str) -> Classification:
        name = normalize_domain(domain)
        hit = self._cache.get(name)
        if hit is not None:
            return hit
        res = self._match(name)
        if len(self._cache) >= self._cache_size:
            self._cache.clear()
        self._cache[name] = res
        return res

    def _match(self, name: str) -> Classification:
        if not name:
            return UNKNOWN
        for rs in self.layers:
            r = rs.exact.get(name)
            if r is not None:
                return _result(r, rs.source, f"={name}")
        labels = name.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            for rs in self.layers:
                r = rs.suffix.get(suffix)
                if r is not None:
                    return _result(r, rs.source, suffix)
        return UNKNOWN

    def summary(self) -> dict:
        return {"layers": [{"source": rs.source, "rules": len(rs)} for rs in self.layers],
                "errors": self.errors, "categories": self.labels}


def _result(r: Rule, source: str, pattern: str) -> Classification:
    return Classification(categories=r.categories, service=r.service, service_name=r.service_name,
                          source=source, rule=pattern, confidence=r.confidence)
