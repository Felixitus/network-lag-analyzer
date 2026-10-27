"""Domain → service → category classification, local and rule based.

Rule layers, highest priority first:

1. `manual`  - rules entered in the web UI (stored in the settings table)
2. `local`   - `domain_categories.local.yaml` in the data directory
3. `builtin` - backend/data/domain_categories.yaml (shipped)
4. `ut1`     - optional import of the UT1 lists (python -m backend.dns_category_import),
               kept on disk as a hash index (see Ut1Index) - 4.6 million adult domains alone

Matching walks from the full name to ever shorter suffixes; at each length the
layers are asked in priority order. So the most specific rule wins, and among
equally specific rules the higher layer: a builtin `youtubei.googleapis.com`
beats a manual `googleapis.com`, a manual `youtube.com` beats the builtin one.

Every result says which rule and which layer decided it, and how sure that rule
is. "Unknown" means no rule matched - not that the domain is harmless.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import logging
import mmap
import re
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

log = logging.getLogger(__name__)

BUILTIN_PATH = Path(__file__).resolve().parent.parent / "data" / "domain_categories.yaml"
LOCAL_FILE = "domain_categories.local.yaml"
UT1_INDEX = "ut1_categories.idx"
UT1_META = "ut1_categories.json"
UT1_SOURCE = "UT1 list (Université Toulouse Capitole, CC BY-SA 4.0)"
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
    phase_gap: float | None = None   # minutes; service-specific gap for activity phases


@dataclass(frozen=True, slots=True)
class Classification:
    categories: tuple[str, ...]
    service: str | None = None
    service_name: str | None = None
    source: str | None = None       # layer that decided, None = no rule matched
    rule: str | None = None         # matched pattern; "=name" for an exact rule
    confidence: str | None = None
    phase_gap: float | None = None

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
        gap = entry.get("phase_gap_minutes")
        if gap is not None and not (isinstance(gap, (int, float)) and 1 <= gap <= 120):
            raise RuleError(f"{sid or 'shared'}: phase_gap_minutes must be 1-120")
        rule = Rule(cats, sid, entry.get("name"), conf, float(gap) if gap is not None else None)
        for key, target in (("domains", into.suffix), ("exact", into.exact)):
            for d in entry.get(key) or ():
                d = normalize_domain(str(d))
                if not valid_domain(d):
                    raise RuleError(f"{sid or 'shared'}: invalid domain {d!r}")
                target[d] = rule

    for sid, entry in (data.get("services") or {}).items():
        add(entry or {}, str(sid), rs)
    sh = data.get("shared") or {}
    # `shared` is either one entry (older local files) or one entry per provider. A provider
    # gets a name but no service id: it says who delivered, never which service was used.
    default_cat = ["infrastructure"] if "infrastructure" in known else ["other"]
    for entry in ([sh] if "domains" in sh else sh.values()):
        entry = dict(entry or {})
        entry.setdefault("categories", default_cat)
        add(entry, None, shared)
    # A service entry for the same name is the more specific statement than
    # "shared infrastructure", so shared rules only fill gaps.
    for d, r in shared.suffix.items():
        rs.suffix.setdefault(d, r)
    for d, r in shared.exact.items():
        rs.exact.setdefault(d, r)
    return rs, labels


def load_category_info(path: Path) -> dict[str, str]:
    """`category_info` of a rule file: one sentence per category on what counts there and what not."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {str(k): str(v) for k, v in (data.get("category_info") or {}).items()}


def load_yaml_rules(path: Path, source: str, known: set[str] | None = None) -> tuple[RuleSet, dict[str, str]]:
    with open(path, encoding="utf-8") as f:
        return _rule_set_from_data(yaml.safe_load(f) or {}, source, known)


def ut1_key(domain: str) -> int:
    """56-bit hash of a domain, shifted left by 8 so the low byte can carry the category code.

    With 5 million entries the chance that any two collide is about 1:6000, and that an
    unlisted domain hits a listed hash about 1:10^10 per lookup - negligible next to how
    rough a category list is anyway."""
    return int.from_bytes(hashlib.blake2b(domain.encode("utf-8"), digest_size=7).digest(), "big") << 8


class _Ut1Suffix:
    """dict-like view on the index, so the classifier can treat it like any other rule layer."""

    def __init__(self, index: "Ut1Index"):
        self._index = index

    def get(self, name: str, default=None):
        return self._index.lookup(name) or default

    def values(self):
        return self._index.rules.values()

    def __iter__(self):
        return iter(())


class Ut1Index:
    """The UT1 lists as a sorted file of 8-byte records (hash << 8 | category code), searched
    with a binary search on the memory-mapped file: no RAM for millions of names, a lookup is
    about 23 reads of 8 bytes. The metadata file names the categories and the import."""

    source = "ut1"

    def __init__(self, idx: Path, meta: dict, known: set[str]):
        self.meta = meta
        cats = meta.get("categories") or []
        self.rules = {i: Rule((c,), None, UT1_SOURCE, "medium") for i, c in enumerate(cats) if c in known}
        self._f = open(idx, "rb")
        size = idx.stat().st_size
        if size != 8 * int(meta.get("count", -1)):
            self._f.close()
            raise OSError(f"{idx.name}: {size} bytes, metadata says {meta.get('count')} entries")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ) if size else None
        self._n = size // 8
        self._lock = threading.Lock()      # mmap slicing is not documented as thread-safe
        self.exact: dict[str, Rule] = {}
        self.suffix = _Ut1Suffix(self)

    @classmethod
    def open(cls, data_dir: Path, known: set[str]) -> "Ut1Index | None":
        idx, meta = data_dir / UT1_INDEX, data_dir / UT1_META
        if not idx.exists() or not meta.exists():
            return None
        return cls(idx, json.loads(meta.read_text(encoding="utf-8")), known)

    def __len__(self) -> int:
        return self._n

    def _rec(self, i: int) -> int:
        return struct.unpack_from(">Q", self._mm, 8 * i)[0]

    def lookup(self, name: str) -> Rule | None:
        if not self._n:
            return None
        key = ut1_key(name)
        with self._lock:
            i = bisect.bisect_left(range(self._n), key, key=self._rec)
            rec = self._rec(i) if i < self._n else None
        if rec is None or rec >> 8 != key >> 8:
            return None
        return self.rules.get(rec & 0xFF)

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
        self._f.close()

    @property
    def fingerprint_token(self) -> str:
        return f"{self.meta.get('sha256')}|{self.meta.get('count')}|{','.join(self.meta.get('categories') or [])}"


def manual_rule_set(overrides: dict, known: set[str]) -> RuleSet:
    """`overrides`: {domain: {"categories": [...], "exact": bool, "service_name": str|None}}."""
    rs = RuleSet("manual", {}, {})
    for dom, o in (overrides or {}).items():
        cats = tuple(c for c in (o.get("categories") or ()) if c in known)
        if not cats or not valid_domain(dom):
            continue
        name = (o.get("service_name") or "").strip() or None
        # A named manual rule defines a service of its own, so that activity phases
        # can be built for it like for a shipped service.
        sid = f"manual:{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}" if name else None
        r = Rule(cats, sid, name, "high")
        (rs.exact if o.get("exact") else rs.suffix)[normalize_domain(dom)] = r
    return rs


class Classifier:
    def __init__(self, layers: Iterable[RuleSet], labels: dict[str, str], errors: list[str] | None = None,
                 cache_size: int = 50_000):
        order = {name: i for i, name in enumerate(LAYERS)}
        self.layers = sorted(layers, key=lambda rs: order.get(rs.source, len(order)))
        self.labels = labels
        self.info: dict[str, str] = {}
        self.errors = errors or []
        self._cache: dict[str, Classification] = {}
        self._cache_size = cache_size
        # service id → rule; the highest layer that names a service defines it.
        self.services: dict[str, Rule] = {}
        for rs in self.layers:
            for r in (*rs.exact.values(), *rs.suffix.values()):
                if r.service and r.service not in self.services:
                    self.services[r.service] = r
        self.fingerprint = _fingerprint(self.layers)

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
            try:
                ut1 = Ut1Index.open(Path(data_dir), known)
                if ut1 is not None:
                    layers.append(ut1)
            except (OSError, ValueError) as e:
                errors.append(f"{UT1_INDEX} ignored: {e}")
                log.error("UT1 index ignored: %s", e)
        layers.append(manual_rule_set(overrides or {}, known))
        clf = cls(layers, labels, errors)
        clf.info = load_category_info(builtin)
        return clf

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

    def close(self) -> None:
        """Releases the UT1 index file (Windows cannot replace a file that is still mapped)."""
        for rs in self.layers:
            if hasattr(rs, "close"):
                rs.close()

    def service_info(self, service: str) -> Rule | None:
        return self.services.get(service)

    def summary(self) -> dict:
        return {"layers": [{"source": rs.source, "rules": len(rs),
                            **({"imported": rs.meta.get("imported_at"), "list_date": rs.meta.get("list_date"),
                                "counts": rs.meta.get("counts")} if isinstance(rs, Ut1Index) else {})}
                           for rs in self.layers],
                "category_info": self.info,
                "errors": self.errors, "categories": self.labels}


def _fingerprint(layers: list[RuleSet]) -> str:
    """Changes whenever any rule changes - stored data derived from rules is rebuilt then."""
    h = hashlib.sha1()
    for rs in layers:
        h.update(rs.source.encode())
        token = getattr(rs, "fingerprint_token", None)
        if token is not None:            # millions of hashed names: the import itself identifies them
            h.update(token.encode())
            continue
        for kind, d in (("=", rs.exact), ("~", rs.suffix)):
            for name in sorted(d):
                r = d[name]
                h.update(f"{kind}{name}|{','.join(r.categories)}|{r.service}|{r.confidence}|{r.phase_gap};".encode())
    return h.hexdigest()[:16]


def _result(r: Rule, source: str, pattern: str) -> Classification:
    return Classification(categories=r.categories, service=r.service, service_name=r.service_name,
                          source=source, rule=pattern, confidence=r.confidence, phase_gap=r.phase_gap)
