#!/usr/bin/env python3
"""
CVE Scanner — mass sequential multi-CVE checker.

Mode:
  - single : scan satu URL
  - mass   : scan banyak URL dari file .txt (threaded)

Alur per target (tetap sequential per-CVE):
  target -> CVE #1 -> vulnerable? STOP untuk target ini
         -> aman?       lanjut CVE #2
         -> ... sampai habis

Nambah CVE baru: tinggal tambah 1 baris di CVE_REGISTRY.
"""

import argparse
import concurrent.futures
import importlib
import inspect
import json
import os
import sys
import threading
import time
from datetime import datetime

# ── ANSI color ──────────────────────────────────────────────────────────

_USE_COLOR = ("NO_COLOR" not in os.environ and sys.stdout.isatty())


def _c(code, t):
    return t if not _USE_COLOR else f"\x1b[{code}m{t}\x1b[0m"


def cyan(t):   return _c("1;36", t)
def green(t):  return _c("1;32", t)
def red(t):    return _c("1;31", t)
def yellow(t): return _c("1;33", t)
def gray(t):   return _c("0;90", t)
def bold(t):   return _c("1", t)


_PRINT_LOCK = threading.Lock()


def _log(msg):
    with _PRINT_LOCK:
        print(msg, flush=True)


# ── banner ──────────────────────────────────────────────────────────────

def _print_banner():
    """Tampilkan ASCII banner di awal."""
    art = r"""
  ____ __     __ _____ ____
 / ___|\ \   / /| ____/ ___|  ___ __ _ _ __  _ __   ___ _ __
| |     \ \ / / |  _| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |___   \ V /  | |___ ___) | (_| (_| | | | | | | |  __/ |
 \____|   \_/   |_____|____/ \___\__,_|_| |_|_| |_|\___|_|
"""
    if _USE_COLOR:
        palette = (51, 45, 39, 33, 27, 21)
        lines = []
        for i, line in enumerate(art.strip("\n").split("\n")):
            color = palette[min(i, len(palette) - 1)]
            lines.append(f"\x1b[1;38;5;{color}m{line}\x1b[0m")
        print("\n" + "\n".join(lines))
    else:
        print(art)

    print(gray("  CVE Scanner  ") + cyan("·")
          + gray("  mass CVE checker  ") + cyan("·")
          + gray("  dev : t.me/JayaXploit"))
    print(gray("  " + "─" * 62))
    print()


# ── REGISTRY CVE ────────────────────────────────────────────────────────
# Format: (CVE_ID, NAMA, MODULE_PATH, FUNC_NAME, KWARGS)
# - MODULE_PATH : import path, mis. "cve_modules.jce"
# - FUNC_NAME   : nama function di modul, mis. "check_cve_2026_48907"
# - KWARGS      : dict parameter tambahan ({} kalau nggak ada)
#
# Nambah CVE baru = tambah 1 tuple di bawah ini. Selesai.

CVE_REGISTRY = [
    ("CVE-2026-48907", "Joomla JCE unauth RCE",
     "cve_modules.jce",      "check_cve_2026_48907",
     {"verify_rce": True}),

    ("CVE-2026-48939", "Joomla iCagenda RCE",
     "cve_modules.icagenda", "check_cve_2026_48939",
     {"check_version_only": True, "max_attempts": 20}),

    ("CVE-2026-102785", "YOOtheme Pro unauth RCE",
     "cve_modules.yootheme", "check_cve_2026_102785",
     {"write_proof": False}),

    ("CVE-2026-65891", "Joomla JCE rename hidden-file",
     "cve_modules.jce_rename", "check_cve_2026_65891",
     {"mode": "check"}),

    ("CVE-2026-63030+CVE-2026-60137", "WordPress REST batch SQLi + PrivEsc",
     "cve_modules.wp_batch", "check_cve_2026_63030_60137",
     {"safe_mode": True}),

    ("CVE-2026-85097", "Bricksforge unauth file upload RCE",
     "cve_modules.bricksforge", "check_cve_2026_85097",
     {"detect_only": True}),

    ("CVE-2026-101110", "OrdaSoft Book Library SQLi (Joomla)",
     "cve_modules.booklibrary", "check_cve_2026_101110",
     {"check_only": True}),

    ("CVE-2026-111497", "Node.js Brotli OOB write (Node2Shell)",
     "cve_modules.node2shell", "check_cve_2026_111497",
     {"full2": False}),

    ("CVE-2026-65643", "cPanel domain parking command injection",
     "cve_modules.cpanel_park", "check_cve_2026_65643",
     {}), 

    ("CVE-2026-48908", "SP Page Builder unauth RCE",
     "cve_modules.sppagebuilder", "check_cve_2026_48908",
     {"detect_only": True}),
]


# ── loader otomatis ─────────────────────────────────────────────────────

def _load_modules():
    """Import semua modul dari registry, return dict {cve_id: (cfg, func)}."""
    loaded = {}
    for cve_id, name, mod_path, func_name, kwargs in CVE_REGISTRY:
        try:
            mod = importlib.import_module(mod_path)
            fn = getattr(mod, func_name)
            loaded[cve_id] = {
                "name": name, "fn": fn, "kwargs": dict(kwargs),
            }
        except (ImportError, AttributeError) as e:
            _log(yellow(f"[!] skip {cve_id} ({mod_path}.{func_name}): {e}"))
    return loaded


# ── core scan (satu target) ─────────────────────────────────────────────

def scan_target(target_url, modules, timeout=20, only_cve=None):
    start = time.time()
    target_url = (target_url or "").strip()
    if not target_url:
        return {"target": target_url, "status": "error",
                "cve": None, "evidence": "empty target",
                "elapsed": 0.0, "checks": []}

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    checks = []

    for cve_id, meta in modules.items():
        if only_cve and cve_id != only_cve:
            continue

        fn = meta["fn"]
        kwargs = dict(meta["kwargs"])

        sig = inspect.signature(fn)
        if "timeout" in sig.parameters:
            kwargs.setdefault("timeout", timeout)

        t0 = time.time()
        try:
            result = fn(target_url, **kwargs)
        except Exception as e:
            dt = time.time() - t0
            checks.append({"cve": cve_id, "status": "error",
                           "reason": f"exception: {e}", "elapsed": dt})
            continue

        dt = time.time() - t0
        if result.get("vulnerable"):
            checks.append({
                "cve": cve_id, "status": "vulnerable",
                "reason": result.get("reason", ""),
                "evidence": result.get("evidence"),
                "raw": result, "elapsed": dt,
            })
            return {"target": target_url, "status": "vulnerable",
                    "cve": cve_id, "evidence": result.get("evidence"),
                    "elapsed": time.time() - start, "checks": checks}

        checks.append({
            "cve": cve_id, "status": "safe",
            "reason": result.get("reason", ""),
            "raw": result, "elapsed": dt,
        })

    return {"target": target_url, "status": "safe", "cve": None,
            "evidence": None, "elapsed": time.time() - start,
            "checks": checks}


# ── format output ───────────────────────────────────────────────────────

def _fmt_line(r):
    if r["status"] == "vulnerable":
        return (f"{green('[VULN]')}  {r['target']}  "
                f"{red(r['cve'])}  {gray(r['evidence'] or '')}")
    if r["status"] == "safe":
        return f"{green('[SAFE]')}  {r['target']}"
    return f"{yellow('[ERR ]')}  {r['target']}  {gray(r['evidence'] or '')}"


def print_summary(results, elapsed):
    n_vuln = sum(1 for r in results if r["status"] == "vulnerable")
    n_safe = sum(1 for r in results if r["status"] == "safe")
    n_err = sum(1 for r in results if r["status"] == "error")

    print()
    print(bold("═" * 70))
    print(bold("  HASIL MASS SCAN"))
    print(bold("═" * 70))
    print(f"  total target : {len(results)}")
    print(f"  vulnerable   : {green(str(n_vuln))}")
    print(f"  safe         : {green(str(n_safe))}")
    print(f"  error        : {yellow(str(n_err))}")
    print(f"  elapsed      : {elapsed:.2f}s")
    if n_vuln:
        print()
        print(bold("  TARGET VULNERABLE:"))
        for r in results:
            if r["status"] == "vulnerable":
                print(f"    - {r['target']}  "
                      f"{red(r['cve'])}  {gray(r['evidence'] or '')}")
    print(bold("═" * 70))


def write_result_file(results, elapsed, path="result.txt"):
    """Tulis hasil scan ke file teks. Vulnerable ditaruh paling atas."""
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n_vuln = sum(1 for r in results if r["status"] == "vulnerable")
    n_safe = sum(1 for r in results if r["status"] == "safe")
    n_err = sum(1 for r in results if r["status"] == "error")

    lines = []
    lines.append("=" * 60)
    lines.append("CVE SCAN RESULT")
    lines.append("=" * 60)
    lines.append(f"Scan finished : {started}")
    lines.append(f"Total target  : {len(results)}")
    lines.append(f"Vulnerable    : {n_vuln}")
    lines.append(f"Safe          : {n_safe}")
    lines.append(f"Error         : {n_err}")
    lines.append(f"Elapsed       : {elapsed:.2f}s")
    lines.append("=" * 60)
    lines.append("")

    # vulnerable dulu
    for r in results:
        if r["status"] != "vulnerable":
            continue
        lines.append(f"[VULN] {r['target']}")
        lines.append(f"  CVE      : {r['cve']}")
        lines.append(f"  Evidence : {r['evidence'] or ''}")
        lines.append(f"  Time     : {r['elapsed']:.2f}s")
        lines.append("")

    # sisanya ringkas
    for r in results:
        if r["status"] == "safe":
            lines.append(f"[SAFE] {r['target']}")
        elif r["status"] == "error":
            lines.append(f"[ERR ] {r['target']}  ({r['evidence']})")

    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(gray(f"[*] result disimpan: {os.path.abspath(path)}"))
    except OSError as e:
        print(red(f"[!] gagal simpan result: {e}"))


# ── reader target file ──────────────────────────────────────────────────

def read_target_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as e:
        print(red(f"[!] gagal baca file target: {e}"))
        sys.exit(2)

    seen, targets = set(), []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if not ln.startswith(("http://", "https://")):
            ln = "https://" + ln
        key = ln.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        targets.append(ln)
    return targets


# ── batch runner ────────────────────────────────────────────────────────

def run_mass(targets, modules, timeout, threads, only_cve):
    total = len(targets)
    done = 0
    t_start = time.time()
    results = []

    print(bold(f"\n[*] Mass scan: {total} target, threads={threads}"))
    print(gray("─" * 70))

    def _worker(url):
        return scan_target(url, modules, timeout=timeout, only_cve=only_cve)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_worker, u): u for u in targets}
        try:
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"target": futures[fut], "status": "error",
                         "cve": None, "evidence": f"exception: {e}",
                         "elapsed": 0.0, "checks": []}
                results.append(r)
                done += 1
                _log(f"  [{done}/{total}] {_fmt_line(r)}")
        except KeyboardInterrupt:
            print(red("\n[!] interrupted, menunggu worker berhenti..."))
            pool.shutdown(wait=False, cancel_futures=True)

    elapsed = time.time() - t_start
    # urutkan: vulnerable dulu, lalu safe, lalu error
    order = {"vulnerable": 0, "safe": 1, "error": 2}
    results.sort(key=lambda r: order.get(r["status"], 3))
    return results, elapsed


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    _print_banner()

    ap = argparse.ArgumentParser(
        description="Mass CVE scanner (sequential per-CVE, threaded per-target).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Contoh:\n"
            "  python main.py -u https://target.com\n"
            "  python main.py -f targets.txt\n"
            "  python main.py -f targets.txt --threads 10 --output result.txt\n"
            "  python main.py -f targets.txt --only-cve CVE-2026-48907\n"
        ),
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url", help="single target URL")
    src.add_argument("-f", "--file", help="file target .txt (1 URL per baris)")
    ap.add_argument("--threads", type=int, default=5,
                    help="worker paralel untuk mass mode (default 5)")
    ap.add_argument("--timeout", type=int, default=20,
                    help="timeout per HTTP request (default 20s)")
    ap.add_argument("--only-cve", metavar="CVE_ID",
                    help="cuma cek CVE tertentu")
    ap.add_argument("-o", "--output", default="result.txt",
                    help="file hasil scan (default result.txt)")
    ap.add_argument("--json", dest="json_out", metavar="FILE",
                    help="opsional: simpan juga hasil dalam JSON")
    args = ap.parse_args()

    modules = _load_modules()
    if not modules:
        print(red("[!] Tidak ada modul CVE yang bisa di-import."))
        print(gray("    Cek folder cve_modules/ dan isi CVE_REGISTRY."))
        sys.exit(2)

    print(bold("[*] Modul CVE ter-load:"))
    for cve_id, meta in modules.items():
        print(f"    - {cyan(cve_id)}  {gray(meta['name'])}")

    # single mode
    if args.url:
        r = scan_target(args.url, modules,
                        timeout=args.timeout, only_cve=args.only_cve)
        print()
        print(_fmt_line(r))
        elapsed = r["elapsed"]
        results = [r]
    else:
        targets = read_target_file(args.file)
        if not targets:
            print(red("[!] file target kosong / nggak ada URL valid."))
            sys.exit(2)
        results, elapsed = run_mass(
            targets, modules,
            timeout=args.timeout,
            threads=max(1, args.threads),
            only_cve=args.only_cve,
        )

    print_summary(results, elapsed)
    write_result_file(results, elapsed, path=args.output)

    if args.json_out:
        safe = []
        for r in results:
            d = dict(r)
            d["checks"] = [
                {k: v for k, v in c.items() if k != "raw"}
                for c in d.get("checks", [])
            ]
            safe.append(d)
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(safe, fh, indent=2, ensure_ascii=False)
            print(gray(f"[*] JSON disimpan: {os.path.abspath(args.json_out)}"))
        except OSError as e:
            print(red(f"[!] gagal simpan JSON: {e}"))

    n_vuln = sum(1 for r in results if r["status"] == "vulnerable")
    sys.exit(0 if n_vuln else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(red("\n[!] interrupted"))
        sys.exit(130)