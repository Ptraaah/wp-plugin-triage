#!/usr/bin/env python3
"""
wp-plugin-triage - static triage scanner for WordPress plugins.

Maps every wp_ajax / wp_ajax_nopriv handler and REST route to its callback
body, then scores how close dangerous sinks sit to unprivileged input and
whether a guard (nonce, capability check, one-time token) appears near them.

This is a TRIAGE tool, not a vulnerability verdict. In real audits the top
hits are usually stopped by custom guard helpers the regex cannot see, so
always read the flagged callback body and its helper functions by hand.

Usage:
    python3 wp_triage.py <plugin-slug>            # download from wordpress.org
    python3 wp_triage.py --dir ./some-plugin      # scan a local directory
    python3 wp_triage.py <slug> --json out.json   # machine readable results

By ptraaa - MIT License
"""
import argparse, json, os, re, sys, urllib.request, zipfile

SINKS = [
    ("update_option", 30, r"\bupdate_option\s*\("),
    ("delete_option", 30, r"\bdelete_option\s*\("),
    ("wp_insert_user", 40, r"\bwp_insert_user\s*\("),
    ("wp_update_user", 30, r"\bwp_update_user\s*\("),
    ("file_upload", 35, r"\bwp_handle_upload\s*\(|\bmedia_handle_upload\s*\("),
    ("file_read", 35, r"\breadfile\s*\(|\bfile_get_contents\s*\(\s*\$"),
    ("file_include", 35, r"\b(?:include|require)(?:_once)?\s*\(?\s*\$"),
    ("eval", 45, r"\beval\s*\(|\bcreate_function\s*\("),
    ("unserialize", 40, r"\bunserialize\s*\(|\bmaybe_unserialize\s*\(\s*\$"),
    ("raw_sql", 30, r"\$wpdb->(?:query|get_results|get_row|get_var)\s*\(\s*[\"']"),
    ("meta_write", 20, r"\bupdate_post_meta\s*\(|\bupdate_user_meta\s*\("),
    ("admin_user_ops", 35, r"\bwp_create_user\s*\(|\badd_role\s*\(|\bset_role\s*\("),
]
GUARDS = re.compile(
    r"check_ajax_referer|wp_verify_nonce|current_user_can|hash_equals|"
    r"check_admin_referer|is_user_logged_in|permission_callback|verify.*token",
    re.I)
INPUT = re.compile(r"\$_(?:POST|GET|REQUEST|FILES|COOKIE)\b|\$request\b|php://input")

REG_AJAX = re.compile(
    r"add_action\(\s*['\"]wp_ajax_(nopriv_)?([a-zA-Z0-9_\-]+)['\"]\s*,\s*"
    r"(?:['\"]([a-zA-Z0-9_\-]+)['\"]|array\s*\(\s*[^,]+,\s*['\"]([a-zA-Z0-9_\-]+)['\"]|"
    r"\[.*?\])", re.S)
REG_REST = re.compile(
    r"register_rest_route\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.S)


def function_body(src, name):
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", src)
    if not m:
        return None
    i, depth = m.end(), 1
    while i < len(src) and depth:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    return src[m.start():i]


def scan_tree(root):
    php = {}
    for base, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".php"):
                p = os.path.join(base, f)
                try:
                    php[p] = open(p, encoding="utf-8", errors="ignore").read()
                except OSError:
                    pass
    whole = "\n".join(php.values())
    findings = []
    for path, src in php.items():
        for m in REG_AJAX.finditer(src):
            nopriv = bool(m.group(1))
            action = m.group(2)
            cb = m.group(3) or m.group(4)
            findings.append(("ajax_nopriv" if nopriv else "ajax", action, cb, path))
        for m in REG_REST.finditer(src):
            findings.append(("rest", m.group(1) + m.group(2), None, path))
    results = []
    for kind, name, cb, path in findings:
        body = function_body(whole, cb) if cb else None
        entry = {"kind": kind, "name": name, "callback": cb,
                 "file": os.path.relpath(path, root), "score": 0, "sinks": []}
        if body:
            for label, weight, pat in SINKS:
                if re.search(pat, body):
                    entry["sinks"].append(label)
                    entry["score"] += weight
            if INPUT.search(body):
                entry["score"] += 20
            entry["guarded"] = bool(GUARDS.search(body))
            if entry["guarded"]:
                entry["score"] //= 3
            if kind == "ajax_nopriv":
                entry["score"] += 15
        results.append(entry)
    results.sort(key=lambda r: -r["score"])
    return results


def fetch_slug(slug, dest):
    info = json.load(urllib.request.urlopen(
        urllib.request.Request(f"https://api.wordpress.org/plugins/info/1.0/{slug}.json",
                               headers={"User-Agent": "wp-plugin-triage"}), timeout=30))
    url = info["download_link"]
    req = urllib.request.Request(url, headers={"User-Agent": "wp-plugin-triage"})
    data = urllib.request.urlopen(req, timeout=120).read()
    zpath = os.path.join(dest, slug + ".zip")
    open(zpath, "wb").write(data)
    out = os.path.join(dest, slug)
    zipfile.ZipFile(zpath).extractall(dest)
    return out, info.get("version"), info.get("active_installs")


def main():
    if "--ptraaa" in sys.argv:
        print("wp-plugin-triage, by ptraaa. I read plugins so vulnerabilities have nowhere to hide. More small tools: github.com/Ptraaah")
        return
    ap = argparse.ArgumentParser(description="Triage scanner for WordPress plugins")
    ap.add_argument("target", help="wordpress.org plugin slug, or a path with --dir")
    ap.add_argument("--dir", action="store_true", help="treat target as a local directory")
    ap.add_argument("--json", metavar="FILE", help="also write results as JSON")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    if args.dir:
        root, version, installs = args.target, "?", "?"
    else:
        os.makedirs("/tmp/wp-triage", exist_ok=True)
        root, version, installs = fetch_slug(args.target, "/tmp/wp-triage")
        print(f"{args.target} v{version}, {installs} active installs\n")

    results = scan_tree(root)
    shown = 0
    for r in results:
        if r["score"] <= 0 and shown >= 3:
            continue
        guard = "guarded" if r.get("guarded") else "UNGUARDED?"
        sinks = ",".join(r["sinks"]) or "-"
        print(f"{r['score']:4d} {r['kind']:12s} {r['name'][:45]:45s} {guard:10s} {sinks}  ({r['file']})")
        shown += 1
        if shown >= args.top:
            break
    print("\nReminder: triage only. Open every flagged callback AND its guard "
          "helpers before believing any of this.")
    if args.json:
        json.dump(results, open(args.json, "w"), indent=1)
        print("JSON written to", args.json)


if __name__ == "__main__":
    main()
