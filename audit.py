#!/usr/bin/env python3
"""
termux-security-audit v0.9.0
Authorized web security audit pipeline for Termux:
HTTP discovery -> Nmap -> Nuclei -> CVE extraction -> SearchSploit correlation.
This tool reports evidence and candidates. It does not exploit targets.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl
from urllib.request import Request, urlopen

VERSION = "0.9.0"
MAX_URLS = 100
MAX_DEPTH = 3
TIMEOUT = 6
NUCLEI_MAX_TARGETS = 12
NUCLEI_CONCURRENCY = 6
NUCLEI_BULK_SIZE = 6
NUCLEI_RATE_LIMIT = 10

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/login", "/login.php", "/admin",
    "/admin.php", "/dashboard", "/register", "/register.php", "/signup",
    "/search", "/search.php", "/api", "/api/", "/docs", "/debug",
    "/server-status", "/phpinfo.php", "/info.php", "/test", "/backup",
    "/uploads/",
]

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.parameters = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("a", "link"):
            value = attrs.get("href")
            if value:
                self.links.append(value)
        elif tag == "script":
            value = attrs.get("src")
            if value:
                self.links.append(value)
        elif tag == "form":
            value = attrs.get("action") or ""
            self.forms.append(value)
        elif tag in ("input", "textarea", "select"):
            name = attrs.get("name")
            if name:
                self.parameters.append(name)

def normalize_url(base, value):
    if not value:
        return None
    value = value.strip()
    if not value or value.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absolute = urljoin(base, value)
    p = urlparse(absolute)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))

def same_origin(url, origin):
    a, b = urlparse(url), urlparse(origin)
    return a.scheme == b.scheme and a.netloc.lower() == b.netloc.lower()

def fetch(url):
    req = Request(url, headers={
        "User-Agent": f"termux-security-audit/{VERSION}",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    with urlopen(req, timeout=TIMEOUT) as r:
        return r.geturl(), r.status, r.headers.get("Content-Type", ""), r.read()

def extract_candidates(base_url, body):
    text = body.decode("utf-8", errors="ignore")
    parser = LinkParser()
    parser.feed(text)
    raw_values = parser.links + parser.forms
    raw_values += re.findall(r"""(?:href|src|action)\\s*=\\s*["']([^"']+)["']""", text, re.I)
    urls = []
    for raw in raw_values:
        child = normalize_url(base_url, raw)
        if child:
            urls.append(child)
    return list(dict.fromkeys(urls)), parser.parameters

def discover(target):
    queue = deque([(target, 0)])
    seen, discovered, errors = set(), [], []
    parameters = {}

    while queue and len(discovered) < MAX_URLS:
        current, depth = queue.popleft()
        current = normalize_url(target, current)
        if not current or current in seen or not same_origin(current, target):
            continue
        seen.add(current)
        try:
            final_url, status, content_type, body = fetch(current)
        except Exception as exc:
            errors.append({"url": current, "error": str(exc)})
            continue

        final_url = normalize_url(target, final_url) or current
        seen.add(final_url)
        discovered.append({"url": final_url, "depth": depth, "status": status,
                           "content_type": content_type, "source": "crawl"})

        sample = body[:4096].lower()
        looks_html = "html" in content_type.lower() or b"<html" in sample or b"<body" in sample or b"<a " in sample
        if not looks_html or depth >= MAX_DEPTH:
            continue

        children, names = extract_candidates(final_url, body)
        if names:
            parameters[final_url] = sorted(set(names))
        for child in children:
            if same_origin(child, target) and child not in seen:
                queue.append((child, depth + 1))

    for path in COMMON_PATHS:
        if len(discovered) >= MAX_URLS:
            break
        candidate = normalize_url(target, path)
        if not candidate or candidate in seen:
            continue
        try:
            final_url, status, content_type, body = fetch(candidate)
            final_url = normalize_url(target, final_url) or candidate
            seen.update((candidate, final_url))
            discovered.append({"url": final_url, "depth": 1, "status": status,
                               "content_type": content_type, "source": "common-path"})
            sample = body[:4096].lower()
            if "html" in content_type.lower() or b"<html" in sample:
                children, names = extract_candidates(final_url, body)
                if names:
                    parameters[final_url] = sorted(set(names))
                for child in children:
                    if same_origin(child, target) and child not in seen:
                        queue.append((child, 2))
        except Exception as exc:
            errors.append({"url": candidate, "error": str(exc)})

    while queue and len(discovered) < MAX_URLS:
        current, depth = queue.popleft()
        current = normalize_url(target, current)
        if not current or current in seen or not same_origin(current, target):
            continue
        seen.add(current)
        try:
            final_url, status, content_type, body = fetch(current)
            final_url = normalize_url(target, final_url) or current
            seen.add(final_url)
            discovered.append({"url": final_url, "depth": depth, "status": status,
                               "content_type": content_type, "source": "crawl"})
            sample = body[:4096].lower()
            if depth < MAX_DEPTH and ("html" in content_type.lower() or b"<html" in sample):
                children, names = extract_candidates(final_url, body)
                if names:
                    parameters[final_url] = sorted(set(names))
                for child in children:
                    if same_origin(child, target) and child not in seen:
                        queue.append((child, depth + 1))
        except Exception as exc:
            errors.append({"url": current, "error": str(exc)})

    unique, used = [], set()
    for item in discovered:
        if item["url"] not in used:
            used.add(item["url"])
            unique.append(item)
    return unique[:MAX_URLS], errors, parameters

def run_command(args, timeout=None):
    try:
        r = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return 124, stdout, stderr + "\ncommand timed out"

def find_searchsploit():
    candidates = [
        shutil.which("searchsploit"),
        str(Path.home() / "bin" / "searchsploit"),
        str(Path.home() / "exploit-database" / "searchsploit"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None

def run_nmap(target, workdir):
    xml_path = workdir / "nmap.xml"
    rc, stdout, stderr = run_command(
        ["nmap", "-4", "-Pn", "-T4", "-sV", "--version-light",
         "--host-timeout", "90s",
         "-p", "80,443,8000,8008,8080,8443",
         "-oX", str(xml_path), target], timeout=120)

    services = []
    if xml_path.exists():
        try:
            root = ET.parse(xml_path).getroot()
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                services.append({
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                    "cpe": [x.text for x in service.findall("cpe")] if service is not None else [],
                })
        except Exception as exc:
            stderr += f"\nNmap XML parse error: {exc}"
    return {"returncode": rc, "stdout": stdout, "stderr": stderr,
            "xml": str(xml_path), "open_ports": services}

def select_nuclei_targets(target, urls, parameters):
    """Choose a small, high-value endpoint set for phone-friendly scanning."""
    selected = [target]
    dynamic = []
    interesting = []
    for item in urls:
        url = item["url"]
        if url == target:
            continue
        if url in parameters or "?" in url:
            dynamic.append(url)
        path = urlparse(url).path.lower()
        if any(token in path for token in (
            "/login", "/admin", "/api", "/search", "/upload", "/debug",
            "/labs/", "/phpinfo", "/server-status", "/redirect", "/profile"
        )):
            interesting.append(url)
    for url in dynamic + interesting + [x["url"] for x in urls]:
        if url not in selected:
            selected.append(url)
        if len(selected) >= NUCLEI_MAX_TARGETS:
            break
    return selected

def run_nuclei(targets, workdir, deep=False):
    target_file = workdir / "nuclei_targets.txt"
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    output = workdir / "nuclei.jsonl"
    args = [
        "nuclei", "-list", str(target_file), "-jsonl", "-o", str(output),
        "-c", str(NUCLEI_CONCURRENCY),
        "-bs", str(NUCLEI_BULK_SIZE),
        "-rl", str(NUCLEI_RATE_LIMIT if not deep else 20),
        "-stats", "-si", "10",
    ]
    if not deep:
        args += ["-severity", "critical,high,medium,low"]
    rc, stdout, stderr = run_command(args, timeout=900)
    return [{"mode": "selected", "returncode": rc, "stdout": stdout,
             "stderr": stderr, "output": str(output), "targets": len(targets),
             "concurrency": NUCLEI_CONCURRENCY, "bulk_size": NUCLEI_BULK_SIZE,
             "rate_limit": NUCLEI_RATE_LIMIT}]

def load_nuclei(files):
    raw = []
    for filename in files:
        path = Path(filename)
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                if line.strip():
                    raw.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    dedup = {}
    for item in raw:
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        template = item.get("template-id") or item.get("template") or "unknown"
        matched = item.get("matched-at") or item.get("host") or ""
        key = (template, matched)

        if key not in dedup:
            dedup[key] = {
                "template": template,
                "name": info.get("name"),
                "severity": (info.get("severity") or "info").lower(),
                "type": info.get("type"),
                "description": info.get("description"),
                "matched_at": matched,
                "host": item.get("host"),
                "cves": sorted(set(cves)),
                "tags": info.get("tags") or [],
                "reference": info.get("reference"),
                "occurrences": 1,
            }
        else:
            dedup[key]["occurrences"] += 1
            dedup[key]["cves"] = sorted(set(dedup[key]["cves"]) | set(cves))

    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    for f in dedup.values():
        blob = " ".join([
            f["name"] or "", f["template"], " ".join(f["tags"])
        ]).lower()
        if any(x in blob for x in ("exposure", "disclosure", "exposed", "directory-listing")):
            category = "exposure"
        elif any(x in blob for x in ("misconfig", "missing-", "cookie", "header")):
            category = "misconfiguration"
        elif f["cves"]:
            category = "vulnerability"
        elif any(x in blob for x in ("detect", "fingerprint", "tech-", "dns-", "ssl-")):
            category = "fingerprint"
        else:
            category = "informational"
        f["category"] = category
        f["rank"] = rank.get(f["severity"], 0)

    return sorted(dedup.values(), key=lambda x: (-x["rank"], x["name"] or ""))

def searchsploit_cve(cve, searchsploit_bin):
    rc, stdout, _ = run_command([searchsploit_bin, "--cve", cve, "-j"], timeout=30)
    if rc != 0 or not stdout.strip():
        return []
    try:
        return json.loads(stdout).get("RESULTS_EXPLOIT") or []
    except json.JSONDecodeError:
        return []

def correlate_cves(findings, searchsploit_bin):
    matches = []
    for f in findings:
        for cve in f.get("cves", []):
            for e in searchsploit_cve(cve, searchsploit_bin):
                matches.append({
                    "cve": cve, "finding": f["name"], "template": f["template"],
                    "edb_id": e.get("EDB-ID"), "title": e.get("Title"),
                    "date": e.get("Date_Published"), "type": e.get("Type"),
                    "platform": e.get("Platform"), "path": e.get("Path"),
                })
    return matches

def searchsploit_fingerprint(nmap_result, searchsploit_bin):
    candidates = []
    for service in nmap_result.get("open_ports", []):
        product = service.get("product")
        version = service.get("version")
        if not product:
            continue
        query = " ".join(x for x in (product, version) if x)
        rc, stdout, _ = run_command([searchsploit_bin, query], timeout=30)
        if rc != 0:
            continue
        for line in stdout.splitlines():
            line = line.strip()
            if "|" not in line:
                continue
            edb_id, title = [x.strip() for x in line.split("|", 1)]
            if re.fullmatch(r"\d+", edb_id):
                candidates.append({
                    "port": service.get("port"), "product": product, "version": version,
                    "edb_id": edb_id, "title": title, "confidence": "low",
                    "note": "Fingerprint match only; verify exact product, version and configuration.",
                })
    return candidates

def main():
    p = argparse.ArgumentParser(description="Termux web security auditor v0.8.0")
    p.add_argument("target", help="Authorized target URL or hostname")
    p.add_argument("-o", "--output", default="audit-report.json")
    p.add_argument("--deep", action="store_true", help="include informational/fingerprint findings; slower")
    args = p.parse_args()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        print("ERROR: invalid target")
        return 2

    searchsploit_bin = find_searchsploit()
    missing = [x for x in ("nmap", "nuclei") if shutil.which(x) is None]
    if not searchsploit_bin:
        missing.append("searchsploit")
    if missing:
        print("ERROR: missing tool(s): " + ", ".join(missing))
        print("SearchSploit lookup paths: PATH, ~/bin/searchsploit, ~/exploit-database/searchsploit")
        return 2

    workdir = Path(".audit-v0.8.0")
    workdir.mkdir(exist_ok=True)

    print(f"TERMUX SECURITY AUDIT v{VERSION}")
    print("=" * 48)
    print(f"Target: {target}")
    print(f"SearchSploit: {searchsploit_bin}\n")

    print("[1/4] Discovering HTTP endpoints...")
    urls, errors, parameters = discover(target)
    discovery = {"urls": urls, "errors": errors, "parameters": parameters,
                 "max_urls": MAX_URLS, "max_depth": MAX_DEPTH}
    (workdir / "discovery.json").write_text(
        json.dumps(discovery, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"      Discovered URLs: {len(urls)}")
    print(f"      Parameterized endpoints: {len(parameters)}")

    target_urls = select_nuclei_targets(target, urls, parameters)
    if not args.deep:
        target_urls = target_urls[:NUCLEI_MAX_TARGETS]
    print(f"      Nuclei targets selected: {len(target_urls)} (max {NUCLEI_MAX_TARGETS})")
    print("      Nuclei mode: " + ("DEEP" if args.deep else "FAST"))

    print("[2/4] Running Nmap...")
    nmap = run_nmap(parsed.hostname, workdir)
    print(f"      Open ports: {len(nmap['open_ports'])}")

    print("[3/4] Running Nuclei...")
    nuclei_runs = run_nuclei(target_urls, workdir, deep=args.deep)
    nuclei_files = [x["output"] for x in nuclei_runs if Path(x["output"]).exists()]
    findings = load_nuclei(nuclei_files)
    print(f"      Unique findings: {len(findings)}")

    print("[4/4] Correlating CVEs with SearchSploit...")
    cve_matches = correlate_cves(findings, searchsploit_bin)
    fingerprint = searchsploit_fingerprint(nmap, searchsploit_bin)

    severity = Counter(f["severity"] for f in findings)
    categories = Counter(f["category"] for f in findings)
    cves = sorted({c for f in findings for c in f.get("cves", [])})
    important = [
        {"severity": f["severity"], "category": f["category"], "name": f["name"],
         "template": f["template"], "matched_at": f["matched_at"],
         "cves": f["cves"], "occurrences": f["occurrences"]}
        for f in findings if f["severity"] in ("critical", "high", "medium", "low")
    ]

    report = {
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "discovery": discovery,
        "nmap": nmap,
        "nuclei_runs": nuclei_runs,
        "findings": findings,
        "cve_exploitdb": cve_matches,
        "fingerprint_candidates": fingerprint,
        "summary": {
            "discovered_urls": len(urls), "parameterized_endpoints": len(parameters),
            "open_ports": len(nmap["open_ports"]),
            "unique_findings": len(findings), "unique_cves": len(cves),
            "severity": dict(severity), "category": dict(categories),
            "important_findings": important,
        },
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\nAUDIT COMPLETE")
    print("=" * 48)
    print(f"Discovered URLs : {len(urls)}")
    print(f"Parameterized   : {len(parameters)}")
    print(f"Open ports      : {len(nmap['open_ports'])}")
    print(f"Findings        : {len(findings)}")
    print(f"Unique CVEs     : {len(cves)}")
    for s in ("critical", "high", "medium", "low", "info"):
        print(f"{s.title():<16}: {severity.get(s, 0)}")
    print(f"CVE/EDB matches : {len(cve_matches)}")
    print(f"Fingerprint cand.: {len(fingerprint)}")
    print(f"Report          : {output}")

    if important:
        print("\nIMPORTANT FINDINGS")
        for f in important:
            print(f"[{f['severity']}] {f['category']} | {f['name']} | {f['matched_at']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
