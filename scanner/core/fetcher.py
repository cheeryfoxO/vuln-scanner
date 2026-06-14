"""Fetch popular open-source wordlists for bug bounty reconnaissance.

Usage: python -m scanner fetch-wordlists [--all] [--dirs] [--subdomains]
"""
import os
import sys
import json
import hashlib
from urllib.request import urlopen, Request
from urllib.error import URLError

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
EXTERNAL_DIR = os.path.join(DATA_DIR, "external")

# Wordlist sources — lightweight selections from well-known repos
SOURCES = {
    "dirs": [
        {
            "name": "seclists-common",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            "desc": "SecLists common web paths (~4.6k entries)",
        },
        {
            "name": "seclists-directory-list-lowercase",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt",
            "desc": "DirBuster lowercase small (~8k entries)",
        },
        {
            "name": "seclists-raft-small-dirs",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
            "desc": "RAFT small directories (~20k entries)",
        },
        {
            "name": "seclists-raft-small-files",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt",
            "desc": "RAFT small files (~13k entries)",
        },
        {
            "name": "seclists-quickhits",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt",
            "desc": "Quick hits — high-value paths (~2.5k entries)",
        },
        {
            "name": "seclists-api-endpoints",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/endpoints.txt",
            "desc": "Common API endpoints",
        },
    ],
    "subdomains": [
        {
            "name": "seclists-subdomains-top1m-20000",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
            "desc": "Top 20k subdomains from 1M list",
        },
        {
            "name": "seclists-subdomains-top1m-5000",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            "desc": "Top 5k subdomains from 1M list",
        },
        {
            "name": "seclists-dns-jhaddix",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
            "desc": "Jhaddix curated DNS list (~10k entries)",
        },
        {
            "name": "seclists-deepmagic-top5000",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt",
            "desc": "Deepmagic top 50k prefixes",
        },
    ],
}

UA = "Mozilla/5.0 (compatible; vuln-scanner-fetcher/1.0)"


def _download(url, out_path, verbose=True):
    """Download a file with progress reporting. Returns (path, count)."""
    try:
        req = Request(url, headers={"User-Agent": UA})
        with urlopen(req, timeout=60) as resp:
            raw = resp.read()
        # Decode
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")

        lines = [l.strip() for l in text.splitlines()
                 if l.strip() and not l.startswith("#")]
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(set(lines))) + "\n")
        if verbose:
            print(f"  ✓ {os.path.basename(out_path)}: {len(lines)} entries")
        return out_path, len(lines)
    except URLError as e:
        if verbose:
            print(f"  ✗ {url}: {e}")
        return None, 0
    except Exception as e:
        if verbose:
            print(f"  ✗ {url}: {e}")
        return None, 0


def download_all(verbose=True):
    """Download all wordlists. Returns summary dict."""
    os.makedirs(EXTERNAL_DIR, exist_ok=True)
    results = {"dirs": {}, "subdomains": {}}

    if verbose:
        print("Downloading directory wordlists...")
    for src in SOURCES["dirs"]:
        out = os.path.join(EXTERNAL_DIR, f"dirs-{src['name']}.txt")
        path, count = _download(src["url"], out, verbose)
        if path:
            results["dirs"][src["name"]] = {"path": path, "count": count,
                                              "desc": src["desc"]}

    if verbose:
        print("\nDownloading subdomain wordlists...")
    for src in SOURCES["subdomains"]:
        out = os.path.join(EXTERNAL_DIR, f"subs-{src['name']}.txt")
        path, count = _download(src["url"], out, verbose)
        if path:
            results["subdomains"][src["name"]] = {"path": path, "count": count,
                                                    "desc": src["desc"]}

    # Save manifest
    manifest_path = os.path.join(EXTERNAL_DIR, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Build merged files
    _merge_wordlists(results, verbose)

    return results


def _merge_wordlists(results, verbose=True):
    """Merge downloaded + built-in wordlists into unified files."""
    builtin_dirs = os.path.join(DATA_DIR, "dirs.txt")
    builtin_subs = os.path.join(DATA_DIR, "subdomains.txt")

    # Merge dirs
    all_dirs = set()
    if os.path.exists(builtin_dirs):
        with open(builtin_dirs, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    all_dirs.add(line)
    for info in results.get("dirs", {}).values():
        if os.path.exists(info["path"]):
            with open(info["path"], encoding="utf-8") as f:
                all_dirs.update(l.strip() for l in f if l.strip())

    merged_dirs = os.path.join(EXTERNAL_DIR, "dirs-merged.txt")
    with open(merged_dirs, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_dirs)) + "\n")
    if verbose:
        print(f"\n  Merged dirs: {len(all_dirs)} entries → {merged_dirs}")

    # Merge subs
    all_subs = set()
    if os.path.exists(builtin_subs):
        with open(builtin_subs, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    all_subs.add(line)
    for info in results.get("subdomains", {}).values():
        if os.path.exists(info["path"]):
            with open(info["path"], encoding="utf-8") as f:
                all_subs.update(l.strip() for l in f if l.strip())

    merged_subs = os.path.join(EXTERNAL_DIR, "subs-merged.txt")
    with open(merged_subs, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_subs)) + "\n")
    if verbose:
        print(f"  Merged subdomains: {len(all_subs)} entries → {merged_subs}")


def print_status():
    """Show downloaded wordlists."""
    manifest = os.path.join(EXTERNAL_DIR, "manifest.json")
    if not os.path.exists(manifest):
        print("No external wordlists downloaded yet.")
        print("Run: python -m scanner fetch-wordlists --all")
        return

    with open(manifest, encoding="utf-8") as f:
        data = json.load(f)

    print("Downloaded wordlists:\n")
    total_dirs = total_subs = 0
    for kind, label in [("dirs", "Directory wordlists"), ("subdomains", "Subdomain wordlists")]:
        print(f"  {label}:")
        for name, info in data.get(kind, {}).items():
            print(f"    {name:40s} {info['count']:>6d} entries  — {info['desc']}")
            if kind == "dirs":
                total_dirs += info["count"]
            else:
                total_subs += info["count"]
        print()

    merged_dirs = os.path.join(EXTERNAL_DIR, "dirs-merged.txt")
    merged_subs = os.path.join(EXTERNAL_DIR, "subs-merged.txt")
    if os.path.exists(merged_dirs):
        with open(merged_dirs, encoding="utf-8") as f:
            md = sum(1 for _ in f)
        print(f"  Merged dirs: {md} entries (deduplicated)")
    if os.path.exists(merged_subs):
        with open(merged_subs, encoding="utf-8") as f:
            ms = sum(1 for _ in f)
        print(f"  Merged subs: {ms} entries (deduplicated)")

    print(f"\n  Usage:")
    print(f"    python -m scanner scan TARGET -m dirscan \\")
    print(f"      --dirscan-wordlist {merged_dirs}")
    print(f"    python -m scanner scan TARGET -m subdomain \\")
    print(f"      --subdomain-wordlist {merged_subs}")


def run_fetch(kind="all"):
    """Main entry point for the fetch-wordlists command."""
    if kind == "status":
        print_status()
        return

    print(f"Fetching wordlists ({kind})...\n"
          f"  Output: {EXTERNAL_DIR}/\n")

    if kind == "all":
        download_all()
    elif kind == "dirs":
        # Only download dirs
        temp = {"dirs": {}, "subdomains": {}}
        os.makedirs(EXTERNAL_DIR, exist_ok=True)
        for src in SOURCES["dirs"]:
            out = os.path.join(EXTERNAL_DIR, f"dirs-{src['name']}.txt")
            path, count = _download(src["url"], out)
            if path:
                temp["dirs"][src["name"]] = {"path": path, "count": count,
                                              "desc": src["desc"]}
        manifest_path = os.path.join(EXTERNAL_DIR, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(temp, f, indent=2, ensure_ascii=False)
    elif kind == "subdomains":
        temp = {"dirs": {}, "subdomains": {}}
        os.makedirs(EXTERNAL_DIR, exist_ok=True)
        for src in SOURCES["subdomains"]:
            out = os.path.join(EXTERNAL_DIR, f"subs-{src['name']}.txt")
            path, count = _download(src["url"], out)
            if path:
                temp["subdomains"][src["name"]] = {"path": path, "count": count,
                                                     "desc": src["desc"]}
        manifest_path = os.path.join(EXTERNAL_DIR, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(temp, f, indent=2, ensure_ascii=False)

    print_status()
