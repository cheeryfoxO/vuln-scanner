"""Scan presets — save/load named scan configurations.

Built-in presets:
  quick     — fast, non-invasive recon (fingerprint + headers + cors + dirscan)
  recon     — full recon (subdomain + dirscan + params + fingerprint)
  api       — API-focused (sqli + xss + ssrf + jwt + cors + headers)
  injection — injection only (sqli + xss + cmdi + lfi + ssti)
  owasp     — OWASP Top 10 coverage
  full      — all 18 modules

User presets saved to ~/.scanner-presets.json

Usage:
  scanner scan target --preset quick
  scanner scan target --preset api --delay 200 -v  (override flags still work)
  scanner scan target --preset injection --save-preset my-custom
  scanner --list-presets
"""
import json
import os
import sys

PRESETS_FILE = os.path.join(os.path.expanduser("~"), ".scanner-presets.json")

BUILTIN_PRESETS = {
    "quick": {
        "desc": "Fast non-invasive recon (fingerprint + headers + cors + dirscan)",
        "modules": "fingerprint,headers,cors,dirscan",
        "threads": 20,
        "delay": 50,
        "depth": 1,
    },
    "recon": {
        "desc": "Full recon (subdomain + dirscan + params + fingerprint)",
        "modules": "subdomain,dirscan,params,fingerprint",
        "threads": 15,
        "delay": 100,
        "depth": 2,
    },
    "api": {
        "desc": "API-focused testing (sqli + xss + ssrf + jwt + cors + headers)",
        "modules": "sqli,xss,ssrf,jwt,cors,headers",
        "threads": 10,
        "delay": 200,
        "depth": 1,
    },
    "injection": {
        "desc": "Injection attacks only (sqli + xss + cmdi + lfi + ssti)",
        "modules": "sqli,xss,cmdi,lfi,ssti",
        "threads": 5,
        "delay": 300,
        "depth": 1,
    },
    "owasp": {
        "desc": "OWASP Top 10 coverage (sqli + xss + cmdi + lfi + ssrf + csrf + headers + cors + jwt + idor)",
        "modules": "sqli,xss,cmdi,lfi,ssrf,csrf,headers,cors,jwt,idor",
        "threads": 8,
        "delay": 200,
        "depth": 2,
    },
    "full": {
        "desc": "All 18 modules (comprehensive)",
        "modules": "all",
        "threads": 10,
        "delay": 200,
        "depth": 2,
    },
}


def load_presets():
    """Load user presets from disk. Merges with builtins (user overrides)."""
    all_presets = dict(BUILTIN_PRESETS)
    if os.path.exists(PRESETS_FILE):
        try:
            with open(PRESETS_FILE, encoding="utf-8") as f:
                user = json.load(f)
            all_presets.update(user)
        except (json.JSONDecodeError, TypeError):
            pass
    return all_presets


def save_user_preset(name, modules, **kwargs):
    """Save a user preset to disk. Returns True on success."""
    user = {}
    if os.path.exists(PRESETS_FILE):
        try:
            with open(PRESETS_FILE, encoding="utf-8") as f:
                user = json.load(f)
        except (json.JSONDecodeError, TypeError):
            user = {}

    preset = {"modules": modules, "desc": f"User preset: {name}"}
    preset.update({k: v for k, v in kwargs.items() if v is not None and k != "preset"})

    user[name] = preset
    os.makedirs(os.path.dirname(PRESETS_FILE), exist_ok=True)
    with open(PRESETS_FILE, "w", encoding="utf-8") as f:
        json.dump(user, f, indent=2, ensure_ascii=False)
    return True


def list_presets():
    """Print all available presets."""
    presets = load_presets()
    print("\nScan presets:\n")
    for name, cfg in sorted(presets.items()):
        builtin = "[builtin]" if name in BUILTIN_PRESETS else "[user]"
        print(f"  {name:14s} {builtin:10s} {cfg.get('desc', '')}")
        print(f"  {'':14s} modules: {cfg.get('modules', 'all')}")
        mods = cfg.get("modules", "all")
        if mods != "all":
            count = len(mods.split(","))
        else:
            count = "all"
        print(f"  {'':14s} {count} modules, {cfg.get('threads', 10)} threads, "
              f"{cfg.get('delay', 100)}ms delay, depth={cfg.get('depth', 1)}")
        print()
    print(f"  Presets file: {PRESETS_FILE}")


def apply_preset(args, preset_name):
    """Apply a preset to parsed CLI args. Modifies args in-place.

    Only fills in values that the user didn't explicitly set.
    """
    presets = load_presets()
    preset = presets.get(preset_name)
    if not preset:
        print(f"Unknown preset: {preset_name}")
        print("Run: python -m scanner --list-presets")
        sys.exit(1)

    # Apply modules if user didn't specify -m
    if not getattr(args, "modules", None) or args.modules == "all":
        args.modules = preset.get("modules", "all")

    # Apply optional flags (only if user didn't set them)
    if not hasattr(args, "_threads_set") or not args._threads_set:
        args.threads = preset.get("threads", args.threads)
    if not hasattr(args, "_delay_set") or not args._delay_set:
        args.delay = preset.get("delay", args.delay)
    if not hasattr(args, "_depth_set") or not args._depth_set:
        args.depth = preset.get("depth", args.depth)
