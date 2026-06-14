"""CLI entry point -- argument parsing and wiring."""
import argparse
import json
import sys

from scanner.core.engine import Engine
from scanner.core.request import RequestHandler
from scanner.core.output import Output
from scanner.core.report import generate_html
from scanner.core.presets import apply_preset, save_user_preset, list_presets
from scanner.modules.subdomain import SubdomainModule
from scanner.modules.dirscan import DirscanModule
from scanner.modules.params import ParamsModule
from scanner.modules.sqli import SqliModule
from scanner.modules.xss import XssModule
from scanner.modules.dom_xss import DomXssModule
from scanner.modules.stored_xss import StoredXssModule
from scanner.modules.cmdi import CmdiModule
from scanner.modules.lfi import LfiModule
from scanner.modules.redirect import RedirectModule
from scanner.modules.ssrf import SsrfModule
from scanner.modules.csrf import CsrfModule
from scanner.modules.headers import HeadersModule
from scanner.modules.cors import CorsModule
from scanner.modules.ssti import SstiModule
from scanner.modules.fingerprint import FingerprintModule
from scanner.modules.jwt import JwtModule
from scanner.modules.idor import IdorModule


MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule, StoredXssModule, CmdiModule, LfiModule, RedirectModule, SsrfModule, CsrfModule, HeadersModule, CorsModule, SstiModule, FingerprintModule, JwtModule, IdorModule]


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Modular vulnerability reconnaissance tool",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan = subparsers.add_parser("scan", help="Run scan against a target")
    scan.add_argument("target", help="Target domain or URL (e.g., example.com or https://example.com)")
    scan.add_argument("-m", "--modules", default="all",
                      help="Comma-separated module names (subdomain,dirscan,params) or 'all'")
    scan.add_argument("-t", "--threads", type=int, default=10,
                      help="Concurrency hint (default: 10)")
    scan.add_argument("-o", "--output", help="Save JSON report to file")
    scan.add_argument("-r", "--report", help="Save HTML report to file")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose progress output")
    scan.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan.add_argument("--subdomain-wordlist", help="Custom subdomain wordlist file")
    scan.add_argument("--dirscan-wordlist", help="Custom directory wordlist file")
    scan.add_argument("--sqli-threshold", type=int, default=5,
                      help="SQLi time-based threshold in seconds (default: 5)")
    scan.add_argument("--delay", type=int, default=0,
                      help="Delay between requests in ms (rate limiting)")
    scan.add_argument("--cookie", help="Cookie string (e.g., 'session=abc; token=xyz')")
    scan.add_argument("--header", action="append", dest="headers",
                      help="Extra header (repeatable, e.g., -H 'X-Key: val')")
    scan.add_argument("--scope", help="Restrict to domain (e.g., '*.example.com')")
    scan.add_argument("--depth", type=int, default=1,
                      help="Crawl depth (default: 1, no recursion)")
    scan.add_argument("--proxy", help="Proxy URL (e.g., 'http://127.0.0.1:8080' for Burp)")
    scan.add_argument("--resume", metavar="FILE",
                      help="Resume interrupted scan from JSON output file")
    scan.add_argument("--preset", help="Load named scan preset (quick, recon, api, injection, owasp, full)")
    scan.add_argument("--save-preset", metavar="NAME",
                      help="Save current config as a named preset")
    scan.add_argument("--list-presets", action="store_true", help="List available presets")

    # list command
    subparsers.add_parser("list", help="List available modules")

    # fetch-wordlists command
    fetch_wl = subparsers.add_parser("fetch-wordlists", help="Download popular open-source wordlists")
    fetch_wl.add_argument("--all", action="store_const", dest="fetch_kind", const="all",
                          help="Download all wordlists (dirs + subdomains) [default]")
    fetch_wl.add_argument("--dirs", action="store_const", dest="fetch_kind", const="dirs",
                          help="Download directory wordlists only")
    fetch_wl.add_argument("--subdomains", action="store_const", dest="fetch_kind", const="subdomains",
                          help="Download subdomain wordlists only")
    fetch_wl.add_argument("--status", action="store_const", dest="fetch_kind", const="status",
                          help="Show downloaded wordlists status")
    fetch_wl.set_defaults(fetch_kind="all")

    # passive command
    passive = subparsers.add_parser("passive", help="Scan imported HAR/Burp traffic files")
    passive.add_argument("file", help="HAR or Burp XML file to parse")
    passive.add_argument("-m", "--modules", default="all",
                         help="Comma-separated module names or 'all'")
    passive.add_argument("-t", "--threads", type=int, default=10,
                         help="Concurrency hint (default: 10)")
    passive.add_argument("-o", "--output", help="Save JSON report to file")
    passive.add_argument("-r", "--report", help="Save HTML report to file")
    passive.add_argument("-v", "--verbose", action="store_true", help="Verbose progress output")
    passive.add_argument("--no-color", action="store_true", help="Disable colored output")
    passive.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    passive.add_argument("--delay", type=int, default=0,
                         help="Delay between requests in ms (rate limiting)")
    passive.add_argument("--cookie", help="Additional cookie string")
    passive.add_argument("--proxy", help="Proxy URL for replay")

    # web command
    web = subparsers.add_parser("web", help="Launch web-based scan interface")
    web.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8085, help="Port (default: 8085)")
    web.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Build engine and register all modules
    engine = Engine()
    for cls in MODULE_CLASSES:
        kwargs = {}
        sub_wl = getattr(args, "subdomain_wordlist", None)
        dir_wl = getattr(args, "dirscan_wordlist", None)
        if cls is SubdomainModule and sub_wl:
            kwargs["wordlist_path"] = sub_wl
        if cls is DirscanModule and dir_wl:
            kwargs["wordlist_path"] = dir_wl
        mod = cls(**kwargs)
        engine.register(mod)

    if args.command == "list":
        print("Available modules:")
        for name, desc in engine.list_modules().items():
            print(f"  {name:12} {desc}")
        return

    if getattr(args, "list_presets", False):
        list_presets()
        return

    if args.command == "fetch-wordlists":
        from scanner.core.fetcher import run_fetch
        run_fetch(getattr(args, "fetch_kind", "all"))
        return

    if args.command == "passive":
        from scanner.core.passive import run_passive
        from scanner.core.report import generate_html

        module_names = [m.strip() for m in args.modules.split(",")] if args.modules != "all" else ["all"]

        rh = RequestHandler(
            timeout=args.timeout,
            delay=getattr(args, "delay", 0),
            cookies=getattr(args, "cookie", None),
            proxy=getattr(args, "proxy", None),
        )
        out = Output(verbose=args.verbose, use_color=not args.no_color, json_path=args.output)

        out.log_progress(f"Passive scan: {args.file}")
        report = run_passive(args.file, module_names, rh, out, threads=args.threads)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"JSON report saved to {args.output}")

        if getattr(args, "report", None):
            generate_html(f"passive:{args.file}", report, args.report)
            print(f"HTML report saved to {args.report}")

        total = sum(len(v) for v in report.get("findings", {}).values())
        print(f"Passive scan complete. {total} findings from {report.get('scanned_targets', 0)} targets.")
        return

    if args.command == "web":
        from scanner.web.app import run_web
        run_web(
            host=getattr(args, "host", "127.0.0.1"),
            port=getattr(args, "port", 8080),
            open_browser=not getattr(args, "no_browser", False),
        )
        return

    # Parse module names
    if getattr(args, "preset", None):
        apply_preset(args, args.preset)

    if args.modules == "all":
        module_names = ["all"]
    else:
        module_names = [m.strip() for m in args.modules.split(",")]

    # Build dependencies
    extra_headers = {}
    if getattr(args, "headers", None):
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    proxy = getattr(args, "proxy", None)

    request_handler = RequestHandler(
        timeout=args.timeout,
        delay=getattr(args, "delay", 0),
        cookies=getattr(args, "cookie", None),
        extra_headers=extra_headers or None,
        proxy=proxy,
    )
    output = Output(
        verbose=args.verbose,
        use_color=not args.no_color,
        json_path=args.output,
    )

    # Run
    if proxy:
        output.log_progress(f"Using proxy: {proxy} (SSL verify disabled)")
    resume_from = getattr(args, "resume", None)
    if resume_from:
        output.log_progress(f"Resuming from checkpoint: {resume_from}")
    else:
        output.log_progress(f"Starting scan against {args.target}")
    report = engine.run(
        args.target, module_names, request_handler, output,
        threads=args.threads,
        scope=getattr(args, "scope", None),
        depth=getattr(args, "depth", 1),
        resume=resume_from,
    )

    # Write JSON report
    if args.output:
        output.write_report(args.target, report["modules"])
        print(f"\nJSON report saved to {args.output}")

    # Write HTML report
    report_path = getattr(args, "report", None)
    if report_path:
        generate_html(args.target, report, report_path)
        print(f"HTML report saved to {report_path}")

    # Summary
    total = sum(len(v) for v in report["findings"].values())
    print(f"\nScan complete. {total} findings across {len(report['modules'])} modules.")

    # Save preset if requested
    save_name = getattr(args, "save_preset", None)
    if save_name:
        save_user_preset(
            save_name,
            modules=args.modules,
            threads=args.threads,
            delay=getattr(args, "delay", 100),
            depth=getattr(args, "depth", 1),
        )
        print(f"Preset saved: {save_name}")


if __name__ == "__main__":
    main()
