"""CLI entry point -- argument parsing and wiring."""
import argparse
import sys

from scanner.core.engine import Engine
from scanner.core.request import RequestHandler
from scanner.core.output import Output
from scanner.core.report import generate_html
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


MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule, StoredXssModule, CmdiModule, LfiModule, RedirectModule, SsrfModule, CsrfModule, HeadersModule, CorsModule, SstiModule]


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

    if args.command == "fetch-wordlists":
        from scanner.core.fetcher import run_fetch
        run_fetch(getattr(args, "fetch_kind", "all"))
        return

    # Parse module names
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


if __name__ == "__main__":
    main()
