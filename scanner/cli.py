"""CLI entry point -- argument parsing and wiring."""
import argparse
import sys

from scanner.core.engine import Engine
from scanner.core.request import RequestHandler
from scanner.core.output import Output
from scanner.modules.subdomain import SubdomainModule
from scanner.modules.dirscan import DirscanModule
from scanner.modules.params import ParamsModule
from scanner.modules.sqli import SqliModule
from scanner.modules.xss import XssModule
from scanner.modules.dom_xss import DomXssModule
from scanner.modules.stored_xss import StoredXssModule
from scanner.modules.cmdi import CmdiModule
from scanner.modules.lfi import LfiModule


MODULE_CLASSES = [SubdomainModule, DirscanModule, ParamsModule, SqliModule, XssModule, DomXssModule, StoredXssModule, CmdiModule, LfiModule]


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
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose progress output")
    scan.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan.add_argument("--subdomain-wordlist", help="Custom subdomain wordlist file")
    scan.add_argument("--dirscan-wordlist", help="Custom directory wordlist file")
    scan.add_argument("--sqli-threshold", type=int, default=5,
                      help="SQLi time-based threshold in seconds (default: 5)")

    # list command
    subparsers.add_parser("list", help="List available modules")

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

    # Parse module names
    if args.modules == "all":
        module_names = ["all"]
    else:
        module_names = [m.strip() for m in args.modules.split(",")]

    # Build dependencies
    request_handler = RequestHandler(timeout=args.timeout)
    output = Output(
        verbose=args.verbose,
        use_color=not args.no_color,
        json_path=args.output,
    )

    # Run
    output.log_progress(f"Starting scan against {args.target}")
    report = engine.run(args.target, module_names, request_handler, output, threads=args.threads)

    # Write JSON report
    if args.output:
        output.write_report(args.target, report["modules"])
        print(f"\nReport saved to {args.output}")

    # Summary
    total = sum(len(v) for v in report["findings"].values())
    print(f"\nScan complete. {total} findings across {len(report['modules'])} modules.")


if __name__ == "__main__":
    main()
