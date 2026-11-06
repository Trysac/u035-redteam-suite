"""Command line interface: ``python -m redteam_suite run ...``."""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import cast

from .errors import RedteamError
from .probes import load_probes, select_probes
from .runner import SuiteReport, run_suite
from .targets import HttpTarget, Target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="Run benign adversarial probes against an LLM target you own.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run the probes", allow_abbrev=False)
    group = run.add_mutually_exclusive_group(required=True)
    group.add_argument("--target-url", metavar="URL", help="HTTP endpoint to test")
    group.add_argument("--target", metavar="MODULE:FACTORY", help="trusted Python factory")
    run.add_argument("--canary", required=True, metavar="TOKEN", help="canary string")
    run.add_argument("--category", action="append", default=[], metavar="C")
    run.add_argument("--probe", action="append", default=[], metavar="ID")
    run.add_argument("--format", choices=("text", "json"), default="text")
    run.add_argument("--allow-remote", action="store_true", help="allow non-loopback hosts")
    return parser


def _load_target(spec: str) -> Target:
    """Import ``module:factory`` and call it. This executes trusted code."""
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("--target must look like module:factory")
    try:
        module = importlib.import_module(module_name)
        target = getattr(module, attribute)()
    except Exception as exc:
        raise ValueError(f"cannot load the target: {type(exc).__name__}") from exc
    if not callable(getattr(target, "send", None)):
        raise ValueError("the target factory must return an object with send(prompt)")
    return cast(Target, target)


def _format_text(report: SuiteReport) -> str:
    lines: list[str] = []
    for item in report.results:
        if item.error is not None:
            status = "ERROR"
        elif item.succeeded:
            status = "SUCCEEDED"
        else:
            status = "resisted"
        head = f"{status:<9} {item.severity:<8} {item.probe_id:<10}"
        line = f"{head} {item.owasp} {item.category} {item.latency_ms:.1f}ms"
        if item.error is not None:
            line += f" {item.error!a}"
        lines.append(line)
    lines.append(f"{report.succeeded_count} of {len(report.results)} probes succeeded")
    return "\n".join(lines)


def _run(args: argparse.Namespace) -> int:
    remote = args.target_url is not None
    try:
        probes = select_probes(load_probes(), args.category, args.probe)
        if not probes:
            raise ValueError("no probes selected")
        target: Target
        if remote:
            target = HttpTarget(args.target_url, allow_remote=args.allow_remote)
        else:
            target = _load_target(args.target)
        report = run_suite(target, probes, args.canary)
    except (RedteamError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(report.to_json() if args.format == "json" else _format_text(report))
    if remote and all(item.error is not None for item in report.results):
        print("error: no probe could reach the target", file=sys.stderr)
        return 2
    return 1 if report.has_blocking_success else 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the exit code (0 clean, 1 high/critical finding, 2 error)."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code is None:
            return 0
        return exc.code if isinstance(exc.code, int) else 2
    return _run(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
