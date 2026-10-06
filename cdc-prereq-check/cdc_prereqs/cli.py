"""Command-line interface and report output."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import SOURCES, __version__
from .core import LAYERS, CheckOutcome, Skip, Status, csv_list

ICONS = {Status.PASS: "✔", Status.WARN: "!", Status.FAIL: "✘", Status.SKIP: "-", Status.ERROR: "✘"}
COLORS = {Status.PASS: "32", Status.WARN: "33", Status.FAIL: "31", Status.SKIP: "90", Status.ERROR: "35"}


def common_arguments(p: argparse.ArgumentParser) -> None:
    db = p.add_argument_group("database connection")
    db.add_argument("--host", help="database host; defaults to the RDS endpoint when --rds-instance is set")
    db.add_argument("--port", type=int, help="database port (default: the engine default)")
    db.add_argument("--user", default="cdc_user", help="the CDC user Onehouse will use (default: cdc_user)")
    db.add_argument("--password", help="password; prefer the CDC_DB_PASSWORD env var or the prompt")
    db.add_argument("--database", help="Postgres database / MySQL database / Oracle service name")
    db.add_argument("--tables", help="comma-separated schema.table list to check; default: every table in scope")
    db.add_argument("--heartbeat-table", default="onehouse_heartbeat")
    db.add_argument("--connect-timeout", type=int, default=10, help="seconds (default: 10)")

    infra = p.add_argument_group("cloud infrastructure")
    infra.add_argument("--cloud", choices=("aws", "gcp"), default="aws")
    infra.add_argument("--aws-region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    infra.add_argument("--aws-profile")
    infra.add_argument("--rds-instance", help="RDS DB instance identifier")
    infra.add_argument("--eks-cluster", help="EKS cluster name of the Onehouse data plane")
    infra.add_argument("--onehouse-request-prefix",
                       help="shortcut: sets --eks-cluster to onehouse-customer-cluster-<prefix>")
    infra.add_argument("--glue-registry", help="Glue schema registry name to look for")
    infra.add_argument("--source-eni", help="override the analyzer source (ENI or instance ID)")
    infra.add_argument("--dest-eni", help="override the analyzer destination ENI")
    infra.add_argument("--skip-reachability-analyzer", action="store_true",
                       help="do not run VPC Reachability Analyzer (it costs about $0.10 per run)")
    infra.add_argument("--keep-reachability-path", action="store_true",
                       help="keep the analyzer path and result in the console for inspection")

    run = p.add_argument_group("run control")
    run.add_argument("--layers", default=",".join(LAYERS),
                     help=f"comma-separated subset of {', '.join(LAYERS)} (default: all)")
    run.add_argument("--only", help="comma-separated check IDs or prefixes, e.g. database.grants,infra")
    run.add_argument("--format", choices=("text", "json"), default="text")
    run.add_argument("--list-checks", action="store_true", help="print the checks and exit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdc-prereq-check",
        description="Check the prerequisites for a Onehouse CDC source. Every check is read-only on the database.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="source", metavar="SOURCE", required=True)
    for name, cls in SOURCES.items():
        sp = sub.add_parser(name, help=f"{cls.label} CDC ({cls.docs_url})",
                            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        common_arguments(sp)
        cls.add_arguments(sp.add_argument_group(f"{cls.label} options"))
    return parser


class TextReporter:
    def __init__(self, stream=sys.stdout):
        self.stream = stream
        self.color = stream.isatty() and not os.environ.get("NO_COLOR")
        self.layer = None

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def header(self, validator) -> None:
        print(self.paint(f"Onehouse {validator.label} CDC prerequisite check", "1"), file=self.stream)
        print(f"Docs: {validator.docs_url}", file=self.stream)

    def __call__(self, o: CheckOutcome) -> None:
        if o.layer != self.layer:
            self.layer = o.layer
            print("\n" + self.paint(o.layer.upper(), "1;4"), file=self.stream)
        r = o.result
        tag = self.paint(f"{ICONS[r.status]} {r.status.value:<5}", COLORS[r.status])
        print(f"{tag} {o.title}: {r.message}", file=self.stream)
        for line in r.details:
            print(self.paint(f"        {line}", "90"), file=self.stream)
        if r.fix and r.status in (Status.FAIL, Status.WARN, Status.ERROR):
            for i, line in enumerate(r.fix.splitlines()):
                print(f"        {'fix: ' if i == 0 else '     '}{line}", file=self.stream)
        self.stream.flush()

    def summary(self, outcomes: list[CheckOutcome]) -> None:
        counts = {s: sum(1 for o in outcomes if o.result.status == s) for s in Status}
        parts = [self.paint(f"{n} {s.value.lower()}", COLORS[s]) for s, n in counts.items() if n]
        print("\nSummary: " + ", ".join(parts), file=self.stream)
        if counts[Status.FAIL] or counts[Status.ERROR]:
            print("Fix every FAIL before you create the Onehouse source. Then run this check again.",
                  file=self.stream)
        elif counts[Status.WARN]:
            print("No blocking problems. Read each WARN before you continue.", file=self.stream)
        else:
            print("All prerequisites pass.", file=self.stream)


def resolve_host(validator) -> None:
    """Fill --host / --port from the RDS endpoint when only --rds-instance is given."""
    args = validator.args
    if args.host or not args.rds_instance or args.cloud != "aws":
        return
    try:
        endpoint = validator._rds_instance()["Endpoint"]
    except (Skip, Exception):  # noqa: BLE001 - the infra checks report the real error
        return
    args.host = endpoint["Address"]
    args.port = args.port or endpoint.get("Port")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cls = SOURCES[args.source]

    if args.list_checks:
        for spec in cls.specs():
            print(f"{spec.layer:<9} {spec.id:<32} {spec.title}")
        return 0

    layers = csv_list(args.layers)
    unknown = [l for l in layers if l not in LAYERS]
    if unknown:
        print(f"error: unknown layer(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    validator = cls(args)
    resolve_host(validator)
    if not args.host and set(layers) & {"network", "database"}:
        print("error: pass --host (or --rds-instance on AWS) to run the network and database layers",
              file=sys.stderr)
        return 2
    if "database" in layers and args.password is None and "CDC_DB_PASSWORD" not in os.environ \
            and not sys.stdin.isatty():
        print("error: no password: set CDC_DB_PASSWORD or pass --password", file=sys.stderr)
        return 2

    if args.format == "text":
        reporter = TextReporter()
        reporter.header(validator)
        outcomes = validator.run(layers, csv_list(args.only), on_result=reporter)
        reporter.summary(outcomes)
    else:
        outcomes = validator.run(layers, csv_list(args.only))
        json.dump({"source": cls.name, "version": __version__,
                   "checks": [o.to_dict() for o in outcomes]}, sys.stdout, indent=2)
        print()

    failed = any(o.result.status in (Status.FAIL, Status.ERROR) for o in outcomes)
    return 1 if failed else 0
