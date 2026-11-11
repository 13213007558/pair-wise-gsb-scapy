"""Command line entry point for the offline RA-guard checker."""

import argparse
import sys
from pathlib import Path

from .engine import RaGuardInspector
from .report import build_report, write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ra-guard-audit",
        description=(
            "Offline IPv6 Router Advertisement guard review of a captured "
            "pcap. Extension headers, truncation and fragmentation are "
            "handled explicitly; frames that cannot be decided are reported "
            "as inconclusive rather than passed."
        ),
    )
    parser.add_argument("pcap", type=Path, help="path to the input pcap/pcapng")
    parser.add_argument(
        "--json-out",
        type=Path,
        help="write the full machine-readable report to this path",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        help="write the human-readable Markdown report to this path",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print the summary counts",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.pcap.is_file():
        print("error: pcap not found: %s" % args.pcap, file=sys.stderr)
        return 2

    inspector = RaGuardInspector()
    records = inspector.inspect_file(args.pcap)
    summary = inspector.summary()
    report = build_report(args.pcap, records, summary)

    if args.json_out:
        write_json(report, args.json_out)
    if args.markdown_out:
        write_markdown(report, args.markdown_out)

    print("pcap: %s" % args.pcap)
    print(
        "frames: %d (IPv6 %d), fragment flows: %d, incomplete: %d"
        % (
            summary.total_frames,
            summary.ipv6_frames,
            summary.fragment_flows,
            summary.incomplete_flows,
        )
    )
    for verdict, count in summary.counts.items():
        print("  %-13s %d" % (verdict, count))

    if not args.quiet:
        print("")
        for record in records:
            print(
                "frame %3d  %-12s  %s"
                % (record.frame, record.verdict, ", ".join(record.reasons))
            )
            for note in record.details:
                print("             - %s" % note)

    if args.json_out:
        print("")
        print("json report:     %s" % args.json_out)
    if args.markdown_out:
        print("markdown report: %s" % args.markdown_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
