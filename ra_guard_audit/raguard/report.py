"""Human and machine-readable report rendering for inspection results."""

import json
from datetime import datetime, timezone
from pathlib import Path

from .constants import (
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
    VERDICT_OUT_OF_SCOPE,
    VERDICT_RA,
    VERDICT_VIOLATION,
)

VERDICT_TITLES = {
    VERDICT_RA: "Validated Router Advertisement",
    VERDICT_VIOLATION: "Violation",
    VERDICT_INCONCLUSIVE: "Inconclusive (not passed by default)",
    VERDICT_BENIGN: "Benign non-RA traffic",
    VERDICT_OUT_OF_SCOPE: "Out of scope (non-IPv6)",
}


def build_report(pcap_path: Path, records, summary) -> dict:
    return {
        "pcap": str(pcap_path),
        "generated_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "summary": {
            "total_frames": summary.total_frames,
            "ipv6_frames": summary.ipv6_frames,
            "verdict_counts": summary.counts,
            "fragment_flows": summary.fragment_flows,
            "incomplete_fragment_flows": summary.incomplete_flows,
        },
        "verdict_legend": VERDICT_TITLES,
        "frames": [record.to_dict() for record in records],
    }


def write_json(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _fmt_addresses(record: dict) -> str:
    src = record["src"] or "-"
    dst = record["dst"] or "-"
    hlim = str(record["hop_limit"]) if record["hop_limit"] is not None else "-"
    return "%s -> %s (hlim %s)" % (src, dst, hlim)


def write_markdown(report: dict, path: str | Path) -> Path:
    path = Path(path)
    lines: list[str] = []
    lines.append("# Offline RA-Guard Inspection Report")
    lines.append("")
    lines.append("- Capture: `%s`" % report["pcap"])
    lines.append("- Generated (UTC): %s" % report["generated_utc"])
    lines.append("")
    summary = report["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append("| Total frames | %d |" % summary["total_frames"])
    lines.append("| IPv6 frames | %d |" % summary["ipv6_frames"])
    for verdict, count in summary["verdict_counts"].items():
        lines.append(
            "| %s | %d |" % (VERDICT_TITLES[verdict], count)
        )
    lines.append("| Fragment flows | %d |" % summary["fragment_flows"])
    lines.append(
        "| Incomplete fragment flows | %d |"
        % summary["incomplete_fragment_flows"]
    )
    lines.append("")

    sections = (
        VERDICT_VIOLATION,
        VERDICT_INCONCLUSIVE,
        VERDICT_RA,
        VERDICT_BENIGN,
        VERDICT_OUT_OF_SCOPE,
    )
    for verdict in sections:
        frames = [f for f in report["frames"] if f["verdict"] == verdict]
        if not frames:
            continue
        lines.append("## %s (%d)" % (VERDICT_TITLES[verdict], len(frames)))
        lines.append("")
        for frame in frames:
            lines.append(
                "### Frame %d — %s" % (frame["frame"], _fmt_addresses(frame))
            )
            lines.append("")
            lines.append("- Wire length: %d, captured: %d" % (
                frame["wire_length"], frame["captured_length"]
            ))
            if frame["icmpv6_type"] is not None:
                lines.append("- ICMPv6 type: %d" % frame["icmpv6_type"])
            if frame["checksum_declared"] is not None:
                lines.append(
                    "- ICMPv6 checksum: declared 0x%04x, computed 0x%04x"
                    % (
                        frame["checksum_declared"],
                        frame["checksum_computed"],
                    )
                )
            if frame["extension_headers"]:
                lines.append(
                    "- Extension header chain (next-header values): %s"
                    % ", ".join(str(h) for h in frame["extension_headers"])
                )
            if frame["flow_key"]:
                lines.append(
                    "- Fragment: %s, offset %s, M %s"
                    % (
                        frame["flow_key"],
                        frame["fragment_offset"],
                        frame["fragment_more"],
                    )
                )
            lines.append(
                "- Reason codes: %s"
                % ", ".join("`%s`" % r for r in frame["reasons"])
            )
            for note in frame["details"]:
                lines.append("  - %s" % note)
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
