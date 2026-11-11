# Offline RA-Guard Audit Toolkit

A reusable, offline reviewer for IPv6 Router Advertisements (RAs) captured from
a switch mirror port. The input is a local pcap; the output locates every
original frame and states the evidence behind each decision.

The checker never searches for the raw byte `0x86` (ICMPv6 type 134). It walks
the IPv6 header chain to the actual terminal protocol, then applies Hop Limit,
source-address, ICMPv6 structure and checksum checks.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `ra` | A fully validated Router Advertisement. |
| `violation` | An RA or Neighbor Discovery frame that fails a guard check. |
| `inconclusive` | The frame cannot be decided reliably. It is never passed by default. |
| `benign` | IPv6 traffic that is demonstrably not an RA. |
| `out_of_scope` | A frame that does not carry IPv6 (for example ARP). |

`inconclusive` covers truncated captures, ESP-encrypted payloads, undersized
fragment-zero packets whose ICMPv6 type is hidden, and fragment flows that
never complete in the trace.

## Decision criteria

A frame is treated as an RA only after the extension header chain resolves to
next header `58` (ICMPv6) and the first ICMPv6 octet is `134`. Validation then
requires all of the following:

- Hop Limit equals `255`, as mandated for ND messages by RFC 4861 section 3.1.
- Source address is inside `fe80::/10` (RFC 4291 link-local scope).
- ICMPv6 code is zero and the body is at least the 16-octet fixed RA header
  (RFC 4861 section 4.2).
- The ICMPv6 checksum, recomputed over the IPv6 pseudo-header from the
  captured bytes, matches the declared checksum (RFC 4443 section 2.3).

Extension headers (Hop-by-Hop, Destination Options, Routing, Fragment, AH) are
walked on the raw captured octets, so an RA hidden behind one or more extension
headers is still reached, while truncation is detected rather than normalised
away.

### Fragmentation and RFC 6980

RFC 6980 section 4 forbids fragmentation of all Neighbor Discovery messages and
requires dropping an offset-zero fragment whose fragmentable part is too short
to reveal the ICMPv6 type. Fragmented traffic is therefore split into:

- Fragmented ND, including a hidden or truncated fragment zero: `violation`.
- Fragmented non-ND traffic (UDP, TCP, non-ND ICMPv6 such as echo): `benign`.
- Flows missing their first fragment or never completed: `inconclusive`.

Reassembly state is keyed on `(source, destination, fragment identification)`
and records overlaps and missing byte ranges; it does not rely on a single-flow
helper that would discard evidence.

## Layout

```
raguard/
  constants.py          protocol numbers, reason codes, verdict taxonomy
  chain.py              byte-level extension header walk and truncation
  icmpv6_analysis.py    hop limit, source scope, structure and checksum
  fragment.py           RFC 6980 fragment-flow state machine
  engine.py             two-pass inspection engine and FrameRecord model
  report.py             JSON and Markdown rendering
  cli.py                command line entry point
tests/
  make_sample_pcap.py   synthetic capture generator (no real network data)
  test_ra_guard.py      assertion suite over the synthetic capture
samples/                generated example pcap
reports/                generated example reports
```

## Usage

From this directory, with Scapy importable:

```console
PYTHONPATH=. python3 -m raguard.cli path/to/capture.pcap \
  --json-out reports/report.json \
  --markdown-out reports/report.md
```

Programmatic use:

```python
from raguard import RaGuardInspector, build_report, write_markdown

inspector = RaGuardInspector()
records = inspector.inspect_file("capture.pcap")
summary = inspector.summary()
write_markdown(build_report("capture.pcap", records, summary), "report.md")
```

Each `FrameRecord` carries the frame number, wire and captured lengths,
addresses, Hop Limit, extension-header values, fragment identifiers and
offsets, ICMPv6 type and checksum values, plus machine-readable reason codes
and human-readable notes.

## Reproducing the sample

The sample uses RFC 3849 documentation prefixes (`2001:db8::/32`), RFC 4291
link-local and multicast addresses, RFC 5737 IPv4 documentation space, and
locally administered MAC addresses. It contains no real network information.

```console
PYTHONPATH=. python3 tests/make_sample_pcap.py samples/ra_guard_sample.pcap
PYTHONPATH=. python3 tests/test_ra_guard.py
PYTHONPATH=. python3 -m raguard.cli samples/ra_guard_sample.pcap \
  --json-out reports/ra_guard_report.json \
  --markdown-out reports/ra_guard_report.md
```

## Sample coverage

The 23-frame capture includes a legitimate RA; RAs with a non-255 Hop Limit or
a routable source; RAs placed after Hop-by-Hop, Destination Options and two
extension headers; a malformed short RA with a bad checksum; a fragmented RA;
an undersized fragment zero that hides the ICMPv6 type; an orphan fragment;
benign fragmented UDP; TCP and UDP payloads containing `0x86`; echo, NS and NA
traffic; an ESP packet; two truncation points; and a legacy ARP frame.
