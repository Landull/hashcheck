#!/usr/bin/env python3
"""
hashcheck - compute and verify file hashes.

Hash a single file or an entire folder with MD5, SHA-1 and SHA-256,
check a file against an expected hash, or compare everything against
a known-hash list (e.g. a known-bad IOC list or a known-good baseline).

Standard library only. Python 3.8+.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

__version__ = "1.0.0"

ALGORITHMS = ("md5", "sha1", "sha256")
CHUNK_SIZE = 1024 * 1024  # 1 MiB
HEX_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def hash_file(path, algorithms=ALGORITHMS):
    """Return {algorithm: hexdigest} for a file, read in chunks."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def iter_files(target, recursive=True):
    """Yield file paths under target (or target itself if it's a file)."""
    if os.path.isfile(target):
        yield target
        return
    if recursive:
        for root, _dirs, files in os.walk(target):
            for name in sorted(files):
                yield os.path.join(root, name)
    else:
        for name in sorted(os.listdir(target)):
            path = os.path.join(target, name)
            if os.path.isfile(path):
                yield path


def load_known_hashes(path):
    """
    Load a known-hash list. Accepted line formats:
      <hash>
      <hash>  <filename>        (sha256sum / md5sum style)
      <hash>,<label>            (CSV)
    Lines starting with # are ignored. Algorithm is inferred from length.
    Returns {hash_lowercase: label}.
    """
    known = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                value, _, label = line.partition(",")
            else:
                parts = line.split(None, 1)
                value = parts[0]
                label = parts[1].lstrip("*") if len(parts) > 1 else ""
            value = value.strip().lower()
            if len(value) in HEX_LENGTHS and all(c in "0123456789abcdef" for c in value):
                known[value] = label.strip()
    return known


def build_records(target, algorithms, recursive, known=None):
    records = []
    for path in iter_files(target, recursive):
        record = {"path": path}
        try:
            record["size"] = os.path.getsize(path)
            record.update(hash_file(path, algorithms))
            record["error"] = ""
        except OSError as exc:
            record["size"] = ""
            for name in algorithms:
                record[name] = ""
            record["error"] = str(exc)
        if known is not None:
            match = next((record[a] for a in algorithms if record.get(a) in known), None)
            record["match"] = "MATCH" if match else ""
            record["match_label"] = known.get(match, "") if match else ""
        records.append(record)
    return records


def print_table(records, algorithms, show_match):
    for r in records:
        if r["error"]:
            print(f"[!] {r['path']}: {r['error']}", file=sys.stderr)
            continue
        flag = ""
        if show_match and r.get("match"):
            label = f" ({r['match_label']})" if r["match_label"] else ""
            flag = f"  <-- MATCH{label}"
        print(f"{r['path']}{flag}")
        for name in algorithms:
            print(f"  {name.upper():<7} {r[name]}")


def write_output(records, fmt, out_path, algorithms, show_match):
    fields = ["path", "size", *algorithms]
    if show_match:
        fields += ["match", "match_label"]
    fields.append("error")

    fh = open(out_path, "w", newline="", encoding="utf-8") if out_path else sys.stdout
    try:
        if fmt == "csv":
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
        else:
            json.dump(
                {
                    "tool": f"hashcheck {__version__}",
                    "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "files": [{k: r.get(k, "") for k in fields} for r in records],
                },
                fh,
                indent=2,
            )
            fh.write("\n")
    finally:
        if out_path:
            fh.close()


def cmd_verify(path, expected):
    expected = expected.strip().lower()
    algo = HEX_LENGTHS.get(len(expected))
    if not algo:
        print("[!] Expected hash must be MD5 (32), SHA-1 (40) or SHA-256 (64) hex chars.",
              file=sys.stderr)
        return 2
    actual = hash_file(path, (algo,))[algo]
    if actual == expected:
        print(f"[OK] {algo.upper()} matches: {actual}")
        return 0
    print(f"[FAIL] {algo.upper()} mismatch\n  expected {expected}\n  actual   {actual}")
    return 1


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="hashcheck",
        description="Compute and verify MD5 / SHA-1 / SHA-256 hashes for files and folders.",
    )
    p.add_argument("target", help="file or folder to hash")
    p.add_argument("-a", "--algo", choices=ALGORITHMS, action="append",
                   help="algorithm to use (repeatable; default: all three)")
    p.add_argument("-v", "--verify", metavar="HASH",
                   help="verify a single file against an expected hash")
    p.add_argument("-k", "--known", metavar="FILE",
                   help="compare against a known-hash list and flag matches")
    p.add_argument("--matches-only", action="store_true",
                   help="with --known, only report files that matched")
    p.add_argument("-n", "--no-recurse", action="store_true",
                   help="don't descend into subfolders")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table",
                   help="output format (default: table)")
    p.add_argument("-o", "--output", metavar="FILE", help="write csv/json output to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if not os.path.exists(args.target):
        print(f"[!] Not found: {args.target}", file=sys.stderr)
        return 2

    if args.verify:
        if not os.path.isfile(args.target):
            print("[!] --verify needs a single file.", file=sys.stderr)
            return 2
        return cmd_verify(args.target, args.verify)

    algorithms = tuple(dict.fromkeys(args.algo)) if args.algo else ALGORITHMS
    known = load_known_hashes(args.known) if args.known else None
    if known is not None and not known:
        print(f"[!] No valid hashes found in {args.known}", file=sys.stderr)
        return 2

    records = build_records(args.target, algorithms, not args.no_recurse, known)
    if known is not None and args.matches_only:
        records = [r for r in records if r.get("match")]

    show_match = known is not None
    if args.format == "table" and not args.output:
        print_table(records, algorithms, show_match)
    else:
        fmt = "json" if args.format == "table" else args.format
        write_output(records, fmt, args.output, algorithms, show_match)

    if show_match:
        hits = sum(1 for r in records if r.get("match"))
        print(f"\n[*] {hits} match(es) against {len(known)} known hash(es).", file=sys.stderr)
        return 1 if hits else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
