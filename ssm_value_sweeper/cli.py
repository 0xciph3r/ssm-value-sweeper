"""Command line interface: snapshot / find / diff.

Design notes:
- Values are decrypted (WithDecryption=True) and immediately hashed; the
  plaintext is never written to the report unless --store-values is given.
- Trailing newlines are stripped before hashing. Secret material copied
  through editors/terminal heredocs routinely gains a trailing '\\n', which
  silently produces two different hashes for the same key. This one detail
  caused a full false-alarm investigation once; the tool bakes the fix in.
- All subcommands accept 1..N --profile values (e.g. --profile a,b,c) for
  sweeping several accounts in one run.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _sessions(profiles):
    import boto3

    for name in profiles:
        yield (name, boto3.Session(profile_name=name) if name else boto3.Session())


def _ssm(session):
    client = session.client("ssm")
    def get_parameter(name, decrypt=True):
        resp = client.get_parameter(Name=name, WithDecryption=decrypt)
        return resp["Parameter"]
    return client, get_parameter


def normalize(value: str) -> str:
    """Strip trailing newlines/CRs only. Never touch leading whitespace:
    some real-world tokens are indentation-sensitive (JWTs are not, but
    caution is cheap)."""
    return (value or "").rstrip("\r\n")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(normalize(value).encode("utf-8")).hexdigest()


def iter_params(ssm_client, path_prefix="/", recurse=True):
    paginator = ssm_client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(
        Path=path_prefix,
        Recursive=recurse,
        WithDecryption=True,
        PaginationConfig={"PageSize": 10},
    ):
        for p in page.get("Parameters", []):
            yield p


def cmd_snapshot(args):
    for prof, session in _sessions(args.profiles):
        client, _ = _ssm(session)
        out_name = args.out or f"snapshot-{prof or 'default'}.json"
        rows = []
        for p in iter_params(client, args.path_prefix):
            value = p.get("Value") or ""
            row = {
                "Name": p["Name"],
                "Type": p["Type"],
                "sha256_16": sha256_hex(value)[:16],
                "sha256": sha256_hex(value),
            }
            if args.store_values:
                sys.stderr.write(
                    f"[warn] --store-values: writing plaintext value for {p['Name']} to {out_name}\n"
                )
                row["Value"] = value
            rows.append(row)
        Path(out_name).write_text(json.dumps(rows, indent=2))
        print(f"[{prof or 'default'}] {len(rows)} parameter(s) -> {out_name}")


def _target(args):
    """Return (plaintext_or_None, hash_or_None) from whatever was given."""
    if args.file:
        value = Path(args.file).read_text().rstrip("\r\n")
        return value, sha256_hex(value)
    if args.string:
        value = args.string.rstrip("\r\n")
        return value, sha256_hex(value)
    if args.hash:
        h = args.hash.lower().strip()
        if len(h) not in (16, 64):
            sys.exit("error: --hash expects 16 or 64 hex chars")
        return None, h
    sys.exit("error: give the secret via --file, --string, or --hash")


def cmd_find(args):
    plaintext, target_hash = _target(args)
    matches = []
    total = 0
    for prof, session in _sessions(args.profiles):
        client, get_parameter = _ssm(session)
        for p in iter_params(client, args.path_prefix):
            total += 1
            value = p.get("Value") or ""
            hit = False
            why = ""
            if plaintext is not None and args.substring:
                if plaintext and plaintext in value:
                    hit, why = True, "substring-of-value"
            elif plaintext is not None:
                if sha256_hex(value) == target_hash:
                    hit, why = True, "exact-value"
            else:  # hash-only target
                if sha256_hex(value) == target_hash:
                    hit, why = True, "exact-value"
            if hit:
                matches.append({
                    "profile": prof or "default",
                    "Name": p["Name"],
                    "Type": p["Type"],
                    "match": why,
                })
                print(f"MATCH [{prof or 'default'}] {p['Name']}  ({why})")
    print(f"\nScanned {total} parameter(s). Matches: {len(matches)}")
    if matches:
        out = args.out or "find-report.json"
        Path(out).write_text(json.dumps(matches, indent=2))
        print(f"Report -> {out}")
        sys.exit(0)
    sys.exit(1)


def cmd_diff(args):
    a = {r["Name"]: r for r in json.loads(Path(args.old).read_text())}
    b = {r["Name"]: r for r in json.loads(Path(args.new).read_text())}
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(n for n in set(a) & set(b) if a[n]["sha256"] != b[n]["sha256"])
    print(f"added   : {len(added)}")
    print(f"removed : {len(removed)}")
    print(f"changed : {len(changed)}")
    for label, names in (("added", added), ("removed", removed), ("changed", changed)):
        for n in names:
            print(f"  {label}: {n}")
    if args.out:
        Path(args.out).write_text(json.dumps(
            {"added": added, "removed": removed, "changed": changed}, indent=2))
        print(f"Report -> {args.out}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="ssm-value-sweeper",
        description="Sweep SSM Parameter Store for a secret by its VALUE (name-agnostic).",
        epilog="Values are hashed at read time; plaintext never enters reports "
               "unless you explicitly pass --store-values.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("snapshot", "find"):
        sp = sub.add_parser(name)
        sp.add_argument("--profiles", default="default",
                        help="comma-separated AWS profile names to sweep, e.g. account-a,account-b")
        sp.add_argument("--path-prefix", default="/",
                        help="parameter path root (default /, recursive)")

    s = sub.add_parser("snapshot", help="name+type+hash inventory of all parameters")
    s.add_argument("--out", default=None, help="output json path (default snapshot-<profile>.json)")
    s.add_argument("--store-values", action="store_true",
                   help="include plaintext values in the output (dangerous)")
    s.set_defaults(func=cmd_snapshot)

    f = sub.add_parser("find", help="find parameters carrying a rotated secret")
    tgt = f.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--file", help="file containing the rotated plaintext secret")
    tgt.add_argument("--string", help="the rotated plaintext secret (shell history risk)")
    tgt.add_argument("--hash", help="sha256 of the secret: 64 hex (or 16-char prefix)")
    f.add_argument("--substring", action="store_true",
                   help="also/instead report values CONTAINING the plaintext "
                        "(catches keys embedded in URLs/webhook strings)")
    f.add_argument("--out", default=None, help="matches json path")
    f.set_defaults(func=cmd_find)

    d = sub.add_parser("diff", help="diff two snapshot files")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--out", default=None)
    d.set_defaults(func=cmd_diff)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.profiles = [x.strip() for x in (args.profiles or "default").split(",") if x.strip()]
    args.func(args)


if __name__ == "__main__":
    main()
