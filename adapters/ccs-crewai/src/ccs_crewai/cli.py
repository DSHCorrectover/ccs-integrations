"""Command-line receipt verifier for ccs-crewai.

Usage::

    ccs-crewai-verify --version
    ccs-crewai-verify receipt.json
    ccs-crewai-verify --chain receipt.json   # file contains {"l1": ..., "behavior": ...}

The CLI has no CrewAI dependency, so it can be installed in minimal audit
environments. It performs open-source structural and Ed25519 signature checks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .verifier import verify_chain, verify_l1_receipt


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _verify_receipt_file(path: str, *, chain: bool, check_expiry: bool) -> int:
    try:
        data = _load_json(path)
    except FileNotFoundError:
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    if chain:
        if not isinstance(data, dict) or "l1" not in data:
            print(
                "error: chain verification expects an object with an 'l1' key "
                "(optional 'behavior').",
                file=sys.stderr,
            )
            return 2
        ok, reason = verify_chain(
            data.get("l1"),
            data.get("behavior"),
            check_expiry=check_expiry,
        )
        label = "L1 + behavior chain"
    else:
        # Accept either a bare L1 receipt or a wrapper record.
        l1 = data.get("l1", data) if isinstance(data, dict) else data
        if not isinstance(l1, dict):
            print("error: receipt must be a JSON object", file=sys.stderr)
            return 2
        ok, reason = verify_l1_receipt(l1, check_expiry=check_expiry)
        label = "L1 receipt"

    if ok:
        print(f"VALID: {label} ({Path(path).name})")
        return 0

    print(f"INVALID: {label} ({Path(path).name}): {reason}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccs-crewai-verify",
        description="Verify CCS L1 and behavior receipts produced by ccs-crewai.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ccs-crewai-verify {__version__}",
    )
    parser.add_argument(
        "receipt",
        nargs="?",
        help="Path to a receipt JSON file. Omit with --version to print version.",
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help="Verify an L1 + behavior chain wrapper ({'l1': ..., 'behavior': ...}).",
    )
    parser.add_argument(
        "--check-expiry",
        action="store_true",
        help="Also reject expired receipts.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.receipt:
        parser.print_help()
        return 2
    return _verify_receipt_file(
        args.receipt,
        chain=args.chain,
        check_expiry=args.check_expiry,
    )


if __name__ == "__main__":
    raise SystemExit(main())
