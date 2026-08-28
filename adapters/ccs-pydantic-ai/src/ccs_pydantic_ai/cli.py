"""Command-line interface for CCS receipt verification.

Usage::

    # Verify a single L1 receipt
    ccs-verify receipt.json

    # Verify from stdin
    cat receipt.json | ccs-verify -

    # Verify a full chain (L1 + behavior)
    ccs-verify --chain l1.json behavior.json

    # Verify a ReceiptRecord envelope (contains "l1" and optionally "behavior")
    ccs-verify record.json

    # Verify a JSONL stream of receipts (one per line)
    ccs-verify --stream receipts.jsonl

    # Machine-readable JSON output
    ccs-verify --json receipt.json

    # Check expiry
    ccs-verify --check-expiry receipt.json

Exit codes:
    0  All receipts valid
    1  One or more receipts invalid
    2  Usage / input error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from . import __version__
from .verifier import verify_l1_receipt, verify_chain

# Exit codes
EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2


def _load_json(path: str) -> Any:
    """Load JSON from a file path or '-' for stdin."""
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _verify_one(
    data: dict[str, Any],
    *,
    check_expiry: bool = False,
) -> tuple[bool, str, str]:
    """Verify a single receipt object.

    Supports three input shapes:
    - A bare L1 receipt (30 fields, has ``signature`` and ``verdict``)
    - A ReceiptRecord envelope (``{"l1": {...}, "behavior": {...}}``)
    - A behavior receipt (``receipt_type == "ccs.behavior_evidence.v1"``) —
      returns invalid because behavior receipts require an L1 to link against.

    Returns:
        ``(ok, reason, kind)`` where *kind* is ``"l1"`` or ``"chain"``.
    """
    if not isinstance(data, dict):
        return False, "input must be a JSON object", "unknown"

    # ReceiptRecord envelope
    if "l1" in data and isinstance(data["l1"], dict):
        l1 = data["l1"]
        behavior = data.get("behavior")
        ok, reason = verify_chain(l1, behavior, check_expiry=check_expiry)
        kind = "chain" if behavior is not None else "l1"
        return ok, reason, kind

    # Bare behavior receipt without L1
    if data.get("receipt_type") == "ccs.behavior_evidence.v1":
        return False, "behavior receipt requires an L1 receipt to link (use --chain)", "behavior"

    # Bare L1 receipt
    ok, reason = verify_l1_receipt(data, check_expiry=check_expiry)
    return ok, reason, "l1"


def _verify_stream(
    lines: Sequence[str],
    *,
    check_expiry: bool = False,
) -> list[dict[str, Any]]:
    """Verify a JSONL stream. Returns a list of result dicts."""
    results: list[dict[str, Any]] = []
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            results.append({
                "line": i,
                "valid": False,
                "reason": f"JSON parse error: {exc}",
                "kind": "unknown",
            })
            continue
        ok, reason, kind = _verify_one(data, check_expiry=check_expiry)
        results.append({
            "line": i,
            "valid": ok,
            "reason": reason,
            "kind": kind,
        })
    return results


def _format_result(result: dict[str, Any]) -> str:
    """Format a single result for human-readable output."""
    status = "✓ Valid" if result["valid"] else "✗ Invalid"
    parts = [f"[{status}]"]
    if "line" in result:
        parts.append(f"line {result['line']}")
    parts.append(f"({result['kind']})")
    if not result["valid"]:
        parts.append(f"— {result['reason']}")
    return " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ccs-verify",
        description="Verify CCS (Correctover Conformance Shape) cryptographic receipts.",
        epilog="Exit codes: 0=valid, 1=invalid, 2=usage error. "
               "Docs: https://github.com/DSHCorrectover/ccs-integrations",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="-",
        help="Path to a JSON receipt file, or '-' for stdin (default: stdin).",
    )
    parser.add_argument(
        "--chain",
        nargs=2,
        metavar=("L1", "BEHAVIOR"),
        help="Verify a full chain: L1 receipt and behavior receipt as separate files.",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Treat input as JSONL (one receipt per line) and verify all.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results as machine-readable JSON.",
    )
    parser.add_argument(
        "--check-expiry",
        action="store_true",
        help="Also reject receipts whose expires_at is in the past.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ccs-verify {__version__}",
    )

    args = parser.parse_args(argv)

    # --- --chain mode: two separate files ---
    if args.chain:
        try:
            l1_path, behavior_path = args.chain
            l1 = _load_json(l1_path)
            behavior = _load_json(behavior_path)
        except (json.JSONDecodeError, OSError) as exc:
            msg = {"error": f"failed to load input: {exc}"}
            print(json.dumps(msg, indent=2) if args.json_output else f"Error: {exc}",
                  file=sys.stderr)
            return EXIT_USAGE

        ok, reason = verify_chain(l1, behavior, check_expiry=args.check_expiry)
        result = {"valid": ok, "reason": reason, "kind": "chain"}
        if args.json_output:
            print(json.dumps(result, indent=2))
        else:
            print(_format_result(result))
        return EXIT_VALID if ok else EXIT_INVALID

    # --- --stream mode: JSONL ---
    if args.stream:
        try:
            if args.path == "-":
                lines = sys.stdin.readlines()
            else:
                with open(args.path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
        except OSError as exc:
            msg = {"error": f"failed to read input: {exc}"}
            print(json.dumps(msg, indent=2) if args.json_output else f"Error: {exc}",
                  file=sys.stderr)
            return EXIT_USAGE

        results = _verify_stream(lines, check_expiry=args.check_expiry)
        all_valid = all(r["valid"] for r in results)

        if args.json_output:
            output = {
                "valid": all_valid,
                "total": len(results),
                "passed": sum(1 for r in results if r["valid"]),
                "failed": sum(1 for r in results if not r["valid"]),
                "results": results,
            }
            print(json.dumps(output, indent=2))
        else:
            for r in results:
                print(_format_result(r))
            total = len(results)
            passed = sum(1 for r in results if r["valid"])
            print(f"\n{passed}/{total} valid")

        return EXIT_VALID if all_valid else EXIT_INVALID

    # --- single receipt mode ---
    try:
        data = _load_json(args.path)
    except json.JSONDecodeError as exc:
        msg = {"error": f"invalid JSON: {exc}"}
        print(json.dumps(msg, indent=2) if args.json_output else f"Error: invalid JSON — {exc}",
              file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        msg = {"error": f"cannot read file: {exc}"}
        print(json.dumps(msg, indent=2) if args.json_output else f"Error: {exc}",
              file=sys.stderr)
        return EXIT_USAGE

    ok, reason, kind = _verify_one(data, check_expiry=args.check_expiry)
    result = {"valid": ok, "reason": reason, "kind": kind}

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(_format_result(result))

    return EXIT_VALID if ok else EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
