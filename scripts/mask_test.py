#!/usr/bin/env python3
"""
Masking test script: run PII masking on input text and print comparison.

Usage:
    python scripts/mask_test.py "田中太郎です。090-1234-5678に電話してください。"
    echo "田中太郎です。" | python scripts/mask_test.py
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from app.masking import redact_text_with_mapping, warmup


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run PII masking on input text and show original vs masked output."
    )
    parser.add_argument(
        "text",
        nargs="?",
        default=None,
        help="Input text to mask. If omitted, reads from stdin.",
    )
    parser.add_argument(
        "--no-warmup",
        action="store_true",
        help="Skip GiNZA warmup (faster for repeated runs, but first call may be slow).",
    )
    args = parser.parse_args()

    if args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read().strip()
        if not text:
            print("Error: No input text. Provide as argument or via stdin.", file=sys.stderr)
            sys.exit(1)

    if not args.no_warmup:
        print("Loading GiNZA model (warmup)...", file=sys.stderr)
        warmup()
        print("Done.\n", file=sys.stderr)

    masked_text, mapping = redact_text_with_mapping(text)

    # Print comparison
    print("=" * 60)
    print("INPUT (original):")
    print("-" * 60)
    print(text)
    print()
    print("OUTPUT (masked):")
    print("-" * 60)
    print(masked_text)
    print()
    if mapping:
        print("PII MAPPING:")
        print("-" * 60)
        for placeholder, original in sorted(mapping.items()):
            print(f"  {placeholder} -> {original}")
    else:
        print("PII MAPPING: (none detected)")
    print("=" * 60)


if __name__ == "__main__":
    main()
