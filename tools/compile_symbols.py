#!/usr/bin/env python3
"""Compile symbol files from category directories into a single main.sym."""

import argparse
import sys
from pathlib import Path


def find_sym_files(symbol_dir: Path) -> list[Path]:
    """Find all .sym files in category subdirectories (not main.sym)."""
    sym_files = []
    for category_dir in sorted(symbol_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        for sym_file in sorted(category_dir.glob("*.sym")):
            sym_files.append(sym_file)
    return sym_files


def compile_symbols(profile_dir: Path) -> int:
    """Merge all category .sym files into main.sym, sorted by address."""
    symbol_dir = profile_dir / "symbol"
    if not symbol_dir.is_dir():
        print(f"Error: symbol directory not found: {symbol_dir}", file=sys.stderr)
        return 1

    sym_files = find_sym_files(symbol_dir)
    output = symbol_dir / "main.sym"

    entries = []
    for sym_file in sym_files:
        with open(sym_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)

    # Sort by address (second column)
    entries.sort(key=lambda line: line.split()[1] if len(line.split()) >= 2 else "")

    with open(output, "w") as f:
        for entry in entries:
            f.write(entry + "\n")

    print(f"Compiled {len(entries)} symbols into {output}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Compile symbol files into main.sym")
    parser.add_argument("profile_dir", type=Path, help="Path to profile directory")
    args = parser.parse_args()

    sys.exit(compile_symbols(args.profile_dir))


if __name__ == "__main__":
    main()
