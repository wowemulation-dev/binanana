#!/usr/bin/env python3
"""Validate a binanana profile for consistency and completeness."""

import argparse
import json
import sys
from pathlib import Path


def validate_info(profile_dir: Path) -> list[str]:
    """Validate info.json exists and has required fields."""
    errors = []
    info_path = profile_dir / "info.json"

    if not info_path.exists():
        errors.append(f"Missing info.json in {profile_dir}")
        return errors

    with open(info_path) as f:
        info = json.load(f)

    required = ["os", "arch", "module_name", "module_base"]
    for field in required:
        if field not in info:
            errors.append(f"Missing required field '{field}' in info.json")

    valid_os = ["windows", "darwin", "linux"]
    valid_arch = ["amd64", "arm64", "i386"]
    if info.get("os") not in valid_os:
        errors.append(f"Invalid os '{info.get('os')}', expected one of {valid_os}")
    if info.get("arch") not in valid_arch:
        errors.append(f"Invalid arch '{info.get('arch')}', expected one of {valid_arch}")

    # Validate module_base is valid hex
    base = info.get("module_base", "")
    try:
        int(base, 16)
    except ValueError:
        errors.append(f"Invalid module_base '{base}', expected hex string")

    return errors


def validate_symbols(profile_dir: Path) -> list[str]:
    """Validate symbol files for format correctness."""
    errors = []
    symbol_dir = profile_dir / "symbol"

    if not symbol_dir.is_dir():
        errors.append(f"Missing symbol directory in {profile_dir}")
        return errors

    addresses_seen = {}
    total_functions = 0
    total_labels = 0

    for category_dir in sorted(symbol_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        for sym_file in sorted(category_dir.glob("*.sym")):
            with open(sym_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Strip comments for parsing
                    comment_idx = line.find(";")
                    parse_line = line[:comment_idx].strip() if comment_idx >= 0 else line

                    parts = parse_line.split()
                    if len(parts) < 3:
                        errors.append(
                            f"{sym_file}:{line_num}: too few columns "
                            f"(got {len(parts)}, need >= 3)"
                        )
                        continue

                    name, addr, kind = parts[0], parts[1], parts[2]

                    # Validate address is hex
                    try:
                        int(addr, 16)
                    except ValueError:
                        errors.append(
                            f"{sym_file}:{line_num}: invalid address '{addr}'"
                        )
                        continue

                    # Validate kind
                    if kind not in ("f", "l"):
                        errors.append(
                            f"{sym_file}:{line_num}: invalid kind '{kind}', "
                            f"expected 'f' or 'l'"
                        )

                    # Check for duplicate addresses
                    if addr in addresses_seen:
                        prev = addresses_seen[addr]
                        errors.append(
                            f"{sym_file}:{line_num}: duplicate address {addr} "
                            f"(also in {prev})"
                        )
                    addresses_seen[addr] = f"{sym_file}:{line_num}"

                    if kind == "f":
                        total_functions += 1
                    elif kind == "l":
                        total_labels += 1

    # Summary
    info_path = profile_dir / "info.json"
    if info_path.exists():
        with open(info_path) as f:
            info = json.load(f)
        function_count = info.get("function_count", 0)
        if function_count > 0:
            coverage = total_functions / function_count * 100
            print(
                f"  Functions: {total_functions}/{function_count} "
                f"({coverage:.1f}% coverage)"
            )
        else:
            print(f"  Functions: {total_functions}")
    else:
        print(f"  Functions: {total_functions}")

    print(f"  Data labels: {total_labels}")
    print(f"  Total symbols: {total_functions + total_labels}")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate a binanana profile")
    parser.add_argument("profile_dir", type=Path, help="Path to profile directory")
    args = parser.parse_args()

    profile_dir = args.profile_dir
    print(f"Validating {profile_dir}...")

    all_errors = []
    all_errors.extend(validate_info(profile_dir))
    all_errors.extend(validate_symbols(profile_dir))

    if all_errors:
        print(f"\n{len(all_errors)} error(s):")
        for err in all_errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("  No errors.")
        sys.exit(0)


if __name__ == "__main__":
    main()
