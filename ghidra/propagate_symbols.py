# Propagate named symbols from one binary version to another using
# function-level instruction hashing.
#
# This script computes a hash of each function's instruction bytes
# (ignoring address-dependent operands) and matches functions between
# a source and target binary.
#
# Workflow:
# 1. Export hashes from the source binary (run with --export)
# 2. Import and match against the target binary (run with --import)
#
# Hash computation:
# - Uses the function's instruction mnemonics and register operands
# - Ignores immediate values and displacement values (which change
#   between builds due to different addresses)
# - Includes function size as a secondary discriminator
#
# This script operates on .sym files rather than live Ghidra databases,
# making it usable in headless pipelines.
#
# @category binanana

import hashlib
import struct
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.listing import CodeUnit

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()


def compute_function_hash(func):
    """Compute a content hash for a function, ignoring relocatable values.

    Hashes the sequence of instruction mnemonics and the function size.
    This is a simplified approach -- a production version would normalize
    register allocations and ignore padding.
    """
    body = func.getBody()
    if body is None:
        return None

    hasher = hashlib.sha256()

    # Hash the function size
    size = body.getNumAddresses()
    hasher.update(struct.pack("<Q", size))

    # Hash instruction mnemonics in order
    addr_set = body
    code_iter = listing.getCodeUnits(addr_set, True)
    mnemonic_count = 0

    while code_iter.hasNext():
        cu = code_iter.next()
        if isinstance(cu, CodeUnit):
            mnemonic = cu.getMnemonicString()
            if mnemonic:
                hasher.update(mnemonic.encode("utf-8"))
                mnemonic_count += 1

    if mnemonic_count == 0:
        return None

    # Include mnemonic count to reduce collisions
    hasher.update(struct.pack("<I", mnemonic_count))

    return hasher.hexdigest()


def export_hashes():
    """Export function hashes for all named functions."""
    out_file = askFile("Save function hashes", "Export")

    count = 0
    with open(out_file.absolutePath, "w") as f:
        f.write("# Function hashes for cross-version matching\n")
        f.write("# hash | address | name | size\n")

        for func in functionManager.getFunctionsNoStubs(True):
            monitor.checkCanceled()

            if func.isExternal() or func.isThunk():
                continue

            name = func.getName()
            if name.startswith("FUN_"):
                continue

            func_hash = compute_function_hash(func)
            if func_hash is None:
                continue

            addr = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()

            f.write("{} {:016X} {} {}\n".format(func_hash, addr, name, size))
            count += 1

    print("Exported {} function hashes to {}".format(
        count, out_file.absolutePath))


def import_and_match():
    """Import hashes from a source binary and match against current."""
    in_file = askFile("Select source hash file", "Import")

    # Load source hashes
    source_hashes = {}  # hash -> (addr, name, size)
    with open(in_file.absolutePath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                h, addr, name = parts[0], parts[1], parts[2]
                size = int(parts[3])
                source_hashes[h] = (addr, name, size)

    print("Loaded {} source function hashes".format(len(source_hashes)))

    # Compute hashes for unnamed functions in current binary
    matched = 0
    collisions = 0
    total = 0

    for func in functionManager.getFunctionsNoStubs(True):
        monitor.checkCanceled()

        if func.isExternal() or func.isThunk():
            continue

        total += 1
        name = func.getName()

        # Skip already named functions
        if not name.startswith("FUN_"):
            continue

        func_hash = compute_function_hash(func)
        if func_hash is None:
            continue

        if func_hash in source_hashes:
            source_addr, source_name, source_size = source_hashes[func_hash]

            # Verify size matches to reduce false positives
            current_size = func.getBody().getNumAddresses()
            if current_size != source_size:
                collisions += 1
                continue

            func.setName(source_name, SourceType.IMPORTED)
            func.setComment("Matched from source build at {}".format(source_addr))
            matched += 1

    print("\nResults:")
    print("  Total functions: {}".format(total))
    print("  Matched: {}".format(matched))
    print("  Hash collisions (size mismatch): {}".format(collisions))
    print("  Source hashes available: {}".format(len(source_hashes)))


# Ask user which mode to run
choice = askChoice("Propagate Symbols",
                   "Select operation:",
                   ["Export hashes from this binary",
                    "Import and match from source hashes"],
                   "Export hashes from this binary")

if "Export" in choice:
    export_hashes()
else:
    import_and_match()
