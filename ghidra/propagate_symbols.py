# Propagate named symbols from one binary version to another using
# function-level hashing.
#
# Two hash modes:
#   mnemonic - SHA-256 of function size + instruction mnemonics + count.
#              Works for same-architecture matching (high accuracy).
#   semantic - SHA-256 of architecture-independent properties: basic block
#              count, callee count, instruction count, integer constants.
#              Works for cross-architecture matching (32-bit <-> 64-bit).
#
# Workflow:
# 1. Export hashes from the source binary (run with export <file> [mode])
# 2. Import and match against the target binary (run with import <file>)
#
# Hash file format (one line per function):
#   sha256_hex address function_name size [mode]
#
# The mode field is optional; defaults to "mnemonic" if absent.
#
# @category binanana

import hashlib
import struct
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()


def compute_mnemonic_hash(func):
    """Compute a mnemonic-based hash for same-architecture matching.

    Hashes the sequence of instruction mnemonics and the function size.
    This provides high accuracy when source and target have the same
    architecture and compiler version.
    """
    body = func.getBody()
    if body is None:
        return None

    hasher = hashlib.sha256()

    # Hash the function size
    size = body.getNumAddresses()
    hasher.update(struct.pack("<Q", size))

    # Hash instruction mnemonics in order
    code_iter = listing.getCodeUnits(body, True)
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


def compute_semantic_hash(func):
    """Compute a semantic hash for cross-architecture matching.

    Hashes architecture-independent properties:
    - Instruction count (not byte size, normalizes x86/x64 encoding)
    - Basic block count
    - Number of called functions (callees)
    - Integer constants used in comparisons and assignments
    - String constant references (if resolvable)

    This survives recompilation across architectures for structurally
    similar functions. Lower accuracy than mnemonic hashing but works
    cross-architecture.
    """
    body = func.getBody()
    if body is None:
        return None

    hasher = hashlib.sha256()

    # Count instructions (not bytes)
    code_iter = listing.getCodeUnits(body, True)
    instr_count = 0
    while code_iter.hasNext():
        cu = code_iter.next()
        if isinstance(cu, CodeUnit):
            instr_count += 1

    if instr_count == 0:
        return None

    hasher.update(struct.pack("<I", instr_count))

    # Basic block count via control flow
    block_model = ghidra.program.model.block.BasicBlockModel(currentProgram)
    block_iter = block_model.getCodeBlocksContaining(body, monitor)
    block_count = 0
    while block_iter.hasNext():
        block_iter.next()
        block_count += 1

    hasher.update(struct.pack("<I", block_count))

    # Count callees (functions this function calls)
    callee_count = 0
    code_iter2 = listing.getCodeUnits(body, True)
    seen_callees = set()

    while code_iter2.hasNext():
        cu = code_iter2.next()
        if isinstance(cu, CodeUnit):
            refs = cu.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isCall():
                    target = ref.getToAddress()
                    target_offset = target.getOffset()
                    if target_offset not in seen_callees:
                        seen_callees.add(target_offset)
                        callee_count += 1

    hasher.update(struct.pack("<I", callee_count))

    # Collect sorted integer constants from scalar operands
    # Only include constants > 0xFF to filter out register indices
    # and small immediates that vary with register allocation
    constants = set()
    code_iter3 = listing.getCodeUnits(body, True)

    while code_iter3.hasNext():
        cu = code_iter3.next()
        if isinstance(cu, CodeUnit):
            for i in range(cu.getNumOperands()):
                op_type = cu.getOperandType(i)
                # Check for scalar/immediate operands
                if (op_type & 0x1) != 0:  # SCALAR flag
                    try:
                        scalar = cu.getScalar(i)
                        if scalar is not None:
                            val = scalar.getUnsignedValue()
                            if val > 0xFF:
                                constants.add(val)
                    except Exception:
                        pass

    # Hash sorted constants for deterministic output
    for c in sorted(constants):
        hasher.update(struct.pack("<Q", c & 0xFFFFFFFFFFFFFFFF))

    hasher.update(struct.pack("<I", len(constants)))

    # Collect string references
    string_refs = []
    code_iter4 = listing.getCodeUnits(body, True)

    while code_iter4.hasNext():
        cu = code_iter4.next()
        if isinstance(cu, CodeUnit):
            refs = cu.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isData():
                    target = ref.getToAddress()
                    data = listing.getDataAt(target)
                    if data is not None:
                        dt = data.getDataType()
                        if dt is not None and "string" in dt.getName().lower():
                            try:
                                val = data.getValue()
                                if val is not None:
                                    s = str(val)
                                    if len(s) > 2:
                                        string_refs.append(s)
                            except Exception:
                                pass

    for s in sorted(string_refs):
        hasher.update(s.encode("utf-8", errors="replace"))

    hasher.update(struct.pack("<I", len(string_refs)))

    return hasher.hexdigest()


def compute_function_hash(func, mode="mnemonic"):
    """Dispatch to the appropriate hash function."""
    if mode == "semantic":
        return compute_semantic_hash(func)
    return compute_mnemonic_hash(func)


def export_hashes(output_path=None, mode="mnemonic"):
    """Export function hashes for all named functions."""
    if output_path is None:
        out_file = askFile("Save function hashes", "Export")
        output_path = out_file.absolutePath

    count = 0
    with open(str(output_path), "w") as f:
        f.write("# Function hashes for cross-version matching\n")
        f.write("# hash | address | name | size | mode\n")

        for func in functionManager.getFunctionsNoStubs(True):
            monitor.checkCanceled()

            if func.isExternal() or func.isThunk():
                continue

            name = func.getName()
            if name.startswith("FUN_"):
                continue

            func_hash = compute_function_hash(func, mode)
            if func_hash is None:
                continue

            addr = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()

            f.write("{} {:016X} {} {} {}\n".format(
                func_hash, addr, name, size, mode
            ))
            count += 1

    print("Exported {} function hashes ({} mode) to {}".format(
        count, mode, output_path
    ))


def import_and_match(input_path=None):
    """Import hashes from a source binary and match against current."""
    if input_path is None:
        in_file = askFile("Select source hash file", "Import")
        input_path = in_file.absolutePath

    # Load source hashes, grouped by mode
    source_hashes = {}  # hash -> (addr, name, size, mode)
    with open(str(input_path), "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                h, addr, name = parts[0], parts[1], parts[2]
                size = int(parts[3])
                mode = parts[4] if len(parts) >= 5 else "mnemonic"
                source_hashes[h] = (addr, name, size, mode)

    # Determine which modes are present
    modes = set(entry[3] for entry in source_hashes.values())
    print("Loaded {} source function hashes (modes: {})".format(
        len(source_hashes), ", ".join(sorted(modes))
    ))

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

        # Try each mode present in the source hashes
        for mode in modes:
            func_hash = compute_function_hash(func, mode)
            if func_hash is None:
                continue

            if func_hash in source_hashes:
                source_addr, source_name, source_size, source_mode = \
                    source_hashes[func_hash]

                if source_mode != mode:
                    continue

                # Verify size matches for mnemonic mode (stricter)
                current_size = func.getBody().getNumAddresses()
                if mode == "mnemonic" and current_size != source_size:
                    collisions += 1
                    continue

                func.setName(source_name, SourceType.IMPORTED)
                func.setComment(
                    "Matched from source build at {} ({} mode)".format(
                        source_addr, mode
                    )
                )
                matched += 1
                break  # Stop trying other modes once matched

    print("\nResults:")
    print("  Total functions: {}".format(total))
    print("  Matched: {}".format(matched))
    print("  Hash collisions (size mismatch): {}".format(collisions))
    print("  Source hashes available: {}".format(len(source_hashes)))


# Headless mode: args are mode, file_path, [hash_mode]
# GUI mode: prompts via askChoice/askFile
headless_args = getScriptArgs()
if headless_args:
    action = headless_args[0].lower()
    file_path = headless_args[1] if len(headless_args) > 1 else None
    hash_mode = headless_args[2] if len(headless_args) > 2 else "mnemonic"
    if action == "export":
        export_hashes(file_path, hash_mode)
    elif action == "import":
        import_and_match(file_path)
    else:
        print("Unknown action '{}'. Use 'export' or 'import'.".format(action))
else:
    choice = askChoice("Propagate Symbols",
                       "Select operation:",
                       ["Export hashes (mnemonic mode)",
                        "Export hashes (semantic mode)",
                        "Import and match from source hashes"],
                       "Export hashes (mnemonic mode)")
    if "mnemonic" in choice:
        export_hashes(mode="mnemonic")
    elif "semantic" in choice:
        export_hashes(mode="semantic")
    else:
        import_and_match()
