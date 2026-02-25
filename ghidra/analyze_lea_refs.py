# LEA operand scanner for string-to-code mapping.
#
# Walks all code units in .text and collects references to known
# string addresses. This bypasses broken xref engines by using
# Ghidra's instruction-level reference resolution (getReferencesFrom),
# which decodes RIP-relative LEA operands directly from instruction
# bytes without needing data flow analysis.
#
# Uses Ghidra's Listing API to build the target string set instead of
# raw memory.getBytes(), which returns zeroed bytes for Arxan-
# protected binaries.
#
# Target string categories:
#   - Lua "Usage:" strings (1,463 in Classic 1.13.2)
#   - CG*Data update field names (294)
#   - ERROR_ enum strings (656)
#   - Source file paths (701)
#   - RTTI type_info strings (2,069)
#   - CVar names (67)
#
# For each match, records the containing function (if any) and
# the string category. This creates a function-to-subsystem mapping
# even when decompilation is not possible.
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_lea_refs.py ["/path/to/output.txt"]
#
# @category binanana

LOG_PREFIX = "[binanana] "

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()
refManager = currentProgram.getReferenceManager()

POINTER_SIZE = currentProgram.getDefaultPointerSize()
IS_64BIT = POINTER_SIZE == 8


def read_char_array(data):
    """Read a char[N] data item as a string using Ghidra's value API.

    memory.getBytes() with Python bytearray does not reliably return data
    in PyGhidra, but data.getValue() works for char[N] types.
    """
    try:
        val = data.getValue()
        return str(val) if val is not None else None
    except Exception:
        return None


def get_string_value(data):
    """Extract a string value from a defined data item.

    Handles multiple Ghidra data type representations:
      - "string" / "TerminatedCString": data.getValue() returns the string
      - "char[N]" arrays: read raw bytes
      - Structures with char[N] components (e.g. TypeDescriptor):
        dig into components to find embedded string fields
    Returns the string value or None.
    """
    dt = data.getDataType()
    if dt is None:
        return None
    dt_name = dt.getName().lower()
    if "string" in dt_name:
        try:
            val = data.getValue()
            return str(val) if val is not None else None
        except Exception:
            return None
    if dt_name.startswith("char["):
        return read_char_array(data)
    num_components = data.getNumComponents()
    if num_components > 0:
        for i in range(num_components):
            component = data.getComponent(i)
            if component is None:
                continue
            comp_dt = component.getDataType()
            if comp_dt is None:
                continue
            comp_name = comp_dt.getName().lower()
            if comp_name.startswith("char["):
                val = read_char_array(component)
                if val:
                    return val
            if "string" in comp_name:
                try:
                    val = component.getValue()
                    if val is not None:
                        return str(val)
                except Exception:
                    continue
    return None


def get_section_range(name):
    """Find a section's start and end addresses."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return (block.getStart().getOffset(),
                    block.getEnd().getOffset() + 1)
    return None, None


def categorize_string(s):
    """Assign a category to a string based on its prefix/pattern."""
    if s.startswith("Usage: ") or s.startswith("Usage:"):
        return "lua_api"
    if s.startswith(".?AV") or s.startswith(".?AU"):
        return "rtti"
    if s.startswith("ERROR_"):
        return "error_enum"
    if "Data::" in s and s.startswith("CG"):
        return "update_field"
    # Source file paths
    lower = s.lower()
    if "buildserver" in lower and (lower.endswith(".cpp") or
                                    lower.endswith(".h") or
                                    lower.endswith(".cc")):
        return "source_path"
    # CVar references
    if s.startswith("CVar "):
        return "cvar"
    return None


def build_target_set():
    """Build set of target string addresses with their categories.

    Iterates defined string data in .rdata and .data using the Listing
    API instead of scanning raw bytes.
    """
    targets = {}

    for block in memory.getBlocks():
        if block.getName() not in (".rdata", ".data"):
            continue

        sec_name = block.getName()
        print(LOG_PREFIX + "Building target string set from {}...".format(sec_name))
        sec_count = 0

        data_iter = listing.getDefinedData(block.getStart(), True)
        while data_iter.hasNext():
            monitor.checkCanceled()
            data = data_iter.next()
            if data.getAddress().compareTo(block.getEnd()) > 0:
                break

            value = get_string_value(data)
            if value and len(value) >= 3:
                cat = categorize_string(value)
                if cat:
                    targets[data.getAddress().getOffset()] = (cat, value)
                    sec_count += 1

        print(LOG_PREFIX + "  {} targets in {}".format(sec_count, sec_name))

    return targets


def scan_code_references(targets):
    """Walk .text code units and find references to target addresses.

    Uses Ghidra's getReferencesFrom() on each code unit, which
    resolves RIP-relative LEA operands at the instruction level.
    This works even when the xref engine (getReferencesTo) fails
    due to broken import resolution.
    """
    text_start, text_end = get_section_range(".text")
    if text_start is None or text_end is None:
        print(LOG_PREFIX + "ERROR: .text section not found")
        return []

    results = []  # (instr_addr, func_addr, target_addr, category, value)
    target_set = set(targets.keys())

    addr = addressSpace.getAddress(text_start)
    end_addr = addressSpace.getAddress(text_end - 1)

    processed = 0
    found = 0

    print(LOG_PREFIX + "Scanning .text code units for references to {} target strings...".format(
        len(targets)))

    while addr is not None and addr.compareTo(end_addr) < 0:
        if processed % 500000 == 0 and processed > 0:
            monitor.checkCanceled()
            print(LOG_PREFIX + "  Processed {} code units, found {} matches...".format(
                processed, found))

        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            # Try next address
            addr = addr.add(1)
            processed += 1
            continue

        # Check references from this instruction
        refs = cu.getReferencesFrom()
        if refs:
            for ref in refs:
                ref_addr = ref.getToAddress().getOffset()
                if ref_addr in target_set:
                    instr_addr = addr.getOffset()
                    func = functionManager.getFunctionContaining(addr)
                    func_addr = func.getEntryPoint().getOffset() if func else 0
                    cat, val = targets[ref_addr]
                    results.append((instr_addr, func_addr, ref_addr, cat, val))
                    found += 1

        # Advance past this code unit
        try:
            next_addr = cu.getMaxAddress().add(1)
            addr = next_addr
        except Exception:
            addr = addr.add(1)

        processed += 1

    print(LOG_PREFIX + "  Scan complete: {} code units processed, {} references found".format(
        processed, found))

    return results


def analyze_lea_refs():
    """Main analysis: build target set and scan for references."""
    targets = build_target_set()

    # Print target breakdown
    categories = {}
    for addr, (cat, val) in targets.items():
        categories[cat] = categories.get(cat, 0) + 1
    print(LOG_PREFIX + "Target string categories:")
    for cat, count in sorted(categories.items()):
        print(LOG_PREFIX + "  {}: {}".format(cat, count))
    print(LOG_PREFIX + "  Total: {}".format(len(targets)))

    # Scan code
    results = scan_code_references(targets)

    # Aggregate by category
    cat_results = {}
    func_results = {}  # func_addr -> set of categories

    for instr_addr, func_addr, target_addr, cat, val in results:
        if cat not in cat_results:
            cat_results[cat] = []
        cat_results[cat].append((instr_addr, func_addr, target_addr, val))

        if func_addr:
            if func_addr not in func_results:
                func_results[func_addr] = set()
            func_results[func_addr].add(cat)

    # Print results
    print(LOG_PREFIX + "")
    print(LOG_PREFIX + "Results by category:")
    for cat in sorted(cat_results.keys()):
        entries = cat_results[cat]
        unique_funcs = len(set(e[1] for e in entries if e[1]))
        print(LOG_PREFIX + "  {}: {} references in {} functions".format(
            cat, len(entries), unique_funcs))

    print(LOG_PREFIX + "Functions with string references: {}".format(len(func_results)))

    # Export results
    output_path = None
    headless_args = getScriptArgs()
    if headless_args:
        output_path = headless_args[0]
    else:
        try:
            out_file = askFile(
                "Save LEA reference scan results? (Cancel to skip)", "Save")
            output_path = out_file.absolutePath
        except Exception:
            pass

    if output_path:
        with open(str(output_path), "w") as f:
            f.write("# LEA Operand Reference Scan Results\n")
            f.write("# instr_addr | func_addr | target_addr | category | string_value\n\n")

            for cat in sorted(cat_results.keys()):
                f.write("## {} ({} references)\n\n".format(
                    cat, len(cat_results[cat])))
                for instr_addr, func_addr, target_addr, val in cat_results[cat]:
                    f.write("{:016X} {:016X} {:016X} {} {}\n".format(
                        instr_addr, func_addr, target_addr, cat, val))
                f.write("\n")

            f.write("## Function-to-category mapping ({} functions)\n\n".format(
                len(func_results)))
            for func_addr in sorted(func_results.keys()):
                cats = sorted(func_results[func_addr])
                f.write("{:016X} {}\n".format(func_addr, ",".join(cats)))

        print(LOG_PREFIX + "Results saved to {}".format(str(output_path)))
    else:
        print(LOG_PREFIX + "Results not saved to file")


analyze_lea_refs()
