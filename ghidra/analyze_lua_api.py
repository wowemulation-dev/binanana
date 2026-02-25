# Analyze Lua API Usage: strings and resolve them to native functions.
#
# WoW Classic embeds "Usage: FunctionName(params)" strings for every
# Lua-exposed function. These strings sit in .rdata adjacent to the
# function pointer table entries.
#
# This script:
# 1. Finds all "Usage: " strings in .rdata and .data using the Listing API
# 2. Scans .text for LEA instructions that reference each string
# 3. Traces from the LEA to find the associated native function pointer
# 4. Names the native function based on the Lua API name
#
# Uses Ghidra's Listing API to iterate defined data items rather than raw
# memory.getBytes() scanning. This works on binaries with Arxan protection
# where .data bytes are zeroed on disk but Ghidra's analyzers have already
# identified the strings.
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_lua_api.py ["/path/to/output.txt"]
#
# @category binanana

from ghidra.program.model.symbol import SourceType

LOG_PREFIX = "[binanana] "

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()

IMAGE_BASE = currentProgram.getImageBase().getOffset()


def get_section_range(name):
    """Find a section's start and end addresses."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return (block.getStart().getOffset(),
                    block.getEnd().getOffset())
    return None, None


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


def find_usage_strings():
    """Find all 'Usage: ' strings in .rdata and .data using the Listing API."""
    entries = []
    for block in memory.getBlocks():
        if block.getName() not in (".rdata", ".data"):
            continue
        print(LOG_PREFIX + "Scanning {} for Usage: strings...".format(block.getName()))
        sec_count = 0
        data_iter = listing.getDefinedData(block.getStart(), True)
        while data_iter.hasNext():
            monitor.checkCanceled()
            data = data_iter.next()
            if data.getAddress().compareTo(block.getEnd()) > 0:
                break
            value = get_string_value(data)
            if value and value.startswith("Usage: "):
                entries.append((data.getAddress().getOffset(), value))
                sec_count += 1
        print(LOG_PREFIX + "  {} Usage: strings in {}".format(sec_count, block.getName()))
    return entries


def parse_usage_string(usage_str):
    """Parse 'Usage: C_Namespace.FuncName(params)' into components."""
    # Strip "Usage: " prefix
    if usage_str.startswith("Usage: "):
        usage_str = usage_str[7:]

    # Extract function name (before parenthesis)
    paren_idx = usage_str.find("(")
    if paren_idx >= 0:
        func_name = usage_str[:paren_idx].strip()
        params = usage_str[paren_idx:]
    else:
        func_name = usage_str.strip()
        params = ""

    return func_name, params


def find_lea_references(string_addr):
    """Find LEA instructions in .text that reference this string address.

    x64 LEA uses RIP-relative addressing: LEA reg, [RIP + disp32]
    The effective address = instruction_addr + instruction_length + disp32
    """
    text_start, text_end = get_section_range(".text")
    if text_start is None:
        return []

    refs = []
    # Search for references using Ghidra's reference manager
    ghidra_addr = addressSpace.getAddress(string_addr)
    ref_manager = currentProgram.getReferenceManager()
    refs_to = ref_manager.getReferencesTo(ghidra_addr)

    for ref in refs_to:
        from_addr = ref.getFromAddress().getOffset()
        if text_start <= from_addr <= text_end:
            refs.append(from_addr)

    return refs


def name_function_at(addr, name):
    """Name a function at the given address."""
    ghidra_addr = addressSpace.getAddress(addr)
    func = functionManager.getFunctionAt(ghidra_addr)

    if func is not None:
        sym = func.getSymbol()
        if sym is not None and sym.getSource() == SourceType.DEFAULT:
            func.setName(name, SourceType.ANALYSIS)
            return True
    else:
        # Try to find the containing function
        func = functionManager.getFunctionContaining(ghidra_addr)
        if func:
            sym = func.getSymbol()
            if sym is not None and sym.getSource() == SourceType.DEFAULT:
                func.setName(name, SourceType.ANALYSIS)
                return True

    return False


def analyze_lua_api():
    """Main analysis: find Usage: strings and resolve to native functions."""
    print(LOG_PREFIX + "Scanning for Lua API Usage: strings...")
    usage_entries = find_usage_strings()
    print(LOG_PREFIX + "Found {} Usage: strings".format(len(usage_entries)))

    resolved = 0
    unresolved = []

    for string_addr, usage_str in usage_entries:
        monitor.checkCanceled()

        func_name, params = parse_usage_string(usage_str)
        if not func_name:
            continue

        # Create a safe symbol name
        safe_name = "Script_" + func_name.replace(".", "_")

        # Find code references to this string
        refs = find_lea_references(string_addr)
        if refs:
            # The reference is in the registration function.
            # Name the containing function.
            for ref_addr in refs:
                ghidra_ref = addressSpace.getAddress(ref_addr)
                containing = functionManager.getFunctionContaining(ghidra_ref)
                if containing:
                    c_sym = containing.getSymbol()
                    if c_sym and c_sym.getSource() == SourceType.DEFAULT:
                        containing.setName(safe_name, SourceType.ANALYSIS)
                        containing.setComment(
                            "Lua API: {}".format(usage_str))
                        resolved += 1
                        break
        else:
            unresolved.append((string_addr, func_name))

    print(LOG_PREFIX + "")
    print(LOG_PREFIX + "Results:")
    print(LOG_PREFIX + "  Usage: strings found: {}".format(len(usage_entries)))
    print(LOG_PREFIX + "  Functions resolved: {}".format(resolved))
    print(LOG_PREFIX + "  Unresolved: {}".format(len(unresolved)))

    if unresolved:
        print(LOG_PREFIX + "First 20 unresolved:")
        for addr, name in unresolved[:20]:
            print(LOG_PREFIX + "  {:016X} {}".format(addr, name))

    # Export results to file
    output_path = None
    headless_args = getScriptArgs()
    if headless_args:
        output_path = headless_args[0]
    else:
        try:
            out_file = askFile("Save Lua API results? (Cancel to skip)", "Save")
            output_path = out_file.absolutePath
        except Exception:
            pass

    if output_path:
        with open(str(output_path), "w") as f:
            f.write("# Lua API Analysis Results\n")
            f.write("# string_addr | function_name | params | resolved\n")
            for string_addr, usage_str in usage_entries:
                func_name, params = parse_usage_string(usage_str)
                is_resolved = func_name not in [n for _, n in unresolved]
                f.write("{:016X} {} {} {}\n".format(
                    string_addr, func_name, params,
                    "resolved" if is_resolved else "unresolved"))
        print(LOG_PREFIX + "Results saved to {}".format(str(output_path)))
    else:
        print(LOG_PREFIX + "Results not saved to file")


analyze_lua_api()
