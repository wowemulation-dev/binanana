# Structural Lua registration table scanner.
#
# Scans .rdata and .data sections for luaL_Reg-style registration
# tables: contiguous arrays of {const char* name, lua_CFunction func}
# pointer pairs where the first pointer targets .rdata (string) and
# the second targets .text (function).
#
# Uses Ghidra's Listing API to read defined data items instead of
# raw memory.getBytes(), which returns zeroed bytes for Arxan-
# protected binaries.
#
# Ghidra parity for BN MCP's discover_lua_tables tool.
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_lua_tables.py ["/path/to/output.txt"]
#
# @category binanana

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType

LOG_PREFIX = "[binanana] "

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()

POINTER_SIZE = currentProgram.getDefaultPointerSize()
IS_64BIT = POINTER_SIZE == 8
ENTRY_SIZE = POINTER_SIZE * 2


def get_section_range(name):
    """Find a section's start and end addresses."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return (block.getStart().getOffset(),
                    block.getEnd().getOffset() + 1)
    return None, None


def get_string_value_at(addr):
    """Get string value at an address using the Listing API."""
    ghidra_addr = addressSpace.getAddress(addr)
    data = listing.getDataAt(ghidra_addr)
    if data is None:
        data = listing.getDataContaining(ghidra_addr)
    if data is None:
        return None
    try:
        val = str(data.getValue())
        return val if val else None
    except Exception:
        return None


def is_valid_lua_name(s):
    """Check if a string is a valid Lua function/method name."""
    if not s or len(s) > 100:
        return False
    if not (s[0].isalpha() or s[0] == '_'):
        return False
    return all(c.isalnum() or c == '_' for c in s)


def name_function_at(addr, name):
    """Create or rename a function at the given address."""
    ghidra_addr = addressSpace.getAddress(addr)
    func = functionManager.getFunctionAt(ghidra_addr)

    if func is None:
        try:
            func = functionManager.createFunction(
                name, ghidra_addr, None, SourceType.ANALYSIS)
        except Exception:
            return False
    elif func.getSymbol() and func.getSymbol().getSource() == SourceType.DEFAULT:
        func.setName(name, SourceType.ANALYSIS)
    else:
        return False  # Already has a user-defined name

    return func is not None


def infer_class_name(table_entries):
    """Try to infer a class name from the Lua method names in a table.

    WoW Lua tables often use patterns like:
    - CSimpleFontString methods: GetText, SetText, etc.
    - Global functions: GetSpellInfo, UnitName, etc.

    We look for the most common prefix or try RTTI nearby.
    """
    # For now, return None. The naming will use Script_ prefix.
    # Future: scan backwards from table_addr for RTTI type_info.
    return None


def scan_lua_tables():
    """Scan .rdata and .data for luaL_Reg-style pointer pair arrays.

    Uses Listing API to iterate defined data items. Looks for consecutive
    pairs of (pointer-to-data-section, pointer-to-.text) aligned on
    ENTRY_SIZE boundaries.
    """
    MIN_ENTRIES = 3

    text_start, text_end = get_section_range(".text")
    rdata_start, rdata_end = get_section_range(".rdata")
    if text_start is None or rdata_start is None:
        print(LOG_PREFIX + "ERROR: Required sections not found")
        return []

    data_start, data_end = get_section_range(".data")

    all_tables = []

    for block in memory.getBlocks():
        if block.getName() not in (".rdata", ".data"):
            continue

        sec_name = block.getName()
        print(LOG_PREFIX + "Scanning {} for luaL_Reg tables...".format(sec_name))

        # Collect all pointer-type data items in this block
        pointers = []  # list of (addr_offset, value_offset, is_pointer_type)
        data_iter = listing.getDefinedData(block.getStart(), True)
        while data_iter.hasNext():
            monitor.checkCanceled()
            data = data_iter.next()
            if data.getAddress().compareTo(block.getEnd()) > 0:
                break

            dt = data.getDataType()
            if not isinstance(dt, PointerDataType):
                continue

            val = data.getValue()
            if val is None:
                continue

            pointers.append((data.getAddress().getOffset(), val.getOffset()))

        # Look for consecutive pointer pairs forming luaL_Reg entries.
        # Each entry is two adjacent pointers: name_ptr then func_ptr.
        # Entries are contiguous (no gaps between pairs).
        i = 0
        current_table_start = None
        current_entries = []

        while i < len(pointers) - 1:
            monitor.checkCanceled()
            name_addr, name_ptr = pointers[i]
            func_addr, func_ptr = pointers[i + 1]

            # Check pair adjacency: func pointer immediately follows name pointer
            if func_addr != name_addr + POINTER_SIZE:
                # Not a valid pair - finalize current table
                if len(current_entries) >= MIN_ENTRIES:
                    all_tables.append((current_table_start, sec_name,
                                       list(current_entries)))
                current_table_start = None
                current_entries = []
                i += 1
                continue

            # Check if name_ptr targets a data section and func_ptr targets .text
            name_in_rdata = rdata_start <= name_ptr < rdata_end
            name_in_data = data_start and data_start <= name_ptr < data_end
            func_in_text = text_start <= func_ptr < text_end

            if (name_in_rdata or name_in_data) and func_in_text:
                # Check contiguity with previous entry
                if current_table_start is not None:
                    expected_addr = (current_entries[-1][0] +
                                     ENTRY_SIZE)  # name_addr of prev + entry size
                    if name_addr != expected_addr:
                        # Gap - finalize previous table, start new
                        if len(current_entries) >= MIN_ENTRIES:
                            all_tables.append((current_table_start, sec_name,
                                               list(current_entries)))
                        current_table_start = name_addr
                        current_entries = [(name_addr, name_ptr, func_ptr)]
                        i += 2
                        continue

                if current_table_start is None:
                    current_table_start = name_addr
                current_entries.append((name_addr, name_ptr, func_ptr))
                i += 2
            else:
                # Not a valid pair
                if len(current_entries) >= MIN_ENTRIES:
                    all_tables.append((current_table_start, sec_name,
                                       list(current_entries)))
                current_table_start = None
                current_entries = []
                i += 1

        # Handle table at end of section
        if len(current_entries) >= MIN_ENTRIES:
            all_tables.append((current_table_start, sec_name,
                               list(current_entries)))

    return all_tables


def analyze_lua_tables():
    """Main analysis: scan data sections for luaL_Reg-style tables."""
    all_tables = scan_lua_tables()

    # Validate tables: at least 80% of entries must have valid Lua names
    validated_tables = []
    total_entries = 0
    total_named = 0

    for table_addr, sec_name, entries in all_tables:
        valid_count = 0
        resolved_entries = []

        for entry_addr, name_ptr, func_ptr in entries:
            lua_name = get_string_value_at(name_ptr)
            if lua_name and is_valid_lua_name(lua_name):
                valid_count += 1
                resolved_entries.append((name_ptr, func_ptr, lua_name))
            else:
                resolved_entries.append((name_ptr, func_ptr, None))

        validity_ratio = valid_count / len(entries) if entries else 0
        if validity_ratio >= 0.80:
            validated_tables.append({
                "table_addr": table_addr,
                "section": sec_name,
                "entry_count": len(entries),
                "valid_names": valid_count,
                "entries": resolved_entries,
            })
            total_entries += len(entries)

    # Name functions
    for table in validated_tables:
        class_name = infer_class_name(table["entries"])
        prefix = class_name + "__Script_" if class_name else "Script_"

        for name_ptr, func_ptr, lua_name in table["entries"]:
            if lua_name:
                func_name = prefix + lua_name
                if name_function_at(func_ptr, func_name):
                    total_named += 1

    print(LOG_PREFIX + "")
    print(LOG_PREFIX + "Results:")
    print(LOG_PREFIX + "  Raw table candidates: {}".format(len(all_tables)))
    print(LOG_PREFIX + "  Validated tables (>=80% valid names): {}".format(
        len(validated_tables)))
    print(LOG_PREFIX + "  Total entries: {}".format(total_entries))
    print(LOG_PREFIX + "  Functions named: {}".format(total_named))

    # Export results
    output_path = None
    headless_args = getScriptArgs()
    if headless_args:
        output_path = headless_args[0]
    else:
        try:
            out_file = askFile(
                "Save Lua table scan results? (Cancel to skip)", "Save")
            output_path = out_file.absolutePath
        except Exception:
            pass

    if output_path:
        with open(str(output_path), "w") as f:
            f.write("# Lua Registration Table Analysis\n")
            f.write("# table_addr | entry_count | valid_names | section\n")
            f.write("# entries: name_addr func_addr lua_name\n\n")

            for table in validated_tables:
                f.write("TABLE {:016X} {} {} {}\n".format(
                    table["table_addr"], table["entry_count"],
                    table["valid_names"], table["section"]))
                for name_ptr, func_ptr, lua_name in table["entries"]:
                    display_name = lua_name or "(invalid)"
                    f.write("  {:016X} {:016X} {}\n".format(
                        name_ptr, func_ptr, display_name))
                f.write("\n")

        print(LOG_PREFIX + "Results saved to {}".format(str(output_path)))
    else:
        print(LOG_PREFIX + "Results not saved to file")


analyze_lua_tables()
