# Heuristic vtable scanner for MSVC binaries.
#
# Scans .rdata and .data sections for vtable-like structures:
# contiguous runs of pointers that target the .text section.
# For each candidate vtable, checks vtable[-1] for a MSVC RTTI
# Complete Object Locator (COL) pointer and resolves the class
# name if present.
#
# Uses Ghidra's Listing API to read defined data items instead of
# raw memory.getBytes(), which returns zeroed bytes for Arxan-
# protected binaries.
#
# Ghidra parity for BN MCP's scan_vtables tool.
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_vtables.py ["/path/to/output.txt"]
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

IMAGE_BASE = currentProgram.getImageBase().getOffset()

# Detect architecture
POINTER_SIZE = currentProgram.getDefaultPointerSize()
IS_64BIT = POINTER_SIZE == 8


def get_section_range(name):
    """Find a section's start and end addresses."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return (block.getStart().getOffset(),
                    block.getEnd().getOffset() + 1)
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


def build_type_info_map():
    """Build a map of type_info addr/RVA -> demangled class name.

    Iterates defined string data in .rdata and .data using the Listing
    API, looking for RTTI type descriptor name strings (.?AV* / .?AU*).
    """
    ti_map = {}

    for block in memory.getBlocks():
        if block.getName() not in (".rdata", ".data"):
            continue

        data_iter = listing.getDefinedData(block.getStart(), True)
        while data_iter.hasNext():
            monitor.checkCanceled()
            data = data_iter.next()
            if data.getAddress().compareTo(block.getEnd()) > 0:
                break

            value = get_string_value(data)
            if not value:
                continue
            if not (value.startswith(".?AV") or value.startswith(".?AU")):
                continue
            if not value.endswith("@@"):
                continue

            string_addr = data.getAddress().getOffset()
            # type_info struct starts before the name string
            type_info_addr = string_addr - (0x10 if IS_64BIT else 0x08)

            # Demangle: strip .?AV/.?AU prefix and @@ suffix
            name = value[4:]
            if name.endswith("@@"):
                name = name[:-2]
            parts = [p for p in name.split("@") if p]
            parts.reverse()
            demangled = "::".join(parts)

            if IS_64BIT:
                ti_rva = type_info_addr - IMAGE_BASE
                ti_map[ti_rva] = (demangled, type_info_addr)
            else:
                ti_map[type_info_addr] = (demangled, type_info_addr)

    return ti_map


def try_resolve_col(vtable_addr, ti_map):
    """Check vtable[-1] for a COL pointer and resolve the class name.

    Uses the Listing API to read the pointer at vtable[-1]. If the
    COL address has defined data, reads its fields to find the
    type descriptor reference.
    """
    col_ptr_addr = addressSpace.getAddress(vtable_addr - POINTER_SIZE)
    col_data = listing.getDataAt(col_ptr_addr)
    if col_data is None:
        return None, None

    dt = col_data.getDataType()
    if not isinstance(dt, PointerDataType):
        return None, None

    col_val = col_data.getValue()
    if col_val is None:
        return None, None

    col_candidate = col_val.getOffset()

    # Verify the candidate is in a data section
    rdata_start, rdata_end = get_section_range(".rdata")
    data_start, data_end = get_section_range(".data")

    in_rdata = rdata_start and rdata_start <= col_candidate < rdata_end
    in_data = data_start and data_start <= col_candidate < data_end

    if not (in_rdata or in_data):
        return None, None

    # Read COL fields using Listing API
    # COL is a struct; try to read individual fields as defined data
    try:
        if IS_64BIT:
            # x64 COL: signature=0 at +0x00 (dword), typeDescRVA at +0x0C (dword)
            sig_data = listing.getDataAt(addressSpace.getAddress(col_candidate))
            if sig_data is None:
                return None, None
            sig_val = sig_data.getValue()
            if sig_val is None:
                return None, None
            sig = int(sig_val.longValue()) if hasattr(sig_val, 'longValue') else int(sig_val)
            if sig != 1:
                return None, None

            td_data = listing.getDataAt(addressSpace.getAddress(col_candidate + 0x0C))
            if td_data is None:
                return None, None
            td_val = td_data.getValue()
            if td_val is None:
                return None, None
            if hasattr(td_val, 'longValue'):
                type_desc_rva = int(td_val.longValue())
            else:
                type_desc_rva = int(td_val)

            if type_desc_rva in ti_map:
                class_name, ti_addr = ti_map[type_desc_rva]
                return class_name, ti_addr
        else:
            # x86 COL: signature=0 at +0x00 (dword), typeDescPtr at +0x0C (pointer)
            sig_data = listing.getDataAt(addressSpace.getAddress(col_candidate))
            if sig_data is None:
                return None, None
            sig_val = sig_data.getValue()
            if sig_val is None:
                return None, None
            sig = int(sig_val.longValue()) if hasattr(sig_val, 'longValue') else int(sig_val)
            if sig != 0:
                return None, None

            td_data = listing.getDataAt(addressSpace.getAddress(col_candidate + 0x0C))
            if td_data is None:
                return None, None
            td_val = td_data.getValue()
            if td_val is None:
                return None, None
            # For x86, this is a pointer (absolute address)
            if hasattr(td_val, 'getOffset'):
                type_desc_ptr = td_val.getOffset()
            else:
                if hasattr(td_val, 'longValue'):
                    type_desc_ptr = int(td_val.longValue())
                else:
                    type_desc_ptr = int(td_val)

            if type_desc_ptr in ti_map:
                class_name, ti_addr = ti_map[type_desc_ptr]
                return class_name, ti_addr
    except Exception:
        pass

    return None, None


def name_symbol(addr, name, is_function=False):
    """Create a named symbol at the given address."""
    ghidra_addr = addressSpace.getAddress(addr)

    if is_function:
        func = functionManager.getFunctionAt(ghidra_addr)
        if func is None:
            try:
                functionManager.createFunction(
                    name, ghidra_addr, None, SourceType.ANALYSIS)
            except Exception:
                pass
        else:
            sym = func.getSymbol()
            if sym is not None and sym.getSource() == SourceType.DEFAULT:
                func.setName(name, SourceType.ANALYSIS)
    else:
        existing = symbolTable.getPrimarySymbol(ghidra_addr)
        if existing is None or existing.getSource() == SourceType.DEFAULT:
            symbolTable.createLabel(ghidra_addr, name, SourceType.ANALYSIS)


def scan_vtable_candidates(text_start, text_end):
    """Scan .rdata and .data for contiguous pointer runs into .text.

    Uses Listing API getDefinedData() to iterate pointer-type data items
    and groups consecutive text-targeting pointers into vtable candidates.
    """
    MIN_METHODS = 2
    results = []

    for block in memory.getBlocks():
        if block.getName() not in (".rdata", ".data"):
            continue

        sec_name = block.getName()
        print(LOG_PREFIX + "Scanning {} for vtable candidates...".format(sec_name))

        current_run = []      # list of (entry_addr, pointer_value)
        current_start = None
        last_entry_end = None  # track address continuity

        data_iter = listing.getDefinedData(block.getStart(), True)
        while data_iter.hasNext():
            monitor.checkCanceled()
            data = data_iter.next()
            if data.getAddress().compareTo(block.getEnd()) > 0:
                break

            dt = data.getDataType()
            entry_addr = data.getAddress().getOffset()
            entry_size = data.getLength()

            is_pointer = isinstance(dt, PointerDataType)
            is_contiguous = (last_entry_end is None or
                             entry_addr == last_entry_end)

            if is_pointer and is_contiguous:
                val = data.getValue()  # Returns Address for pointer types
                if val is not None:
                    ptr_offset = val.getOffset()
                    if text_start <= ptr_offset < text_end:
                        if current_start is None:
                            current_start = entry_addr
                        current_run.append((entry_addr, ptr_offset))
                        last_entry_end = entry_addr + entry_size
                        continue

            # Not a text pointer or not contiguous - end current run
            if len(current_run) >= MIN_METHODS:
                results.append((current_start, sec_name, list(current_run)))
            current_run = []
            current_start = None

            # If this entry is a pointer to text, start a new run
            if is_pointer:
                val = data.getValue()
                if val is not None:
                    ptr_offset = val.getOffset()
                    if text_start <= ptr_offset < text_end:
                        current_start = entry_addr
                        current_run.append((entry_addr, ptr_offset))
                        last_entry_end = entry_addr + entry_size
                        continue

            last_entry_end = entry_addr + entry_size

        # Handle run at end of section
        if len(current_run) >= MIN_METHODS:
            results.append((current_start, sec_name, list(current_run)))

    return results


def analyze_vtables():
    """Main analysis: scan data sections for vtable-like pointer arrays."""
    print(LOG_PREFIX + "Building type_info lookup table...")
    ti_map = build_type_info_map()
    print(LOG_PREFIX + "  {} type_info entries indexed".format(len(ti_map)))

    text_start, text_end = get_section_range(".text")
    if text_start is None:
        print(LOG_PREFIX + "ERROR: .text section not found")
        return

    candidates = scan_vtable_candidates(text_start, text_end)
    if not candidates:
        print(LOG_PREFIX + "No vtable candidates found")
        return

    results = []
    total_vfuncs = 0

    for vtable_start, sec_name, run in candidates:
        num_methods = len(run)
        method_addrs = [ptr_val for _, ptr_val in run]

        class_name, ti_addr = try_resolve_col(vtable_start, ti_map)

        results.append({
            "vtable_addr": vtable_start,
            "num_methods": num_methods,
            "class_name": class_name,
            "type_info_addr": ti_addr,
            "section": sec_name,
            "method_addrs": method_addrs,
        })
        total_vfuncs += num_methods

    # Sort: named entries first (alphabetical), then unnamed by address
    named = [r for r in results if r["class_name"]]
    unnamed = [r for r in results if not r["class_name"]]
    named.sort(key=lambda r: r["class_name"])
    unnamed.sort(key=lambda r: r["vtable_addr"])
    results = named + unnamed

    # Name symbols in Ghidra
    named_count = 0
    for r in results:
        if r["class_name"]:
            safe_name = r["class_name"].replace("::", "__")
            safe_name = safe_name.replace("<", "_").replace(">", "_")
            safe_name = safe_name.replace(",", "_").replace(" ", "")
            safe_name = safe_name.replace("*", "ptr").replace("&", "ref")

            name_symbol(r["vtable_addr"], "vtable__" + safe_name)
            for i, method_addr in enumerate(r["method_addrs"]):
                vfunc_name = "{}__vfunc{:02d}".format(safe_name, i)
                name_symbol(method_addr, vfunc_name, is_function=True)

            named_count += 1

    print(LOG_PREFIX + "")
    print(LOG_PREFIX + "Results:")
    print(LOG_PREFIX + "  Vtable candidates: {}".format(len(results)))
    print(LOG_PREFIX + "  With RTTI name: {}".format(named_count))
    print(LOG_PREFIX + "  Without RTTI name: {}".format(len(results) - named_count))
    print(LOG_PREFIX + "  Total virtual methods: {}".format(total_vfuncs))

    # Export results
    output_path = None
    headless_args = getScriptArgs()
    if headless_args:
        output_path = headless_args[0]
    else:
        try:
            out_file = askFile("Save vtable scan results? (Cancel to skip)", "Save")
            output_path = out_file.absolutePath
        except Exception:
            pass

    if output_path:
        with open(str(output_path), "w") as f:
            f.write("# Vtable Scan Results\n")
            f.write("# vtable_addr | num_methods | class_name | type_info_addr | section\n")
            for r in results:
                cn = r["class_name"] or "(unnamed)"
                ti = "{:016X}".format(r["type_info_addr"]) if r["type_info_addr"] else "-"
                f.write("{:016X} {} {} {} {}\n".format(
                    r["vtable_addr"], r["num_methods"], cn, ti, r["section"]))
        print(LOG_PREFIX + "Results saved to {}".format(str(output_path)))
    else:
        print(LOG_PREFIX + "Results not saved to file")


analyze_vtables()
