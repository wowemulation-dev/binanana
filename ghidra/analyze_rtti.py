# Analyze MSVC RTTI structures and name vtables/virtual methods.
#
# This script walks the RTTI chain in MSVC binaries (x86 and x64):
#   type_info string (.?AVClassName@@)
#     -> type_info struct (string address - 0x10 on x64, - 0x08 on x86)
#       -> Complete Object Locator (contains reference to type_info)
#         -> vtable[-1] (pointer to COL)
#           -> vtable[0..N] (virtual method pointers)
#
# Uses Ghidra's Listing API to read defined data instead of raw
# memory.getBytes() scanning. This handles Arxan-protected binaries
# where .data section bytes are zeroed on disk but Ghidra's analyzers
# have already identified strings and structures at the data-type level.
#
# String detection covers multiple data type representations:
#   - "string" / "TerminatedCString" (Ghidra's string analyzers)
#   - "char[N]" arrays (created by Ghidra's RTTI analyzer for
#     TypeDescriptor name fields)
#
# For COL and vtable resolution, the script uses Ghidra's reference
# manager to follow xrefs. If the RTTI analyzer has already created
# these structures, references will exist. If raw bytes are zeroed
# and no references exist, the script outputs RTTI strings only.
#
# Output: Names vtables, COLs, and virtual methods in the Ghidra
# database. Optionally exports results to a .sym file.
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_rtti.py ["/path/to/output.txt"]
#
# @category binanana

from ghidra.program.model.symbol import SourceType

LOG_PREFIX = "[binanana] "

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()
refManager = currentProgram.getReferenceManager()

# Image base for RVA calculations
IMAGE_BASE = currentProgram.getImageBase().getOffset()

# Architecture detection
POINTER_SIZE = currentProgram.getDefaultPointerSize()
IS_64BIT = POINTER_SIZE == 8


def get_section_block(name):
    """Find a memory block by section name."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return block
    return None


def get_data_section_blocks():
    """Get .rdata and .data memory blocks."""
    blocks = []
    for name in [".rdata", ".data"]:
        block = get_section_block(name)
        if block is not None:
            blocks.append(block)
    return blocks


def get_text_range():
    """Find the .text section boundaries."""
    block = get_section_block(".text")
    if block is None:
        return None, None
    return (block.getStart().getOffset(), block.getEnd().getOffset())


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

    # Standard string types: getValue() works directly
    if "string" in dt_name:
        try:
            val = data.getValue()
            return str(val) if val is not None else None
        except Exception:
            return None

    # char[N] arrays created by Ghidra's RTTI analyzer
    if dt_name.startswith("char["):
        return read_char_array(data)

    # Structures (e.g. TypeDescriptor): check components for char[N] fields
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


def find_rtti_strings():
    """Find all .?AV/.?AU type_info name strings using Ghidra's Listing API.

    Iterates over defined data in .rdata and .data sections, checking for
    RTTI mangled name patterns. Handles multiple data representations:
      - Standalone string data items (Arxan-protected binaries where
        Ghidra's auto-analyzer identified strings)
      - TypeDescriptor structures with char[N] name components (normal
        binaries where Ghidra's RTTI analyzer created full structures)
    """
    blocks = get_data_section_blocks()
    if not blocks:
        print(LOG_PREFIX + "ERROR: no data sections found")
        return []

    entries = []
    seen_addrs = set()

    for block in blocks:
        sec_name = block.getName()
        sec_start = block.getStart()
        sec_end = block.getEnd()
        print(LOG_PREFIX + "Scanning {} for RTTI strings ({:016X} - {:016X})...".format(
            sec_name, sec_start.getOffset(), sec_end.getOffset()))
        sec_count = 0

        data_iter = listing.getDefinedData(sec_start, True)
        while data_iter.hasNext():
            monitor.checkCanceled()

            data = data_iter.next()
            if data.getAddress().compareTo(sec_end) > 0:
                break

            value = get_string_value(data)
            if not value:
                continue

            if (value.startswith(".?AV") or value.startswith(".?AU")) and value.endswith("@@"):
                # For TypeDescriptor structures, the type_info base IS the
                # data address. For standalone strings, back up by the header.
                dt_name = data.getDataType().getName() if data.getDataType() else ""
                if "TypeDescriptor" in dt_name or "type_info" in dt_name.lower():
                    type_info_addr = data.getAddress().getOffset()
                    # The string component is at +0x10 (x64) or +0x08 (x86)
                    string_addr = type_info_addr + (0x10 if IS_64BIT else 0x08)
                else:
                    string_addr = data.getAddress().getOffset()
                    type_info_addr = string_addr - (0x10 if IS_64BIT else 0x08)

                if type_info_addr not in seen_addrs:
                    seen_addrs.add(type_info_addr)
                    entries.append((type_info_addr, string_addr, value))
                    sec_count += 1

        print(LOG_PREFIX + "  {} RTTI strings in {}".format(sec_count, sec_name))

    return entries


def demangle_rtti_name(mangled):
    """Convert .?AVClassName@Namespace@@ to Namespace::ClassName."""
    name = mangled
    if name.startswith(".?AV"):
        name = name[4:]
    elif name.startswith(".?AU"):
        name = name[4:]
    if name.endswith("@@"):
        name = name[:-2]

    # Split on @ and reverse (MSVC stores inner-to-outer)
    parts = [p for p in name.split("@") if p]
    parts.reverse()
    return "::".join(parts)


def find_col_for_type_info(type_info_addr):
    """Find a COL that references this type_info using Ghidra's reference manager.

    In MSVC RTTI, the COL contains a reference to the type_info:
      x64: RVA at offset +0x0C, signature = 1
      x86: absolute pointer at offset +0x0C, signature = 0

    Ghidra's RTTI analyzer may have created these references. We check xrefs
    to the type_info address and verify COL structure layout.

    Returns the COL address, or None if not found.
    """
    ghidra_ti_addr = addressSpace.getAddress(type_info_addr)
    expected_sig = 1 if IS_64BIT else 0

    # Check references TO this type_info address
    refs = refManager.getReferencesTo(ghidra_ti_addr)
    for ref in refs:
        monitor.checkCanceled()
        from_addr = ref.getFromAddress().getOffset()

        # The type_info reference is at COL +0x0C on both x86 and x64
        candidate_col = from_addr - 0x0C

        col_ghidra_addr = addressSpace.getAddress(candidate_col)
        col_data = listing.getDataAt(col_ghidra_addr)

        # Try reading the signature from raw bytes
        try:
            buf = bytearray(4)
            memory.getBytes(col_ghidra_addr, buf)
            sig = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]
            if sig == expected_sig:
                return candidate_col
        except Exception:
            pass

        # If raw bytes are zeroed, check if Ghidra has a defined structure
        if col_data is not None:
            dt = col_data.getDataType()
            if dt is not None:
                dt_name = dt.getName()
                if "Locator" in dt_name or "RTTI" in dt_name or "COL" in dt_name:
                    return candidate_col

    return None


def read_pointer_at(addr_offset):
    """Read a pointer value at the given address.

    Handles three cases:
      1. Standalone pointer data: data.getValue() works directly
      2. Component inside a pointer array (e.g. pointer[6]): use
         listing.getDataContaining() and index into the component
      3. Fall back to raw bytes if no defined data exists
    Returns the target address as int, or None.
    """
    ghidra_addr = addressSpace.getAddress(addr_offset)

    # Try 1: exact data at this address
    data = listing.getDataAt(ghidra_addr)
    if data is not None:
        try:
            value = data.getValue()
            if value is not None:
                return value.getOffset()
        except Exception:
            pass
        # If it's an array, get the first component
        if data.getNumComponents() > 0:
            comp = data.getComponent(0)
            if comp is not None:
                try:
                    value = comp.getValue()
                    if value is not None:
                        return value.getOffset()
                except Exception:
                    pass

    # Try 2: this address is inside a larger data item (pointer array)
    data = listing.getDataContaining(ghidra_addr)
    if data is not None and data.getNumComponents() > 0:
        # Calculate which component index this address corresponds to
        base = data.getAddress().getOffset()
        offset = addr_offset - base
        if POINTER_SIZE > 0 and offset % POINTER_SIZE == 0:
            comp_idx = offset // POINTER_SIZE
            if comp_idx < data.getNumComponents():
                comp = data.getComponent(comp_idx)
                if comp is not None:
                    try:
                        value = comp.getValue()
                        if value is not None:
                            return value.getOffset()
                    except Exception:
                        pass

    # Try 3: raw bytes (unreliable in PyGhidra but try anyway)
    try:
        buf = bytearray(POINTER_SIZE)
        memory.getBytes(ghidra_addr, buf)
        result = 0
        for i in range(POINTER_SIZE - 1, -1, -1):
            result = (result << 8) | buf[i]
        if result != 0:
            return result
    except Exception:
        pass

    return None


def find_vtable_for_col(col_addr):
    """Find vtable that has COL pointer at vtable[-1] using xrefs.

    In MSVC, vtable[-1] holds the address of the COL. Ghidra's RTTI
    analyzer creates a reference from vtable[-1] to the COL.

    Returns the vtable address (vtable[0]), or None if not found.
    """
    text_start, text_end = get_text_range()
    if text_start is None or text_end is None:
        return None

    ghidra_col_addr = addressSpace.getAddress(col_addr)

    refs = refManager.getReferencesTo(ghidra_col_addr)
    for ref in refs:
        monitor.checkCanceled()
        from_addr = ref.getFromAddress().getOffset()

        # vtable[-1] points to COL, so vtable[0] is at from_addr + ptr_size
        vtable_candidate = from_addr + POINTER_SIZE

        # Verify vtable[0] points into .text
        target = read_pointer_at(vtable_candidate)
        if target is not None and text_start <= target <= text_end:
            return vtable_candidate

    return None


def count_vtable_entries(vtable_addr):
    """Count virtual method pointers in vtable.

    Walks forward from vtable[0], checking each pointer-sized entry
    to see if it points into .text.
    """
    text_start, text_end = get_text_range()
    if text_start is None or text_end is None:
        return 0

    count = 0
    addr = vtable_addr
    while count < 500:  # Safety limit
        entry_value = read_pointer_at(addr)
        if entry_value is None:
            break
        if text_start <= entry_value <= text_end:
            count += 1
            addr += POINTER_SIZE
        else:
            break

    return count


def get_vtable_entry(vtable_addr, index):
    """Read a single vtable entry at the given index.

    Returns the target address, or None if unreadable.
    """
    return read_pointer_at(vtable_addr + index * POINTER_SIZE)


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


def analyze_rtti():
    """Main analysis: find RTTI entries, trace COLs via xrefs, name vtables."""
    print(LOG_PREFIX + "Scanning for RTTI type_info strings...")
    rtti_entries = find_rtti_strings()
    print(LOG_PREFIX + "Found {} RTTI entries".format(len(rtti_entries)))

    if not rtti_entries:
        print(LOG_PREFIX + "No RTTI entries found, nothing to do")
        return

    results = []
    col_found = 0
    vtable_found = 0

    for type_info_addr, string_addr, mangled in rtti_entries:
        monitor.checkCanceled()

        class_name = demangle_rtti_name(mangled)
        safe_name = class_name.replace("::", "__").replace("<", "_").replace(">", "_")
        safe_name = safe_name.replace(",", "_").replace(" ", "")
        safe_name = safe_name.replace("*", "ptr").replace("&", "ref")

        # Name the type_info
        name_symbol(type_info_addr, "typeinfo__" + safe_name)

        # Find COL via xrefs from type_info
        col_addr = find_col_for_type_info(type_info_addr)
        if col_addr is not None:
            col_found += 1
            name_symbol(col_addr, "col__" + safe_name)

        # Find vtable via xrefs from COL
        vtable_addr = None
        vfunc_count = 0
        if col_addr is not None:
            vtable_addr = find_vtable_for_col(col_addr)
            if vtable_addr is not None:
                vtable_found += 1
                name_symbol(vtable_addr, "vtable__" + safe_name)

                # Count and name virtual methods
                vfunc_count = count_vtable_entries(vtable_addr)
                for i in range(vfunc_count):
                    vfunc_addr = get_vtable_entry(vtable_addr, i)
                    if vfunc_addr is not None:
                        vfunc_name = "{}__vfunc{:02d}".format(safe_name, i)
                        name_symbol(vfunc_addr, vfunc_name, is_function=True)

        results.append({
            "class": class_name,
            "type_info": type_info_addr,
            "col": col_addr,
            "vtable": vtable_addr,
            "vfunc_count": vfunc_count,
        })

    print(LOG_PREFIX + "")
    print(LOG_PREFIX + "Results:")
    print(LOG_PREFIX + "  RTTI entries: {}".format(len(rtti_entries)))
    print(LOG_PREFIX + "  COLs resolved: {}".format(col_found))
    print(LOG_PREFIX + "  Vtables resolved: {}".format(vtable_found))
    print(LOG_PREFIX + "  Total virtual methods named: {}".format(
        sum(r["vfunc_count"] for r in results)))

    if col_found == 0:
        print(LOG_PREFIX + "")
        print(LOG_PREFIX + "NOTE: No COLs resolved. If this binary has Arxan protection,")
        print(LOG_PREFIX + "the .data section bytes may be zeroed and COL/vtable structures")
        print(LOG_PREFIX + "are not recoverable from the static PE. The RTTI string entries")
        print(LOG_PREFIX + "above are still useful for cross-referencing with other tools.")

    # Export results to file
    # In headless mode: use script arg; in GUI mode: prompt user
    output_path = None
    headless_args = getScriptArgs()
    if headless_args:
        output_path = headless_args[0]
    else:
        try:
            out_file = askFile("Save RTTI analysis results? (Cancel to skip)", "Save")
            output_path = out_file.absolutePath
        except Exception:
            pass

    if output_path:
        with open(str(output_path), "w") as f:
            f.write("# RTTI Analysis Results\n")
            f.write("# class_name | type_info | col | vtable | vfunc_count\n")
            for r in results:
                f.write("{} {:016X} {:016X} {:016X} {}\n".format(
                    r["class"], r["type_info"],
                    r["col"] if r["col"] else 0,
                    r["vtable"] if r["vtable"] else 0,
                    r["vfunc_count"]))
        print(LOG_PREFIX + "Results saved to {}".format(output_path))
    else:
        print(LOG_PREFIX + "Results not saved to file")


analyze_rtti()
