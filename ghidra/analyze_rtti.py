# Analyze MSVC x64 RTTI structures and name vtables/virtual methods.
#
# This script walks the RTTI chain in 64-bit MSVC binaries:
#   type_info string (.?AVClassName@@)
#     -> type_info struct (string address - 0x10)
#       -> Complete Object Locator (contains RVA to type_info)
#         -> vtable[-1] (pointer to COL)
#           -> vtable[0..N] (virtual method pointers)
#
# Unlike BN's xref-based approach, this script directly scans .rdata
# for COL structures by matching type_info RVAs as raw bytes. This
# bypasses the broken xref resolution caused by import table
# obfuscation.
#
# Output: Names vtables, COLs, and virtual methods in the Ghidra
# database. Optionally exports results to a .sym file.
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_rtti.py ["/path/to/output.txt"]
#
# @category binanana

import struct
from ghidra.program.model.symbol import SourceType

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()

# Image base for RVA calculations
IMAGE_BASE = currentProgram.getImageBase().getOffset()


def read_bytes(addr, size):
    """Read raw bytes from the binary at an absolute address."""
    buf = bytearray(size)
    ghidra_addr = addressSpace.getAddress(addr)
    memory.getBytes(ghidra_addr, buf)
    return bytes(buf)


def read_uint32(addr):
    """Read a 32-bit unsigned integer (little-endian)."""
    return struct.unpack("<I", read_bytes(addr, 4))[0]


def read_uint64(addr):
    """Read a 64-bit unsigned integer (little-endian)."""
    return struct.unpack("<Q", read_bytes(addr, 8))[0]


def get_rdata_range():
    """Find the .rdata section boundaries."""
    for block in memory.getBlocks():
        if block.getName() == ".rdata":
            start = block.getStart().getOffset()
            end = block.getEnd().getOffset()
            return start, end
    return None, None


def get_text_range():
    """Find the .text section boundaries."""
    for block in memory.getBlocks():
        if block.getName() == ".text":
            start = block.getStart().getOffset()
            end = block.getEnd().getOffset()
            return start, end
    return None, None


def find_rtti_strings():
    """Find all .?AV type_info name strings in .rdata."""
    rdata_start, rdata_end = get_rdata_range()
    if rdata_start is None:
        print("ERROR: .rdata section not found")
        return []

    entries = []
    addr = rdata_start

    # Search for ".?AV" prefix (MSVC RTTI class type_info)
    pattern = b".?AV"
    while addr < rdata_end - 4:
        monitor.checkCanceled()
        try:
            data = read_bytes(addr, 4)
            if data == pattern:
                # Read the full mangled name (null-terminated)
                name_bytes = bytearray()
                i = 0
                while True:
                    b = read_bytes(addr + i, 1)[0]
                    if b == 0:
                        break
                    name_bytes.append(b)
                    i += 1
                    if i > 512:
                        break

                mangled = name_bytes.decode("ascii", errors="replace")
                # type_info struct is at string_addr - 0x10
                # (vfptr at +0x00, _M_d_spare at +0x08, _M_d_name at +0x10)
                type_info_addr = addr - 0x10
                entries.append((type_info_addr, addr, mangled))

            addr += 1
        except Exception:
            addr += 1

    return entries


def demangle_rtti_name(mangled):
    """Convert .?AVClassName@Namespace@@ to Namespace::ClassName."""
    # Strip .?AV prefix and @@ suffix
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


def find_col_for_type_info(type_info_addr, rdata_start, rdata_end):
    """Scan .rdata for a COL that references this type_info via RVA."""
    type_info_rva = type_info_addr - IMAGE_BASE
    rva_bytes = struct.pack("<I", type_info_rva)

    # COL structure (x64 MSVC):
    #   +0x00: uint32_t signature (1 for x64)
    #   +0x04: uint32_t offset
    #   +0x08: uint32_t cdOffset
    #   +0x0C: uint32_t typeDescriptorRVA  <-- we search for this
    #   +0x10: uint32_t classHierarchyRVA
    #   +0x14: uint32_t selfRVA

    # Scan for the RVA bytes at offset +0x0C in potential COL structures
    addr = rdata_start
    while addr < rdata_end - 0x18:
        try:
            data = read_bytes(addr + 0x0C, 4)
            if data == rva_bytes:
                # Verify signature == 1 (x64)
                sig = read_uint32(addr)
                if sig == 1:
                    # Verify selfRVA points back to this COL
                    self_rva = read_uint32(addr + 0x14)
                    if self_rva == addr - IMAGE_BASE:
                        return addr
            addr += 4  # COLs are aligned
        except Exception:
            addr += 4

    return None


def find_vtable_for_col(col_addr, rdata_start, rdata_end):
    """Find vtable that has COL pointer at vtable[-1]."""
    col_rva = col_addr - IMAGE_BASE

    # In x64 MSVC, vtable[-1] stores an RVA to the COL (as part of the
    # meta-info pointer). We scan for a uint32 RVA or uint64 pointer.
    # Actually, in x64 MSVC, vtable[-1] is the address of the COL stored
    # as a full 64-bit pointer.
    col_ptr_bytes = struct.pack("<Q", col_addr)

    addr = rdata_start
    while addr < rdata_end - 8:
        try:
            data = read_bytes(addr, 8)
            if data == col_ptr_bytes:
                # vtable starts at addr + 8
                vtable_addr = addr + 8
                # Verify first entry points to .text
                first_entry = read_uint64(vtable_addr)
                text_start, text_end = get_text_range()
                if text_start and text_start <= first_entry <= text_end:
                    return vtable_addr
            addr += 8
        except Exception:
            addr += 8

    return None


def count_vtable_entries(vtable_addr):
    """Count virtual method pointers in vtable."""
    text_start, text_end = get_text_range()
    if text_start is None:
        return 0

    count = 0
    addr = vtable_addr
    while True:
        try:
            entry = read_uint64(addr)
            if text_start <= entry <= text_end:
                count += 1
                addr += 8
            else:
                break
        except Exception:
            break

        if count > 500:  # Safety limit
            break

    return count


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
            if func.getSource() == SourceType.DEFAULT:
                func.setName(name, SourceType.ANALYSIS)
    else:
        existing = symbolTable.getPrimarySymbol(ghidra_addr)
        if existing is None or existing.getSource() == SourceType.DEFAULT:
            symbolTable.createLabel(ghidra_addr, name, SourceType.ANALYSIS)


def analyze_rtti():
    """Main analysis: find RTTI entries, trace COLs, name vtables."""
    print("Scanning for RTTI type_info strings...")
    rtti_entries = find_rtti_strings()
    print("Found {} RTTI entries".format(len(rtti_entries)))

    rdata_start, rdata_end = get_rdata_range()
    if rdata_start is None:
        print("ERROR: .rdata not found")
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

        # Find COL
        col_addr = find_col_for_type_info(type_info_addr, rdata_start, rdata_end)
        if col_addr is None:
            continue
        col_found += 1
        name_symbol(col_addr, "col__" + safe_name)

        # Find vtable
        vtable_addr = find_vtable_for_col(col_addr, rdata_start, rdata_end)
        if vtable_addr is None:
            continue
        vtable_found += 1
        name_symbol(vtable_addr, "vtable__" + safe_name)

        # Count and name virtual methods
        vfunc_count = count_vtable_entries(vtable_addr)
        for i in range(vfunc_count):
            vfunc_addr = read_uint64(vtable_addr + i * 8)
            vfunc_name = "{}__vfunc{:02d}".format(safe_name, i)
            name_symbol(vfunc_addr, vfunc_name, is_function=True)

        results.append({
            "class": class_name,
            "type_info": type_info_addr,
            "col": col_addr,
            "vtable": vtable_addr,
            "vfunc_count": vfunc_count,
        })

    print("\nResults:")
    print("  RTTI entries: {}".format(len(rtti_entries)))
    print("  COLs resolved: {}".format(col_found))
    print("  Vtables resolved: {}".format(vtable_found))
    print("  Total virtual methods named: {}".format(
        sum(r["vfunc_count"] for r in results)))

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
        print("Results saved to {}".format(output_path))
    else:
        print("Results not saved to file")


analyze_rtti()
