# Analyze Lua API Usage: strings and resolve them to native functions.
#
# WoW Classic embeds "Usage: FunctionName(params)" strings for every
# Lua-exposed function. These strings sit in .rdata adjacent to the
# function pointer table entries.
#
# This script:
# 1. Finds all "Usage: " strings in .rdata
# 2. Scans .text for LEA instructions that reference each string
# 3. Traces from the LEA to find the associated native function pointer
# 4. Names the native function based on the Lua API name
#
# @category binanana

import re
import struct
from ghidra.program.model.symbol.SourceType import *

memory = currentProgram.getMemory()
functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()
listing = currentProgram.getListing()

IMAGE_BASE = currentProgram.getImageBase().getOffset()


def read_bytes(addr, size):
    """Read raw bytes from the binary at an absolute address."""
    buf = bytearray(size)
    ghidra_addr = addressSpace.getAddress(addr)
    memory.getBytes(ghidra_addr, buf)
    return bytes(buf)


def read_uint64(addr):
    """Read a 64-bit unsigned integer (little-endian)."""
    return struct.unpack("<Q", read_bytes(addr, 8))[0]


def get_section_range(name):
    """Find a section's start and end addresses."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return (block.getStart().getOffset(),
                    block.getEnd().getOffset())
    return None, None


def find_usage_strings():
    """Find all 'Usage: ' strings in .rdata."""
    rdata_start, rdata_end = get_section_range(".rdata")
    if rdata_start is None:
        print("ERROR: .rdata section not found")
        return []

    entries = []
    pattern = b"Usage: "
    addr = rdata_start

    while addr < rdata_end - len(pattern):
        monitor.checkCanceled()
        try:
            data = read_bytes(addr, len(pattern))
            if data == pattern:
                # Read the full string
                string_bytes = bytearray()
                i = 0
                while True:
                    b = read_bytes(addr + i, 1)[0]
                    if b == 0:
                        break
                    string_bytes.append(b)
                    i += 1
                    if i > 512:
                        break

                usage_str = string_bytes.decode("ascii", errors="replace")
                entries.append((addr, usage_str))
                addr += i + 1
            else:
                addr += 1
        except Exception:
            addr += 1

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
    # For a RIP-relative LEA, we need:
    #   effective_addr = lea_addr + 7 + disp32 (typical LEA is 7 bytes)
    # But instruction length varies. Scan for the displacement value.

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
        if func.getSource() == SourceType.DEFAULT:
            func.setName(name, SourceType.ANALYSIS)
            return True
    else:
        # Try to find the containing function
        func = functionManager.getFunctionContaining(ghidra_addr)
        if func and func.getSource() == SourceType.DEFAULT:
            func.setName(name, SourceType.ANALYSIS)
            return True

    return False


def analyze_lua_api():
    """Main analysis: find Usage: strings and resolve to native functions."""
    print("Scanning for Lua API Usage: strings...")
    usage_entries = find_usage_strings()
    print("Found {} Usage: strings".format(len(usage_entries)))

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
                    if containing.getSource() == SourceType.DEFAULT:
                        containing.setName(safe_name, SourceType.ANALYSIS)
                        containing.setComment(
                            "Lua API: {}".format(usage_str))
                        resolved += 1
                        break
        else:
            unresolved.append((string_addr, func_name))

    print("\nResults:")
    print("  Usage: strings found: {}".format(len(usage_entries)))
    print("  Functions resolved: {}".format(resolved))
    print("  Unresolved: {}".format(len(unresolved)))

    if unresolved:
        print("\nFirst 20 unresolved:")
        for addr, name in unresolved[:20]:
            print("  {:016X} {}".format(addr, name))

    # Optionally export
    try:
        out_file = askFile("Save Lua API results? (Cancel to skip)", "Save")
        with open(out_file.absolutePath, "w") as f:
            f.write("# Lua API Analysis Results\n")
            f.write("# string_addr | function_name | params | resolved\n")
            for string_addr, usage_str in usage_entries:
                func_name, params = parse_usage_string(usage_str)
                is_resolved = func_name not in [n for _, n in unresolved]
                f.write("{:016X} {} {} {}\n".format(
                    string_addr, func_name, params,
                    "resolved" if is_resolved else "unresolved"))
        print("Results saved to {}".format(out_file.absolutePath))
    except Exception:
        print("Results not saved to file (cancelled)")


analyze_lua_api()
