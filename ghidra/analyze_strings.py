# Extract embedded source file paths and debug strings.
#
# WoW Classic binaries embed full build paths from __FILE__ macros
# in assertion and logging code. This script extracts and categorizes
# them.
#
# Categories extracted:
# - Source file paths (.cpp, .h)
# - ERROR_ enum strings
# - CG*Data update field names
# - JamJSON type names
# - CVar registration strings
# - Assert/debug format strings
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_strings.py ["/path/to/output.txt"]
#
# @category binanana

import struct
from ghidra.program.model.symbol import SourceType

memory = currentProgram.getMemory()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()


def read_bytes(addr, size):
    """Read raw bytes from the binary."""
    buf = bytearray(size)
    ghidra_addr = addressSpace.getAddress(addr)
    memory.getBytes(ghidra_addr, buf)
    return bytes(buf)


def get_section_range(name):
    """Find a section's boundaries."""
    for block in memory.getBlocks():
        if block.getName() == name:
            return (block.getStart().getOffset(),
                    block.getEnd().getOffset())
    return None, None


def read_string_at(addr, max_len=512):
    """Read a null-terminated ASCII string."""
    result = bytearray()
    for i in range(max_len):
        try:
            b = read_bytes(addr + i, 1)[0]
        except Exception:
            break
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            break
        result.append(b)
    return result.decode("ascii", errors="replace") if result else None


def scan_strings(rdata_start, rdata_end, prefix):
    """Find all strings in .rdata starting with the given prefix."""
    results = []
    prefix_bytes = prefix.encode("ascii")
    addr = rdata_start

    while addr < rdata_end - len(prefix_bytes):
        monitor.checkCanceled()
        try:
            data = read_bytes(addr, len(prefix_bytes))
            if data == prefix_bytes:
                full_string = read_string_at(addr)
                if full_string:
                    results.append((addr, full_string))
                    addr += len(full_string) + 1
                    continue
        except Exception:
            pass
        addr += 1

    return results


def analyze_strings():
    """Main analysis: extract and categorize embedded strings."""
    rdata_start, rdata_end = get_section_range(".rdata")
    if rdata_start is None:
        print("ERROR: .rdata section not found")
        return

    print("Scanning .rdata ({:016X} - {:016X}, {:.1f} MB)...".format(
        rdata_start, rdata_end, (rdata_end - rdata_start) / 1024 / 1024))

    # Source file paths
    print("\nScanning for source file paths...")
    # Try common build path prefixes
    prefixes = [
        "D:\\BuildServer\\",
        "d:\\buildserver\\",
        "D:\\buildserver\\",
    ]
    source_paths = []
    for prefix in prefixes:
        source_paths.extend(scan_strings(rdata_start, rdata_end, prefix))
    # Deduplicate
    seen = set()
    unique_paths = []
    for addr, s in source_paths:
        if s not in seen:
            seen.add(s)
            unique_paths.append((addr, s))
    source_paths = unique_paths
    print("  Found {} source file paths".format(len(source_paths)))

    # Categorize by extension
    cpp_files = [(a, s) for a, s in source_paths if s.lower().endswith(".cpp")]
    h_files = [(a, s) for a, s in source_paths if s.lower().endswith(".h")]
    cc_files = [(a, s) for a, s in source_paths if s.lower().endswith(".cc")]
    print("    .cpp: {}, .h: {}, .cc: {}".format(
        len(cpp_files), len(h_files), len(cc_files)))

    # CG*Data update field strings
    print("\nScanning for update field names...")
    update_fields = []
    for prefix in ["CGUnitData", "CGPlayerData", "CGActivePlayerData",
                    "CGItemData", "CGGameObjectData", "CGObjectData",
                    "CGContainerData", "CGCorpseData", "CGDynamicObjectData",
                    "CGAreaTriggerData"]:
        update_fields.extend(scan_strings(rdata_start, rdata_end, prefix))
    print("  Found {} update field names".format(len(update_fields)))

    # JamJSON type names
    print("\nScanning for JamJSON types...")
    jam_types = scan_strings(rdata_start, rdata_end, "JamJSON")
    print("  Found {} JamJSON types".format(len(jam_types)))

    # CVar strings (look for "CVar" references)
    print("\nScanning for CVar references...")
    cvar_refs = scan_strings(rdata_start, rdata_end, "CVar ")
    print("  Found {} CVar references".format(len(cvar_refs)))

    # Summary
    print("\n=== Summary ===")
    print("Source file paths: {}".format(len(source_paths)))
    print("Update field names: {}".format(len(update_fields)))
    print("JamJSON types: {}".format(len(jam_types)))
    print("CVar references: {}".format(len(cvar_refs)))

    # Export results to file
    output_path = None
    headless_args = getScriptArgs()
    if headless_args:
        output_path = headless_args[0]
    else:
        try:
            out_file = askFile("Save string analysis? (Cancel to skip)", "Save")
            output_path = out_file.absolutePath
        except Exception:
            pass

    if output_path:
        with open(str(output_path), "w") as f:
            f.write("# String Analysis Results\n\n")

            f.write("## Source File Paths ({})\n\n".format(len(source_paths)))
            for addr, s in sorted(source_paths, key=lambda x: x[1]):
                f.write("{:016X} {}\n".format(addr, s))

            f.write("\n## Update Field Names ({})\n\n".format(
                len(update_fields)))
            for addr, s in update_fields:
                f.write("{:016X} {}\n".format(addr, s))

            f.write("\n## JamJSON Types ({})\n\n".format(len(jam_types)))
            for addr, s in jam_types:
                f.write("{:016X} {}\n".format(addr, s))

            f.write("\n## CVar References ({})\n\n".format(len(cvar_refs)))
            for addr, s in cvar_refs:
                f.write("{:016X} {}\n".format(addr, s))

        print("\nResults saved to {}".format(str(output_path)))
    else:
        print("Results not saved to file")


analyze_strings()
