# Extract embedded source file paths and debug strings.
#
# WoW Classic binaries embed full build paths from __FILE__ macros
# in assertion and logging code. This script extracts and categorizes
# them.
#
# Uses Ghidra's Listing API to iterate over already-defined string
# data items rather than raw memory scanning. This handles Arxan-
# protected binaries where .data bytes are zeroed on disk but
# Ghidra's analyzers have identified strings at the data-type level.
#
# Categories extracted:
# - Source file paths (.cpp, .h)
# - CG*Data update field names
# - JamJSON type names
# - CVar registration strings
#
# Usage (GUI): Run from Script Manager, optionally saves results.
# Usage (headless): -postScript analyze_strings.py ["/path/to/output.txt"]
#
# @category binanana


LOG_PREFIX = "[binanana] "

memory = currentProgram.getMemory()
listing = currentProgram.getListing()


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


def find_strings_with_prefixes(prefixes):
    """Find all defined strings matching any prefix in .rdata and .data."""
    results = []
    for block in memory.getBlocks():
        if block.getName() not in (".rdata", ".data"):
            continue
        print(LOG_PREFIX + "Scanning {} ({:016X} - {:016X}, {:.1f} MB)...".format(
            block.getName(),
            block.getStart().getOffset(),
            block.getEnd().getOffset(),
            (block.getEnd().getOffset() - block.getStart().getOffset()) / 1024 / 1024))
        data_iter = listing.getDefinedData(block.getStart(), True)
        while data_iter.hasNext():
            monitor.checkCanceled()
            data = data_iter.next()
            if data.getAddress().compareTo(block.getEnd()) > 0:
                break
            value = get_string_value(data)
            if not value:
                continue
            for prefix in prefixes:
                if value.startswith(prefix):
                    results.append((data.getAddress().getOffset(), value))
                    break
    return results


def analyze_strings():
    """Main analysis: extract and categorize embedded strings."""
    # Source file paths
    print(LOG_PREFIX + "Scanning for source file paths...")
    source_prefixes = [
        "D:\\BuildServer\\",
        "d:\\buildserver\\",
        "D:\\buildserver\\",
    ]
    source_paths = find_strings_with_prefixes(source_prefixes)
    # Deduplicate
    seen = set()
    unique_paths = []
    for addr, s in source_paths:
        if s not in seen:
            seen.add(s)
            unique_paths.append((addr, s))
    source_paths = unique_paths
    print(LOG_PREFIX + "  Found {} source file paths".format(len(source_paths)))

    # Categorize by extension
    cpp_files = [(a, s) for a, s in source_paths if s.lower().endswith(".cpp")]
    h_files = [(a, s) for a, s in source_paths if s.lower().endswith(".h")]
    cc_files = [(a, s) for a, s in source_paths if s.lower().endswith(".cc")]
    print(LOG_PREFIX + "    .cpp: {}, .h: {}, .cc: {}".format(
        len(cpp_files), len(h_files), len(cc_files)))

    # CG*Data update field strings
    print(LOG_PREFIX + "Scanning for update field names...")
    update_field_prefixes = [
        "CGUnitData", "CGPlayerData", "CGActivePlayerData",
        "CGItemData", "CGGameObjectData", "CGObjectData",
        "CGContainerData", "CGCorpseData", "CGDynamicObjectData",
        "CGAreaTriggerData",
    ]
    update_fields = find_strings_with_prefixes(update_field_prefixes)
    print(LOG_PREFIX + "  Found {} update field names".format(len(update_fields)))

    # JamJSON type names
    print(LOG_PREFIX + "Scanning for JamJSON types...")
    jam_types = find_strings_with_prefixes(["JamJSON"])
    print(LOG_PREFIX + "  Found {} JamJSON types".format(len(jam_types)))

    # CVar strings
    print(LOG_PREFIX + "Scanning for CVar references...")
    cvar_refs = find_strings_with_prefixes(["CVar "])
    print(LOG_PREFIX + "  Found {} CVar references".format(len(cvar_refs)))

    # Summary
    print(LOG_PREFIX + "")
    print(LOG_PREFIX + "=== Summary ===")
    print(LOG_PREFIX + "Source file paths: {}".format(len(source_paths)))
    print(LOG_PREFIX + "Update field names: {}".format(len(update_fields)))
    print(LOG_PREFIX + "JamJSON types: {}".format(len(jam_types)))
    print(LOG_PREFIX + "CVar references: {}".format(len(cvar_refs)))

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

        print(LOG_PREFIX + "Results saved to {}".format(str(output_path)))
    else:
        print(LOG_PREFIX + "Results not saved to file")


analyze_strings()
