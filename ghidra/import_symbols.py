# Import binanana .sym symbols into Ghidra.
#
# Usage (GUI): Run from Script Manager, prompts for .sym file path.
# Usage (headless): -postScript import_symbols.py "/path/to/input.sym"
#
# Creates functions at 'f' entries (with end address if provided),
# creates labels at 'l' entries. Skips entries where a user-defined
# name already exists.
#
# @category binanana

from ghidra.program.model.symbol import SourceType

functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
listing = currentProgram.getListing()
addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace()

# Support both GUI (askFile) and headless (getScriptArgs) modes
args = getScriptArgs()
if args:
    import java.io.File
    file_location = java.io.File(args[0])
else:
    file_location = askFile("Choose .sym file to import", "Import")


def parse_attributes(parts):
    """Parse key=value attributes from symbol line parts."""
    attrs = {}
    i = 0
    while i < len(parts):
        part = parts[i]
        if "=" in part:
            key, _, value = part.partition("=")
            # Handle quoted values that may span multiple parts
            if value.startswith('"') and not value.endswith('"'):
                while i + 1 < len(parts) and not parts[i + 1].endswith('"'):
                    i += 1
                    value += " " + parts[i]
                if i + 1 < len(parts):
                    i += 1
                    value += " " + parts[i]
            value = value.strip('"')
            attrs[key] = value
        i += 1
    return attrs


def import_symbols():
    count_func = 0
    count_label = 0
    count_skip = 0

    input_path = str(file_location.absolutePath) if hasattr(file_location, 'absolutePath') else str(file_location)
    with open(input_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            monitor.checkCanceled()

            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip comment
            comment_idx = line.find(";")
            comment = line[comment_idx + 1:].strip() if comment_idx >= 0 else None
            parse_line = line[:comment_idx].strip() if comment_idx >= 0 else line

            parts = parse_line.split()
            if len(parts) < 3:
                print("Line {}: too few columns, skipping".format(line_num))
                continue

            name = parts[0]
            addr_str = parts[1]
            kind = parts[2]

            try:
                addr_int = int(addr_str, 16)
            except ValueError:
                print("Line {}: invalid address '{}', skipping".format(
                    line_num, addr_str))
                continue

            addr = addressSpace.getAddress(addr_int)
            attrs = parse_attributes(parts[3:])

            if kind == "f":
                # Create or rename function
                existing = functionManager.getFunctionAt(addr)
                if existing is not None:
                    if existing.getSource() != SourceType.DEFAULT:
                        count_skip += 1
                        continue
                    existing.setName(name, SourceType.USER_DEFINED)
                else:
                    end_str = attrs.get("end")
                    if end_str:
                        try:
                            end_int = int(end_str, 16)
                            end_addr = addressSpace.getAddress(end_int)
                            body = addressSpace.getAddressSet(addr, end_addr)
                        except ValueError:
                            body = None
                    else:
                        body = None

                    try:
                        functionManager.createFunction(
                            name, addr, body or addr.getNewAddressSet(),
                            SourceType.USER_DEFINED)
                    except Exception as e:
                        print("Line {}: failed to create function '{}' at {}: {}".format(
                            line_num, name, addr_str, e))
                        continue

                if comment:
                    func = functionManager.getFunctionAt(addr)
                    if func:
                        func.setComment(comment)

                count_func += 1

            elif kind == "l":
                # Create data label
                existing = symbolTable.getPrimarySymbol(addr)
                if existing is not None and existing.getSource() != SourceType.DEFAULT:
                    count_skip += 1
                    continue

                symbolTable.createLabel(addr, name, SourceType.USER_DEFINED)

                if comment:
                    code_unit = listing.getCodeUnitAt(addr)
                    if code_unit:
                        code_unit.setComment(code_unit.EOL_COMMENT, comment)

                count_label += 1

    print("Imported {} functions, {} labels ({} skipped, already named)".format(
        count_func, count_label, count_skip))


import_symbols()
