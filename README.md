# binanana

Symbol database and analysis tools for WoW Classic client binaries.

Based on the [binana](https://github.com/thunderbrewhq/binana) project
(which covers WoW 3.3.5a), binanana extends the approach to the Classic
client family: Classic (1.13.x), Classic Era (1.14.x, 1.15.x), TBC
Classic (2.5.x), and Wrath Classic (3.4.x).

All Classic clients are 64-bit x86-64 Windows PE binaries with:

- Obfuscated import tables (all API calls resolved at runtime)
- Control Flow Guard (CFG)
- TLS callbacks
- MSVC RTTI with 2,000-3,400 type_info entries
- 700-900 embedded source file paths
- TACT/CASC content delivery (statically linked)

## Contents

- [Overview](#overview)
- [Dependencies](#dependencies)
- [Project structure](#project-structure)
- [Symbol files](#symbol-files)
- [Header files](#header-files)
- [Ghidra](#ghidra)
  - [Setup](#setup)
  - [Headless analysis](#headless-analysis)
  - [GUI mode](#gui-mode)
  - [Script compatibility](#script-compatibility)
  - [Importing symbols](#importing-symbols)
  - [Importing C headers](#importing-c-headers)
  - [Ghidra server](#ghidra-server)
- [Ghidra extension](#ghidra-extension)
- [Binary Ninja](#binary-ninja)
- [Cross-version propagation](#cross-version-propagation)
- [Available profiles](#available-profiles)

## Overview

The project has three layers:

1. **Profiles** -- Per-build symbol files (`.sym`), C headers, and
   metadata (`info.json`). This is the version-controlled knowledge base.
2. **Ghidra scripts** -- Python scripts for automated analysis: RTTI
   chain walking, Lua API string resolution, symbol export/import,
   cross-version function matching.
3. **Tools** -- CLI utilities for compiling symbols, validating profiles,
   and dumping Arxan-protected binaries from memory.

## Dependencies

- Python 3.13 (PyGhidra requires JPype1 which has no 3.14+ wheels)
- Ghidra >= 12.0 (for PyGhidra CPython 3 script support)
- JDK 21+ (installed by setup-ghidra)
- Gradle 8.5+ (for building the Ghidra extension)
- Make
- Bash shell

For Binary Ninja workflows:

- Binary Ninja with binary_ninja_mcp plugin

For the memory dumper (`tools/wow-dumper`):

- Rust 1.92+ with `x86_64-pc-windows-msvc` target
- cargo-xwin (cross-compilation from Linux)
- Wine 9+ (wine-staging recommended)

## Project structure

```text
binanana/
  profile/
    {version}-{platform}-{arch}/
      info.json              # Binary metadata
      symbol/
        {category}/
          func.sym           # Function symbols
          label.sym          # Data label symbols
        main.sym             # Compiled (all symbols merged)
      include/
        main.h               # Master header
        {subsystem}/*.h      # Per-subsystem C headers
  ghidra/
    analyze_rtti.py          # Batch RTTI chain walker
    analyze_vtables.py       # Heuristic vtable scanner
    analyze_lua_api.py       # Lua API Usage: string resolver
    analyze_lua_tables.py    # luaL_Reg registration table scanner
    analyze_lea_refs.py      # LEA instruction reference scanner
    analyze_strings.py       # Source path and debug string extractor
    export_symbols.py        # Export named symbols from Ghidra
    import_symbols.py        # Import symbols into Ghidra
    propagate_symbols.py     # Cross-version function hash matching
  tools/
    compile_symbols.py       # Merge category .sym files into main.sym
    validate_profile.py      # Check symbol integrity
    wow-dumper/              # Rust tool: dump Arxan-protected binaries
  extension/
    build.gradle             # Gradle build for Ghidra extension
    settings.gradle          # Project name (WowEmulation)
    extension.properties     # Extension metadata
    Module.manifest          # Empty (no special module requirements)
    src/main/java/wowemulation/
      WowBinaryAnalyzer.java # WoW binary detection (auto-analysis)
  script/
    analyze                  # Run Ghidra headless analysis pipeline
    build-extension          # Build the Ghidra extension zip
    compile-symbols          # Shell wrapper for symbol compilation
    dump-client              # Dump Arxan-protected binary via Wine
    export-from-binja        # Export symbols from Binary Ninja
    install-extension        # Build and install extension to Ghidra
    setup-ghidra             # Install Ghidra + PyGhidra + ghidra-mcp
  Makefile
```

## Symbol files

Symbol files map addresses to functions and data labels. The format is
compatible with Ghidra's `ImportSymbolsScript.py`:

```text
FunctionName 00000001400AD020 f end=00000001400AD0A3
DataLabel 0000000142B60E20 l
FunctionName 00000001400B1470 f end=00000001400B1590 type="int64_t __fastcall func(void*)"
SomeFunc 00000001400C0000 f ; demangled: SomeNamespace::SomeFunc(int, char const*)
```

Fields:

- **Name**: Symbol name (no spaces)
- **Address**: 16-digit hex address (64-bit)
- **Kind**: `f` for function, `l` for data label
- **end=ADDR**: End address (one past last instruction)
- **type="..."**: C type signature
- **; comment**: Human-readable note (e.g., demangled name)

Symbols are organized by category in `symbol/{category}/func.sym` and
`symbol/{category}/label.sym`. The `script/compile-symbols` script
merges all category files into `symbol/main.sym`.

## Header files

C header files describe struct layouts matching the binary's memory
representation. They use conditional compilation for tool-specific
handling:

```c
#ifdef GHIDRA
// Ghidra-specific includes
#endif
```

## Ghidra

### Setup

Install Ghidra and PyGhidra (Fedora):

```bash
# Full install (Ghidra GUI + PyGhidra + ghidra-mcp)
make setup-ghidra

# Headless only (Ghidra + PyGhidra, no GUI plugins)
make setup-ghidra-headless
```

This installs:

- Ghidra 12.0.3 to `/opt/ghidra`
- JDK 25
- Python 3.13 (PyGhidra requires JPype1; 3.14+ is not supported)
- PyGhidra 3.0.2 + JPype1 (from Ghidra's bundled wheels)
- ghidra-mcp 2.0.2 (full mode only)

After installation, load the environment:

```bash
source /etc/profile.d/ghidra.sh
```

### Headless analysis

Ghidra has two headless launchers:

| Launcher | Scripts | Use case |
|----------|---------|----------|
| `analyzeHeadless` | Java and Jython (Python 2.7) only | Legacy scripts |
| PyGhidra headless | CPython 3.13 | binanana scripts |

The binanana scripts use Python 3 and must run through PyGhidra.

Run the full analysis pipeline:

```bash
./script/analyze <binary-path> <profile-dir>
```

Example:

```bash
./script/analyze ~/Downloads/wow_classic/Wow.exe \
    profile/classic-1.13.2-31650-windows-win64
```

The script creates a temporary Ghidra project directory that is
automatically cleaned up on exit.

This executes seven post-scripts:

1. `analyze_rtti.py` -- Walk RTTI type_info -> COL -> vtable chains
2. `analyze_vtables.py` -- Heuristic vtable scanner for data sections
3. `analyze_lua_api.py` -- Resolve Lua API Usage: strings to native
   functions
4. `analyze_lua_tables.py` -- Find luaL_Reg registration tables
5. `analyze_lea_refs.py` -- Scan LEA instructions for string references
6. `analyze_strings.py` -- Extract source paths and debug strings
7. `export_symbols.py` -- Export all named symbols to .sym format

To run individual scripts:

```bash
python3.13 -m pyghidra.ghidra_launch \
    --install-dir /opt/ghidra \
    ghidra.app.util.headless.AnalyzeHeadless \
    /tmp/ghidra_project project_name \
    -import /path/to/binary \
    -postScript ghidra/analyze_rtti.py "/path/to/output.txt" \
    -overwrite -deleteProject
```

Script arguments are passed after the script path. Each script accepts
an optional output file path as its first argument. Without an argument,
results print to stdout only.

### GUI mode

Launch Ghidra:

```bash
ghidraRun
```

The binanana scripts are in the `ghidra/` directory. To use them:

1. Window -> Script Manager
2. Script Directories -> Add: `<repo>/ghidra/`
3. Filter by "binanana" category
4. Run any script (they prompt for file paths in GUI mode)

All scripts work in both GUI and headless modes. In GUI mode they use
`askFile()` prompts; in headless mode they accept `getScriptArgs()`.

### Script compatibility

The Ghidra scripts use PyGhidra-compatible imports:

```python
# Correct (works in PyGhidra and Jython):
from ghidra.program.model.symbol import SourceType

# Broken in PyGhidra (JPype enum wildcard import issue):
from ghidra.program.model.symbol.SourceType import *
```

JPype does not support wildcard imports from Java enum types. Use direct
imports (`import SourceType`) and qualify constants as
`SourceType.DEFAULT`, `SourceType.ANALYSIS`, etc.

### Importing symbols

1. Open Ghidra -> Window -> Script Manager
2. Run `import_symbols.py` from the binanana category
3. Select `profile/<version>/symbol/main.sym`

Or in headless mode:

```bash
python3.13 -m pyghidra.ghidra_launch \
    --install-dir /opt/ghidra \
    ghidra.app.util.headless.AnalyzeHeadless \
    /tmp/project project_name \
    -process binary.exe \
    -postScript ghidra/import_symbols.py "profile/version/symbol/main.sym" \
    -noanalysis
```

### Importing C headers

1. Open Ghidra -> File -> Parse C Source...
2. Select `clib.prf` as parse configuration
3. Add `profile/<version>/include/main.h` to source files
4. Add `profile/<version>/include` to include paths
5. Add `-DGHIDRA` to parse options
6. Press Parse to Program

### Ghidra server

The Ghidra archive includes a server (`/opt/ghidra/server/`) for
collaborative multi-user repository sharing. This is not required for
binanana's headless analysis workflow. It is useful if multiple analysts
need to share a Ghidra project database.

See `/opt/ghidra/server/svrREADME.md` for server setup.

## Ghidra extension

The `extension/` directory contains an installable Ghidra extension
that bundles both a Java binary detector and the Python analysis
scripts into a single package.

### What it provides

When installed, the extension adds:

1. **WoW Binary Detector** -- A Java analyzer that runs during
   Ghidra's auto-analysis. It scans `.rdata` for the `CObject` RTTI
   signature to identify WoW binaries and sets program properties
   with the RTTI entry count.
2. **Script Manager integration** -- All Python scripts from `ghidra/`
   appear in Script Manager automatically, without manual directory
   configuration.

The Java code is limited to binary detection (~100 lines). All
analysis logic (RTTI chain walking, Lua API resolution, symbol
management) remains in Python.

### Building and installing

Requirements: Gradle 8.5+, JDK 21+, `GHIDRA_INSTALL_DIR` environment
variable set.

```bash
# Build the extension zip
make build-extension

# Build and install to the system Ghidra installation
make install-extension
```

The built zip is in `extension/dist/`. It can also be installed via
Ghidra's `File -> Install Extensions` dialog (green + button).

### Architecture note

Ghidra's auto-analysis extension points (`AbstractAnalyzer`,
`AbstractProgramWrapperLoader`, `ProgramPlugin`) require Java.
Ghidra's `ClassSearcher` scans compiled `.class` files on the
classpath; Python classes created via JPype are not visible to it.
This is why binary detection uses Java while analysis logic stays
in Python.

## Binary Ninja

For binaries loaded in Binary Ninja with the binary_ninja_mcp plugin:

```bash
# Export user-named symbols from BN to binanana format
./script/export-from-binja profile/classic-1.13.2-31650-windows-win64

# Or via Make
make export-from-binja PROFILE=profile/classic-1.13.2-31650-windows-win64
```

This connects to BN's HTTP API at `localhost:9009`, exports user-named
functions and data labels, and writes to `symbol/export/func.sym` and
`symbol/export/label.sym`.

## Cross-version propagation

The `propagate_symbols.py` script matches functions across binary
versions using instruction-level hashing. Workflow:

1. Analyze one version thoroughly (e.g., 1.13.2)
2. Open the analyzed binary in Ghidra, run `propagate_symbols.py` with
   mode "export" to save function hashes
3. Open the target binary, run `propagate_symbols.py` with mode "import"
   and the hash file from step 2
4. Review matched symbols and commit to the target profile

In headless mode:

```bash
# Export hashes from source binary
python3.13 -m pyghidra.ghidra_launch --install-dir /opt/ghidra \
    ghidra.app.util.headless.AnalyzeHeadless /tmp/project src \
    -process Wow_1.13.2.exe -noanalysis \
    -postScript ghidra/propagate_symbols.py "export" "/tmp/hashes.txt"

# Import and match against target binary
python3.13 -m pyghidra.ghidra_launch --install-dir /opt/ghidra \
    ghidra.app.util.headless.AnalyzeHeadless /tmp/project tgt \
    -process Wow_1.14.0.exe -noanalysis \
    -postScript ghidra/propagate_symbols.py "import" "/tmp/hashes.txt"
```

## Available profiles

| Version | Build | Product | Platform | Binary |
|---------|-------|---------|----------|--------|
| 3.13.3 | 9370 | Agent | windows-i386 | Agent.exe |
| 1.13.2 | 31650 | Classic | windows-win64 | Wow.exe |
| 1.14.0 | 40618 | Classic Era | windows-win64 | WowClassic.exe |
| 1.14.1 | 41794 | Classic Era | windows-win64 | WowClassic.exe |
| 1.14.2 | 42597 | Classic Era | windows-win64 | WowClassic.exe |
| 1.15.2 | 55140 | Classic Era | windows-win64 | WowClassic.exe |
| 1.15.2 | 55140 | Classic Era | macos-arm64 | World of Warcraft Classic |
| 1.15.8 | 64272 | Classic Era | windows-win64 | WowClassic.exe |
| 2.5.3 | 42328 | TBC Classic | windows-win64 | WowClassic.exe |
| 3.4.3 | 53788 | Wrath Classic | windows-win64 | WowClassic.exe |
