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
  - [Headless analysis](#headless-analysis)
  - [Importing symbols](#importing-symbols)
  - [Importing C headers](#importing-c-headers)
- [Cross-version propagation](#cross-version-propagation)
- [Available profiles](#available-profiles)

## Overview

The project has three layers:

1. **Profiles** -- Per-build symbol files (`.sym`), C headers, and
   metadata (`info.json`). This is the version-controlled knowledge base.
2. **Ghidra scripts** -- Python scripts for automated analysis: RTTI
   chain walking, Lua API string resolution, symbol export/import,
   cross-version function matching.
3. **Tools** -- Python CLI for compiling symbols, validating profiles,
   and generating tool-specific output formats.

## Dependencies

- Python >= 3.11
- Ghidra >= 11.0 (for analysis scripts)
- Make
- Bash shell

## Project structure

```
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
    export_symbols.py        # Export named symbols from Ghidra
    import_symbols.py        # Import symbols into Ghidra
    analyze_rtti.py          # Batch RTTI chain walker
    analyze_lua_api.py       # Lua API Usage: string resolver
    analyze_strings.py       # Source path and debug string extractor
    propagate_symbols.py     # Cross-version function hash matching
  tools/
    compile_symbols.py       # Merge category .sym files into main.sym
    validate_profile.py      # Check symbol integrity
  script/
    compile-symbols          # Shell wrapper for symbol compilation
    analyze                  # Run Ghidra headless analysis pipeline
  Makefile
```

## Symbol files

Symbol files map addresses to functions and data labels. The format is
compatible with Ghidra's `ImportSymbolsScript.py`:

```
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

### Headless analysis

Run the automated analysis pipeline on a new binary:

```bash
./script/analyze <ghidra-project-dir> <binary-path> <profile-dir>
```

This runs in Ghidra's headless mode and executes:

1. `analyze_rtti.py` -- Walk RTTI type_info -> COL -> vtable chains
2. `analyze_lua_api.py` -- Resolve Lua API Usage: strings to native
   functions
3. `analyze_strings.py` -- Extract source paths and debug strings
4. `export_symbols.py` -- Export all named symbols to .sym format

### Importing symbols

1. Open Ghidra -> Window -> Script Manager
2. Run `ImportSymbolsScript.py` (built-in)
3. Select `profile/<version>/symbol/main.sym`

### Importing C headers

1. Open Ghidra -> File -> Parse C Source...
2. Select `clib.prf` as parse configuration
3. Add `profile/<version>/include/main.h` to source files
4. Add `profile/<version>/include` to include paths
5. Add `-DGHIDRA` to parse options
6. Press Parse to Program

## Cross-version propagation

The `propagate_symbols.py` script matches functions across binary
versions using instruction-level hashing. Workflow:

1. Thoroughly analyze one version (e.g., 1.13.2)
2. Run `propagate_symbols.py --source 1.13.2 --target 1.14.0`
3. Review and commit matched symbols for the target version
4. Manually analyze only the delta (new/changed functions)

## Available profiles

| Version | Build | Product | Platform | Binary |
|---------|-------|---------|----------|--------|
| 1.13.2 | 31650 | Classic | windows-win64 | Wow.exe |
| 1.14.0 | 40618 | Classic Era | windows-win64 | WowClassic.exe |
| 1.14.1 | 41794 | Classic Era | windows-win64 | WowClassic.exe |
| 1.14.2 | 42597 | Classic Era | windows-win64 | WowClassic.exe |
| 1.15.2 | 55140 | Classic Era | windows-win64 | WowClassic.exe |
| 1.15.2 | 55140 | Classic Era | macos-arm64 | World of Warcraft Classic.app |
| 1.15.8 | 64272 | Classic Era | windows-win64 | WowClassic.exe |
| 2.5.3 | 42328 | TBC Classic | windows-win64 | WowClassic.exe |
| 3.4.3 | 53788 | Wrath Classic | windows-win64 | WowClassic.exe |
