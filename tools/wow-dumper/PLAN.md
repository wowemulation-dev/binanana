# wow-dumper: Arxan Memory Dumper for WoW Classic

## Problem

WoW Classic binaries use Arxan TransformIT protection. On disk, `.data`
sections are zeroed and the import table is obfuscated. After the Arxan
loader runs during process startup, all sections are decrypted in memory.
The binanana Ghidra pipeline currently analyzes the on-disk binary, which
limits results (91 of 2,858 RTTI COLs resolved on Classic 1.13.2).

A clean memory dump would give the Ghidra pipeline full access to all
sections, matching what Binary Ninja sees when analyzing a running process.

## Approach

Build a standalone Rust Windows executable that:

1. Launches a WoW client binary with `CREATE_SUSPENDED`
2. Resumes the process to let Arxan decrypt sections
3. Detects when decryption completes via pattern matching
4. Reads all memory sections via `ReadProcessMemory`
5. Reconstructs a valid PE file on disk
6. Terminates the child process

The tool runs under Wine on Linux. A shell wrapper script sets up a
dedicated Wine prefix, places the tool alongside the client binary,
and extracts the dump.

## Architecture

```text
tools/wow-dumper/
  Cargo.toml
  src/
    main.rs           # CLI entry point
    process.rs        # CreateProcessW, suspend/resume, memory reading
    arxan.rs          # Decryption detection (pattern scanning)
    pe.rs             # PE reconstruction from memory dump
    patterns.rs       # Byte patterns for Arxan init detection
```

## Phase 1: Process Lifecycle

Create the WoW process suspended and manage its lifetime.

### Dependencies

- `windows` crate for Win32 API bindings
- `ntapi` crate for `NtQueryInformationProcess`, PEB access

### Functions

```
create_suspended(exe_path) -> (HANDLE, HANDLE, u64)
    CreateProcessW with CREATE_SUSPENDED
    Returns (process_handle, thread_handle, image_base)

get_image_base(process_handle) -> u64
    NtQueryInformationProcess(ProcessBasicInformation) to get PEB address
    ReadProcessMemory to read PEB.ImageBaseAddress

resume_process(process_handle)
    NtResumeProcess

suspend_process(process_handle)
    NtSuspendProcess

terminate_process(process_handle)
    TerminateProcess

read_memory(process_handle, addr, size) -> Vec<u8>
    ReadProcessMemory wrapper

enumerate_regions(process_handle) -> Vec<MemoryRegion>
    VirtualQueryEx loop from 0 to max address
    Returns base, size, protection, type for each committed region
```

## Phase 2: Arxan Detection

Detect when Arxan finishes decrypting sections.

### Strategy (from Arctium launcher)

Arctium uses a two-stage approach:

1. Resume the process, let Arxan run
2. Repeatedly scan memory for an "init pattern" -- a `MOV DWORD [rip+X], 1`
   instruction sequence that appears only after decryption
3. Once found, compute the init flag address from the pattern's RIP-relative
   offset
4. Poll the flag address until it becomes non-zero

The init pattern for x64 WoW Classic:
```
C7 05 ?? ?? ?? ?? 01 00 00 00   ; mov dword [rip+disp32], 1
48 8D ?? ?? ?? ?? ??             ; lea reg, [rip+disp32]
48 8D ?? ?? ?? ?? ??             ; lea reg, [rip+disp32]
E8 ?? ?? ?? ??                   ; call rel32
85                               ; test ...
```

`??` = wildcard byte.

### Scan Loop

```
wait_for_arxan(process_handle, image_base, region_size) -> Result<()>
    loop:
        suspend_process()
        data = read_memory(image_base, region_size)
        match = pattern_scan(data, INIT_PATTERN)
        if match found:
            compute init_flag_addr from RIP-relative offset at match+2
            poll init_flag_addr until non-zero
            return Ok
        resume_process()
        sleep(50ms)
```

### Fallback: Section Protection Monitoring

If the init pattern does not match (different WoW version), fall back to
monitoring memory protection changes:

1. Query `.text` section protection
2. Wait for it to cycle through `PAGE_EXECUTE_READWRITE` (Arxan decrypting)
   and return to `PAGE_EXECUTE_READ` (done)

### Per-Version Pattern Sets

Different WoW builds may need different init patterns. Store patterns in
`patterns.rs` keyed by build number. The CLI accepts a `--build` flag or
auto-detects from the PE version resource.

## Phase 3: PE Reconstruction

Read all sections from process memory and write a valid PE to disk.

### Dependencies

- `goblin` crate for PE parsing and writing

### Strategy

1. Read PE headers from the on-disk file (Arxan destroys in-memory headers)
2. Read each section's data from process memory at its virtual address
3. Reconstruct the PE:
   - Copy headers from disk (fix ImageBase for ASLR)
   - Replace each section's raw data with the in-memory decrypted version
   - Set all section raw sizes = virtual sizes (memory dump layout)
   - Zero the security directory (strip digital signature)
   - Recalculate PE checksum
4. Write to `<original_name>.dump.exe`

### Import Table

Arxan replaces IAT entries with pointers to arithmetic obfuscation thunks.
Each thunk computes the real import address through a chain of
`mov rax, imm64 / add / sub / xor / imul / jmp` instructions.

The deobfuscation emulator:

```
deobfuscate_iat_entry(process_handle, thunk_addr) -> u64
    rax = 0, r10 = 0
    ip = thunk_addr
    loop:
        read 16 bytes at ip
        decode instruction:
            MOV RAX, imm64 -> rax = imm64
            MOV R10, imm64 -> r10 = imm64
            ADD RAX, imm32 -> rax += imm32
            SUB RAX, imm32 -> rax -= imm32
            XOR RAX, imm32 -> rax ^= imm32
            IMUL RAX, R10  -> rax *= r10
            JMP rel32      -> ip += offset; continue
            JMP RAX        -> return rax
        ip += insn_len
```

For the initial version, IAT deobfuscation is optional. Ghidra can work
with the encrypted IAT for static analysis of non-import functions. The
deobfuscation can be added later or handled by a separate post-processing
step.

## Phase 4: CLI and Wine Integration

### CLI Interface

```
wow-dumper.exe <path-to-wow.exe> [options]

Options:
    --output <path>     Output file (default: <input>.dump.exe)
    --build <number>    Override build number for pattern selection
    --timeout <secs>    Max wait for Arxan decryption (default: 30)
    --no-iat            Skip IAT deobfuscation (default: skip)
    --verbose           Print progress to stderr
```

### Wine Wrapper Script

`script/dump-client` in binanana:

```bash
#!/bin/bash
# Usage: ./script/dump-client <client-exe> [output-path]
#
# Creates a temporary Wine prefix, copies the dumper tool and client
# binary, runs the dump, and extracts the result.

CLIENT_EXE="$1"
OUTPUT="${2:-${CLIENT_EXE%.exe}.dump.exe}"

WINEPREFIX=$(mktemp -d)
export WINEPREFIX

# Initialize minimal Wine prefix (win64)
WINEARCH=win64 wineboot --init 2>/dev/null

# Copy or symlink client files
CLIENT_DIR=$(dirname "$CLIENT_EXE")
# ... symlink approach to avoid copying large files

# Run the dumper under Wine
wine tools/wow-dumper/target/x86_64-pc-windows-msvc/release/wow-dumper.exe \
    "Z:$(realpath "$CLIENT_EXE")" \
    --output "Z:$(realpath "$OUTPUT")" \
    --verbose

# Clean up Wine prefix
rm -rf "$WINEPREFIX"
```

### Integration with Analysis Pipeline

`script/analyze` gains a `--dump` flag:

```bash
./script/analyze --dump ~/Downloads/wow_classic/classic-1.13.2/WowClassic.exe \
    profile/classic-1.13.2-31650-windows-win64
```

This runs `script/dump-client` first, then passes the dump to Ghidra.

## Phase 5: Build and Cross-Compilation

### Cross-Compile from Linux

```bash
# One-time setup
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc

# Build
cd tools/wow-dumper
cargo xwin build --target x86_64-pc-windows-msvc --release
```

### Makefile Targets

```makefile
build-dumper:
    cd tools/wow-dumper && cargo xwin build \
        --target x86_64-pc-windows-msvc --release

dump-client:
    ./script/dump-client $(CLIENT) $(OUTPUT)
```

### CI Considerations

The dumper requires Wine for testing. CI can build-check
(`cargo xwin check`) without Wine. Actual dump testing is manual
since it requires client binaries.

## Implementation Order

1. **Phase 1**: Process lifecycle (create, suspend, resume, read memory,
   enumerate regions). Test against Agent.exe (no Arxan) under Wine.
2. **Phase 3 (partial)**: PE reconstruction without IAT deobfuscation.
   Produce a dump of Agent.exe and verify Ghidra can import it.
3. **Phase 2**: Arxan detection. Test against WoW Classic under Wine.
   Verify decrypted sections are readable.
4. **Phase 3 (complete)**: Full PE reconstruction from Arxan-protected
   binary. Compare Ghidra results between on-disk and dump analysis.
5. **Phase 4**: CLI polish, Wine wrapper script, pipeline integration.
6. **Phase 5**: Cross-compilation setup, Makefile targets.

## Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `windows` | Win32 API: CreateProcessW, VirtualQueryEx, ReadProcessMemory |
| `ntapi` | NT API: NtQueryInformationProcess, NtSuspendProcess, NtResumeProcess |
| `goblin` | PE parsing and writing (has write support since 0.9) |
| `clap` | CLI argument parsing |

## Risks and Mitigations

**Wine compatibility**: Wine may not implement all NT APIs used by Arxan.
Mitigation: Arctium launcher already works under Wine, confirming the
core APIs function correctly.

**Pattern brittleness**: The init pattern is version-specific. Different
WoW builds have different patterns. Mitigation: Pattern table keyed by
build number, with fallback to section protection monitoring.

**IAT deobfuscation accuracy**: The arithmetic emulator must handle all
instruction variants Arxan uses. Mitigation: Defer IAT deobfuscation to
a later phase. The dump is useful for static analysis even with obfuscated
imports.

**Wine prefix overhead**: Creating a full Wine prefix takes seconds.
Mitigation: Use `WINEARCH=win64 wineboot --init` for minimal prefix.
Reuse prefix across multiple dumps if running batch.

## Expected Results

With a clean dump, the Ghidra pipeline should achieve:

- ~2,858 RTTI entries with near-100% COL resolution (vs 91 currently)
- Full vtable discovery (vs 88 currently)
- Lua API function resolution via xrefs (vs 0 currently)
- LEA reference scanning producing actual matches (vs 0 currently)
- Complete string extraction from decrypted `.data` section

## References

- [Arctium/WoW-Launcher](https://github.com/Arctium/WoW-Launcher) --
  CREATE_SUSPENDED + pattern-based Arxan detection
- [adde88/WoWDumpFix](https://github.com/adde88/WoWDumpFix) --
  IAT deobfuscation emulator, PE header restoration
- [Kittnz/WoW-Dump-Fix](https://github.com/Kittnz/WoW-Dump-Fix) --
  Capstone-based IAT deobfuscation, section remapping
- [pr701/fix-arxan](https://github.com/pr701/fix-arxan) --
  Arxan loader function identification, guard flag patching
- [goblin](https://github.com/m4b/goblin) -- Rust PE read/write
