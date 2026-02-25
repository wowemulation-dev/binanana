/// Arxan TransformIT decryption detection.
///
/// Arxan protects WoW Classic binaries by encrypting code and data
/// sections on disk. During process startup, the Arxan loader decrypts
/// everything in memory before jumping to the original entry point.
///
/// Detection strategy (from Arctium WoW-Launcher):
/// 1. Resume the suspended process so Arxan's loader runs
/// 2. Periodically scan the image for an initialization pattern
/// 3. The pattern is a `mov dword [rip+X], 1` that Arxan writes
///    after decryption completes
/// 4. Once found, compute the flag address and poll until it's non-zero
///
/// Fallback: if the pattern is not found within the timeout, check
/// whether the binary has Arxan at all (unprotected binaries like
/// Agent.exe have no Arxan loader).

use anyhow::{bail, Result};
use std::time::{Duration, Instant};

use crate::patterns;
use crate::process::SuspendedProcess;

/// Detect Arxan protection and wait for decryption to complete.
///
/// Returns `true` if Arxan was detected and decryption completed,
/// `false` if no Arxan protection was found (unprotected binary).
pub fn detect_and_wait(
    proc: &SuspendedProcess,
    timeout_secs: u32,
    build: Option<u32>,
    verbose: bool,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs as u64);
    let start = Instant::now();

    // Read the image size from the PE header in process memory.
    // We need to know how much memory to scan.
    let image_size = read_image_size(proc)?;
    if verbose {
        eprintln!(
            "[wow-dumper] Image at 0x{:X}, size 0x{:X} ({:.1} MB)",
            proc.image_base(),
            image_size,
            image_size as f64 / (1024.0 * 1024.0)
        );
    }

    // Quick check: try to read a few bytes from the code section.
    // If they're already non-zero, the binary may not be Arxan-protected.
    let quick_check = try_quick_detect(proc, image_size)?;
    if quick_check == ArxanState::NotProtected {
        if verbose {
            eprintln!("[wow-dumper] Binary does not appear to be Arxan-protected");
        }
        return Ok(false);
    }

    if verbose {
        eprintln!("[wow-dumper] Arxan protection detected, waiting for decryption...");
    }

    // Resume the process so Arxan can run its decryption
    proc.resume()?;

    // Scan loop: periodically suspend, scan for init pattern, resume
    let poll_interval = Duration::from_millis(100);

    loop {
        if start.elapsed() > timeout {
            proc.suspend()?;
            bail!(
                "Timeout after {}s waiting for Arxan decryption. \
                 Try increasing --timeout or check that Wine can run this binary.",
                timeout_secs
            );
        }

        std::thread::sleep(poll_interval);
        proc.suspend()?;

        // Read the full image
        let data = match proc.read_memory(proc.image_base(), image_size) {
            Ok(d) => d,
            Err(_) => {
                // Memory not yet fully mapped, try again
                proc.resume()?;
                continue;
            }
        };

        // Scan for the initialization pattern
        let pattern = patterns::get_pattern_for_build(build);
        if let Some(match_offset) = patterns::scan(&data, pattern) {
            if verbose {
                eprintln!(
                    "[wow-dumper] Init pattern found at image+0x{:X}",
                    match_offset
                );
            }

            // Compute the init flag address from the RIP-relative displacement.
            // The instruction is: C7 05 [disp32] 01 00 00 00
            // Effective address = RIP + disp32, where RIP = addr of next instruction
            let disp_bytes = &data[match_offset + patterns::INIT_X64_DISP_OFFSET
                ..match_offset + patterns::INIT_X64_DISP_OFFSET + 4];
            let disp = i32::from_le_bytes(disp_bytes.try_into().unwrap());

            // RIP points to the instruction AFTER the mov (10 bytes long)
            let rip = proc.image_base() + match_offset as u64 + patterns::INIT_X64_INSN_LEN as u64;
            let flag_addr = (rip as i64 + disp as i64) as u64;

            if verbose {
                eprintln!("[wow-dumper] Init flag at 0x{:X}, polling...", flag_addr);
            }

            // Poll the flag until it becomes non-zero
            proc.resume()?;
            let flag_result = poll_init_flag(proc, flag_addr, timeout - start.elapsed())?;

            if flag_result {
                proc.suspend()?;
                return Ok(true);
            } else {
                bail!("Init flag did not become non-zero within timeout");
            }
        }

        // Pattern not found yet - Arxan still decrypting
        proc.resume()?;
    }
}

/// Quick detection: check if the binary appears to be Arxan-protected.
///
/// Arxan-protected binaries have zeroed .text sections on disk. After
/// the image is loaded (but before Arxan runs), the .text section
/// will be mostly zeros. Unprotected binaries have valid code.
fn try_quick_detect(proc: &SuspendedProcess, image_size: usize) -> Result<ArxanState> {
    // Read the first 4KB after the PE header (should be start of .text)
    // The PE header is typically 0x1000 bytes, so .text starts around there.
    let text_offset = 0x1000u64;
    if image_size <= text_offset as usize {
        return Ok(ArxanState::NotProtected);
    }

    let sample_size = 4096.min(image_size - text_offset as usize);
    let sample = proc.read_memory(proc.image_base() + text_offset, sample_size)?;

    // Count non-zero bytes. Arxan-protected sections are mostly zeros on disk.
    let nonzero = sample.iter().filter(|&&b| b != 0).count();
    let ratio = nonzero as f64 / sample.len() as f64;

    if ratio > 0.5 {
        // More than half the bytes are non-zero: likely not Arxan-protected,
        // or Arxan already decrypted (fast loader).
        Ok(ArxanState::NotProtected)
    } else {
        Ok(ArxanState::Protected)
    }
}

/// Poll the initialization flag address until it becomes non-zero.
fn poll_init_flag(proc: &SuspendedProcess, flag_addr: u64, timeout: Duration) -> Result<bool> {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if start.elapsed() > timeout {
            return Ok(false);
        }

        std::thread::sleep(poll_interval);
        proc.suspend()?;

        let mut buf = [0u8; 4];
        match proc.read_memory_into(flag_addr, &mut buf) {
            Ok(_) => {
                let value = u32::from_le_bytes(buf);
                if value != 0 {
                    return Ok(true);
                }
            }
            Err(_) => {
                // Memory not readable yet
            }
        }

        proc.resume()?;
    }
}

/// Read the SizeOfImage from the PE optional header in process memory.
fn read_image_size(proc: &SuspendedProcess) -> Result<usize> {
    // Read DOS header to get e_lfanew
    let dos_header = proc.read_memory(proc.image_base(), 64)?;
    if dos_header.len() < 64 {
        bail!("Failed to read DOS header");
    }
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        bail!("Invalid DOS signature");
    }

    let e_lfanew = u32::from_le_bytes(dos_header[0x3C..0x40].try_into().unwrap()) as u64;

    // Read PE signature + COFF header + start of optional header
    let pe_header = proc.read_memory(proc.image_base() + e_lfanew, 0x80)?;
    if pe_header.len() < 0x80 {
        bail!("Failed to read PE header");
    }
    if pe_header[0..4] != [b'P', b'E', 0, 0] {
        bail!("Invalid PE signature");
    }

    // Optional header starts at offset 24 (4 PE sig + 20 COFF header)
    let magic = u16::from_le_bytes(pe_header[24..26].try_into().unwrap());

    // SizeOfImage is at optional_header + 0x38 (same offset for PE32 and PE32+)
    let size_of_image = u32::from_le_bytes(pe_header[24 + 0x38..24 + 0x3C].try_into().unwrap());

    if size_of_image == 0 {
        bail!("SizeOfImage is zero (magic=0x{:04X})", magic);
    }

    Ok(size_of_image as usize)
}

#[derive(Debug, PartialEq)]
enum ArxanState {
    Protected,
    NotProtected,
}
