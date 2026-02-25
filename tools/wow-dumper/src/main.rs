/// wow-dumper: Dump Arxan-protected WoW Classic binaries from memory.
///
/// Launches a WoW executable in suspended state, waits for Arxan to
/// decrypt all sections, reads the decrypted memory, and reconstructs
/// a valid PE file for static analysis in Ghidra or Binary Ninja.
///
/// Designed to run under Wine on Linux.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

mod arxan;
mod patterns;
mod pe;
mod process;

#[derive(Parser)]
#[command(name = "wow-dumper")]
#[command(about = "Dump Arxan-protected WoW Classic binaries from memory")]
#[command(version)]
struct Cli {
    /// Path to the WoW executable
    exe_path: PathBuf,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Override build number for pattern selection
    #[arg(long)]
    build: Option<u32>,

    /// Maximum wait time for Arxan decryption in seconds
    #[arg(long, default_value = "30")]
    timeout: u32,

    /// Print progress to stderr
    #[arg(short, long)]
    verbose: bool,

    /// Skip IAT deobfuscation (not yet implemented, placeholder for future)
    #[arg(long)]
    no_iat: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let output = cli.output.clone().unwrap_or_else(|| {
        let mut p = cli.exe_path.clone();
        let stem = p
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        p.set_file_name(format!("{}.dump.exe", stem));
        p
    });

    if cli.verbose {
        eprintln!("[wow-dumper] Input:  {}", cli.exe_path.display());
        eprintln!("[wow-dumper] Output: {}", output.display());
    }

    // Read on-disk PE for header reconstruction
    let disk_data = std::fs::read(&cli.exe_path)
        .with_context(|| format!("Failed to read {}", cli.exe_path.display()))?;

    if cli.verbose {
        eprintln!(
            "[wow-dumper] On-disk PE: {} bytes ({:.1} MB)",
            disk_data.len(),
            disk_data.len() as f64 / (1024.0 * 1024.0)
        );
    }

    // Create the process suspended
    let mut proc = process::SuspendedProcess::create(&cli.exe_path, cli.verbose)?;

    if cli.verbose {
        eprintln!(
            "[wow-dumper] Process created (PID {}), image base: 0x{:X}",
            proc.pid(),
            proc.image_base()
        );
    }

    // Run the dump pipeline, always terminating the child on exit
    let result = run_dump(&cli, &proc, &disk_data, &output);

    proc.terminate();

    result
}

fn run_dump(
    cli: &Cli,
    proc: &process::SuspendedProcess,
    disk_data: &[u8],
    output: &PathBuf,
) -> Result<()> {
    // Detect and wait for Arxan decryption
    let has_arxan = arxan::detect_and_wait(proc, cli.timeout, cli.build, cli.verbose)?;

    if cli.verbose {
        if has_arxan {
            eprintln!("[wow-dumper] Arxan decryption complete");
        } else {
            eprintln!("[wow-dumper] No Arxan protection detected");
        }
    }

    // Read all sections from process memory
    if cli.verbose {
        eprintln!("[wow-dumper] Reading sections from process memory...");
    }
    let sections = pe::read_sections_from_memory(proc, disk_data, cli.verbose)?;

    // Reconstruct PE
    if cli.verbose {
        eprintln!("[wow-dumper] Reconstructing PE...");
    }
    let dump = pe::reconstruct(disk_data, &sections, proc.image_base())?;

    // Write output
    std::fs::write(output, &dump)
        .with_context(|| format!("Failed to write {}", output.display()))?;

    let section_summary: String = sections
        .iter()
        .map(|s| format!("{} ({}KB)", s.name, s.data.len() / 1024))
        .collect::<Vec<_>>()
        .join(", ");

    if cli.verbose {
        eprintln!(
            "[wow-dumper] Dump written: {} ({} bytes, {:.1} MB)",
            output.display(),
            dump.len(),
            dump.len() as f64 / (1024.0 * 1024.0)
        );
        eprintln!("[wow-dumper] Sections: {}", section_summary);
    }

    // Always print the output path
    println!("{}", output.display());

    Ok(())
}
