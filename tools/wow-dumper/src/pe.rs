/// PE reconstruction from process memory.
///
/// Reads section data from a running process and reconstructs a valid
/// PE file by combining on-disk headers with in-memory section content.
///
/// The on-disk headers are used because Arxan destroys the in-memory
/// PE header. Section data comes from process memory (decrypted).

use anyhow::{bail, Context, Result};
use goblin::pe::PE;

use crate::process::SuspendedProcess;

/// Section data read from process memory.
pub struct SectionData {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size_on_disk: u32,
    pub data: Vec<u8>,
}

/// Read all PE sections from process memory.
///
/// Uses the on-disk PE to determine section layout, then reads each
/// section's virtual address range from the process.
pub fn read_sections_from_memory(
    proc: &SuspendedProcess,
    disk_data: &[u8],
    verbose: bool,
) -> Result<Vec<SectionData>> {
    let pe = PE::parse(disk_data).context("Failed to parse on-disk PE")?;
    let mut sections = Vec::new();

    for section in &pe.sections {
        let name = String::from_utf8_lossy(
            &section.name[..section.name.iter().position(|&b| b == 0).unwrap_or(8)],
        )
        .to_string();

        let va = section.virtual_address;
        let vsize = section.virtual_size;
        let raw_size = section.size_of_raw_data;

        // Read the larger of virtual_size and size_of_raw_data to capture
        // all content. Some sections have vsize=0 and only raw_size.
        let read_size = vsize.max(raw_size) as usize;
        if read_size == 0 {
            if verbose {
                eprintln!("[wow-dumper]   {} (empty, skipped)", name);
            }
            sections.push(SectionData {
                name,
                virtual_address: va,
                virtual_size: vsize,
                raw_size_on_disk: raw_size,
                data: Vec::new(),
            });
            continue;
        }

        let addr = proc.image_base() + va as u64;
        let data = match proc.read_memory(addr, read_size) {
            Ok(d) => d,
            Err(e) => {
                if verbose {
                    eprintln!(
                        "[wow-dumper]   {} at 0x{:X} ({} bytes) - read failed: {}",
                        name, addr, read_size, e
                    );
                }
                // Fill with zeros for unreadable sections (e.g., guard pages)
                vec![0u8; read_size]
            }
        };

        if verbose {
            let nonzero = data.iter().filter(|&&b| b != 0).count();
            eprintln!(
                "[wow-dumper]   {} at 0x{:X} ({} bytes, {:.1}% non-zero)",
                name,
                addr,
                data.len(),
                100.0 * nonzero as f64 / data.len().max(1) as f64
            );
        }

        sections.push(SectionData {
            name,
            virtual_address: va,
            virtual_size: vsize,
            raw_size_on_disk: raw_size,
            data,
        });
    }

    Ok(sections)
}

/// Reconstruct a valid PE file from on-disk headers and in-memory sections.
///
/// Strategy:
/// 1. Copy headers from the on-disk file (Arxan destroys in-memory headers)
/// 2. Fix ImageBase for ASLR
/// 3. Replace each section's raw data with the memory dump
/// 4. Recalculate raw offsets sequentially
/// 5. Zero the security directory and checksum
pub fn reconstruct(
    disk_data: &[u8],
    sections: &[SectionData],
    image_base: u64,
) -> Result<Vec<u8>> {
    let pe = PE::parse(disk_data).context("Failed to parse on-disk PE")?;

    let is_64 = pe.is_64;
    let e_lfanew = pe.header.dos_header.pe_pointer as usize;
    let oh_offset = e_lfanew + 4 + 20; // PE sig + COFF header
    let oh_size = pe.header.coff_header.size_of_optional_header as usize;
    let section_table_offset = oh_offset + oh_size;

    let file_alignment = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.file_alignment)
        .unwrap_or(0x200) as usize;

    let size_of_headers = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.size_of_headers)
        .unwrap_or(0x1000) as usize;

    // Validate
    if pe.sections.len() != sections.len() {
        bail!(
            "Section count mismatch: disk has {}, memory has {}",
            pe.sections.len(),
            sections.len()
        );
    }

    // Build output buffer
    let mut output = Vec::new();

    // Step 1: Copy headers from disk
    let header_end = size_of_headers.min(disk_data.len());
    output.extend_from_slice(&disk_data[..header_end]);
    // Pad to SizeOfHeaders
    output.resize(size_of_headers, 0);

    // Step 2: Fix ImageBase
    patch_image_base(&mut output, oh_offset, is_64, image_base);

    // Step 3: Write section data and patch section headers
    let mut current_offset = size_of_headers;

    for (i, section) in sections.iter().enumerate() {
        // Align current offset to file alignment
        current_offset = align_up(current_offset, file_alignment);

        // Pad output to current offset
        if output.len() < current_offset {
            output.resize(current_offset, 0);
        }

        // Write section data
        output.extend_from_slice(&section.data);

        // Calculate raw size (aligned)
        let raw_size = align_up(section.data.len(), file_alignment);

        // Pad to alignment
        output.resize(current_offset + raw_size, 0);

        // Patch section header in the output
        let sh_offset = section_table_offset + i * 40;
        patch_section_header(&mut output, sh_offset, current_offset as u32, raw_size as u32);

        current_offset += raw_size;
    }

    // Step 4: Zero the security directory (strip digital signature)
    zero_security_directory(&mut output, oh_offset, is_64);

    // Step 5: Zero the checksum (Ghidra doesn't need it)
    zero_checksum(&mut output, oh_offset);

    Ok(output)
}

/// Patch the ImageBase field in the optional header.
fn patch_image_base(buf: &mut [u8], oh_offset: usize, is_64: bool, image_base: u64) {
    if is_64 {
        // PE32+: ImageBase at oh_offset + 0x18, 8 bytes
        let offset = oh_offset + 0x18;
        if offset + 8 <= buf.len() {
            buf[offset..offset + 8].copy_from_slice(&image_base.to_le_bytes());
        }
    } else {
        // PE32: ImageBase at oh_offset + 0x1C, 4 bytes
        let offset = oh_offset + 0x1C;
        if offset + 4 <= buf.len() {
            buf[offset..offset + 4].copy_from_slice(&(image_base as u32).to_le_bytes());
        }
    }
}

/// Patch PointerToRawData and SizeOfRawData in a section header.
fn patch_section_header(
    buf: &mut [u8],
    sh_offset: usize,
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
) {
    // Section header layout:
    //   +0x10: SizeOfRawData (4 bytes)
    //   +0x14: PointerToRawData (4 bytes)
    let raw_size_offset = sh_offset + 0x10;
    let raw_ptr_offset = sh_offset + 0x14;

    if raw_ptr_offset + 4 <= buf.len() {
        buf[raw_size_offset..raw_size_offset + 4]
            .copy_from_slice(&size_of_raw_data.to_le_bytes());
        buf[raw_ptr_offset..raw_ptr_offset + 4]
            .copy_from_slice(&pointer_to_raw_data.to_le_bytes());
    }
}

/// Zero the IMAGE_DIRECTORY_ENTRY_SECURITY data directory entry.
fn zero_security_directory(buf: &mut [u8], oh_offset: usize, is_64: bool) {
    // Data directories start at different offsets for PE32 vs PE32+
    let data_dir_start = oh_offset + if is_64 { 0x70 } else { 0x60 };
    // Security = index 4, each entry is 8 bytes (VirtualAddress + Size)
    let security_offset = data_dir_start + 4 * 8;

    if security_offset + 8 <= buf.len() {
        buf[security_offset..security_offset + 8].fill(0);
    }
}

/// Zero the CheckSum field in the optional header.
fn zero_checksum(buf: &mut [u8], oh_offset: usize) {
    // CheckSum is at oh_offset + 0x40 for both PE32 and PE32+
    let checksum_offset = oh_offset + 0x40;
    if checksum_offset + 4 <= buf.len() {
        buf[checksum_offset..checksum_offset + 4].fill(0);
    }
}

/// Round up to the next multiple of alignment.
fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(100, 0), 100);
    }
}
