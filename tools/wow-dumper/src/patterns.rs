/// Byte patterns for Arxan decryption detection.
///
/// Patterns use `Some(byte)` for exact match and `None` for wildcard.
/// Derived from Arctium WoW-Launcher's pattern definitions.

/// x64 initialization pattern.
///
/// Matches a `mov dword [rip+disp32], 1` followed by two LEA instructions
/// and a CALL. This sequence appears after Arxan finishes decrypting
/// sections and writes 1 to an initialization flag.
///
/// ```asm
/// C7 05 xx xx xx xx 01 00 00 00   mov dword [rip+disp32], 1
/// 48 8D xx xx xx xx xx             lea reg, [rip+disp32]
/// 48 8D xx xx xx xx xx             lea reg, [rip+disp32]
/// E8 xx xx xx xx                   call rel32
/// 85                               test ...
/// ```
pub const INIT_X64: &[Option<u8>] = &[
    Some(0xC7),
    Some(0x05),
    None,
    None,
    None,
    None, // disp32 (offset to init flag)
    Some(0x01),
    Some(0x00),
    Some(0x00),
    Some(0x00), // immediate: 1
    Some(0x48),
    Some(0x8D),
    None,
    None,
    None,
    None,
    None, // lea reg, [rip+disp32]
    Some(0x48),
    Some(0x8D),
    None,
    None,
    None,
    None,
    None, // lea reg, [rip+disp32]
    Some(0xE8),
    None,
    None,
    None,
    None, // call rel32
    Some(0x85), // test ...
];

/// Offset within INIT_X64 where the RIP-relative disp32 starts.
/// The displacement is at pattern bytes [2..6].
pub const INIT_X64_DISP_OFFSET: usize = 2;

/// Length of the instruction containing the displacement.
/// `C7 05 disp32 01 00 00 00` = 10 bytes.
pub const INIT_X64_INSN_LEN: usize = 10;

/// Get the appropriate init pattern for a specific WoW build.
///
/// Currently returns `INIT_X64` for all builds. Future versions may
/// add a lookup table for build-specific patterns when Arxan changes
/// across versions.
pub fn get_pattern_for_build(_build: Option<u32>) -> &'static [Option<u8>] {
    INIT_X64
}

/// Scan `data` for a byte pattern with wildcard support.
///
/// Returns the offset of the first match, or `None` if not found.
pub fn scan(data: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    let pat_len = pattern.len();
    if pat_len == 0 || data.len() < pat_len {
        return None;
    }

    let limit = data.len() - pat_len + 1;
    'outer: for i in 0..limit {
        for (j, expected) in pattern.iter().enumerate() {
            if let Some(byte) = expected {
                if data[i + j] != *byte {
                    continue 'outer;
                }
            }
        }
        return Some(i);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_exact_match() {
        let data = [0x00, 0xC7, 0x05, 0xAA, 0xBB];
        let pattern = [Some(0xC7), Some(0x05)];
        assert_eq!(scan(&data, &pattern), Some(1));
    }

    #[test]
    fn scan_wildcard() {
        let data = [0xC7, 0x05, 0x12, 0x34, 0x56, 0x78, 0x01];
        let pattern = [Some(0xC7), Some(0x05), None, None, None, None, Some(0x01)];
        assert_eq!(scan(&data, &pattern), Some(0));
    }

    #[test]
    fn scan_no_match() {
        let data = [0x00, 0x01, 0x02];
        let pattern = [Some(0xFF)];
        assert_eq!(scan(&data, &pattern), None);
    }

    #[test]
    fn scan_empty_pattern() {
        let data = [0x00];
        let pattern: &[Option<u8>] = &[];
        assert_eq!(scan(&data, pattern), None);
    }
}
