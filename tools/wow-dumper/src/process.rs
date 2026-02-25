/// Windows process lifecycle management.
///
/// Creates a suspended process, reads its memory, and controls
/// suspend/resume/terminate. Uses Win32 API for standard operations
/// and NT API (ntdll) for suspend/resume and PEB access.

use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::mem;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
use windows::Win32::System::Threading::{
    CreateProcessW, GetProcessId, TerminateProcess, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTUPINFOW,
};

// NT API functions linked directly from ntdll.
// The windows crate does not expose NtSuspendProcess/NtResumeProcess.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process_handle: *mut c_void) -> i32;
    fn NtResumeProcess(process_handle: *mut c_void) -> i32;
    fn NtQueryInformationProcess(
        process_handle: *mut c_void,
        info_class: u32,
        info: *mut c_void,
        info_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

/// PROCESS_BASIC_INFORMATION layout (matches both x86 and x64 via
/// pointer-sized fields with proper repr(C) alignment).
#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: *const u8,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from: usize,
}

/// PEB offset to ImageBaseAddress field.
#[cfg(target_pointer_width = "64")]
const PEB_IMAGE_BASE_OFFSET: usize = 0x10;
#[cfg(target_pointer_width = "32")]
const PEB_IMAGE_BASE_OFFSET: usize = 0x08;

/// A process created in suspended state.
pub struct SuspendedProcess {
    process_handle: HANDLE,
    thread_handle: HANDLE,
    image_base: u64,
    pid: u32,
    terminated: bool,
}

/// Description of a committed memory region.
#[derive(Debug)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
}

impl SuspendedProcess {
    /// Launch an executable in suspended state and read its image base.
    pub fn create(exe_path: &Path, verbose: bool) -> Result<Self> {
        let exe_str = exe_path
            .to_str()
            .context("Executable path is not valid UTF-8")?;
        let dir_str = exe_path
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(".");

        let exe_wide = to_wide_null(exe_str);
        let dir_wide = to_wide_null(dir_str);

        let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        // CREATE_SUSPENDED = 0x4
        let flags = PROCESS_CREATION_FLAGS(0x4);

        unsafe {
            CreateProcessW(
                windows::core::PCWSTR(exe_wide.as_ptr()),
                windows::core::PWSTR::null(),
                None,
                None,
                false,
                flags,
                None,
                windows::core::PCWSTR(dir_wide.as_ptr()),
                &si,
                &mut pi,
            )
            .context("CreateProcessW failed")?;
        }

        let process_handle = pi.hProcess;
        let thread_handle = pi.hThread;
        let pid = unsafe { GetProcessId(process_handle) };

        if verbose {
            eprintln!("[wow-dumper] Process created, reading PEB...");
        }

        // Resume briefly so the loader maps the image, then suspend again.
        // Some binaries need the loader to run before the image base is valid.
        unsafe {
            NtResumeProcess(handle_ptr(process_handle));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            NtSuspendProcess(handle_ptr(process_handle));
        }

        let image_base = read_image_base(process_handle)?;

        Ok(Self {
            process_handle,
            thread_handle,
            image_base,
            pid,
            terminated: false,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn process_handle(&self) -> HANDLE {
        self.process_handle
    }

    /// Suspend all threads in the process.
    pub fn suspend(&self) -> Result<()> {
        let status = unsafe { NtSuspendProcess(handle_ptr(self.process_handle)) };
        if status < 0 {
            bail!("NtSuspendProcess failed: NTSTATUS 0x{:08X}", status as u32);
        }
        Ok(())
    }

    /// Resume all threads in the process.
    pub fn resume(&self) -> Result<()> {
        let status = unsafe { NtResumeProcess(handle_ptr(self.process_handle)) };
        if status < 0 {
            bail!("NtResumeProcess failed: NTSTATUS 0x{:08X}", status as u32);
        }
        Ok(())
    }

    /// Read memory from the process at the given address.
    pub fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let bytes_read = self.read_memory_into(addr, &mut buf)?;
        buf.truncate(bytes_read);
        Ok(buf)
    }

    /// Read memory into the provided buffer. Returns bytes actually read.
    pub fn read_memory_into(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut bytes_read: usize = 0;
        unsafe {
            ReadProcessMemory(
                self.process_handle,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                Some(&mut bytes_read),
            )
            .context("ReadProcessMemory failed")?;
        }
        Ok(bytes_read)
    }

    /// Enumerate committed memory regions in the process.
    pub fn query_regions(&self) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let mut addr: u64 = 0;

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    Some(addr as *const c_void),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if ret == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                regions.push(MemoryRegion {
                    base: mbi.BaseAddress as u64,
                    size: mbi.RegionSize as u64,
                    protect: mbi.Protect.0,
                });
            }

            let next = addr.checked_add(mbi.RegionSize as u64);
            match next {
                Some(n) if n > addr => addr = n,
                _ => break,
            }
        }

        Ok(regions)
    }

    /// Terminate the child process.
    pub fn terminate(&mut self) {
        if !self.terminated {
            unsafe {
                let _ = TerminateProcess(self.process_handle, 1);
            }
            self.terminated = true;
        }
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.thread_handle);
            let _ = CloseHandle(self.process_handle);
        }
    }
}

/// Read the image base address from the process PEB.
fn read_image_base(process_handle: HANDLE) -> Result<u64> {
    // Get PEB address via NtQueryInformationProcess
    let mut pbi: ProcessBasicInformation = unsafe { mem::zeroed() };
    let mut return_length: u32 = 0;

    let status = unsafe {
        NtQueryInformationProcess(
            handle_ptr(process_handle),
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            mem::size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        )
    };

    if status < 0 {
        bail!(
            "NtQueryInformationProcess failed: NTSTATUS 0x{:08X}",
            status as u32
        );
    }

    let peb_addr = pbi.peb_base_address as u64;
    if peb_addr == 0 {
        bail!("PEB address is null");
    }

    // Read ImageBaseAddress from PEB
    let mut image_base_buf = [0u8; mem::size_of::<usize>()];
    let mut bytes_read: usize = 0;

    unsafe {
        ReadProcessMemory(
            process_handle,
            (peb_addr + PEB_IMAGE_BASE_OFFSET as u64) as *const c_void,
            image_base_buf.as_mut_ptr() as *mut c_void,
            image_base_buf.len(),
            Some(&mut bytes_read),
        )
        .context("Failed to read ImageBaseAddress from PEB")?;
    }

    // Interpret as pointer-sized little-endian integer
    let image_base = match mem::size_of::<usize>() {
        8 => u64::from_le_bytes(image_base_buf[..8].try_into().unwrap()),
        4 => u32::from_le_bytes(image_base_buf[..4].try_into().unwrap()) as u64,
        _ => bail!("Unsupported pointer size"),
    };

    if image_base == 0 {
        bail!("ImageBaseAddress is null");
    }

    Ok(image_base)
}

/// Convert a HANDLE to a raw pointer for ntdll calls.
fn handle_ptr(h: HANDLE) -> *mut c_void {
    h.0 as *mut c_void
}

/// Encode a string as null-terminated UTF-16 for Win32 API.
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
