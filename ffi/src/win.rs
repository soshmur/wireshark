//! Windows privilege and DLL probes. This module is the only `unsafe` in the tree.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `%SystemRoot%\System32\Npcap` — where Npcap installs `wpcap.dll` unless
/// WinPcap-compatible mode was chosen. Adding it to the DLL search path makes
/// both installation modes work.
pub fn npcap_dir() -> Option<String> {
    let mut buf = [0u16; 512];
    // SAFETY: the length passed equals the buffer length; the call writes at
    // most that many u16s.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return None;
    }
    let sys = String::from_utf16_lossy(&buf[..n as usize]);
    Some(format!("{sys}\\Npcap"))
}

pub fn prepare_dll_search_path() {
    if let Some(dir) = npcap_dir() {
        let wide = to_wide(&dir);
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        unsafe {
            SetDllDirectoryW(wide.as_ptr());
        }
    }
}

pub fn load_wpcap() -> Result<(), String> {
    let wide = to_wide("wpcap.dll");
    // SAFETY: `wide` is NUL-terminated and outlives the call; the module handle
    // is released below.
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    if module.is_null() {
        return Err(format!(
            "wpcap.dll could not be loaded (looked in {}, then the standard search path)",
            npcap_dir().unwrap_or_else(|| "System32\\Npcap".to_string())
        ));
    }
    // SAFETY: `module` is a valid handle returned by LoadLibraryW above.
    unsafe {
        FreeLibrary(module);
    }
    Ok(())
}

pub fn is_elevated() -> Option<bool> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing;
    // `token` is a valid out-pointer.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return None;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned: u32 = 0;
    // SAFETY: `elevation` is a correctly sized, writable buffer for the
    // TokenElevation class, and the size passed matches it.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            ptr::addr_of_mut!(elevation).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` was opened above and is closed exactly once.
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return None;
    }
    Some(elevation.TokenIsElevated != 0)
}
