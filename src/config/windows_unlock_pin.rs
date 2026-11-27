use std::{
    fs::File,
    io,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{CreateFileW, ReplaceFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL},
};

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(super) fn private_file(path: &Path) -> io::Result<File> {
    // Only the owner may access the staged config, even when the directory is shared.
    let path = wide(path);
    let mut descriptor = null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows_sys::w!("D:P(A;;FA;;;OW)"),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            &security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        let file = if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(File::from_raw_handle(handle as _))
        };
        LocalFree(descriptor);
        file
    }
}

pub(super) fn replace(path: &Path, replacement: &Path) -> io::Result<()> {
    // With no ignore flags, ReplaceFile must preserve the destination DACL.
    let path = wide(path);
    let replacement = wide(replacement);
    if unsafe {
        ReplaceFileW(
            path.as_ptr(),
            replacement.as_ptr(),
            null(),
            0,
            null(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
