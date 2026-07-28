use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::{Component, Path, PrefixComponent},
    ptr,
};

use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    },
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, RtlNtStatusToDosError, ERROR_INSUFFICIENT_BUFFER, HANDLE,
        INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, STATUS_NO_SUCH_FILE,
        STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
        STATUS_REPARSE_POINT_ENCOUNTERED,
    },
    Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetKernelObjectSecurity,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        GetTokenInformation, IsValidAcl, IsValidSecurityDescriptor, IsValidSid, TokenUser,
        ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, FileBasicInfo, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DEVICE,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_STANDARD_INFO, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    },
    System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
    System::IO::IO_STATUS_BLOCK,
};
use zeroize::Zeroizing;

use super::{MutationMetadata, ObjectIdentity, ObjectKind, ObjectMetadata};

const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;
const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 64 * 1024;
const FILE_READ_DATA: u32 = 1;

pub(super) struct DirectoryHandle(OwnedHandle);

pub(super) struct FileHandle(File);

impl DirectoryHandle {
    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle() as HANDLE
    }
}

impl FileHandle {
    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle() as HANDLE
    }
}

pub(super) fn open_parent(path: &Path) -> io::Result<DirectoryHandle> {
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix)) => prefix,
        _ => return Err(invalid_absolute_path()),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid_absolute_path());
    }
    let mut directory = open_root(prefix)?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid_absolute_path());
        };
        let (next, metadata) = open_ancestor_at(&directory, name)?;
        if metadata.kind != ObjectKind::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source ancestor is not a direct directory",
            ));
        }
        directory = next;
    }
    Ok(directory)
}

fn open_root(prefix: PrefixComponent<'_>) -> io::Result<DirectoryHandle> {
    use std::path::Prefix;

    if !matches!(
        prefix.kind(),
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _)
    ) {
        return Err(invalid_absolute_path());
    }
    let mut wide = prefix.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(invalid_absolute_path());
    }
    if !matches!(wide.last(), Some(unit) if *unit == b'\\' as u16 || *unit == b'/' as u16) {
        wide.push(b'\\' as u16);
    }
    wide.push(0);
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    let handle = DirectoryHandle(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
    let metadata = metadata_by_handle(handle.raw())?;
    if metadata.kind != ObjectKind::Directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration parent is not a directory",
        ));
    }
    Ok(handle)
}

fn open_ancestor_at(
    parent: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<(DirectoryHandle, ObjectMetadata)> {
    let handle = open_relative(
        parent.raw(),
        name,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    .map_err(RelativeOpenError::into_io)?;
    let metadata = metadata_by_handle(handle.as_raw_handle() as HANDLE)?;
    Ok((DirectoryHandle(handle), metadata))
}

pub(super) fn probe_at(
    parent: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<Option<ObjectMetadata>> {
    match open_relative(
        parent.raw(),
        name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    ) {
        Ok(handle) => metadata_by_handle(handle.as_raw_handle() as HANDLE).map(Some),
        Err(RelativeOpenError::NotFound) => Ok(None),
        Err(RelativeOpenError::ReparsePoint) => Ok(Some(reparse_point_metadata())),
        Err(RelativeOpenError::Io(error)) => Err(error),
    }
}

pub(super) fn open_directory_at(
    parent: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<(DirectoryHandle, ObjectMetadata)> {
    let handle = open_relative(
        parent.raw(),
        name,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    .map_err(RelativeOpenError::into_io)?;
    let metadata = metadata_by_handle(handle.as_raw_handle() as HANDLE)?;
    Ok((DirectoryHandle(handle), metadata))
}

pub(super) fn open_file_at(
    parent: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<(FileHandle, ObjectMetadata)> {
    open_file_at_with_access(
        parent,
        name,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
    )
}

pub(super) fn open_protected_file_at(
    parent: &DirectoryHandle,
    name: &OsStr,
    read_security: bool,
) -> io::Result<(FileHandle, ObjectMetadata)> {
    let security_access = if read_security { READ_CONTROL } else { 0 };
    open_file_at_with_access(
        parent,
        name,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE | security_access,
    )
}

fn open_file_at_with_access(
    parent: &DirectoryHandle,
    name: &OsStr,
    desired_access: u32,
) -> io::Result<(FileHandle, ObjectMetadata)> {
    let handle = open_relative(
        parent.raw(),
        name,
        desired_access,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    .map_err(RelativeOpenError::into_io)?;
    let metadata = metadata_by_handle(handle.as_raw_handle() as HANDLE)?;
    let file = File::from(handle);
    Ok((FileHandle(file), metadata))
}

pub(super) fn has_owner_restricted_dacl(file: &FileHandle) -> io::Result<bool> {
    let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut required = 0_u32;
    let initial = unsafe {
        GetKernelObjectSecurity(file.raw(), requested, ptr::null_mut(), 0, &mut required)
    };
    if initial != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || required == 0
        || required as usize > MAX_SECURITY_DESCRIPTOR_BYTES
    {
        return Err(io::Error::last_os_error());
    }

    let words = (required as usize)
        .checked_add(size_of::<usize>() - 1)
        .ok_or_else(|| io::Error::other("security descriptor size overflow"))?
        / size_of::<usize>();
    let mut descriptor = vec![0_usize; words];
    let loaded = unsafe {
        GetKernelObjectSecurity(
            file.raw(),
            requested,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if loaded == 0 {
        return Err(io::Error::last_os_error());
    }

    let descriptor = descriptor.as_mut_ptr().cast();
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Ok(false);
    }
    let mut owner = ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return Ok(false);
    }
    if !owner_is_current_process_user(owner)? {
        return Ok(false);
    }
    let mut dacl_present = 0;
    let mut dacl = ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Ok(false);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Ok(false);
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Ok(false);
    }
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Ok(false);
        }
        let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                    return Ok(false);
                }
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = (&raw const allowed.SidStart).cast_mut().cast();
                if unsafe { IsValidSid(sid) } == 0 || unsafe { EqualSid(owner, sid) } == 0 {
                    return Ok(false);
                }
            }
            ACCESS_DENIED_ACE_TYPE => {
                if usize::from(header.AceSize) < size_of::<ACCESS_DENIED_ACE>() {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn owner_is_current_process_user(owner: *mut core::ffi::c_void) -> io::Result<bool> {
    let mut raw_token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if raw_token.is_null() || raw_token == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "process token open returned an invalid handle",
        ));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token as RawHandle) };

    let mut required = 0_u32;
    let initial = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if initial != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || required < size_of::<TOKEN_USER>() as u32
    {
        return Err(io::Error::last_os_error());
    }
    let words = (required as usize)
        .checked_add(size_of::<usize>() - 1)
        .ok_or_else(|| io::Error::other("token user size overflow"))?
        / size_of::<usize>();
    let mut token_user = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            token_user.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*token_user.as_ptr().cast::<TOKEN_USER>() };
    if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Ok(false);
    }
    Ok(unsafe { EqualSid(owner, user.User.Sid) } != 0)
}

pub(super) fn read_directory(
    directory: &DirectoryHandle,
    limit_plus_one: usize,
) -> io::Result<Vec<OsString>> {
    if limit_plus_one == 0 {
        return Ok(Vec::new());
    }
    let word_count = DIRECTORY_BUFFER_BYTES / size_of::<u64>();
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(word_count)
        .map_err(io::Error::other)?;
    buffer.resize(word_count, 0_u64);
    let mut names = Vec::new();
    names
        .try_reserve_exact(limit_plus_one)
        .map_err(io::Error::other)?;
    let mut info_class = FileIdBothDirectoryRestartInfo;

    loop {
        let success = unsafe {
            GetFileInformationByHandleEx(
                directory.raw(),
                info_class,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_BYTES as u32,
            )
        };
        if success == 0 {
            let code = unsafe { GetLastError() };
            if code == windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES {
                break;
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        info_class = FileIdBothDirectoryInfo;

        let mut offset = 0_usize;
        loop {
            if offset
                .checked_add(size_of::<FILE_ID_BOTH_DIR_INFO>())
                .is_none_or(|end| end > DIRECTORY_BUFFER_BYTES)
            {
                return Err(invalid_directory_record());
            }

            let entry = unsafe {
                ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_BOTH_DIR_INFO>(),
                )
            };
            let name_bytes = entry.FileNameLength as usize;
            if !name_bytes.is_multiple_of(size_of::<u16>()) {
                return Err(invalid_directory_record());
            }
            let name_offset = offset
                .checked_add(offset_of!(FILE_ID_BOTH_DIR_INFO, FileName))
                .ok_or_else(invalid_directory_record)?;
            let name_end = name_offset
                .checked_add(name_bytes)
                .ok_or_else(invalid_directory_record)?;
            if name_end > DIRECTORY_BUFFER_BYTES {
                return Err(invalid_directory_record());
            }

            let name_units = name_bytes / size_of::<u16>();
            let mut wide_name = Vec::new();
            wide_name
                .try_reserve_exact(name_units)
                .map_err(io::Error::other)?;
            for byte_offset in (name_offset..name_end).step_by(size_of::<u16>()) {
                wide_name.push(unsafe {
                    ptr::read_unaligned(buffer.as_ptr().cast::<u8>().add(byte_offset).cast::<u16>())
                });
            }
            if wide_name.as_slice() != [b'.' as u16]
                && wide_name.as_slice() != [b'.' as u16, b'.' as u16]
            {
                names.push(OsString::from_wide(&wide_name));
                if names.len() >= limit_plus_one {
                    return Ok(names);
                }
            }

            if entry.NextEntryOffset == 0 {
                break;
            }
            let next = entry.NextEntryOffset as usize;
            if next < size_of::<FILE_ID_BOTH_DIR_INFO>() {
                return Err(invalid_directory_record());
            }
            offset = offset
                .checked_add(next)
                .ok_or_else(invalid_directory_record)?;
        }
    }

    Ok(names)
}

pub(super) fn read_file_limited(
    file: &mut FileHandle,
    limit_plus_one: usize,
    mut on_chunk: impl FnMut(usize),
) -> io::Result<Vec<u8>> {
    let capacity = limit_plus_one.min(READ_BUFFER_BYTES);
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(io::Error::other)?;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];

    while output.len() < limit_plus_one {
        let remaining = limit_plus_one - output.len();
        let read_limit = remaining.min(READ_BUFFER_BYTES);
        let read = file.0.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        output.try_reserve(read).map_err(io::Error::other)?;
        output.extend_from_slice(&buffer[..read]);
        on_chunk(read);
    }

    Ok(output)
}

pub(super) fn read_sensitive_file_limited(
    file: &mut FileHandle,
    limit_plus_one: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let capacity = limit_plus_one.min(READ_BUFFER_BYTES);
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(capacity)
        .map_err(io::Error::other)?;
    let mut buffer = Zeroizing::new([0_u8; READ_BUFFER_BYTES]);

    while output.len() < limit_plus_one {
        let remaining = limit_plus_one - output.len();
        let read_limit = remaining.min(READ_BUFFER_BYTES);
        let read = file.0.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        output.try_reserve(read).map_err(io::Error::other)?;
        output.extend_from_slice(&buffer[..read]);
    }

    Ok(output)
}

pub(super) fn metadata_file(file: &FileHandle) -> io::Result<ObjectMetadata> {
    metadata_by_handle(file.raw())
}

fn open_relative(
    parent: HANDLE,
    name: &OsStr,
    desired_access: u32,
    create_options: u32,
) -> Result<OwnedHandle, RelativeOpenError> {
    let mut wide = relative_leaf(name).map_err(RelativeOpenError::Io)?;
    let byte_len = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            RelativeOpenError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relative leaf name is too long",
            ))
        })?;
    let unicode_name = windows_sys::Win32::Foundation::UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut raw = ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            desired_access,
            &attributes,
            &mut io_status,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            create_options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        if status == STATUS_REPARSE_POINT_ENCOUNTERED {
            return Err(RelativeOpenError::ReparsePoint);
        }
        if matches!(
            status,
            STATUS_NO_SUCH_FILE | STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
        ) {
            return Err(RelativeOpenError::NotFound);
        }
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(RelativeOpenError::Io(io::Error::from_raw_os_error(
            code as i32,
        )));
    }
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(RelativeOpenError::Io(io::Error::other(
            "relative open returned an invalid handle",
        )));
    }

    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn reparse_point_metadata() -> ObjectMetadata {
    ObjectMetadata {
        kind: ObjectKind::Other,
        identity: ObjectIdentity {
            volume: 0,
            file_id: [0; 16],
        },
        links: 0,
        size: 0,
        mutation: MutationMetadata {
            modified_seconds: 0,
            modified_nanos: 0,
            changed_seconds: 0,
            changed_nanos: 0,
            attributes: u64::from(FILE_ATTRIBUTE_REPARSE_POINT),
        },
    }
}

fn metadata_by_handle(handle: HANDLE) -> io::Result<ObjectMetadata> {
    let basic: FILE_BASIC_INFO = query_handle_info(handle, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = query_handle_info(handle, FileStandardInfo)?;
    let identity: FILE_ID_INFO = query_handle_info(handle, FileIdInfo)?;

    let attributes =
        u64::from(basic.FileAttributes) | ((standard.DeletePending as u64) << u32::BITS);
    let rejected_attributes = u64::from(FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE);
    let kind = if attributes & rejected_attributes != 0 {
        ObjectKind::Other
    } else if standard.Directory {
        ObjectKind::Directory
    } else {
        ObjectKind::RegularFile
    };
    let (modified_seconds, modified_nanos) = windows_time_parts(basic.LastWriteTime);
    let (changed_seconds, changed_nanos) = windows_time_parts(basic.ChangeTime);
    let size = u64::try_from(standard.EndOfFile)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative source file size"))?;

    Ok(ObjectMetadata {
        kind,
        identity: ObjectIdentity {
            volume: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        links: standard.NumberOfLinks.into(),
        size,
        mutation: MutationMetadata {
            modified_seconds,
            modified_nanos,
            changed_seconds,
            changed_nanos,
            attributes,
        },
    })
}

fn query_handle_info<T: Default>(handle: HANDLE, class: i32) -> io::Result<T> {
    let mut output = T::default();
    let success = unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            (&mut output as *mut T).cast(),
            size_of::<T>() as u32,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(output)
    }
}

fn windows_time_parts(value: i64) -> (i64, i64) {
    const TICKS_PER_SECOND: i64 = 10_000_000;
    const NANOS_PER_TICK: i64 = 100;
    (
        value.div_euclid(TICKS_PER_SECOND),
        value.rem_euclid(TICKS_PER_SECOND) * NANOS_PER_TICK,
    )
}

fn invalid_absolute_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "source path is not an absolute normalized disk or UNC path",
    )
}

fn relative_leaf(value: &OsStr) -> io::Result<Vec<u16>> {
    let wide = value.encode_wide().collect::<Vec<_>>();
    if wide.is_empty()
        || wide == [b'.' as u16]
        || wide == [b'.' as u16, b'.' as u16]
        || wide.iter().any(|unit| {
            *unit == 0 || *unit == b'/' as u16 || *unit == b'\\' as u16 || *unit == b':' as u16
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source name is not a single relative leaf",
        ));
    }
    Ok(wide)
}

fn invalid_directory_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows returned an invalid directory record",
    )
}

enum RelativeOpenError {
    NotFound,
    ReparsePoint,
    Io(io::Error),
}

impl RelativeOpenError {
    fn into_io(self) -> io::Error {
        match self {
            Self::NotFound => io::Error::new(io::ErrorKind::NotFound, "source leaf not found"),
            Self::ReparsePoint => {
                io::Error::new(io::ErrorKind::InvalidData, "source leaf is a reparse point")
            }
            Self::Io(error) => error,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER},
        Security::{
            AddAccessAllowedAce, CopySid, CreateWellKnownSid, GetFileSecurityW, GetLengthSid,
            GetSecurityDescriptorOwner, InitializeAcl, InitializeSecurityDescriptor,
            SetFileSecurityW, SetSecurityDescriptorControl, SetSecurityDescriptorDacl, WinWorldSid,
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_DESCRIPTOR,
            SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
        Storage::FileSystem::FILE_GENERIC_READ,
        System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
    };

    use super::*;
    use crate::config::source_snapshot::{
        load_protected_file_snapshot, ProtectedFilePolicy, ProtectedFileSnapshotError,
    };

    #[derive(Clone, Copy)]
    enum DaclShape {
        OwnerOnly,
        OwnerAndWorld,
        Null,
    }

    #[test]
    fn private_snapshot_requires_protected_owner_only_dacl() {
        let directory = TempDir::new().expect("create test directory");
        let path = directory.path().join("private-key.pem");
        fs::write(&path, b"private material").expect("write private material");

        set_test_dacl(&path, DaclShape::OwnerOnly, false);
        assert!(matches!(
            load_protected_file_snapshot(&path, 1024, ProtectedFilePolicy::OwnerRestricted),
            Err(ProtectedFileSnapshotError::Untrusted)
        ));

        set_test_dacl(&path, DaclShape::OwnerOnly, true);
        assert_eq!(
            load_protected_file_snapshot(&path, 1024, ProtectedFilePolicy::OwnerRestricted)
                .expect("load owner-restricted material")
                .into_bytes()
                .as_slice(),
            b"private material"
        );

        set_test_dacl(&path, DaclShape::OwnerAndWorld, true);
        assert!(matches!(
            load_protected_file_snapshot(&path, 1024, ProtectedFilePolicy::OwnerRestricted),
            Err(ProtectedFileSnapshotError::Untrusted)
        ));

        set_test_dacl(&path, DaclShape::Null, true);
        assert!(matches!(
            load_protected_file_snapshot(&path, 1024, ProtectedFilePolicy::OwnerRestricted),
            Err(ProtectedFileSnapshotError::Untrusted)
        ));
    }

    #[test]
    fn stable_snapshot_does_not_apply_private_key_dacl_policy() {
        let directory = TempDir::new().expect("create test directory");
        let path = directory.path().join("certificate.pem");
        fs::write(&path, b"public material").expect("write public material");
        set_test_dacl(&path, DaclShape::OwnerAndWorld, true);

        assert_eq!(
            load_protected_file_snapshot(&path, 1024, ProtectedFilePolicy::Stable)
                .expect("load public material")
                .into_bytes()
                .as_slice(),
            b"public material"
        );
    }

    fn set_test_dacl(path: &Path, shape: DaclShape, protected: bool) {
        let wide_path = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let owner = file_owner(wide_path.as_ptr());
        let owner_sid = owner.as_ptr().cast_mut().cast();
        let owner_bytes = unsafe { GetLengthSid(owner_sid) } as usize;

        let mut world = vec![0_usize; SECURITY_MAX_SID_SIZE as usize / size_of::<usize>() + 1];
        let mut world_bytes = SECURITY_MAX_SID_SIZE;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinWorldSid,
                    ptr::null_mut(),
                    world.as_mut_ptr().cast(),
                    &mut world_bytes,
                )
            },
            0,
            "create world SID: {}",
            io::Error::last_os_error()
        );

        let ace_overhead = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
        let acl_bytes = size_of::<ACL>()
            + if matches!(shape, DaclShape::Null) {
                0
            } else {
                ace_overhead + owner_bytes
            }
            + if matches!(shape, DaclShape::OwnerAndWorld) {
                ace_overhead + world_bytes as usize
            } else {
                0
            };
        let mut acl = vec![0_usize; acl_bytes.div_ceil(size_of::<usize>())];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        if !matches!(shape, DaclShape::Null) {
            assert_ne!(
                unsafe { InitializeAcl(acl_ptr, acl_bytes as u32, ACL_REVISION) },
                0,
                "initialize ACL: {}",
                io::Error::last_os_error()
            );
            assert_ne!(
                unsafe { AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_GENERIC_READ, owner_sid) },
                0,
                "add owner ACE: {}",
                io::Error::last_os_error()
            );
            if matches!(shape, DaclShape::OwnerAndWorld) {
                assert_ne!(
                    unsafe {
                        AddAccessAllowedAce(
                            acl_ptr,
                            ACL_REVISION,
                            FILE_GENERIC_READ,
                            world.as_mut_ptr().cast(),
                        )
                    },
                    0,
                    "add world ACE: {}",
                    io::Error::last_os_error()
                );
            }
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        assert_ne!(
            unsafe {
                InitializeSecurityDescriptor(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                )
            },
            0,
            "initialize security descriptor: {}",
            io::Error::last_os_error()
        );
        let dacl = if matches!(shape, DaclShape::Null) {
            ptr::null()
        } else {
            acl_ptr
        };
        assert_ne!(
            unsafe {
                SetSecurityDescriptorDacl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    1,
                    dacl,
                    0,
                )
            },
            0,
            "set descriptor DACL: {}",
            io::Error::last_os_error()
        );
        assert_ne!(
            unsafe {
                SetSecurityDescriptorControl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    SE_DACL_PROTECTED,
                    if protected { SE_DACL_PROTECTED } else { 0 },
                )
            },
            0,
            "set DACL protection: {}",
            io::Error::last_os_error()
        );
        let protection = if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    wide_path.as_ptr(),
                    DACL_SECURITY_INFORMATION | protection,
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                )
            },
            0,
            "set file DACL: {}",
            io::Error::last_os_error()
        );
    }

    fn file_owner(path: *const u16) -> Vec<usize> {
        let mut required = 0_u32;
        assert_eq!(
            unsafe {
                GetFileSecurityW(
                    path,
                    OWNER_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_INSUFFICIENT_BUFFER);
        let mut descriptor = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetFileSecurityW(
                    path,
                    OWNER_SECURITY_INFORMATION,
                    descriptor.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            },
            0,
            "read file owner: {}",
            io::Error::last_os_error()
        );
        let mut owner = ptr::null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorOwner(
                    descriptor.as_mut_ptr().cast(),
                    &mut owner,
                    &mut defaulted,
                )
            },
            0,
            "read owner SID: {}",
            io::Error::last_os_error()
        );
        let owner_bytes = unsafe { GetLengthSid(owner) };
        let mut copy = vec![0_usize; (owner_bytes as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe { CopySid(owner_bytes, copy.as_mut_ptr().cast(), owner) },
            0,
            "copy owner SID: {}",
            io::Error::last_os_error()
        );
        copy
    }
}
