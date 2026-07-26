use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::Path,
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
        GetLastError, RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
        OBJ_DONT_REPARSE, STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND,
    },
    Storage::FileSystem::{
        CreateFileW, FileBasicInfo, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DEVICE,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, OPEN_EXISTING,
        SYNCHRONIZE,
    },
    System::IO::IO_STATUS_BLOCK,
};

use super::{MutationMetadata, ObjectIdentity, ObjectKind, ObjectMetadata};

const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;
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
    let wide = nul_terminated(path.as_os_str())?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
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
    let handle = open_relative(
        parent.raw(),
        name,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    .map_err(RelativeOpenError::into_io)?;
    let metadata = metadata_by_handle(handle.as_raw_handle() as HANDLE)?;
    let file = File::from(handle);
    Ok((FileHandle(file), metadata))
}

pub(super) fn read_directory(
    directory: &DirectoryHandle,
    limit_plus_one: usize,
) -> io::Result<Vec<OsString>> {
    if limit_plus_one == 0 {
        return Ok(Vec::new());
    }
    let word_count = DIRECTORY_BUFFER_BYTES / size_of::<u64>();
    let mut buffer = vec![0_u64; word_count];
    let mut names = Vec::new();
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

            let mut wide_name = Vec::with_capacity(name_bytes / size_of::<u16>());
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
) -> io::Result<Vec<u8>> {
    let capacity = limit_plus_one.min(READ_BUFFER_BYTES);
    let mut output = Vec::with_capacity(capacity);
    let mut buffer = [0_u8; READ_BUFFER_BYTES];

    while output.len() < limit_plus_one {
        let remaining = limit_plus_one - output.len();
        let read_limit = remaining.min(READ_BUFFER_BYTES);
        let read = file.0.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
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

fn nul_terminated(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL code unit",
        ));
    }
    wide.push(0);
    Ok(wide)
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
    Io(io::Error),
}

impl RelativeOpenError {
    fn into_io(self) -> io::Error {
        match self {
            Self::NotFound => io::Error::new(io::ErrorKind::NotFound, "source leaf not found"),
            Self::Io(error) => error,
        }
    }
}
