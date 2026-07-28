use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

use rustix::fd::AsFd;
use rustix::fs::{fstat, openat, statat, AtFlags, Dir, Mode, OFlags, RawMode, Stat, CWD};

use super::{MutationMetadata, ObjectIdentity, ObjectKind, ObjectMetadata};

pub(super) struct DirectoryHandle {
    fd: OwnedFd,
}

pub(super) struct FileHandle {
    file: File,
}

pub(super) fn open_parent(path: &Path) -> io::Result<DirectoryHandle> {
    let fd = openat(
        CWD,
        path.as_os_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    Ok(DirectoryHandle { fd })
}

pub(super) fn probe_at(
    directory: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<Option<ObjectMetadata>> {
    match statat(directory.fd.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(metadata_from_stat(&stat))),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) => Err(io::Error::from_raw_os_error(error.raw_os_error())),
    }
}

pub(super) fn open_directory_at(
    directory: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<(DirectoryHandle, ObjectMetadata)> {
    let opened = open_directory(directory.fd.as_fd(), name)?;
    let metadata = metadata_file_descriptor(&opened.fd)?;
    Ok((opened, metadata))
}

pub(super) fn open_file_at(
    directory: &DirectoryHandle,
    name: &OsStr,
) -> io::Result<(FileHandle, ObjectMetadata)> {
    let fd = openat(
        directory.fd.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    let metadata = metadata_file_descriptor(&fd)?;
    Ok((
        FileHandle {
            file: File::from(fd),
        },
        metadata,
    ))
}

pub(super) fn read_directory(
    directory: &DirectoryHandle,
    limit_plus_one: usize,
) -> io::Result<Vec<OsString>> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(limit_plus_one)
        .map_err(io::Error::other)?;
    let reader = Dir::read_from(&directory.fd).map_err(errno)?;
    for entry in reader {
        let entry = entry.map_err(errno)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        entries.push(OsString::from_vec(name.to_vec()));
        if entries.len() >= limit_plus_one {
            break;
        }
    }
    Ok(entries)
}

pub(super) fn read_file_limited(
    file: &mut FileHandle,
    limit_plus_one: usize,
    mut on_chunk: impl FnMut(usize),
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut remaining = limit_plus_one;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let chunk_len = remaining.min(buffer.len());
        let read = file.file.read(&mut buffer[..chunk_len])?;
        if read == 0 {
            break;
        }
        bytes.try_reserve(read).map_err(io::Error::other)?;
        bytes.extend_from_slice(&buffer[..read]);
        remaining -= read;
        on_chunk(read);
    }
    Ok(bytes)
}

pub(super) fn metadata_file(file: &FileHandle) -> io::Result<ObjectMetadata> {
    metadata_file_descriptor(file.file.as_fd())
}

fn open_directory<Fd: AsFd>(directory: Fd, name: &OsStr) -> io::Result<DirectoryHandle> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    Ok(DirectoryHandle { fd })
}

fn metadata_file_descriptor<Fd: AsFd>(fd: Fd) -> io::Result<ObjectMetadata> {
    fstat(fd)
        .map(|stat| metadata_from_stat(&stat))
        .map_err(errno)
}

fn metadata_from_stat(stat: &Stat) -> ObjectMetadata {
    let raw_mode = stat.st_mode as RawMode;
    let kind = if rustix::fs::FileType::from_raw_mode(raw_mode).is_file() {
        ObjectKind::RegularFile
    } else if rustix::fs::FileType::from_raw_mode(raw_mode).is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::Other
    };
    let mut file_id = [0_u8; 16];
    file_id[..8].copy_from_slice(&stat_u64(stat.st_ino).to_ne_bytes());
    ObjectMetadata {
        kind,
        identity: ObjectIdentity {
            volume: stat_u64(stat.st_dev),
            file_id,
        },
        links: stat_u64(stat.st_nlink),
        size: u64::try_from(stat.st_size).unwrap_or(u64::MAX),
        mutation: MutationMetadata {
            modified_seconds: stat.st_mtime,
            modified_nanos: stat_i64(stat.st_mtime_nsec),
            changed_seconds: stat.st_ctime,
            changed_nanos: stat_i64(stat.st_ctime_nsec),
            attributes: stat.st_mode as u64,
        },
    }
}

fn stat_u64<T>(value: T) -> u64
where
    u64: TryFrom<T>,
{
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn stat_i64<T>(value: T) -> i64
where
    i64: TryFrom<T>,
{
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn errno(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}
