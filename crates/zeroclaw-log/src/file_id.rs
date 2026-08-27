//! Stable file identity, used to recognise the same file reached by two paths.
//!
//! The writer replaces the active file by rename in three places: archive
//! rotation, the rolling trim, and schema migration. A reader that names
//! segments by path can therefore be handed one file and end up reading
//! another. Comparing identities lets it tell "this archive is the file I
//! already hold open, under its new name" from "this is a segment I have not
//! read yet".
//!
//! Cross-platform support was verified on Linux, macOS, and Windows before
//! this was written: an open handle does not block the writer's rename on any
//! of them, and the identity survives the rename everywhere.

use std::fs::File;
use std::io;

/// Opaque per-file identity: equal values mean the same underlying file.
///
/// Only equality is meaningful. The component values are platform-specific and
/// are not stable across reboots, so nothing outside this module should read
/// them or persist them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileId {
    volume: u64,
    index: u64,
}

/// Read the identity of an already-open file.
///
/// Taken from the handle rather than the path on purpose: a path can be
/// re-pointed between the open and the query, which is exactly the race this
/// type exists to close.
#[cfg(unix)]
pub(crate) fn file_id(file: &File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok(FileId {
        volume: meta.dev(),
        index: meta.ino(),
    })
}

/// Windows equivalent of the Unix `(dev, ino)` pair.
///
/// `std::os::windows::fs::MetadataExt::{volume_serial_number, file_index}`
/// would be the natural choice, but both are still behind the unstable
/// `windows_by_handle` feature and do not compile on the declared MSRV. This
/// calls the same Win32 entry point those accessors wrap.
#[cfg(windows)]
pub(crate) fn file_id(file: &File) -> io::Result<FileId> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    unsafe extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut std::ffi::c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut info = ByHandleFileInformation::default();
    // SAFETY: `file` is a live `File`, so its raw handle is valid for the
    // duration of this call, and `info` is a properly aligned local of the
    // exact layout the API fills in.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as *mut _, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileId {
        volume: u64::from(info.volume_serial_number),
        index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn identity_survives_a_rename_and_distinguishes_files() {
        let tmp = tempfile::tempdir().unwrap();
        let original = tmp.path().join("trace.jsonl");
        let renamed = tmp.path().join("trace.20260101-000000.jsonl");
        fs::write(&original, "a\n").unwrap();

        let before = file_id(&File::open(&original).unwrap()).unwrap();
        fs::rename(&original, &renamed).unwrap();
        let after = file_id(&File::open(&renamed).unwrap()).unwrap();
        assert_eq!(before, after, "a rename must not change which file this is");

        let other = tmp.path().join("other.jsonl");
        fs::write(&other, "b\n").unwrap();
        assert_ne!(
            before,
            file_id(&File::open(&other).unwrap()).unwrap(),
            "distinct files must have distinct identities"
        );
    }

    #[test]
    fn an_open_handle_survives_replacement_of_its_path() {
        // The property the segment reader depends on: once a file is open, a
        // writer rotation cannot substitute different content underneath it.
        use std::io::Read;

        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let archive = tmp.path().join("trace.20260101-000000.jsonl");
        fs::write(&active, "original\n").unwrap();

        let mut held = File::open(&active).unwrap();
        let held_id = file_id(&held).unwrap();

        // Rotation: the held file is renamed away and a new file takes the path.
        fs::rename(&active, &archive).unwrap();
        fs::write(&active, "replacement\n").unwrap();

        let mut via_handle = String::new();
        held.read_to_string(&mut via_handle).unwrap();
        assert_eq!(
            via_handle, "original\n",
            "the open handle must still see pre-rotation content"
        );

        assert_eq!(
            held_id,
            file_id(&File::open(&archive).unwrap()).unwrap(),
            "the rotated archive is the same file the handle holds"
        );
        assert_ne!(
            held_id,
            file_id(&File::open(&active).unwrap()).unwrap(),
            "the replacement at the same path is a different file"
        );
    }
}
