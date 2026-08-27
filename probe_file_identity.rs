//! Probe: does the fd-binding read model hold on this platform?
//!
//! Scratch binary for PR #10214. Not part of the product; the probe branch is
//! deleted once the questions below are answered.
//!
//! The reader wants to open every log segment up front and keep reading through
//! those handles, so a writer rotation (`fs::rename`) mid-read cannot swap a
//! file out from under it. That is standard on POSIX. Windows is the open
//! question, in two directions:
//!
//!   Q1. Does an open handle BLOCK the writer's rename? If so the model is
//!       unusable there: a log query would stall the write hot path, which is
//!       worse than the bug being fixed.
//!   Q2. After a successful rename, does the already-open handle still read the
//!       ORIGINAL bytes? That is what makes the model correct.
//!   Q3. Is a stable file identity (device + inode, or Windows volume serial +
//!       file index) reachable on the MSRV toolchain? Needed to dedupe the case
//!       where a rotated-away segment is also picked up by the fresh listing.
//!
//! Exit code is 0 only when every check passes, so CI failure means the model
//! does not hold as assumed on that platform.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

fn main() {
    let dir = std::env::temp_dir().join(format!("zc-probe-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create probe dir");

    println!("platform: {}", std::env::consts::OS);
    println!("probe dir: {}", dir.display());
    println!();

    let mut failures = Vec::new();

    if let Err(e) = probe_rename_with_open_handle(&dir) {
        failures.push(format!("Q1/Q2 (rename with open handle): {e}"));
    }
    if let Err(e) = probe_file_identity(&dir) {
        failures.push(format!("Q3 (stable file identity): {e}"));
    }
    if let Err(e) = probe_reader_ordering(&dir) {
        failures.push(format!("Q4 (open-then-enumerate ordering): {e}"));
    }
    if let Err(e) = probe_delete_while_reading(&dir) {
        failures.push(format!("Q5 (delete/rotate while reading): {e}"));
    }

    let _ = fs::remove_dir_all(&dir);

    println!();
    if failures.is_empty() {
        println!("RESULT: all probes passed on {}", std::env::consts::OS);
    } else {
        println!("RESULT: {} probe(s) FAILED on {}", failures.len(), std::env::consts::OS);
        for f in &failures {
            println!("  FAIL {f}");
        }
        std::process::exit(1);
    }
}

/// Q1 + Q2: rename a file while holding a read handle, then read through that
/// handle. The writer must not be blocked, and the handle must still see the
/// bytes it was opened on.
fn probe_rename_with_open_handle(dir: &Path) -> Result<(), String> {
    println!("== Q1/Q2: rename while a read handle is open ==");

    let active = dir.join("active.jsonl");
    let archive = dir.join("active.20260101-000000.jsonl");
    let original = "line-one\nline-two\nline-three\n";
    fs::write(&active, original).map_err(|e| format!("write active: {e}"))?;

    // Reader opens the segment, as the fd-binding model would.
    let mut handle = File::open(&active).map_err(|e| format!("open active: {e}"))?;
    println!("  opened handle on {}", active.display());

    // Writer rotates underneath it.
    match fs::rename(&active, &archive) {
        Ok(()) => println!("  rename succeeded while the handle was open (Q1 OK)"),
        Err(e) => {
            return Err(format!(
                "rename was BLOCKED by the open handle: {e}. \
                 The fd-binding model would stall the writer on this platform."
            ));
        }
    }

    // Writer creates a fresh active file at the same path.
    let replacement = "brand-new-line\n";
    fs::write(&active, replacement).map_err(|e| format!("write replacement: {e}"))?;
    println!("  replacement file created at the original path");

    // The handle must still see the pre-rotation bytes.
    let mut via_handle = String::new();
    handle
        .read_to_string(&mut via_handle)
        .map_err(|e| format!("read via handle: {e}"))?;

    if via_handle == original {
        println!("  handle still reads the original bytes (Q2 OK)");
    } else {
        return Err(format!(
            "handle read {via_handle:?}, expected {original:?}. \
             The handle does not pin the original content."
        ));
    }

    // Seeking within the handle must also stay on the original content: the
    // reader resumes from a byte offset, not always from position zero.
    handle
        .seek(SeekFrom::Start(9))
        .map_err(|e| format!("seek: {e}"))?;
    let mut tail = String::new();
    handle
        .read_to_string(&mut tail)
        .map_err(|e| format!("read after seek: {e}"))?;
    if tail == "line-two\nline-three\n" {
        println!("  seek+read within the handle stays on original content");
    } else {
        return Err(format!("after seek got {tail:?}"));
    }

    // And the path now resolves to the replacement, confirming the two really
    // are different files.
    let via_path = fs::read_to_string(&active).map_err(|e| format!("read via path: {e}"))?;
    if via_path == replacement {
        println!("  the path resolves to the replacement, as expected");
    } else {
        return Err(format!("path read {via_path:?}, expected {replacement:?}"));
    }

    Ok(())
}

/// Q3: can a stable identity be read for a file, so the same inode reached by
/// two different paths can be recognised as one segment?
fn probe_file_identity(dir: &Path) -> Result<(), String> {
    println!();
    println!("== Q3: stable file identity ==");

    let a = dir.join("ident.jsonl");
    fs::write(&a, "x\n").map_err(|e| format!("write: {e}"))?;
    let b = dir.join("ident.20260101-000000.jsonl");

    let before = identity(&a)?;
    println!("  identity before rename: {before:?}");

    fs::rename(&a, &b).map_err(|e| format!("rename: {e}"))?;
    let after = identity(&b)?;
    println!("  identity after rename:  {after:?}");

    if before != after {
        return Err(format!(
            "identity changed across rename ({before:?} -> {after:?}); \
             it cannot be used to recognise a rotated-away segment"
        ));
    }
    println!("  identity is stable across rename (Q3 OK)");

    // A different file must not collide with it.
    let c = dir.join("other.jsonl");
    fs::write(&c, "y\n").map_err(|e| format!("write other: {e}"))?;
    let other = identity(&c)?;
    if other == after {
        return Err("two distinct files report the same identity".into());
    }
    println!("  a distinct file has a distinct identity");

    Ok(())
}

#[cfg(unix)]
fn identity(path: &Path) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).map_err(|e| format!("metadata: {e}"))?;
    Ok((m.dev(), m.ino()))
}

#[cfg(windows)]
fn identity(path: &Path) -> Result<(u64, u64), String> {
    // `std::os::windows::fs::MetadataExt::{volume_serial_number, file_index}`
    // is still behind the unstable `windows_by_handle` feature
    // (rust-lang/rust issue 63010), so it cannot be used on the MSRV
    // toolchain. Call GetFileInformationByHandle directly instead, which is
    // what those accessors wrap.
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

    let file = File::open(path).map_err(|e| format!("open for identity: {e}"))?;
    let mut info = ByHandleFileInformation::default();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as *mut _, &mut info) };
    if ok == 0 {
        return Err(format!(
            "GetFileInformationByHandle failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let index = ((info.file_index_high as u64) << 32) | (info.file_index_low as u64);
    Ok((info.volume_serial_number as u64, index))
}


/// Identity read from a live handle, which is what the reader does. The
/// path-based `identity` above opens its own handle; this one proves the same
/// call works while many handles are already held.
#[cfg(unix)]
fn identity_of(file: &File) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(|e| format!("metadata: {e}"))?;
    Ok((m.dev(), m.ino()))
}

#[cfg(windows)]
fn identity_of(file: &File) -> Result<(u64, u64), String> {
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
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as *mut _, &mut info) };
    if ok == 0 {
        return Err(format!(
            "GetFileInformationByHandle failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let index = ((info.file_index_high as u64) << 32) | (info.file_index_low as u64);
    Ok((info.volume_serial_number as u64, index))
}

/// Q5: can the writer's retention delete an archive that a reader currently
/// holds open?
///
/// This is the question the segment cap raised. A read holds up to eight
/// segment handles for its whole duration, and `run_retention` may want to
/// prune one of those archives in that window.
///
/// POSIX unlink only drops the directory entry, so the reader keeps reading the
/// inode and nothing conflicts. Windows only permits deletion when every open
/// handle was opened with FILE_SHARE_DELETE. If Rust's `File::open` does not
/// request it, `fs::remove_file` fails while a reader is running, and since
/// `remove_archive` is best-effort and only logs a warning, the visible symptom
/// is archives that never get pruned and a disk that grows without bound for as
/// long as queries keep arriving. That would be worse than the bug the handles
/// were introduced to fix, so it has to be measured rather than assumed.
fn probe_delete_while_reading(dir: &Path) -> Result<(), String> {
    println!();
    println!("== Q5: retention deleting an archive held open by a reader ==");

    let work = dir.join("retention");
    fs::create_dir_all(&work).map_err(|e| format!("mkdir: {e}"))?;

    // A realistic set: the active file plus seven archives, matching a default
    // install's retention window and the reader's open cap.
    let active = work.join("trace.jsonl");
    fs::write(&active, "live-1\n").map_err(|e| format!("write active: {e}"))?;
    let mut archives = Vec::new();
    for seq in 1..=7u64 {
        let path = work.join(format!("trace.{seq:010}-20260101-000000.jsonl"));
        fs::write(&path, format!("archived-{seq}\n"))
            .map_err(|e| format!("write archive {seq}: {e}"))?;
        archives.push(path);
    }

    // The reader opens everything it intends to scan, as `open_segment_set`
    // does, and keeps the handles alive for the rest of this function.
    let mut handles = Vec::new();
    handles.push(File::open(&active).map_err(|e| format!("open active: {e}"))?);
    for path in &archives {
        handles.push(File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?);
    }
    println!("  reader holds {} handles open", handles.len());

    // Identity is read through a live handle here, which is what the reader
    // does; the earlier probes only exercised that with a single file open.
    for (i, handle) in handles.iter().enumerate() {
        identity_of(handle).map_err(|e| format!("identity of handle {i}: {e}"))?;
    }
    println!("  identity readable for every open handle");

    // Retention prunes the oldest archive while those handles are live.
    let victim = &archives[0];
    match fs::remove_file(victim) {
        Ok(()) => println!("  retention deleted an open archive (Q5 OK)"),
        Err(e) => {
            return Err(format!(
                "deleting an open archive FAILED: {e}. On this platform a \
                 running query would block retention, so archives would \
                 accumulate while reads are in flight."
            ));
        }
    }

    // The reader must keep working on the deleted file's handle. Its handle is
    // index 1: index 0 is the active file.
    let mut via_handle = String::new();
    handles[1]
        .read_to_string(&mut via_handle)
        .map_err(|e| format!("read deleted archive via handle: {e}"))?;
    if via_handle != "archived-1\n" {
        return Err(format!(
            "handle on the deleted archive read {via_handle:?}, expected \
             \"archived-1\\n\""
        ));
    }
    println!("  the deleted archive is still readable through its open handle");

    // And it is really gone from the directory.
    if victim.exists() {
        return Err("the deleted archive still resolves by path".into());
    }
    println!("  the deleted archive no longer resolves by path");

    // Rotation must still work with the whole set held open, since retention
    // runs right after a rotation.
    let rotated = work.join("trace.0000000008-20260101-000000.jsonl");
    match fs::rename(&active, &rotated) {
        Ok(()) => println!("  rotation succeeded with all handles open"),
        Err(e) => {
            return Err(format!(
                "rotation was BLOCKED while handles were open: {e}"
            ));
        }
    }

    // Deleting the file that was just rotated away, while the reader still
    // holds its pre-rotation handle, is the combination retention actually
    // performs after a rotation.
    match fs::remove_file(&rotated) {
        Ok(()) => println!("  a rotated-then-pruned archive deletes cleanly (Q5 OK)"),
        Err(e) => {
            return Err(format!(
                "deleting a rotated archive still held open FAILED: {e}"
            ));
        }
    }

    let mut still_live = String::new();
    handles[0]
        .read_to_string(&mut still_live)
        .map_err(|e| format!("read rotated-and-deleted file via handle: {e}"))?;
    if still_live != "live-1\n" {
        return Err(format!(
            "handle read {still_live:?} after its file was rotated and deleted"
        ));
    }
    println!("  content stays readable after rotate-then-delete");

    Ok(())
}

/// Q4: the ordering the reader intends to use. Open the active file FIRST, then
/// enumerate archives. Either interleaving of a rotation must leave the full
/// stream reachable.
fn probe_reader_ordering(dir: &Path) -> Result<(), String> {
    println!();
    println!("== Q4: open-active-then-enumerate ordering ==");

    let work = dir.join("ordering");
    fs::create_dir_all(&work).map_err(|e| format!("mkdir: {e}"))?;
    let active = work.join("trace.jsonl");
    let older = work.join("trace.20260101-000000.jsonl");
    fs::write(&older, "old-1\n").map_err(|e| format!("write older: {e}"))?;
    fs::write(&active, "live-1\nlive-2\n").map_err(|e| format!("write active: {e}"))?;

    // Reader step 1: pin the active file.
    let mut active_handle = File::open(&active).map_err(|e| format!("open active: {e}"))?;
    let active_id = identity(&active)?;

    // Rotation lands here, in the window the current code cannot survive.
    let rotated = work.join("trace.20260102-000000.jsonl");
    fs::rename(&active, &rotated).map_err(|e| format!("rotate: {e}"))?;
    let mut fresh = File::create(&active).map_err(|e| format!("new active: {e}"))?;
    fresh
        .write_all(b"live-3\n")
        .map_err(|e| format!("write new active: {e}"))?;
    drop(fresh);

    // Reader step 2: enumerate archives, which now includes the rotated file.
    let mut archives = Vec::new();
    for entry in fs::read_dir(&work).map_err(|e| format!("read_dir: {e}"))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "trace.jsonl" {
            continue;
        }
        archives.push(entry.path());
    }
    archives.sort();
    println!("  enumerated {} archive(s)", archives.len());

    // The rotated file appears in the listing AND is the same inode as the
    // pinned handle. Without dedupe its lines would be counted twice.
    let mut dupes = 0;
    for path in &archives {
        if identity(path)? == active_id {
            dupes += 1;
            println!("  {} is the pinned active file under a new name", path.display());
        }
    }
    if dupes != 1 {
        return Err(format!(
            "expected exactly one archive to match the pinned identity, found {dupes}. \
             Dedupe by identity would not work as designed."
        ));
    }

    // Reading through the pinned handle still yields the pre-rotation content.
    let mut pinned = String::new();
    active_handle
        .read_to_string(&mut pinned)
        .map_err(|e| format!("read pinned: {e}"))?;
    if pinned != "live-1\nlive-2\n" {
        return Err(format!("pinned handle read {pinned:?}"));
    }
    println!("  pinned handle still yields the pre-rotation content");
    println!("  ordering + identity dedupe behaves as the design assumes (Q4 OK)");

    Ok(())
}
