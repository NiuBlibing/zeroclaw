//! Paginated stream reader for the JSONL log file.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::event::LogEvent;
use crate::file_id::{FileId, file_id};

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// RFC 3339 lower bound (inclusive).
    pub since_ts: Option<String>,
    /// RFC 3339 upper bound (exclusive — used by pagination cursor).
    pub until_ts: Option<String>,
    /// Match against the cursor's id when `until_ts` ties.
    pub until_id: Option<String>,
    pub until_line_offset: Option<u64>,
    /// Match exact event.action (case-insensitive).
    pub action: Option<String>,
    /// Match exact event.category (case-insensitive).
    pub category: Option<String>,
    /// Match exact event.outcome (case-insensitive).
    pub outcome: Option<String>,
    /// Minimum severity_number.
    pub severity_min: Option<u8>,
    /// Match exact trace_id.
    pub trace_id: Option<String>,
    /// Substring search across message + attributes.
    pub q: Option<String>,
    /// Hide events with event.category == "internal" by default.
    pub hide_internal: bool,
    /// Per-attribution-field exact-match constraints. Key is any
    /// `zeroclaw.*` attribution name. Empty map = no attribution filter.
    pub field_eq: BTreeMap<String, String>,
}

/// Segment-aware pagination cursor. Identifies a byte position within a named
/// segment file. Pass back as `?until_segment_cursor=` on the next `/api/logs`
/// request to walk older pages across segment boundaries.
///
/// The `anchor_id` field pins the cursor to the exact log event at `off`. When
/// the reader resolves the cursor, it checks that the first non-empty JSONL line
/// at or after `off` in the named segment has `id == anchor_id`. If not — which
/// means the active file was rotated and a new file with the same basename was
/// created since the cursor was issued — the reader searches all segments for the
/// anchor event and rebases the cursor to the segment and offset that contains it.
/// This prevents duplicating or skipping events across an active-file rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentCursor {
    /// Basename of the segment file, e.g. `runtime-trace.jsonl` for the active
    /// file or `runtime-trace.20260101-120000.jsonl` for an archive.
    pub seg: String,
    /// Byte offset within that segment: only lines whose `line_byte_end` is
    /// strictly less than this offset are included on the next page (same
    /// semantics as [`LogFilter::until_line_offset`]).
    pub off: u64,
    /// ID of the oldest event on the page that produced this cursor (i.e. the
    /// event immediately before the `off` boundary in file order). Used to detect
    /// whether the named segment was replaced since the cursor was issued.
    /// `None` for cursors issued by older daemons that predate this field.
    pub anchor_id: Option<String>,
}

impl SegmentCursor {
    /// Parse from wire format `"<seg_basename>:<byte_offset>"` (legacy, no
    /// anchor) or `"<seg_basename>:<byte_offset>:<anchor_id>"` (current).
    /// Returns `None` on any parse error.
    ///
    /// Disambiguation: the offset is always a decimal integer, so a trailing
    /// field that parses as `u64` is the offset (legacy form) and one that does
    /// not is the anchor id (current form).
    pub fn from_wire(s: &str) -> Option<Self> {
        let (head, tail) = s.rsplit_once(':')?;
        let (seg, off, anchor_id) = match tail.parse::<u64>() {
            // Legacy `<seg>:<off>` — the trailing field is the offset.
            Ok(off) => (head, off, None),
            // Current `<seg>:<off>:<anchor>` — the trailing field is the anchor.
            Err(_) => {
                let (seg, off_str) = head.rsplit_once(':')?;
                (seg, off_str.parse().ok()?, Some(tail.to_owned()))
            }
        };
        if seg.is_empty() {
            return None;
        }
        Some(Self {
            seg: seg.to_owned(),
            off,
            anchor_id,
        })
    }

    /// Serialize to wire format.
    pub fn to_wire(&self) -> String {
        match &self.anchor_id {
            Some(id) => format!("{}:{}:{}", self.seg, self.off, id),
            None => format!("{}:{}", self.seg, self.off),
        }
    }
}

/// One page returned by [`load_page`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPage {
    pub events: Vec<LogEvent>,
    #[deprecated(
        since = "0.8.0",
        note = "tie-breaks by lexicographic id and can silently drop events; \
                use `next_cursor_line_offset` / `until_line_offset` instead. \
                Removal tracked in zeroclaw-labs/zeroclaw#8012."
    )]
    pub next_cursor: Option<(String, String)>,
    /// Byte offset past the OLDEST event on this page (the event in
    /// file order that is earliest among this page's matches). Pass
    /// back as [`LogFilter::until_line_offset`] on the next request to
    /// walk older pages. `None` when the page is empty.
    ///
    /// For multi-segment deployments, this is `None` when the oldest event is
    /// in an archive file rather than the active file; use
    /// [`Self::next_segment_cursor`] in that case.
    pub next_cursor_line_offset: Option<u64>,
    /// Segment-aware cursor for the oldest event on this page. Pass back as
    /// `?until_segment_cursor=` on the next request to walk older pages across
    /// segment boundaries. Supersedes `next_cursor_line_offset` for
    /// multi-segment deployments. `None` when the page is empty.
    pub next_segment_cursor: Option<String>,
    /// True when the file was fully scanned. UI uses this to disable
    /// "load older" affordances.
    pub at_end: bool,
}

#[allow(deprecated)] // we still populate `next_cursor` for backwards compat
pub fn load_page(path: &Path, filter: &LogFilter, limit: usize) -> Result<LogPage> {
    let limit = limit.clamp(1, 10_000);

    if !path.exists() {
        return Ok(LogPage {
            events: Vec::new(),
            next_cursor: None,
            next_cursor_line_offset: None,
            next_segment_cursor: None,
            at_end: true,
        });
    }

    let file = File::open(path).with_context(|| format!("opening log: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut window: VecDeque<(LogEvent, u64)> = VecDeque::with_capacity(limit + 1);
    let needle = filter.q.as_deref().map(|s| s.to_ascii_lowercase());
    // `dropped_older` records whether we ever pushed past `limit` and
    // had to evict the oldest matching event. If false at the end, every
    // matching event in the file is in `window` — meaning there are no
    // older results the caller could page back to.
    let mut dropped_older = false;
    // `stopped_early` records whether we bailed out of the scan because
    // we hit the caller's `until_line_offset` cap. When true, there are
    // older events past the cursor and we must report `at_end = false`.
    let mut stopped_early = false;
    // Cap on `line_byte_end`. Lines whose end reaches or exceeds this
    // byte offset belong to a newer page (or are uninteresting partial
    // reads at file end) and stop the scan. `None` means "scan the
    // entire file".
    let until_line_offset = filter.until_line_offset;
    // Running byte offset of the next line we'll read. Starts at 0.
    // We track it manually instead of using `reader.stream_position()`
    // because that method interacts poorly with the `BufReader` borrow
    // we already hold.
    let mut next_byte_offset: u64 = 0;

    let mut buf = String::new();
    loop {
        buf.clear();
        let bytes_read = reader.read_line(&mut buf).context("reading log line")?;
        if bytes_read == 0 {
            break;
        }
        let line_byte_end = next_byte_offset + bytes_read as u64;

        // Stop scanning as soon as we cross the caller's cursor. This
        // is checked BEFORE parsing so we never even attempt to decode
        // JSON for lines that belong to a newer page.
        if let Some(cap) = until_line_offset
            && line_byte_end >= cap
        {
            stopped_early = true;
            break;
        }

        let trimmed = buf.trim();
        next_byte_offset = line_byte_end;

        if trimmed.is_empty() {
            continue;
        }

        let event: LogEvent = match serde_json::from_str(trimmed) {
            Ok(event) => event,
            Err(err) => {
                tracing::trace!(
                    target: "zeroclaw_log",
                    error = ?err,
                    "log: skipping malformed JSONL line"
                );
                continue;
            }
        };

        if !matches_filter(&event, filter, needle.as_deref()) {
            continue;
        }

        window.push_back((event, line_byte_end));
        if window.len() > limit {
            window.pop_front();
            dropped_older = true;
        }
    }

    // The byte-offset cursor must point at the OLDEST event currently
    // in the window — that's the event a follow-up page would resume
    // from in file order. We snapshot its offset before stripping the
    // offsets out of the deque below.
    let oldest_line_offset = window.front().map(|(_, end)| *end);

    let mut events: Vec<LogEvent> = window.into_iter().map(|(e, _)| e).collect();
    // Reverse so newest is first.
    events.reverse();

    // next_cursor is the OLDEST event in the page (the last one in
    // newest-first ordering = events.last()). Caller uses it as
    // `until_ts` / `until_id` for the next "load older" request when
    // they haven't upgraded to byte-offset cursors yet.
    let next_cursor = events.last().map(|e| (e.timestamp.clone(), e.id.clone()));

    let at_end = !dropped_older && !stopped_early || events.is_empty();

    Ok(LogPage {
        events,
        next_cursor,
        next_cursor_line_offset: oldest_line_offset,
        next_segment_cursor: None,
        at_end,
    })
}

fn matches_filter(event: &LogEvent, filter: &LogFilter, needle: Option<&str>) -> bool {
    if filter.hide_internal && event.event.category == "internal" {
        return false;
    }
    if let Some(ref since) = filter.since_ts
        && event.timestamp.as_str() < since.as_str()
    {
        return false;
    }
    if let Some(ref until) = filter.until_ts {
        // Cursor pagination: include events strictly older than the
        // cursor. If the timestamps tie, fall back to id ordering for
        // deterministic pagination.
        match event.timestamp.as_str().cmp(until.as_str()) {
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {
                if let Some(ref until_id) = filter.until_id
                    && event.id.as_str() >= until_id.as_str()
                {
                    return false;
                }
            }
            std::cmp::Ordering::Less => {}
        }
    }
    if let Some(ref action) = filter.action
        && !event.event.action.eq_ignore_ascii_case(action)
    {
        return false;
    }
    if let Some(ref category) = filter.category
        && !event.event.category.eq_ignore_ascii_case(category)
    {
        return false;
    }
    if let Some(ref outcome) = filter.outcome
        && !event.event.outcome.eq_ignore_ascii_case(outcome)
    {
        return false;
    }
    if let Some(min) = filter.severity_min
        && event.severity_number < min
    {
        return false;
    }
    for (key, want) in &filter.field_eq {
        if event.zeroclaw.get(key) != Some(want.as_str()) {
            return false;
        }
    }
    if let Some(ref tid) = filter.trace_id
        && event.trace_id.as_deref() != Some(tid.as_str())
    {
        return false;
    }
    if let Some(n) = needle {
        let hay_msg = event.message.as_deref().unwrap_or("").to_ascii_lowercase();
        let hay_attrs = event.attributes.to_string().to_ascii_lowercase();
        if !hay_msg.contains(n) && !hay_attrs.contains(n) {
            return false;
        }
    }
    true
}

/// Check whether the event at or after `anchor_off` in `seg_path` has the
/// expected `anchor_id`. Returns `false` on any I/O or parse error, on a
/// missing file, or when the first non-empty JSON line found does not match.
fn anchor_matches_offset(seg: &OpenSegment, anchor_off: u64, anchor_id: &str) -> bool {
    // Seek to the line that ends at anchor_off: that line starts somewhere
    // before it. To find the exact line, seek to anchor_off minus a generous
    // window (line is always ≤ 128 KiB) and scan forward. For simplicity,
    // seek to the start of the line by scanning from the previous offset:
    // the cursor was produced as the byte-end of the oldest-matching line,
    // so the line itself ends exactly at anchor_off — we seek before it.
    let seek_pos = anchor_off.saturating_sub(512 * 1024);
    let Ok(mut reader) = seg.reader_at(seek_pos) else {
        return false;
    };
    let mut buf = String::new();
    let mut byte_off = seek_pos;
    loop {
        buf.clear();
        let n = match reader.read_line(&mut buf) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if n == 0 {
            return false;
        }
        byte_off += n as u64;
        if byte_off < anchor_off {
            continue;
        }
        // This is (or is past) the line that produced the cursor.
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        return serde_json::from_str::<LogEvent>(trimmed)
            .map(|e| e.id == anchor_id)
            .unwrap_or(false);
    }
}

/// Search all segments for the event with `anchor_id`. Returns the
/// segment index and the byte-end offset of that line, suitable for
/// use as a new `(cursor_idx, cursor_off)` that excludes the anchor
/// event itself (so the next page returns events older than it).
fn find_anchor_in_segments(segs: &[OpenSegment], anchor_id: &str) -> Option<(usize, u64)> {
    for (i, seg) in segs.iter().enumerate() {
        let Ok(mut reader) = seg.reader_at(0) else {
            continue;
        };
        let mut byte_off: u64 = 0;
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = match reader.read_line(&mut buf) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            let line_end = byte_off + n as u64;
            let trimmed = buf.trim();
            if !trimmed.is_empty()
                && serde_json::from_str::<LogEvent>(trimmed)
                    .map(|e| e.id == anchor_id)
                    .unwrap_or(false)
            {
                return Some((i, line_end));
            }
            byte_off = line_end;
        }
    }
    None
}

pub fn find_event_by_id(path: &Path, id: &str) -> Result<Option<LogEvent>> {
    if !path.exists() {
        return Ok(None);
    }
    let file = File::open(path).with_context(|| format!("opening log: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut found: Option<LogEvent> = None;
    for line in reader.lines() {
        let line = line.context("reading log line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<LogEvent>(trimmed)
            && event.id == id
        {
            found = Some(event); // Don't break — last write wins for duplicate ids.
        }
    }
    Ok(found)
}

/// Helper for the gateway: the path the writer is configured to use.
#[must_use]
pub fn current_log_path() -> Option<PathBuf> {
    crate::writer::runtime_trace_path()
}

/// Split `foo.jsonl` into `("foo", ".jsonl")`. A name with no dot, or one
/// whose only dot is leading, keeps an empty extension.
pub(crate) fn split_base_ext(file_name: &str) -> (&str, &str) {
    match file_name.rfind('.') {
        Some(i) if i > 0 => (&file_name[..i], &file_name[i..]),
        _ => (file_name, ""),
    }
}

/// True when `s` is exactly a `YYYYMMDD-HHMMSS` stamp: 8 digits, `-`, 6 digits.
pub(crate) fn is_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 15
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'-'
        && b[9..].iter().all(u8::is_ascii_digit)
}

/// Width of the zero-padded sequence prefix in a numbered archive name.
///
/// Ten digits keeps the prefix distinguishable from a bare `YYYYMMDD` stamp
/// (eight digits) and leaves headroom far beyond any realistic rotation count.
pub(crate) const SEQ_WIDTH: usize = 10;

/// Ordering key for one archive, derived from its name rather than its mtime.
///
/// Rotation writes the sequence number into the archive name, so segment order
/// is fixed at write time and does not depend on when a reader enumerates the
/// directory. That is what makes the order survive several rotations landing
/// during a single read: an mtime-based key is an observation made at
/// enumeration time, and two rotations can leave it describing an order that
/// no longer holds.
///
/// Archives written before sequence numbers existed carry no number. They are
/// ordered by mtime and sort before every numbered archive, which is correct
/// because they can only predate the upgrade that introduced numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ArchiveOrder {
    /// Pre-numbering archive, ordered by mtime. Sorts before all numbered ones.
    Legacy(SystemTime),
    /// Sequence number taken from the archive name.
    Seq(u64),
}

/// Parse the sequence number out of an archive name core.
///
/// Accepts the numbered form `<seq>-<stamp>`; returns `None` for the legacy
/// `<stamp>` and `<stamp>.<counter>` forms, which carry no number.
pub(crate) fn archive_seq(core: &str) -> Option<u64> {
    let (seq, rest) = core.split_once('-')?;
    // A stamp is `YYYYMMDD-HHMMSS`, whose own first segment is 8 digits. The
    // sequence prefix is zero-padded to 10, so the two cannot be confused.
    if seq.len() != SEQ_WIDTH || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // The remainder must be a bare stamp; otherwise the leading digits are
    // part of something else and this is not a numbered archive.
    if !is_stamp(rest) {
        return None;
    }
    seq.parse().ok()
}

/// True when `core` is a stamp this writer generates, optionally with a
/// same-second disambiguation counter appended.
pub(crate) fn is_archive_core(core: &str) -> bool {
    // Current form: `<seq>-<stamp>`, where the sequence number fixes segment
    // order at write time.
    if archive_seq(core).is_some() {
        return true;
    }
    // Legacy forms, still readable so an upgrade does not orphan existing
    // archives: `<stamp>` and `<stamp>.<counter>`.
    match core.split_once('.') {
        Some((stamp, counter)) => {
            !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()) && is_stamp(stamp)
        }
        None => is_stamp(core),
    }
}

/// Enumerate the archive files that belong to `active`, each paired with its
/// [`ArchiveOrder`] key.
///
/// Matching is restricted to names this writer generates, so unrelated
/// siblings in the same directory are never returned. The active file itself
/// is excluded. Order is unspecified; callers that need stream order sort by
/// the returned key.
pub(crate) fn list_archives(active: &Path) -> Result<Vec<(PathBuf, ArchiveOrder)>> {
    let dir = active.parent().unwrap_or_else(|| Path::new("."));
    let active_name = active
        .file_name()
        .and_then(|s| s.to_str())
        .context("log path has no file name")?;
    let (base, ext) = split_base_ext(active_name);
    let prefix = format!("{base}.");

    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(err) => {
            return Err(err).with_context(|| format!("reading log dir {}", dir.display()));
        }
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("reading entry in {}", dir.display()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name == active_name {
            continue;
        }
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        let core = if ext.is_empty() {
            suffix
        } else {
            let Some(core) = suffix.strip_suffix(ext) else {
                continue;
            };
            core
        };
        if !is_archive_core(core) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            tracing::warn!(
                target: "zeroclaw_log",
                path = %entry.path().display(),
                "log: could not read archive metadata; this archive is excluded from \
                 the merged query result and may be inaccessible",
            );
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        // Prefer the sequence number in the name; fall back to mtime only for
        // archives written before numbering existed.
        let order = match archive_seq(core) {
            Some(seq) => ArchiveOrder::Seq(seq),
            None => ArchiveOrder::Legacy(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)),
        };
        out.push((entry.path(), order));
    }
    Ok(out)
}

/// A log segment held open for the duration of one read.
///
/// Holding the handle is the point. The writer replaces the active file by
/// rename in three places (archive rotation, the rolling trim, and schema
/// migration), and a reader that re-resolves a path mid-read can be handed a
/// different file than the one it enumerated. Reading every byte through these
/// handles removes that possibility instead of trying to detect it afterwards.
pub(crate) struct OpenSegment {
    file: File,
    /// Basename at the time of opening. Cursors are issued and resolved
    /// against this name, so it is captured once rather than re-read.
    name: String,
    /// Identity of the underlying file, used to recognise one file reachable
    /// under two names at once.
    id: FileId,
    /// True for the segment that was the active file when this set was opened.
    /// Only that segment can produce a legacy `next_cursor_line_offset`.
    is_active: bool,
}

impl OpenSegment {
    /// A reader over this segment positioned at `from`.
    ///
    /// Seeking is explicit because several passes (anchor validation, anchor
    /// search, the page scan) share one handle and each needs its own start.
    fn reader_at(&self, from: u64) -> Result<BufReader<&File>> {
        use std::io::Seek;
        (&self.file)
            .seek(std::io::SeekFrom::Start(from))
            .with_context(|| format!("seeking segment {} to byte {from}", self.name))?;
        Ok(BufReader::new(&self.file))
    }
}

/// Open every segment of the logical stream, oldest first with the active file
/// last.
///
/// Two separate properties are needed here, and they are handled by two
/// different mechanisms:
///
///   - *Order* comes from the sequence number in each archive's name, applied
///     by the sort below. It is fixed at rotation time, so no amount of
///     enumeration-time confusion can misorder the result.
///   - *Content stability* comes from holding the handles. A path is re-bound
///     by a rename; an open handle is not. Scanning through these handles is
///     what stops a rotation landing mid-scan from substituting a different
///     file under the same basename.
///
/// The active file is opened *before* the archives are enumerated, which is
/// what keeps the set complete under a concurrent rotation:
///
///   - Rotation lands before the open: the archive it created is already on
///     disk when the listing runs, so it shows up as an ordinary archive.
///   - Rotation lands after the open: the handle already points at the file
///     that was rotated away, so its content stays reachable. The listing then
///     also reports that same file under its new archive name, which is why
///     identities are compared and the duplicate dropped. The sequence number
///     does not help there: the archive genuinely exists and its number is
///     valid, so only the file identity reveals that it is the pinned handle
///     seen twice.
///
/// Either way no segment is lost and none is read twice. Reversing the order
/// would leave a window where a rotation is invisible to both steps.
fn open_segment_set(active: &Path, reads_archives: bool) -> Result<Vec<OpenSegment>> {
    let active_name = active
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();

    // Pin the active file first. A missing active file is the normal state on a
    // fresh workspace, and archives may still hold history worth returning.
    let active_seg = match File::open(active) {
        Ok(file) => {
            let id = file_id(&file)
                .with_context(|| format!("identifying active log {}", active.display()))?;
            Some(OpenSegment {
                file,
                name: active_name,
                id,
                is_active: true,
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("opening active log {}", active.display()));
        }
    };

    let mut archives = if reads_archives {
        list_archives(active)
            .with_context(|| format!("enumerating archives next to {}", active.display()))?
    } else {
        Vec::new()
    };
    // Sort by the name-derived ordering key, not by mtime: the key is fixed at
    // rotation time, so it stays correct no matter when this listing ran.
    archives.sort_by_key(|(_, order)| *order);

    let mut segs = Vec::with_capacity(archives.len() + 1);
    for (path, _) in archives {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(err) => {
                tracing::warn!(
                    target: "zeroclaw_log",
                    error = ?err,
                    path = %path.display(),
                    "log: could not open archive segment; excluded from this read",
                );
                continue;
            }
        };
        let id = match file_id(&file) {
            Ok(id) => id,
            Err(err) => {
                tracing::warn!(
                    target: "zeroclaw_log",
                    error = ?err,
                    path = %path.display(),
                    "log: could not identify archive segment; excluded from this read",
                );
                continue;
            }
        };
        // This archive and the active handle are the same file when a rotation
        // landed between the two steps above. Reading it again would duplicate
        // every event it holds.
        if active_seg.as_ref().is_some_and(|a| a.id == id) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        segs.push(OpenSegment {
            file,
            name,
            id,
            is_active: false,
        });
    }

    // Active file last: it holds the newest events.
    if let Some(active_seg) = active_seg {
        segs.push(active_seg);
    }
    Ok(segs)
}

/// Outcome of a segment-aware page read.
///
/// The anchor miss is reported rather than silently absorbed: only the caller
/// knows whether its segment list came from a listing that could still be
/// refreshed. `load_page_multi` sees one snapshot and cannot tell "the writer
/// rotated a moment ago, re-list and I will find it" apart from "retention
/// pruned this segment for good".
#[derive(Debug)]
pub(crate) enum PageOutcome {
    /// The page was produced, either from a resolved cursor or a full scan.
    Page(Box<LogPage>),
    /// The cursor carried an anchor id that is in none of the supplied
    /// segments. The caller should re-enumerate and retry before falling back
    /// to a full scan.
    AnchorMissing,
}

/// Paginated load across an already-opened segment set.
///
/// `segs` must arrive in stream order, oldest first with the active file last;
/// [`open_segment_set`] is what establishes that. This function does not sort
/// or open anything, so it cannot re-resolve a path that has since been
/// renamed.
///
/// The result is returned newest-first, identical to [`load_page`].
///
/// `segment_cursor` is the composite cursor returned by a prior call as
/// `LogPage::next_segment_cursor`. When absent the full stream is scanned. The
/// old `filter.until_line_offset` field is honoured when `segment_cursor` is
/// absent, interpreted as a cursor into the active file only.
#[allow(deprecated)]
pub(crate) fn load_page_multi(
    segs: &[OpenSegment],
    filter: &LogFilter,
    limit: usize,
    segment_cursor: Option<&SegmentCursor>,
) -> Result<PageOutcome> {
    let limit = limit.clamp(1, 10_000);
    let needle = filter.q.as_deref().map(|s| s.to_ascii_lowercase());

    // Segments arrive oldest first with the active file last; see
    // `open_segment_set`. The active basename is what a legacy byte-offset
    // cursor addresses, and the only segment that can issue one.
    let active_name = segs
        .iter()
        .find(|s| s.is_active)
        .map(|s| s.name.clone())
        .unwrap_or_default();

    // Determine cursor segment name and byte offset.
    let (cursor_seg, cursor_off): (Option<&str>, Option<u64>) = match segment_cursor {
        Some(c) => (Some(c.seg.as_str()), Some(c.off)),
        None => match filter.until_line_offset {
            Some(off) => (Some(active_name.as_str()), Some(off)),
            None => (None, None),
        },
    };

    // Find the index of the cursor segment (or the last segment if absent).
    // If the named segment no longer exists (e.g. its archive was pruned by
    // retention between requests), fall back to a full scan rather than
    // misapplying the offset to an unrelated segment.
    //
    // Active-file rotation check: when the cursor names the active file and
    // carries an anchor_id, verify that the event just before `cursor_off` in
    // that file is actually the anchored event. If the active file was rotated
    // since the cursor was issued, the old content now lives in an archive under
    // a different name, and the same basename maps to a *new* file whose content
    // is unrelated. In that case, look for the archive that contains the anchor
    // event and rebase the cursor to its exact byte-offset boundary so the next
    // page starts cleanly from the right position.
    let (cursor_idx, cursor_off): (usize, Option<u64>) = match cursor_seg {
        None => (segs.len().saturating_sub(1), None),
        Some(name) => match segs.iter().rposition(|s| s.name == name) {
            Some(idx) => {
                // Check whether a rotation invalidated an active-file cursor.
                let anchor_id = segment_cursor.and_then(|c| c.anchor_id.as_deref());
                if let (Some(anchor), Some(off)) = (anchor_id, cursor_off) {
                    if !anchor_matches_offset(&segs[idx], off, anchor) {
                        // The file at this basename no longer contains the
                        // expected anchor event: rotation occurred. Search all
                        // segments for the anchor event and rebase the cursor
                        // to the byte offset immediately after it.
                        match find_anchor_in_segments(segs, anchor) {
                            Some((anchor_idx, anchor_end_off)) => {
                                (anchor_idx, Some(anchor_end_off))
                            }
                            // The anchored event is in none of these segments.
                            // Hand that back so the caller can re-enumerate:
                            // a rotation that landed after its listing puts the
                            // event in an archive this snapshot never saw.
                            None => return Ok(PageOutcome::AnchorMissing),
                        }
                    } else {
                        (idx, cursor_off)
                    }
                } else {
                    (idx, cursor_off)
                }
            }
            // The cursor names a segment that is not in this listing. If it
            // carried an anchor, the caller may be holding a stale list; report
            // the miss so it can re-enumerate. Anchorless legacy cursors have
            // nothing to re-find, so they fall back to a full scan.
            None if segment_cursor
                .and_then(|c| c.anchor_id.as_deref())
                .is_some() =>
            {
                return Ok(PageOutcome::AnchorMissing);
            }
            None => (segs.len().saturating_sub(1), None),
        },
    };

    // Sliding window that accumulates the most-recent `limit` matching events
    // across all scanned segments. Each entry carries the event, its segment
    // basename, and its line_byte_end.
    let mut window: VecDeque<(LogEvent, String, u64)> = VecDeque::with_capacity(limit + 1);
    let mut dropped_older = false;

    for (i, seg) in segs.iter().enumerate() {
        if i > cursor_idx {
            // Segment is newer than the cursor; skip entirely.
            break;
        }
        let seg_until_line_offset = if i == cursor_idx { cursor_off } else { None };

        let mut reader = seg.reader_at(0)?;
        let mut next_byte_offset: u64 = 0;
        let mut buf = String::new();

        loop {
            buf.clear();
            let bytes_read = reader.read_line(&mut buf).context("reading log line")?;
            if bytes_read == 0 {
                break;
            }
            let line_byte_end = next_byte_offset + bytes_read as u64;

            if let Some(cap) = seg_until_line_offset
                && line_byte_end >= cap
            {
                break;
            }

            let trimmed = buf.trim();
            next_byte_offset = line_byte_end;

            if trimmed.is_empty() {
                continue;
            }

            let event: LogEvent = match serde_json::from_str(trimmed) {
                Ok(e) => e,
                Err(err) => {
                    tracing::trace!(
                        target: "zeroclaw_log",
                        error = ?err,
                        "log: skipping malformed JSONL line"
                    );
                    continue;
                }
            };

            if !matches_filter(&event, filter, needle.as_deref()) {
                continue;
            }

            window.push_back((event, seg.name.clone(), line_byte_end));
            if window.len() > limit {
                window.pop_front();
                dropped_older = true;
            }
        }
    }

    // Derive cursors from the oldest event in the window.
    let oldest = window.front();
    let next_segment_cursor = oldest.map(|(evt, seg, off)| {
        SegmentCursor {
            seg: seg.clone(),
            off: *off,
            anchor_id: Some(evt.id.clone()),
        }
        .to_wire()
    });
    let next_cursor_line_offset = oldest.and_then(|(_, seg, off)| {
        if seg == &active_name {
            Some(*off)
        } else {
            None
        }
    });

    let mut events: Vec<LogEvent> = window.into_iter().map(|(e, _, _)| e).collect();
    events.reverse();

    let next_cursor = events.last().map(|e| (e.timestamp.clone(), e.id.clone()));
    // `at_end` answers "are there OLDER events past this page?". Every segment
    // up to and including the cursor's is scanned in full, so the only way an
    // older match can exist is if the sliding window evicted one. Hitting the
    // cursor mid-segment truncates that segment's *newer* tail, which says
    // nothing about older events, so it deliberately does not feed this
    // decision — unlike single-file `load_page`, which folds that in and is
    // therefore conservative. Being conservative here would pin `at_end` to
    // false on every cross-segment page, since the cursor segment is always
    // truncated.
    let at_end = !dropped_older;

    Ok(PageOutcome::Page(Box::new(LogPage {
        events,
        next_cursor,
        next_cursor_line_offset,
        next_segment_cursor,
        at_end,
    })))
}

/// Read one page across the active file and every retained archive.
///
/// This is the entry point for `/api/logs` and the `logs/query` RPC. It owns
/// segment enumeration so callers never hold a list of their own: a list
/// captured outside this call can go stale the moment the writer rotates, and
/// a cursor pointing into the rotated-away file would then resolve against an
/// unrelated new file with the same basename.
///
/// Rotation racing this function is handled by the segment set itself, not by
/// retrying: order comes from the sequence numbers in the archive names, and
/// content is pinned by the open handles. See [`open_segment_set`]. Any number
/// of rotations can land during the read without reordering or truncating the
/// result.
///
/// The one case retrying still covers is an anchored cursor whose event is in
/// none of the opened segments. That is ambiguous from a single snapshot: the
/// segment may have been created after the listing, or retention may have
/// pruned it for good. Re-opening distinguishes the two, since a newly rotated
/// archive is present the second time. A miss that survives the re-open means
/// the segment is genuinely gone, and the cursor is dropped in favour of the
/// newest page.
pub fn query_log_page(
    active: &Path,
    reads_archives: bool,
    filter: &LogFilter,
    limit: usize,
    segment_cursor: Option<&SegmentCursor>,
) -> Result<LogPage> {
    // The opened set is self-consistent: ordered by name-embedded sequence and
    // pinned by handle. See `open_segment_set`.
    let segs = open_segment_set(active, reads_archives)?;
    match load_page_multi(&segs, filter, limit, segment_cursor)? {
        PageOutcome::Page(page) => return Ok(*page),
        // The anchored event is in none of the files that were open. Either the
        // segment was pruned by retention, or it was created between this
        // process's last listing and now. Re-open the whole set once: a newly
        // rotated archive is present in the second listing.
        PageOutcome::AnchorMissing => {}
    }

    let segs = open_segment_set(active, reads_archives)?;
    match load_page_multi(&segs, filter, limit, segment_cursor)? {
        PageOutcome::Page(page) => Ok(*page),
        // Still unreachable after a fresh open: the segment is genuinely gone.
        // Drop the cursor and serve the newest page. Callers that prepend pages
        // to an existing buffer must deduplicate, since this is not older
        // history.
        PageOutcome::AnchorMissing => match load_page_multi(&segs, filter, limit, None)? {
            PageOutcome::Page(page) => Ok(*page),
            PageOutcome::AnchorMissing => {
                unreachable!("cursor-less call cannot produce an anchor miss")
            }
        },
    }
}

/// Find one event by id across the active file and every retained archive,
/// newest source first. Owns archive enumeration for the same reason as
/// [`query_log_page`]: the caller never holds a segment list that can go stale.
///
/// Returns `Ok(None)` when no segment holds the id. An archive that cannot be
/// read is skipped rather than failing the lookup, so a single unreadable file
/// does not hide an event that a later segment still has.
pub fn find_event_across_segments(
    active: &Path,
    reads_archives: bool,
    id: &str,
) -> Result<Option<LogEvent>> {
    // Same handle-based read as `query_log_page`, and the same policy boundary:
    // an id that only exists in an unmanaged archive is not part of this
    // policy's logical stream.
    let segs = open_segment_set(active, reads_archives)?;
    // Newest first (active file, then archives newest to oldest), since a
    // recently rotated event is the likelier target.
    for seg in segs.iter().rev() {
        let reader = match seg.reader_at(0) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::warn!(
                    target: "zeroclaw_log",
                    error = ?err,
                    segment = %seg.name,
                    "log: skipping unreadable segment during id lookup"
                );
                continue;
            }
        };
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<LogEvent>(trimmed)
                && event.id == id
            {
                return Ok(Some(event));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventCategory, Severity};
    use std::io::Write;

    fn write_jsonl(path: &Path, events: &[LogEvent]) {
        let mut file = std::fs::File::create(path).unwrap();
        for event in events {
            let line = serde_json::to_string(event).unwrap();
            file.write_all(line.as_bytes()).unwrap();
            file.write_all(b"\n").unwrap();
        }
    }

    /// Set a file's mtime so a test can make the name-derived and
    /// mtime-derived ordering keys disagree deliberately.
    fn set_mtime(path: &Path, when: SystemTime) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    /// Unwrap a `PageOutcome` that the test expects to be a real page.
    /// Panics on `AnchorMissing`, which in tests always signals a setup bug.
    fn page_of(outcome: PageOutcome) -> LogPage {
        match outcome {
            PageOutcome::Page(page) => *page,
            PageOutcome::AnchorMissing => {
                panic!("expected a page, got AnchorMissing")
            }
        }
    }

    /// Build an `OpenSegment` slice from paths, mirroring how
    /// `open_segment_set` works but taking an explicit archive list so
    /// white-box tests can control exactly which files are visible (e.g. to
    /// reproduce the stale-listing race by omitting a file from the list).
    fn segs_from(
        active: &Path,
        archives: &[(std::path::PathBuf, std::time::SystemTime)],
    ) -> Vec<OpenSegment> {
        let mut segs = Vec::new();
        let mut sorted = archives.to_vec();
        sorted.sort_by_key(|(_, mtime)| *mtime);
        for (path, _) in &sorted {
            let file = std::fs::File::open(path)
                .unwrap_or_else(|e| panic!("segs_from: open {}: {e}", path.display()));
            let id =
                file_id(&file).unwrap_or_else(|e| panic!("segs_from: id {}: {e}", path.display()));
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            segs.push(OpenSegment {
                file,
                name,
                id,
                is_active: false,
            });
        }
        if active.exists() {
            let file = std::fs::File::open(active)
                .unwrap_or_else(|e| panic!("segs_from: open active {}: {e}", active.display()));
            let id = file_id(&file)
                .unwrap_or_else(|e| panic!("segs_from: id active {}: {e}", active.display()));
            let name = active
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            segs.push(OpenSegment {
                file,
                name,
                id,
                is_active: true,
            });
        }
        segs
    }

    fn make_event(action: &str, agent: Option<&str>) -> LogEvent {
        let mut event = LogEvent::new(Severity::Info, action, EventCategory::Agent);
        if let Some(alias) = agent {
            event.zeroclaw.set("agent_alias", alias);
        }
        event
    }

    #[test]
    fn empty_file_returns_at_end() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let page = load_page(&path, &LogFilter::default(), 10).unwrap();
        assert!(page.events.is_empty());
        assert!(page.at_end);
    }

    #[test]
    fn returns_newest_first_within_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut events = Vec::new();
        for index in 0..5 {
            let mut event = make_event("test", None);
            // Force monotonically increasing timestamp.
            event.timestamp = format!("2026-05-15T19:00:0{index}.000Z");
            event.message = Some(format!("event-{index}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let page = load_page(&path, &LogFilter::default(), 3).unwrap();
        assert_eq!(page.events.len(), 3);
        assert_eq!(page.events[0].message.as_deref(), Some("event-4"));
        assert_eq!(page.events[1].message.as_deref(), Some("event-3"));
        assert_eq!(page.events[2].message.as_deref(), Some("event-2"));
        assert!(!page.at_end);
    }

    #[test]
    fn filter_by_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let events = vec![
            make_event("a", Some("clamps")),
            make_event("b", Some("glados")),
            make_event("c", Some("clamps")),
        ];
        write_jsonl(&path, &events);

        let mut field_eq = BTreeMap::new();
        field_eq.insert("agent_alias".into(), "clamps".into());
        let filter = LogFilter {
            field_eq,
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert_eq!(page.events.len(), 2);
    }

    #[test]
    fn filter_by_native_trace_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut a = make_event("a", None);
        a.trace_id = Some("turn-1".into());
        let mut b = make_event("b", None);
        b.trace_id = Some("turn-2".into());
        let mut c = make_event("c", None);
        c.trace_id = Some("turn-1".into());
        write_jsonl(&path, &[a, b, c]);

        // The exact turn matches its two rows...
        let filter = LogFilter {
            trace_id: Some("turn-1".into()),
            ..Default::default()
        };
        assert_eq!(load_page(&path, &filter, 10).unwrap().events.len(), 2);

        // ...and an unknown id matches nothing (the bug this fixes: before the
        // layer promotion the native field was always None, so this returned 0
        // for EVERY id, including real ones).
        let filter = LogFilter {
            trace_id: Some("turn-missing".into()),
            ..Default::default()
        };
        assert_eq!(load_page(&path, &filter, 10).unwrap().events.len(), 0);
    }

    #[test]
    fn hide_internal_drops_internal_category() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut agent_event = make_event("a", None);
        agent_event.event.category = "agent".into();
        let mut internal_event = make_event("b", None);
        internal_event.event.category = "internal".into();
        write_jsonl(&path, &[agent_event, internal_event]);

        let filter = LogFilter {
            hide_internal: true,
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event.action, "a");
    }

    #[test]
    fn substring_query_matches_message_and_attributes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut with_alpha_message = make_event("a", None);
        with_alpha_message.message = Some("alpha bravo".into());
        let mut with_attr_payload = make_event("b", None);
        with_attr_payload.attributes = serde_json::json!({ "k": "delta echo" });
        let mut with_foxtrot_message = make_event("c", None);
        with_foxtrot_message.message = Some("foxtrot".into());
        write_jsonl(
            &path,
            &[with_alpha_message, with_attr_payload, with_foxtrot_message],
        );

        let filter = LogFilter {
            q: Some("bravo".into()),
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event.action, "a");

        let attr_filter = LogFilter {
            q: Some("delta".into()),
            ..Default::default()
        };
        let attr_page = load_page(&path, &attr_filter, 10).unwrap();
        assert_eq!(attr_page.events.len(), 1);
        assert_eq!(attr_page.events[0].event.action, "b");
    }

    #[test]
    #[allow(deprecated)] // legacy cursor is the subject under test
    fn cursor_pagination_returns_older_pages() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut events = Vec::new();
        for index in 0..6 {
            let mut event = make_event("test", None);
            event.timestamp = format!("2026-05-15T19:00:0{index}.000Z");
            event.message = Some(format!("event-{index}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let first_page = load_page(&path, &LogFilter::default(), 3).unwrap();
        assert_eq!(first_page.events[0].message.as_deref(), Some("event-5"));
        let (cursor_ts, cursor_id) = first_page.next_cursor.unwrap();

        let older_filter = LogFilter {
            until_ts: Some(cursor_ts),
            until_id: Some(cursor_id),
            ..Default::default()
        };
        let older_page = load_page(&path, &older_filter, 3).unwrap();
        assert_eq!(older_page.events[0].message.as_deref(), Some("event-2"));
        assert_eq!(older_page.events[1].message.as_deref(), Some("event-1"));
        assert_eq!(older_page.events[2].message.as_deref(), Some("event-0"));
        assert!(older_page.at_end);
    }

    #[test]
    #[allow(deprecated)] // legacy cursor is the subject under test
    fn same_timestamp_pagination_walks_all_events_exactly_once() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let shared_ts = "2026-05-15T19:00:00.000Z";
        let ids = ["evt-a", "evt-b", "evt-c", "evt-d", "evt-e"];
        let mut events = Vec::new();
        for id in ids {
            let mut event = make_event("test", None);
            event.timestamp = shared_ts.to_string();
            event.id = id.to_string();
            event.message = Some(format!("event-{id}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let mut seen_ids: Vec<String> = Vec::new();
        let mut page_filter = LogFilter::default();
        let page_size = 2;
        let mut pages_walked = 0;

        loop {
            pages_walked += 1;
            assert!(pages_walked < 20, "pagination must terminate, did not");

            let page = load_page(&path, &page_filter, page_size).unwrap();
            for event in &page.events {
                assert!(
                    !seen_ids.contains(&event.id),
                    "duplicate id {:?} across pages",
                    event.id
                );
                seen_ids.push(event.id.clone());
            }

            if page.at_end {
                // at_end means "no older events exist" but the cursor
                // still points at the last event of the current page;
                // the UI uses at_end to disable the "load older" button.
                break;
            }

            let (cursor_ts, cursor_id) = page
                .next_cursor
                .expect("non-final page must expose a cursor so caller can request older events");
            page_filter = LogFilter {
                until_ts: Some(cursor_ts),
                until_id: Some(cursor_id),
                ..Default::default()
            };
        }

        // Every shared-timestamp event was visited exactly once.
        let mut expected: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        expected.sort();
        let mut actual = seen_ids.clone();
        actual.sort();
        assert_eq!(
            actual, expected,
            "pagination must visit every tied event exactly once"
        );
    }

    #[test]
    #[allow(deprecated)] // legacy cursor is the subject under test
    fn same_timestamp_cursor_does_not_duplicate_boundary_event() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let shared_ts = "2026-05-15T19:00:00.000Z";
        let mut events = Vec::new();
        // ids ordered so that without id tie-break, evt-b could appear on
        // both page 1 and page 2.
        let ids = ["evt-a", "evt-b", "evt-c"];
        for id in ids {
            let mut event = make_event("test", None);
            event.timestamp = shared_ts.to_string();
            event.id = id.to_string();
            event.message = Some(format!("event-{id}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let page1 = load_page(&path, &LogFilter::default(), 1).unwrap();
        assert_eq!(page1.events.len(), 1);
        assert_eq!(page1.events[0].id, "evt-c");
        let (cursor_ts, cursor_id) = page1.next_cursor.unwrap();
        assert_eq!(cursor_id, "evt-c");

        let page2_filter = LogFilter {
            until_ts: Some(cursor_ts),
            until_id: Some(cursor_id),
            ..Default::default()
        };
        let page2 = load_page(&path, &page2_filter, 1).unwrap();
        assert_eq!(page2.events.len(), 1);
        // evt-c must NOT reappear; the next event under the cursor is
        // evt-b (id strictly less than "evt-c" at the same timestamp).
        assert_eq!(page2.events[0].id, "evt-b");
        assert_ne!(page2.events[0].id, page1.events[0].id);
    }

    #[test]
    fn line_offset_pagination_walks_scrambled_ids_exactly_once() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let shared_ts = "2026-05-15T19:00:00.000Z";
        let ids = ["evt-c", "evt-a", "evt-e", "evt-b", "evt-d"];
        let mut events = Vec::new();
        for id in ids {
            let mut event = make_event("test", None);
            event.timestamp = shared_ts.to_string();
            event.id = id.to_string();
            event.message = Some(format!("event-{id}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let mut seen_ids: Vec<String> = Vec::new();
        let mut page_filter = LogFilter::default();
        let page_size = 2;
        let mut pages_walked = 0;

        loop {
            pages_walked += 1;
            assert!(pages_walked < 20, "pagination must terminate");

            let page = load_page(&path, &page_filter, page_size).unwrap();
            for event in &page.events {
                assert!(
                    !seen_ids.contains(&event.id),
                    "duplicate id {:?} across pages",
                    event.id
                );
                seen_ids.push(event.id.clone());
            }

            let Some(line_offset) = page.next_cursor_line_offset else {
                // Empty page or no further bytes to scan — we are done.
                break;
            };

            page_filter = LogFilter {
                until_line_offset: Some(line_offset),
                ..Default::default()
            };
        }

        let mut expected: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        expected.sort();
        let mut actual = seen_ids.clone();
        actual.sort();
        assert_eq!(
            actual, expected,
            "byte-offset cursor must visit every event exactly once even when ids are scrambled"
        );
    }

    #[test]
    fn line_offset_cursor_resumes_with_no_overlap_or_gap() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        // Distinct, strictly increasing timestamps so we can detect any
        // ordering regression independently of same-timestamp logic.
        let mut events = Vec::new();
        for index in 0..6 {
            let mut event = make_event("test", None);
            event.timestamp = format!("2026-05-15T19:00:0{index}.000Z");
            event.id = format!("evt-{index}");
            event.message = Some(format!("event-{index}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let page_size = 2;
        let mut all_seen_ids: Vec<String> = Vec::new();
        let mut page_filter = LogFilter::default();

        loop {
            let page = load_page(&path, &page_filter, page_size).unwrap();
            for event in &page.events {
                assert!(
                    !all_seen_ids.contains(&event.id),
                    "duplicate {:?} across pages",
                    event.id
                );
                all_seen_ids.push(event.id.clone());
            }
            let Some(line_offset) = page.next_cursor_line_offset else {
                break;
            };
            page_filter = LogFilter {
                until_line_offset: Some(line_offset),
                ..Default::default()
            };
        }

        let expected: Vec<String> = (0..6).rev().map(|i| format!("evt-{i}")).collect();
        assert_eq!(
            all_seen_ids, expected,
            "byte-offset cursor must walk the file in newest-first page order without losing or duplicating events"
        );
    }

    #[test]
    fn line_offset_cursor_advances_monotonically() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut events = Vec::new();
        for index in 0..5 {
            let mut event = make_event("test", None);
            event.timestamp = format!("2026-05-15T19:00:0{index}.000Z");
            event.message = Some(format!("event-{index}"));
            events.push(event);
        }
        write_jsonl(&path, &events);

        let mut prev_offset: Option<u64> = None;
        let mut page_filter = LogFilter::default();
        let page_size = 1;

        loop {
            let page = load_page(&path, &page_filter, page_size).unwrap();
            if page.events.is_empty() {
                break;
            }
            let offset = page
                .next_cursor_line_offset
                .expect("non-empty page must expose a line offset cursor");
            if let Some(prev) = prev_offset {
                assert!(
                    offset < prev,
                    "next_cursor_line_offset must strictly decrease across pages as we walk to older events (prev={prev}, next={offset})"
                );
            }
            prev_offset = Some(offset);
            page_filter = LogFilter {
                until_line_offset: Some(offset),
                ..Default::default()
            };
        }
    }

    #[test]
    fn line_offset_cursor_at_file_start_returns_empty_page() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut events = Vec::new();
        for index in 0..3 {
            let mut event = make_event("test", None);
            event.timestamp = format!("2026-05-15T19:00:0{index}.000Z");
            events.push(event);
        }
        write_jsonl(&path, &events);

        let filter = LogFilter {
            until_line_offset: Some(0),
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert!(
            page.events.is_empty(),
            "until_line_offset=0 must skip every line and yield an empty page"
        );
        assert!(page.next_cursor_line_offset.is_none());
        assert!(
            page.at_end,
            "empty page (regardless of cursor state) must report at_end so \
             callers stop paginating instead of looping on a cursor that \
             cannot advance"
        );
    }

    #[test]
    fn empty_page_with_filter_excludes_everything_reports_at_end() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut events = Vec::new();
        for index in 0..4 {
            let mut event = make_event("test", None);
            event.timestamp = format!("2026-05-15T19:00:0{index}.000Z");
            events.push(event);
        }
        write_jsonl(&path, &events);

        // First read: filter excludes everything, no cursor set, full
        // file scanned.
        let filter = LogFilter {
            action: Some("does-not-exist".into()),
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert!(page.events.is_empty());
        assert!(
            page.at_end,
            "empty page after a full-file scan must report at_end"
        );
        assert!(page.next_cursor_line_offset.is_none());

        // Second read: same filter, but a cursor set mid-file. The
        // reader stops at the cursor without matching anything; the
        // page is still empty and `at_end` must still be true.
        let filter_with_cursor = LogFilter {
            action: Some("does-not-exist".into()),
            until_line_offset: Some(50),
            ..Default::default()
        };
        let page2 = load_page(&path, &filter_with_cursor, 10).unwrap();
        assert!(page2.events.is_empty());
        assert!(
            page2.at_end,
            "empty page under an until_line_offset cursor must also report at_end"
        );
    }

    #[test]
    fn action_filter_matches_case_insensitively() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        write_jsonl(
            &path,
            &[
                make_event("LlmRequest", None),
                make_event("tool_call", None),
            ],
        );
        let filter = LogFilter {
            action: Some("llmrequest".into()),
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event.action, "LlmRequest");
    }

    #[test]
    fn category_filter_matches_case_insensitively() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut agent_ev = make_event("a", None);
        agent_ev.event.category = "agent".into();
        let mut tool_ev = make_event("b", None);
        tool_ev.event.category = "tool".into();
        write_jsonl(&path, &[agent_ev, tool_ev]);
        let filter = LogFilter {
            category: Some("AGENT".into()),
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event.action, "a");
    }

    #[test]
    fn outcome_filter_matches_case_insensitively() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trace.jsonl");
        let mut ok_ev = make_event("a", None);
        ok_ev.event.outcome = "success".into();
        let mut fail_ev = make_event("b", None);
        fail_ev.event.outcome = "failure".into();
        write_jsonl(&path, &[ok_ev, fail_ev]);
        let filter = LogFilter {
            outcome: Some("FAILURE".into()),
            ..Default::default()
        };
        let page = load_page(&path, &filter, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event.action, "b");
    }

    #[test]
    fn multi_segment_reads_across_active_and_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        // Archive: two older events.
        let archive = tmp.path().join("trace.20260101-000000.jsonl");
        let mut old_a = make_event("a", None);
        old_a.timestamp = "2026-01-01T00:00:00.000Z".into();
        old_a.message = Some("old-a".into());
        let mut old_b = make_event("b", None);
        old_b.timestamp = "2026-01-01T00:00:01.000Z".into();
        old_b.message = Some("old-b".into());
        write_jsonl(&archive, &[old_a, old_b]);
        let archive_mtime = std::fs::metadata(&archive).unwrap().modified().unwrap();

        // Active file: two newer events.
        let mut new_c = make_event("c", None);
        new_c.timestamp = "2026-06-01T00:00:00.000Z".into();
        new_c.message = Some("new-c".into());
        let mut new_d = make_event("d", None);
        new_d.timestamp = "2026-06-01T00:00:01.000Z".into();
        new_d.message = Some("new-d".into());
        write_jsonl(&active, &[new_c, new_d]);

        let archives = vec![(archive.clone(), archive_mtime)];
        let page = page_of(
            load_page_multi(
                &segs_from(&active, &archives),
                &LogFilter::default(),
                10,
                None,
            )
            .unwrap(),
        );

        assert_eq!(page.events.len(), 4, "all 4 events across segments");
        // Newest first.
        assert_eq!(page.events[0].message.as_deref(), Some("new-d"));
        assert_eq!(page.events[1].message.as_deref(), Some("new-c"));
        assert_eq!(page.events[2].message.as_deref(), Some("old-b"));
        assert_eq!(page.events[3].message.as_deref(), Some("old-a"));
        assert!(page.at_end, "entire stream was scanned");
    }

    #[test]
    fn segment_cursor_paginates_into_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let archive = tmp.path().join("trace.20260101-000000.jsonl");

        let mut old_a = make_event("a", None);
        old_a.timestamp = "2026-01-01T00:00:00.000Z".into();
        old_a.message = Some("old-a".into());
        let mut old_b = make_event("b", None);
        old_b.timestamp = "2026-01-01T00:00:01.000Z".into();
        old_b.message = Some("old-b".into());
        write_jsonl(&archive, &[old_a, old_b]);
        let archive_mtime = std::fs::metadata(&archive).unwrap().modified().unwrap();

        let mut new_c = make_event("c", None);
        new_c.timestamp = "2026-06-01T00:00:00.000Z".into();
        new_c.message = Some("new-c".into());
        let mut new_d = make_event("d", None);
        new_d.timestamp = "2026-06-01T00:00:01.000Z".into();
        new_d.message = Some("new-d".into());
        write_jsonl(&active, &[new_c, new_d]);

        let archives = vec![(archive.clone(), archive_mtime)];

        // Page 1: limit 2 → newest two events (from active file).
        let page1 = page_of(
            load_page_multi(
                &segs_from(&active, &archives),
                &LogFilter::default(),
                2,
                None,
            )
            .unwrap(),
        );
        assert_eq!(page1.events.len(), 2);
        assert_eq!(page1.events[0].message.as_deref(), Some("new-d"));
        assert_eq!(page1.events[1].message.as_deref(), Some("new-c"));
        assert!(!page1.at_end, "there are older events in the archive");
        let cursor_wire = page1
            .next_segment_cursor
            .clone()
            .expect("cursor must be set");

        // Page 2: using the cursor → should return the two archive events.
        let cursor = SegmentCursor::from_wire(&cursor_wire).expect("valid cursor wire format");
        let page2 = page_of(
            load_page_multi(
                &segs_from(&active, &archives),
                &LogFilter::default(),
                2,
                Some(&cursor),
            )
            .unwrap(),
        );
        assert_eq!(page2.events.len(), 2);
        assert_eq!(page2.events[0].message.as_deref(), Some("old-b"));
        assert_eq!(page2.events[1].message.as_deref(), Some("old-a"));
        assert!(page2.at_end, "no older events remain");
    }

    /// Regression for the active-file rotation race: when the active file is
    /// rotated between two pagination requests, the segment cursor produced on
    /// page 1 names the (now-renamed) file's basename, which is the same as the
    /// new active file. Without the anchor_id check, page 2 would apply the old
    /// byte offset to the new file and return newly-written events instead of
    /// the expected older ones.
    #[test]
    fn segment_cursor_survives_active_file_rotation_between_pages() {
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let archive = tmp.path().join("trace.20260101-000000.jsonl");

        // Initial active file has 4 events [a, b, c, d].
        let mut ev_a = make_event("a", None);
        ev_a.timestamp = "2026-01-01T00:00:00.000Z".into();
        ev_a.message = Some("ev-a".into());
        let mut ev_b = make_event("b", None);
        ev_b.timestamp = "2026-01-01T00:00:01.000Z".into();
        ev_b.message = Some("ev-b".into());
        let mut ev_c = make_event("c", None);
        ev_c.timestamp = "2026-01-01T00:00:02.000Z".into();
        ev_c.message = Some("ev-c".into());
        let mut ev_d = make_event("d", None);
        ev_d.timestamp = "2026-01-01T00:00:03.000Z".into();
        ev_d.message = Some("ev-d".into());
        write_jsonl(
            &active,
            &[ev_a.clone(), ev_b.clone(), ev_c.clone(), ev_d.clone()],
        );

        // Page 1: limit 2 → returns [d, c] with a cursor pointing into the
        // active file before c (i.e., the cursor anchors on ev_c).
        let page1 = page_of(
            load_page_multi(&segs_from(&active, &[]), &LogFilter::default(), 2, None).unwrap(),
        );
        assert_eq!(page1.events.len(), 2);
        assert_eq!(page1.events[0].message.as_deref(), Some("ev-d"));
        assert_eq!(page1.events[1].message.as_deref(), Some("ev-c"));
        let cursor_wire = page1
            .next_segment_cursor
            .clone()
            .expect("cursor must be set");

        // Simulate a rotation: rename the active file to an archive, then write
        // a new event [e] into a fresh active file with the same basename.
        std::fs::rename(&active, &archive).unwrap();
        let archive_mtime = std::fs::metadata(&archive).unwrap().modified().unwrap();
        let mut ev_e = make_event("e", None);
        ev_e.timestamp = "2026-01-01T00:00:04.000Z".into();
        ev_e.message = Some("ev-e".into());
        write_jsonl(&active, &[ev_e.clone()]);

        // Page 2 with the cursor from page 1. The cursor names "trace.jsonl"
        // (now a new file) but anchor_id = ev_c.id. The reader should detect
        // the mismatch and find ev_c in the archive, then return [b, a] — not
        // [e, d] as the broken pre-fix implementation would.
        let cursor = SegmentCursor::from_wire(&cursor_wire).expect("valid cursor");
        let archives = vec![(archive.clone(), archive_mtime)];
        let page2 = page_of(
            load_page_multi(
                &segs_from(&active, &archives),
                &LogFilter::default(),
                2,
                Some(&cursor),
            )
            .unwrap(),
        );
        assert_eq!(
            page2.events.len(),
            2,
            "expected [b, a] not newly-written events"
        );
        assert_eq!(
            page2.events[0].message.as_deref(),
            Some("ev-b"),
            "oldest-of-page-1 must not duplicate into page 2"
        );
        assert_eq!(page2.events[1].message.as_deref(), Some("ev-a"));
        assert!(page2.at_end, "all events seen");
    }

    #[test]
    fn query_log_page_recovers_when_rotation_races_enumeration() {
        // The stale-segment-list race: a caller enumerates archives, the writer
        // rotates the active file, and only then does the read happen. The
        // archive holding the anchored event did not exist at enumeration time,
        // so a reader that trusts its input list cannot find the anchor and
        // silently restarts from the newest page.
        //
        // `query_log_page` owns enumeration, so its own listing is taken after
        // the rotation and this scenario resolves. The test drives the public
        // entry point exactly as the gateway does: it never hands in a list.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let archive = tmp.path().join("trace.20260101-000000.jsonl");

        let mut ev_a = make_event("a", None);
        ev_a.timestamp = "2026-01-01T00:00:00.000Z".into();
        ev_a.message = Some("ev-a".into());
        let mut ev_b = make_event("b", None);
        ev_b.timestamp = "2026-01-01T00:00:01.000Z".into();
        ev_b.message = Some("ev-b".into());
        let mut ev_c = make_event("c", None);
        ev_c.timestamp = "2026-01-01T00:00:02.000Z".into();
        ev_c.message = Some("ev-c".into());
        let mut ev_d = make_event("d", None);
        ev_d.timestamp = "2026-01-01T00:00:03.000Z".into();
        ev_d.message = Some("ev-d".into());
        write_jsonl(&active, &[ev_a, ev_b, ev_c, ev_d]);

        // Page 1 over the active file alone: no archives exist yet, so the
        // cursor anchors on ev_c inside `trace.jsonl`.
        let page1 = query_log_page(&active, true, &LogFilter::default(), 2, None).unwrap();
        assert_eq!(page1.events[0].message.as_deref(), Some("ev-d"));
        assert_eq!(page1.events[1].message.as_deref(), Some("ev-c"));
        let cursor_wire = page1
            .next_segment_cursor
            .clone()
            .expect("cursor must be set");

        // The writer rotates: the file the cursor names becomes an archive, and
        // a brand-new `trace.jsonl` holding unrelated content takes its place.
        std::fs::rename(&active, &archive).unwrap();
        let mut ev_e = make_event("e", None);
        ev_e.timestamp = "2026-01-01T00:00:04.000Z".into();
        ev_e.message = Some("ev-e".into());
        write_jsonl(&active, &[ev_e]);

        // Page 2 must continue into the rotated-away history, not restart from
        // the replacement active file.
        let cursor = SegmentCursor::from_wire(&cursor_wire).expect("valid cursor");
        let page2 = query_log_page(&active, true, &LogFilter::default(), 2, Some(&cursor)).unwrap();
        assert_eq!(
            page2.events.len(),
            2,
            "expected the two older events, got {:?}",
            page2
                .events
                .iter()
                .map(|e| e.message.as_deref())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            page2.events[0].message.as_deref(),
            Some("ev-b"),
            "page 2 must resume below the anchor, not return post-rotation writes"
        );
        assert_eq!(page2.events[1].message.as_deref(), Some("ev-a"));
    }

    #[test]
    fn find_event_across_segments_searches_active_then_archives() {
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let archive = tmp.path().join("trace.20260101-000000.jsonl");

        let mut archived = make_event("find-test", None);
        archived.id = "archived-id".into();
        archived.message = Some("in-archive".into());
        write_jsonl(&archive, &[archived]);

        let mut live = make_event("find-test", None);
        live.id = "live-id".into();
        live.message = Some("in-active".into());
        write_jsonl(&active, &[live]);

        let hit = find_event_across_segments(&active, true, "live-id").unwrap();
        assert_eq!(
            hit.expect("active hit").message.as_deref(),
            Some("in-active")
        );

        let hit = find_event_across_segments(&active, true, "archived-id").unwrap();
        assert_eq!(
            hit.expect("archive hit").message.as_deref(),
            Some("in-archive"),
            "an id that has rotated out of the active file must still resolve"
        );

        assert!(
            find_event_across_segments(&active, true, "no-such-id")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rolling_scope_does_not_merge_orphaned_archives() {
        // `rolling` never creates archives, but a path that previously ran
        // `rotating` still has them on disk, explicitly unmanaged. Merging them
        // into a rolling query would resurrect events the rolling window is
        // supposed to have discarded, and nothing would ever prune them since
        // no rotation runs to trigger retention.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let orphan = tmp.path().join("trace.20260101-000000.jsonl");

        let mut old_event = make_event("legacy", None);
        old_event.id = "orphaned".into();
        old_event.timestamp = "2026-01-01T00:00:00.000Z".into();
        old_event.message = Some("from-a-previous-rotating-config".into());
        write_jsonl(&orphan, &[old_event]);

        let mut live = make_event("current", None);
        live.id = "live".into();
        live.timestamp = "2026-01-02T00:00:00.000Z".into();
        live.message = Some("in-the-rolling-window".into());
        write_jsonl(&active, &[live]);

        // reads_archives = false: the rolling scope.
        let page = query_log_page(&active, false, &LogFilter::default(), 10, None).unwrap();
        assert_eq!(
            page.events.len(),
            1,
            "rolling must read the active file alone, got {:?}",
            page.events
                .iter()
                .map(|e| e.message.as_deref())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            page.events[0].message.as_deref(),
            Some("in-the-rolling-window")
        );

        // An id that lives only in the orphaned archive is likewise out of scope.
        assert!(
            find_event_across_segments(&active, false, "orphaned")
                .unwrap()
                .is_none(),
            "an orphaned archive's events are not part of the rolling stream"
        );

        // The same directory under the rotating scope does merge them, which is
        // what makes the distinction a policy boundary rather than a path one.
        let page = query_log_page(&active, true, &LogFilter::default(), 10, None).unwrap();
        assert_eq!(page.events.len(), 2, "rotating merges retained archives");
        assert!(
            find_event_across_segments(&active, true, "orphaned")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn stale_cursor_anchor_reports_missing_rather_than_full_scanning() {
        // `load_page_multi` sees one snapshot and cannot tell "the writer
        // rotated a moment ago, re-list and I will find it" apart from
        // "retention pruned this segment for good". It reports the miss so the
        // caller, which can re-enumerate, decides. This is the deterministic
        // stand-in for the in-call rotation race: rather than injecting timing,
        // the test hands the reader exactly the stale list such a race produces.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let archive = tmp.path().join("trace.20260101-000000.jsonl");

        let mut ev_a = make_event("a", None);
        ev_a.id = "id-a".into();
        ev_a.timestamp = "2026-01-01T00:00:00.000Z".into();
        let mut ev_b = make_event("b", None);
        ev_b.id = "id-b".into();
        ev_b.timestamp = "2026-01-01T00:00:01.000Z".into();
        write_jsonl(&active, &[ev_a, ev_b]);

        // Rotate: the cursor's file becomes an archive, a new active file
        // takes its basename.
        std::fs::rename(&active, &archive).unwrap();
        let mut ev_c = make_event("c", None);
        ev_c.id = "id-c".into();
        ev_c.timestamp = "2026-01-01T00:00:02.000Z".into();
        write_jsonl(&active, &[ev_c]);

        // A cursor anchored on an event that is now in the archive, paired with
        // the pre-rotation (empty) archive list: exactly the state a rotation
        // between enumeration and scanning leaves behind.
        let cursor = SegmentCursor {
            seg: "trace.jsonl".into(),
            off: 4096,
            anchor_id: Some("id-b".into()),
        };
        let outcome = load_page_multi(
            &segs_from(&active, &[]),
            &LogFilter::default(),
            2,
            Some(&cursor),
        )
        .unwrap();
        assert!(
            matches!(outcome, PageOutcome::AnchorMissing),
            "a stale list must surface the anchor miss, not silently full-scan"
        );

        // With the archive present, the same cursor resolves normally.
        let archive_mtime = std::fs::metadata(&archive).unwrap().modified().unwrap();
        let outcome = load_page_multi(
            &segs_from(&active, &[(archive.clone(), archive_mtime)]),
            &LogFilter::default(),
            2,
            Some(&cursor),
        )
        .unwrap();
        assert!(
            matches!(outcome, PageOutcome::Page(_)),
            "the anchor is reachable once the rotated archive is listed"
        );
    }

    #[test]
    fn segment_order_survives_multiple_rotations_during_one_read() {
        // The case an mtime-derived ordering key cannot handle. Two rotations
        // land while a reader is assembling its snapshot:
        //
        //   open A  ->  A rotates to an archive
        //           ->  B becomes active, then rotates too
        //           ->  C becomes active
        //
        // Ordering by enumeration-time mtime can place the newer archive
        // before the older pinned one, and the reader then reverses the merged
        // result into the wrong newest-first order. The sequence number is
        // written into the name at rotation time, so it describes the order
        // regardless of when or in what order a reader observes the files.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");

        // Archives as rotation would leave them, created newest-first on disk
        // so that mtime order is the reverse of true segment order.
        let seg_b = tmp.path().join("trace.0000000002-20260101-000200.jsonl");
        let seg_a = tmp.path().join("trace.0000000001-20260101-000100.jsonl");

        let mut ev_b = make_event("b", None);
        ev_b.id = "id-b".into();
        ev_b.timestamp = "2026-01-01T00:02:00.000Z".into();
        ev_b.message = Some("segment-b".into());
        write_jsonl(&seg_b, &[ev_b]);

        let mut ev_a = make_event("a", None);
        ev_a.id = "id-a".into();
        ev_a.timestamp = "2026-01-01T00:01:00.000Z".into();
        ev_a.message = Some("segment-a".into());
        write_jsonl(&seg_a, &[ev_a]);

        let mut ev_c = make_event("c", None);
        ev_c.id = "id-c".into();
        ev_c.timestamp = "2026-01-01T00:03:00.000Z".into();
        ev_c.message = Some("segment-c".into());
        write_jsonl(&active, &[ev_c]);

        // Force the two keys to disagree, rather than relying on write order
        // and filesystem timestamp resolution to produce a difference. The
        // lower-sequence segment is given the *newer* mtime, so ordering by
        // mtime yields the opposite result to ordering by sequence and the
        // assertion below can tell the two apart.
        let base = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
        set_mtime(&seg_b, base);
        set_mtime(&seg_a, base + std::time::Duration::from_secs(3600));
        let a_mtime = std::fs::metadata(&seg_a).unwrap().modified().unwrap();
        let b_mtime = std::fs::metadata(&seg_b).unwrap().modified().unwrap();
        assert!(
            a_mtime > b_mtime,
            "test setup: the lower-sequence segment must carry the newer mtime"
        );

        let page = query_log_page(&active, true, &LogFilter::default(), 10, None).unwrap();
        let seen: Vec<&str> = page
            .events
            .iter()
            .map(|e| e.message.as_deref().unwrap_or_default())
            .collect();
        assert_eq!(
            seen,
            vec!["segment-c", "segment-b", "segment-a"],
            "segments must be merged newest-first by sequence, not by mtime"
        );
    }

    #[test]
    fn legacy_archives_sort_before_numbered_ones() {
        // Archives written before sequence numbering existed carry no number.
        // They can only predate the upgrade, so they belong at the start of the
        // stream regardless of what their mtimes say.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("trace.jsonl");
        let legacy = tmp.path().join("trace.20260101-000000.jsonl");
        let numbered = tmp.path().join("trace.0000000001-20260101-000100.jsonl");

        let mut ev_old = make_event("old", None);
        ev_old.id = "id-old".into();
        ev_old.timestamp = "2026-01-01T00:00:00.000Z".into();
        ev_old.message = Some("legacy".into());
        write_jsonl(&legacy, &[ev_old]);

        let mut ev_new = make_event("new", None);
        ev_new.id = "id-new".into();
        ev_new.timestamp = "2026-01-01T00:01:00.000Z".into();
        ev_new.message = Some("numbered".into());
        write_jsonl(&numbered, &[ev_new]);

        let mut ev_live = make_event("live", None);
        ev_live.id = "id-live".into();
        ev_live.timestamp = "2026-01-01T00:02:00.000Z".into();
        ev_live.message = Some("active".into());
        write_jsonl(&active, &[ev_live]);

        let page = query_log_page(&active, true, &LogFilter::default(), 10, None).unwrap();
        let seen: Vec<&str> = page
            .events
            .iter()
            .map(|e| e.message.as_deref().unwrap_or_default())
            .collect();
        assert_eq!(
            seen,
            vec!["active", "numbered", "legacy"],
            "a legacy archive must read as older than every numbered archive"
        );
    }
}
