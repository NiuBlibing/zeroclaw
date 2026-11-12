//! Legacy ACP schema reader for installation upgrades and old-schema fixtures.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
#[cfg(any(test, feature = "test-util"))]
use rusqlite::{Transaction, TransactionBehavior};
use std::path::Path;
use zeroclaw_api::media::AttachmentReference;
#[cfg(any(test, feature = "test-util"))]
use zeroclaw_api::model_provider::projected_entry_count;
use zeroclaw_api::model_provider::{ChatMessage, ConversationMessage, ToolCall, ToolResultMessage};
#[cfg(any(test, feature = "test-util"))]
use zeroclaw_api::plan::PlanEntry;
#[cfg(any(test, feature = "test-util"))]
use zeroclaw_api::session_events::transcript::bounded_transcript_messages;
use zeroclaw_api::session_events::transcript::provider_safe_history;
#[cfg(any(test, feature = "test-util"))]
use zeroclaw_log::{Action, EventOutcome};

#[cfg(any(test, feature = "test-util"))]
use crate::session_repository::SessionKillTransition as AcpSessionKillTransition;
use crate::session_repository::SessionTranscript as AcpSessionData;

/// Internal discriminator for `acp_tool_calls.event_kind`. The 'in' row
/// records the call args; the 'out' row records the result. Two append-only
/// rows per call, correlated by the provider-issued `tool_call_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "test-util"))]
enum ToolEventKind {
    In,
    Out,
}

#[cfg(any(test, feature = "test-util"))]
impl ToolEventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "in" => Some(Self::In),
            "out" => Some(Self::Out),
            _ => None,
        }
    }
}

/// Open-call balance after replaying one tool-call id's rows in order. An
/// `in` opens one call; an `out` folds into an open call while the balance
/// is positive and otherwise is an orphan entry that leaves the balance
/// untouched, so an orphan cannot consume a later call that reuses the id.
#[cfg(any(test, feature = "test-util"))]
fn open_calls_after(events: impl IntoIterator<Item = ToolEventKind>) -> usize {
    let mut open = 0usize;
    for event in events {
        match event {
            ToolEventKind::In => open += 1,
            ToolEventKind::Out => open = open.saturating_sub(1),
        }
    }
    open
}

/// Canonical breadcrumb text, duplicated from
/// `zeroclaw_runtime::agent::history::HISTORY_TRIM_BREADCRUMB_CANONICAL`.
/// This crate sits below `zeroclaw-runtime` in the dependency graph and
/// cannot import it; used only for one-time legacy-row migration below.
/// Keep in sync with the runtime constant.
const HISTORY_TRIM_BREADCRUMB_CANONICAL: &str = "[earlier turns omitted to fit the context window]";
const SYNTHETIC_INTERRUPTION_ROLE: &str = "__zeroclaw_turn_stream_interrupted__";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RetainedContextRecord {
    messages: Vec<ConversationMessage>,
}

pub struct LegacyAcpStore {
    conn: Mutex<Connection>,
    // Resolve the installation's canonical format fence on each transcript write.
    sessions_dir: std::path::PathBuf,
    importing: bool,
}

impl LegacyAcpStore {
    pub(crate) fn legacy_metadata(
        &self,
        session_uuid: &str,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let conn = self.legacy_connection()?;
        let (workspace, surface, tokens, plan): (String, Option<String>, i64, Option<String>) = conn.query_row(
            "SELECT workspace_dir, interaction_surface, token_count, plan_json FROM acp_sessions WHERE session_uuid=?1",
            params![session_uuid], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        let mut fields = vec![
            ("workspace_dir".into(), serde_json::json!(workspace)),
            ("interaction_surface".into(), serde_json::json!(surface)),
            (
                "latest_context_input_tokens".into(),
                serde_json::json!(tokens.max(0) as u64),
            ),
            (
                "plan".into(),
                match plan {
                    Some(plan) => serde_json::from_str(&plan)?,
                    None => serde_json::json!([]),
                },
            ),
        ];
        let mut statement = conn.prepare("SELECT e.action,e.outcome,e.payload,e.created_at FROM acp_session_events e JOIN acp_sessions s ON s.id=e.session_id WHERE s.session_uuid=?1 ORDER BY e.id")?;
        for row in statement.query_map(params![session_uuid], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })? {
            let (action, outcome, payload, created_at) = row?;
            fields.push(("protocol_observation".into(), serde_json::json!({"action":action,"outcome":outcome,"payload":payload,"created_at":created_at})));
        }
        Ok(fields)
    }

    pub(crate) fn legacy_checkpoint(
        &self,
        session_uuid: &str,
    ) -> Result<Option<serde_json::Value>> {
        let conn = self.legacy_connection()?;
        let checkpoint: Option<(i64, String, Option<i64>)> = conn.query_row(
            "SELECT c.session_id,c.turn_id,s.retained_context_frontier FROM acp_turn_checkpoints c JOIN acp_sessions s ON s.id=c.session_id WHERE s.session_uuid=?1",
            params![session_uuid], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let Some((session, turn, frontier)) = checkpoint else {
            return Ok(None);
        };
        let mut statement = conn.prepare(
            "SELECT payload FROM acp_turn_checkpoint_events WHERE session_id=?1 ORDER BY id",
        )?;
        let rows = statement
            .query_map(params![session], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let fragments = rows
            .into_iter()
            .map(|raw| serde_json::from_str::<ConversationMessage>(&raw))
            .collect::<serde_json::Result<Vec<_>>>()?;
        Ok(Some(
            serde_json::json!({"turn_id":turn,"retained_context_frontier":frontier,"fragments":fragments}),
        ))
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn new(workspace_dir: &Path) -> Result<Self> {
        let sessions_dir = workspace_dir.join("sessions");
        let guard = crate::session_events::installation::InstallationGuard::acquire(&sessions_dir)?;
        guard.require_legacy()?;
        Self::open_legacy(&sessions_dir, false)
    }

    pub(crate) fn open_import(
        guard: &crate::session_events::installation::InstallationGuard,
    ) -> Result<Self> {
        Self::open_legacy(guard.directory(), true)
    }

    fn legacy_connection(&self) -> Result<parking_lot::MutexGuard<'_, Connection>> {
        Ok(self.conn.lock())
    }

    fn open_legacy(sessions_dir: &Path, importing: bool) -> Result<Self> {
        std::fs::create_dir_all(sessions_dir).context("Failed to create sessions directory")?;
        let db_path = sessions_dir.join("acp-sessions.db");

        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open ACP session DB: {}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;",
        )
        .context("Failed to configure ACP session DB pragmas")?;

        // Schema is create-if-missing: ACP sessions are long-lived user data
        // and must survive daemon restarts. Never drop existing tables here.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS acp_sessions (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_uuid  TEXT NOT NULL UNIQUE,
                 agent_alias   TEXT NOT NULL,
                 workspace_dir TEXT NOT NULL,
                 interaction_surface TEXT,
                 token_count   INTEGER NOT NULL DEFAULT 0,
                 killed_at     TEXT,
                 retained_context_json TEXT,
                 retained_context_frontier INTEGER,
                 created_at    TEXT NOT NULL,
                 last_activity TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_acp_sessions_uuid  ON acp_sessions(session_uuid);
             CREATE INDEX IF NOT EXISTS idx_acp_sessions_alias ON acp_sessions(agent_alias);

             CREATE TABLE IF NOT EXISTS acp_messages (
                 id                INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id        INTEGER NOT NULL REFERENCES acp_sessions(id) ON DELETE CASCADE,
                 role              TEXT NOT NULL,
                 content           TEXT NOT NULL,
                 reasoning_content TEXT,
                 attachments_json TEXT,
                 created_at        TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_acp_messages_session ON acp_messages(session_id, id);

             CREATE TABLE IF NOT EXISTS acp_tool_calls (
                 id           INTEGER PRIMARY KEY AUTOINCREMENT,
                 message_id   INTEGER NOT NULL REFERENCES acp_messages(id) ON DELETE CASCADE,
                 tool_call_id TEXT NOT NULL,
                 tool_name    TEXT NOT NULL,
                 event_kind   TEXT NOT NULL,
                 payload      TEXT NOT NULL,
                 outcome      TEXT,
                 attachments_json TEXT,
                 created_at   TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_acp_tool_calls_message ON acp_tool_calls(message_id, id);
             CREATE INDEX IF NOT EXISTS idx_acp_tool_calls_lookup  ON acp_tool_calls(tool_call_id);

             CREATE TABLE IF NOT EXISTS acp_session_events (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id INTEGER NOT NULL REFERENCES acp_sessions(id) ON DELETE CASCADE,
                 action     TEXT NOT NULL,
                 outcome    TEXT NOT NULL,
                 payload    TEXT,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_acp_session_events_session ON acp_session_events(session_id, id);

             CREATE TABLE IF NOT EXISTS acp_turn_checkpoints (
                 session_id    INTEGER PRIMARY KEY REFERENCES acp_sessions(id) ON DELETE CASCADE,
                 turn_id       TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS acp_turn_checkpoint_events (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id INTEGER NOT NULL REFERENCES acp_turn_checkpoints(session_id) ON DELETE CASCADE,
                 payload    TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_acp_turn_checkpoint_events_session
                 ON acp_turn_checkpoint_events(session_id, id);",
        )
        .context("Failed to create ACP session schema")?;

        Self::ensure_killed_at_column(&conn)
            .context("Failed to migrate ACP session killed marker")?;

        Self::ensure_plan_json_column(&conn)
            .context("Failed to migrate ACP session plan column")?;

        Self::ensure_interaction_surface_column(&conn)
            .context("Failed to migrate ACP session interaction surface")?;

        Self::ensure_projected_message_count_columns(&conn)
            .context("Failed to migrate ACP session projected message count")?;
        Self::ensure_trim_breadcrumb_column(&conn)
            .context("Failed to migrate ACP session trim breadcrumb column")?;
        Self::ensure_principal_id_column(&conn)
            .context("Failed to migrate ACP session principal owner")?;

        Self::ensure_retained_context_columns(&conn)
            .context("Failed to migrate ACP retained context columns")?;

        Self::ensure_message_attachments_column(&conn)
            .context("Failed to migrate ACP message attachments")?;
        Self::ensure_tool_attachments_column(&conn)
            .context("Failed to migrate ACP tool attachments")?;

        Ok(Self {
            conn: Mutex::new(conn),
            sessions_dir: sessions_dir.into(),
            importing,
        })
    }

    fn ensure_message_attachments_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare("PRAGMA table_info(acp_messages)")?;
        let mut rows = stmt.query([])?;
        let mut present = false;
        while let Some(row) = rows.next()? {
            if row.get::<_, String>(1)? == "attachments_json" {
                present = true;
                break;
            }
        }
        drop(rows);
        drop(stmt);
        if !present {
            conn.execute(
                "ALTER TABLE acp_messages ADD COLUMN attachments_json TEXT",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_tool_attachments_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare("PRAGMA table_info(acp_tool_calls)")?;
        let mut rows = stmt.query([])?;
        let mut present = false;
        while let Some(row) = rows.next()? {
            if row.get::<_, String>(1)? == "attachments_json" {
                present = true;
                break;
            }
        }
        drop(rows);
        drop(stmt);
        if !present {
            conn.execute(
                "ALTER TABLE acp_tool_calls ADD COLUMN attachments_json TEXT",
                [],
            )?;
        }
        Ok(())
    }

    /// Add the `principal_id` owner column on upgrade (RFC 7141 session
    /// isolation). Existing rows keep a NULL owner -- visible only to unscoped
    /// connections -- mirroring the unified `session_backend` model.
    fn ensure_principal_id_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        let mut column_present = false;
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            let column: String = row
                .get(1)
                .context("Failed to read ACP session column name")?;
            if column == "principal_id" {
                column_present = true;
                break;
            }
        }
        drop(rows);
        drop(stmt);

        // The column and its index are one migration. An interrupted earlier
        // run can leave the column without the index, so the index statement
        // runs whenever the column exists, not only when it was just added.
        if !column_present {
            match conn.execute("ALTER TABLE acp_sessions ADD COLUMN principal_id TEXT", []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                    if msg.contains("duplicate column name") => {}
                Err(e) => return Err(e).context("Failed to add ACP session principal owner"),
            }
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_acp_sessions_principal \
             ON acp_sessions(principal_id)",
            [],
        )
        .context("Failed to index ACP session principal owner")?;
        Ok(())
    }

    fn ensure_killed_at_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            let column: String = row
                .get(1)
                .context("Failed to read ACP session column name")?;
            if column == "killed_at" {
                return Ok(());
            }
        }
        drop(rows);
        drop(stmt);

        match conn.execute("ALTER TABLE acp_sessions ADD COLUMN killed_at TEXT", []) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("duplicate column name") =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("Failed to add ACP session killed marker"),
        }
    }

    /// Idempotent migration adding the `plan_json` column that stores the
    /// session's latest TodoWrite plan as a JSON array of `PlanEntry`.
    /// Existing user databases predate this column; add it if absent so
    /// the plan survives daemon restarts (durable, like the transcript).
    fn ensure_plan_json_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            let column: String = row
                .get(1)
                .context("Failed to read ACP session column name")?;
            if column == "plan_json" {
                return Ok(());
            }
        }
        drop(rows);
        drop(stmt);

        match conn.execute("ALTER TABLE acp_sessions ADD COLUMN plan_json TEXT", []) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("duplicate column name") =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("Failed to add ACP session plan column"),
        }
    }

    /// Idempotent migration for the host-validated interaction surface bound
    /// to the session. NULL identifies sessions created before the field was
    /// introduced or by ACP entry points that do not declare a UI surface.
    fn ensure_interaction_surface_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            let column: String = row
                .get(1)
                .context("Failed to read ACP session column name")?;
            if column == "interaction_surface" {
                return Ok(());
            }
        }
        drop(rows);
        drop(stmt);

        match conn.execute(
            "ALTER TABLE acp_sessions ADD COLUMN interaction_surface TEXT",
            [],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("duplicate column name") =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("Failed to add ACP session interaction surface"),
        }
    }

    /// Idempotent migration adding the persisted projected conversation-entry
    /// count the session picker reports, together with the message-id
    /// watermark that says when that count is still valid. The message and
    /// tool-call rows remain the single source of truth: the
    /// (count, watermark) pair on `acp_sessions` is a cache of their
    /// projection, and a cache entry is valid exactly when
    /// `projected_count_through IS (SELECT MAX(id) FROM acp_messages WHERE
    /// session_id = s.id)` (SQLite `IS` is null-safe: an empty session with
    /// a NULL watermark is valid at count 0). Message ids are AUTOINCREMENT,
    /// so every insert by any binary lands past any earlier watermark and
    /// turns the cache stale instead of silently wrong. Stale sessions are
    /// rescored lazily from their rows on the read paths, never at open, so
    /// this migration is two plain idempotent column adds and the
    /// constructor never scores a session. A database an earlier build of
    /// this store already completed its one-pass scoring on needs nothing:
    /// that build's schema stamp is simply unused, and its sessions carry a
    /// NULL watermark and rescore lazily.
    fn ensure_projected_message_count_columns(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        let mut count_present = false;
        let mut watermark_present = false;
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            let column: String = row
                .get(1)
                .context("Failed to read ACP session column name")?;
            if column == "projected_message_count" {
                count_present = true;
            }
            if column == "projected_count_through" {
                watermark_present = true;
            }
        }
        drop(rows);
        drop(stmt);

        if !count_present {
            match conn.execute(
                "ALTER TABLE acp_sessions ADD COLUMN projected_message_count INTEGER NOT NULL DEFAULT 0",
                [],
            ) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                    if msg.contains("duplicate column name") => {}
                Err(e) => {
                    return Err(e).context("Failed to add ACP session projected message count");
                }
            }
        }
        if !watermark_present {
            match conn.execute(
                "ALTER TABLE acp_sessions ADD COLUMN projected_count_through INTEGER",
                [],
            ) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                    if msg.contains("duplicate column name") => {}
                Err(e) => {
                    return Err(e).context("Failed to add ACP session projected count watermark");
                }
            }
        }
        Ok(())
    }

    /// Idempotent migration adding the `trim_breadcrumb` column: whether the
    /// persisted transcript's first non-system message is the synthetic
    /// history-trim marker. Stored as one canonical fact alongside the
    /// transcript so a restore never has to infer provenance from message
    /// text (a genuine user turn that happens to equal the localized
    /// breadcrumb string must keep its turn-boundary role).
    fn ensure_trim_breadcrumb_column(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            let column: String = row
                .get(1)
                .context("Failed to read ACP session column name")?;
            if column == "trim_breadcrumb" {
                return Ok(());
            }
        }
        drop(rows);
        drop(stmt);

        // No `NOT NULL DEFAULT 0`: a `0` default would be indistinguishable
        // from an explicit "no breadcrumb" recorded by the owning turn loop.
        // Existing rows get `NULL` (unknown/legacy) and are migrated by
        // text inference on load; every row written after this migration
        // gets an explicit 0 or 1.
        match conn.execute(
            "ALTER TABLE acp_sessions ADD COLUMN trim_breadcrumb INTEGER",
            [],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("duplicate column name") =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("Failed to add ACP session trim breadcrumb column"),
        }
    }

    fn ensure_retained_context_columns(conn: &Connection) -> Result<()> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(acp_sessions)")
            .context("Failed to inspect ACP session schema")?;
        let mut rows = stmt
            .query([])
            .context("Failed to read ACP session schema")?;
        let mut columns = std::collections::HashSet::new();
        while let Some(row) = rows
            .next()
            .context("Failed to read ACP session schema row")?
        {
            columns.insert(
                row.get::<_, String>(1)
                    .context("Failed to read ACP session column name")?,
            );
        }
        drop(rows);
        drop(stmt);
        for (name, sql) in [
            (
                "retained_context_json",
                "ALTER TABLE acp_sessions ADD COLUMN retained_context_json TEXT",
            ),
            (
                "retained_context_frontier",
                "ALTER TABLE acp_sessions ADD COLUMN retained_context_frontier INTEGER",
            ),
        ] {
            if columns.contains(name) {
                continue;
            }
            match conn.execute(sql, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                    if msg.contains("duplicate column name") => {}
                Err(e) => return Err(e).with_context(|| format!("Failed to add {name}")),
            }
        }
        Ok(())
    }

    /// One-time legacy migration for rows written before the
    /// `trim_breadcrumb` column existed (`NULL`): infer provenance from
    /// whether the first non-system message is exactly the canonical
    /// breadcrumb text. A genuine user turn that happens to equal that text
    /// is misclassified on this one-time migration only; callers must
    /// persist the result via `record_inferred_trim_breadcrumb` so the
    /// column stops being `NULL` and later restores read the recorded fact
    /// instead of re-inferring it from message text on every load. This
    /// mirrors the JSONL interactive-session migration in
    /// `zeroclaw_runtime::agent::history::load_interactive_session_history_with_crumb`,
    /// restricted to the locale-independent canonical string because this
    /// crate sits below the runtime i18n layer.
    fn infer_legacy_trim_breadcrumb(messages: &[ConversationMessage]) -> bool {
        messages
            .iter()
            .find_map(|m| match m {
                ConversationMessage::Chat(chat) if chat.role != "system" => Some(chat),
                _ => None,
            })
            .is_some_and(|first| {
                first.role == "user" && first.content == HISTORY_TRIM_BREADCRUMB_CANONICAL
            })
    }

    /// Write the one-time `infer_legacy_trim_breadcrumb` result back to the
    /// still-`NULL` column, using the connection the caller already holds
    /// (avoids re-locking `self.conn`, which the caller's `load_session*`
    /// query has open). After this, the column is no longer `NULL` for this
    /// session, so the next restore reads the recorded fact rather than
    /// inferring it again from user-controlled text.
    fn record_inferred_trim_breadcrumb(
        conn: &Connection,
        session_uuid: &str,
        inferred: bool,
    ) -> Result<()> {
        conn.execute(
            "UPDATE acp_sessions SET trim_breadcrumb = ?1 WHERE session_uuid = ?2",
            params![i64::from(inferred), session_uuid],
        )
        .context("Failed to record inferred legacy trim_breadcrumb")?;
        Ok(())
    }

    /// Record a new session stamped with its owning principal (RFC 7141
    /// session isolation). `principal_id` is the caller's scope, or `None` for
    /// an unscoped/admin connection (NULL owner => visible only to unscoped
    /// connections). Returns the integer `id` assigned by SQLite.
    #[cfg(any(test, feature = "test-util"))]
    pub fn create_session(
        &self,
        session_uuid: &str,
        agent_alias: &str,
        workspace_dir: &str,
        principal_id: Option<&str>,
    ) -> Result<i64> {
        self.create_session_with_interaction_surface(
            session_uuid,
            agent_alias,
            workspace_dir,
            None,
            principal_id,
        )
    }

    /// Record a session with an optional host-validated interaction surface,
    /// stamped with its owning principal (RFC 7141).
    #[cfg(any(test, feature = "test-util"))]
    pub fn create_session_with_interaction_surface(
        &self,
        session_uuid: &str,
        agent_alias: &str,
        workspace_dir: &str,
        interaction_surface: Option<&str>,
        principal_id: Option<&str>,
    ) -> Result<i64> {
        let _installation = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let now = Utc::now().to_rfc3339();
        let conn = self.legacy_connection()?;
        conn.execute(
            "INSERT INTO acp_sessions
               (session_uuid, agent_alias, workspace_dir, interaction_surface, token_count, created_at, last_activity, trim_breadcrumb, principal_id)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5, 0, ?6)",
            params![
                session_uuid,
                agent_alias,
                workspace_dir,
                interaction_surface,
                now,
                principal_id
            ],
        )
        .context("Failed to create ACP session")?;
        Ok(conn.last_insert_rowid())
    }

    /// Load session metadata and full message history for restore.
    /// Returns `None` if the session_uuid is not found.
    pub fn load_session(&self, session_uuid: &str) -> Result<Option<AcpSessionData>> {
        // Legacy reads may repair derived columns. Import already owns this
        // lock; public reads must fence those writes against installation cutover.
        let _installation = (!self.importing)
            .then(|| crate::session_events::installation::legacy_guard(&self.sessions_dir))
            .transpose()?;
        let conn = self.legacy_connection()?;

        let row = conn.query_row(
            "SELECT id, agent_alias, workspace_dir, interaction_surface, token_count, created_at, last_activity, trim_breadcrumb, principal_id
             FROM acp_sessions WHERE session_uuid = ?1",
            params![session_uuid],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        );

        let (
            session_id,
            agent_alias,
            workspace_dir,
            interaction_surface,
            token_count,
            created_at_s,
            last_activity_s,
            trim_breadcrumb_raw,
            principal_id,
        ) = match row {
            Ok(r) => r,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e).context("Failed to query ACP session"),
        };

        let created_at = parse_ts(&created_at_s, "created_at", session_uuid);
        let last_activity = parse_ts(&last_activity_s, "last_activity", session_uuid);

        let messages = Self::load_messages(&conn, session_id)?;
        let retained_context = Self::load_retained_context(&conn, session_id)?;
        let trim_breadcrumb = match trim_breadcrumb_raw {
            Some(v) => v != 0,
            None => {
                let inferred = Self::infer_legacy_trim_breadcrumb(&messages);
                Self::record_inferred_trim_breadcrumb(&conn, session_uuid, inferred)?;
                inferred
            }
        };

        Ok(Some(AcpSessionData {
            session_uuid: session_uuid.to_string(),
            agent_alias,
            workspace_dir,
            interaction_surface,
            latest_context_input_tokens: token_count.max(0) as u64,
            created_at,
            last_activity,
            messages,
            trim_breadcrumb,
            retained_context,
            principal_id,
        }))
    }

    /// Every durable ACP session key, used only to fail closed when a Chat key
    /// collides with the separate ACP namespace.
    pub fn list_session_ids(&self) -> Result<Vec<String>> {
        let conn = self.legacy_connection()?;
        let mut stmt = conn
            .prepare("SELECT session_uuid FROM acp_sessions")
            .context("Failed to prepare ACP session key query")?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .context("Failed to query ACP session keys")?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Failed to read ACP session keys")
    }

    fn load_messages(conn: &Connection, session_id: i64) -> Result<Vec<ConversationMessage>> {
        // Pull all message rows, excluding any `system` row. `insert_messages`
        // has never written one since the write-path filter that keeps the
        // Agent's system prompt out of authoritative replacements, but a
        // database created before that fix can still have one on disk;
        // filtering here is defense in depth so a restored session or a
        // `session/messages` read can't re-expose it even if a write path
        // regresses or an old row survives a partial migration.
        let mut msg_stmt = conn
            .prepare(
                "SELECT id, role, content, reasoning_content, attachments_json
                 FROM acp_messages WHERE session_id = ?1 AND role != 'system' ORDER BY id ASC",
            )
            .context("Failed to prepare message query")?;

        let msg_rows = msg_stmt
            .query_map(params![session_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to read message rows")?;

        // For each message row, pull its tool_calls (event_kind='in') and
        // tool_results (event_kind='out') in id order.
        let mut tc_stmt = conn
            .prepare(
                "SELECT tool_call_id, tool_name, event_kind, payload, attachments_json
                 FROM acp_tool_calls WHERE message_id = ?1 ORDER BY id ASC",
            )
            .context("Failed to prepare tool_call query")?;

        let mut out = Vec::with_capacity(msg_rows.len());
        for (msg_id, role, content, reasoning_content, attachments_json) in msg_rows {
            let attachments = parse_attachments(attachments_json)?;
            // Split this message's tool_calls into ins and outs preserving order.
            let mut ins: Vec<ToolCall> = Vec::new();
            let mut outs: Vec<ToolResultMessage> = Vec::new();
            let rows = tc_stmt
                .query_map(params![msg_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to read tool_call rows")?;
            for (tool_call_id, tool_name, event_kind, payload, attachments_json) in rows {
                match event_kind.as_str() {
                    "in" => ins.push(ToolCall {
                        id: tool_call_id,
                        name: tool_name,
                        arguments: payload,
                        extra_content: None,
                    }),
                    "out" => outs.push(ToolResultMessage {
                        success: None,
                        tool_call_id,
                        content: payload,
                        // Carry the producing tool name (looked up from the
                        // matching 'in' row on write) so a resumed session
                        // retains the producing tool's identity.
                        tool_name,
                        attachments: parse_attachments(attachments_json)?,
                    }),
                    other => {
                        ::zeroclaw_log::record!(
                            ERROR,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Read,
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "session_id": session_id,
                                "message_id": msg_id,
                                "event_kind": other,
                            })),
                            "unknown event_kind in acp_tool_calls"
                        );
                        return Err(anyhow::Error::msg(format!(
                            "unknown event_kind '{other}' in acp_tool_calls for message_id {msg_id}"
                        )));
                    }
                }
            }

            let role = if role == SYNTHETIC_INTERRUPTION_ROLE {
                "system".to_string()
            } else {
                role
            };
            // A row with no 'in' rows is a chat message, with any 'out' rows
            // following it as their own entries: the persisted counter
            // scores the parent row once for its text and each unmatched
            // result once, so the reload must present the same entries.
            if ins.is_empty() {
                out.push(ConversationMessage::Chat(ChatMessage {
                    timestamp: None,
                    role,
                    content,
                    attachments,
                    tool_calls: Vec::new(),
                    tool_result: None,
                    reasoning_content: None,
                }));
                if !outs.is_empty() {
                    out.push(ConversationMessage::ToolResults(outs));
                }
            } else {
                // Assistant turn that issued tool calls. The text may be empty.
                out.push(ConversationMessage::AssistantToolCalls {
                    text: if content.is_empty() {
                        None
                    } else {
                        Some(content)
                    },
                    tool_calls: ins,
                    reasoning_content,
                });
                if !outs.is_empty() {
                    out.push(ConversationMessage::ToolResults(outs));
                }
            }
        }

        Ok(out)
    }

    fn load_retained_context(
        conn: &Connection,
        session_id: i64,
    ) -> Result<Option<Vec<ConversationMessage>>> {
        let payload: Option<String> = conn
            .query_row(
                "SELECT retained_context_json FROM acp_sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()
            .context("Failed to read ACP retained context")?
            .flatten();
        let Some(payload) = payload else {
            return Ok(None);
        };
        let record = serde_json::from_str::<RetainedContextRecord>(&payload)
            .context("Failed to deserialize ACP retained context")?;
        Ok(Some(provider_safe_history(&record.messages)))
    }

    /// Build legacy transcript rows for migration fixtures, excluding runtime
    /// system prompts as the old writer did.
    ///
    /// Returns the projected conversation-entry count of the inserted batch,
    /// folded against the tool-call rows already visible in this transaction:
    /// `append_messages` adds it to the persisted counter.
    #[cfg(any(test, feature = "test-util"))]
    fn insert_messages(
        tx: &Transaction<'_>,
        session_id: i64,
        messages: &[ConversationMessage],
        now: &str,
    ) -> Result<i64> {
        // Track the most recent assistant message_id so a following
        // ToolResults variant can attach its 'out' rows back to it.
        let mut last_assistant_msg_id: Option<i64> = None;
        // Persisted counter mirroring the runtime's projected conversation
        // length: one entry per chat message, non-empty assistant text plus
        // one per tool call, results folding into the call awaiting them.
        let mut projected_increment: i64 = 0;

        for msg in messages {
            match msg {
                ConversationMessage::Chat(chat) if chat.role == "system" => continue,
                ConversationMessage::Chat(chat) => {
                    tx.execute(
                        "INSERT INTO acp_messages
                           (session_id, role, content, reasoning_content, attachments_json, created_at)
                         VALUES (?1, ?2, ?3, NULL, ?4, ?5)",
                        params![
                            session_id,
                            chat.role,
                            chat.content,
                            serde_json::to_string(&chat.attachments)?,
                            now,
                        ],
                    )
                    .context("Failed to insert chat message")?;
                    projected_increment += 1;
                    if chat.role == "assistant" {
                        last_assistant_msg_id = Some(tx.last_insert_rowid());
                    }
                }
                ConversationMessage::AssistantToolCalls {
                    text,
                    tool_calls,
                    reasoning_content,
                } => {
                    if text.as_deref().is_some_and(|text| !text.is_empty()) {
                        projected_increment += 1;
                    }
                    projected_increment += tool_calls.len() as i64;
                    // Zero-entry batch: nothing to persist, keeps the counter
                    // and the reloaded projection equal.
                    if tool_calls.is_empty()
                        && !text.as_deref().is_some_and(|text| !text.is_empty())
                    {
                        continue;
                    }
                    tx.execute(
                        "INSERT INTO acp_messages
                           (session_id, role, content, reasoning_content, created_at)
                         VALUES (?1, 'assistant', ?2, ?3, ?4)",
                        params![
                            session_id,
                            text.as_deref().unwrap_or(""),
                            reasoning_content,
                            now,
                        ],
                    )
                    .context("Failed to insert assistant tool-call message")?;
                    let msg_id = tx.last_insert_rowid();
                    last_assistant_msg_id = Some(msg_id);

                    for tc in tool_calls {
                        tx.execute(
                            "INSERT INTO acp_tool_calls
                               (message_id, tool_call_id, tool_name, event_kind, payload, outcome, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                            params![
                                msg_id,
                                tc.id,
                                tc.name,
                                ToolEventKind::In.as_str(),
                                tc.arguments,
                                now,
                            ],
                        )
                        .context("Failed to insert tool_call 'in' row")?;
                    }
                }
                ConversationMessage::ToolResults(results) => {
                    let msg_id = match last_assistant_msg_id {
                        Some(id) => id,
                        None => {
                            ::zeroclaw_log::record!(
                                ERROR,
                                ::zeroclaw_log::Event::new(
                                    module_path!(),
                                    ::zeroclaw_log::Action::Write,
                                )
                                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                .with_attrs(::serde_json::json!({
                                    "session_id": session_id,
                                })),
                                "ToolResults without preceding AssistantToolCalls"
                            );
                            return Err(anyhow::Error::msg(
                                "ToolResults appeared without a preceding AssistantToolCalls \
                                 message in this turn — cannot determine parent message_id",
                            ));
                        }
                    };
                    // This id's rows for the session, in write order; the
                    // fold below replays them through the shared clamp rule.
                    let mut history_stmt = tx
                        .prepare(
                            "SELECT tc.event_kind
                               FROM acp_tool_calls tc
                               JOIN acp_messages m ON m.id = tc.message_id
                              WHERE m.session_id = ?1 AND tc.tool_call_id = ?2
                              ORDER BY tc.id",
                        )
                        .context("Failed to prepare tool call history query")?;
                    for result in results {
                        let tool_name: String = tx
                            .query_row(
                                "SELECT tool_name FROM acp_tool_calls
                                 WHERE tool_call_id = ?1 AND event_kind = 'in'
                                 ORDER BY id DESC LIMIT 1",
                                params![result.tool_call_id],
                                |row| row.get(0),
                            )
                            .unwrap_or_else(|_| String::from("unknown"));
                        let events: Vec<ToolEventKind> = history_stmt
                            .query_map(params![session_id, result.tool_call_id], |row| {
                                row.get::<_, String>(0)
                            })
                            .context("Failed to look up tool call history")?
                            .collect::<Result<Vec<_>, _>>()
                            .context("Failed to read tool call history rows")?
                            .into_iter()
                            .map(|kind| ToolEventKind::parse(&kind))
                            .collect::<Option<Vec<_>>>()
                            .context("Unknown event_kind in tool call history")?;
                        // A result folds into its call (no entry) while an
                        // 'in' row for this tool_call_id is still unconsumed;
                        // beyond that it is an orphan entry. An orphan leaves
                        // the open-call balance untouched, so a later call
                        // reusing the id still opens fresh.
                        if open_calls_after(events) == 0 {
                            projected_increment += 1;
                        }
                        tx.execute(
                            "INSERT INTO acp_tool_calls
                               (message_id, tool_call_id, tool_name, event_kind, payload, outcome, attachments_json, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![
                                msg_id,
                                result.tool_call_id,
                                tool_name,
                                ToolEventKind::Out.as_str(),
                                result.content,
                                EventOutcome::Unknown.as_str(),
                                serde_json::to_string(&result.attachments)?,
                                now,
                            ],
                        )
                        .context("Failed to insert tool_call 'out' row")?;
                    }
                }
            }
        }

        Ok(projected_increment)
    }

    /// Append `messages` to the visible transcript and keep the persisted
    /// projected-entry count cache in step, in the caller's transaction.
    /// Used only to build old-format migration inputs. The batch's score is
    /// added only while the session's watermark still matches its rows; a cache a writer
    /// without the columns left behind is recomputed from the rows instead.
    #[cfg(any(test, feature = "test-util"))]
    fn append_messages(
        tx: &Transaction<'_>,
        session_uuid: &str,
        session_id: i64,
        messages: &[ConversationMessage],
        now: &str,
    ) -> Result<()> {
        let messages = bounded_transcript_messages(messages);
        // The persisted pair is a cache of the rows' projection, valid only
        // while the watermark matches the session's current MAX(id). Read
        // both before inserting: a mismatch means a writer this store did
        // not observe (a binary without the cache columns, or a raw insert
        // such as the recovery interruption marker) left rows past the
        // watermark, and the increment below would build on a stale base.
        let (watermark, max_id): (Option<i64>, Option<i64>) = tx
            .query_row(
                "SELECT s.projected_count_through,
                        (SELECT MAX(m.id) FROM acp_messages m
                          WHERE m.session_id = s.id)
                   FROM acp_sessions s
                  WHERE s.id = ?1",
                params![session_id],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .context("Failed to read ACP session projected count cache")?;
        let projected_increment = Self::insert_messages(tx, session_id, &messages, now)?;
        let watermark_now: Option<i64> = tx
            .query_row(
                "SELECT MAX(id) FROM acp_messages WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .context("Failed to read ACP session watermark")?;
        if watermark == max_id {
            // A valid cache: keep the increment and move the watermark to
            // the rows this transaction just wrote.
            tx.execute(
                "UPDATE acp_sessions
                    SET last_activity = ?1,
                        projected_message_count = projected_message_count + ?2,
                        projected_count_through = ?3
                  WHERE id = ?4",
                params![now, projected_increment, watermark_now, session_id],
            )
            .with_context(|| format!("Failed to update last_activity for {session_uuid}"))?;
            return Ok(());
        }
        // A stale cache: recompute the whole projection from the rows so the
        // increment never builds on the stale base. A session whose rows
        // cannot be reloaded keeps its stale pair untouched (the reload logs
        // it) and stays stale for a later read to heal once the rows are
        // repaired; the cache must not fail the append itself.
        match Self::load_messages(tx, session_id) {
            Ok(messages) => {
                let projected_count = projected_entry_count(&messages) as i64;
                tx.execute(
                    "UPDATE acp_sessions
                        SET last_activity = ?1,
                            projected_message_count = ?2,
                            projected_count_through = ?3
                      WHERE id = ?4",
                    params![now, projected_count, watermark_now, session_id],
                )
                .with_context(|| format!("Failed to update last_activity for {session_uuid}"))?;
            }
            Err(error) => {
                ::zeroclaw_log::record!(
                    ERROR,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Write,)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({
                            "session_uuid": session_uuid,
                            "error": error.to_string(),
                        })),
                    "Failed to reload ACP session for projected-count resync; leaving its persisted count untouched"
                );
                tx.execute(
                    "UPDATE acp_sessions SET last_activity = ?1 WHERE id = ?2",
                    params![now, session_id],
                )
                .with_context(|| format!("Failed to update last_activity for {session_uuid}"))?;
            }
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-util"))]
    fn session_id(conn: &Connection, session_uuid: &str) -> Result<i64> {
        conn.query_row(
            "SELECT id FROM acp_sessions WHERE session_uuid = ?1",
            params![session_uuid],
            |row| row.get(0),
        )
        .with_context(|| format!("unknown session_uuid: {session_uuid}"))
    }

    /// Append all ConversationMessages from one completed turn in one transaction.
    #[cfg(any(test, feature = "test-util"))]
    pub fn append_turn(&self, session_uuid: &str, messages: &[ConversationMessage]) -> Result<()> {
        let _family_guard = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        if messages.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut conn = self.legacy_connection()?;
        let session_id = Self::session_id(&conn, session_uuid)?;
        let tx = conn
            .transaction()
            .context("Failed to begin append_turn transaction")?;
        Self::append_messages(&tx, session_uuid, session_id, messages, &now)?;

        tx.commit().context("Failed to commit append_turn")?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn begin_turn_checkpoint(
        &self,
        session_uuid: &str,
        turn_id: &str,
        messages: &[ConversationMessage],
    ) -> Result<()> {
        let _family_guard = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let mut conn = self.legacy_connection()?;
        let session_id = Self::session_id(&conn, session_uuid)?;
        let tx = conn
            .transaction()
            .context("Failed to begin ACP turn checkpoint transaction")?;
        tx.execute(
            "INSERT INTO acp_turn_checkpoints (session_id, turn_id) VALUES (?1, ?2)",
            params![session_id, turn_id],
        )
        .context("Failed to begin ACP turn checkpoint")?;
        Self::append_checkpoint_events(&tx, session_id, messages)?;
        tx.commit()
            .context("Failed to commit ACP turn checkpoint")?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-util"))]
    fn append_checkpoint_events(
        tx: &Transaction<'_>,
        session_id: i64,
        messages: &[ConversationMessage],
    ) -> Result<i64> {
        let mut frontier = tx
            .query_row(
                "SELECT COALESCE(MAX(id), 0) FROM acp_turn_checkpoint_events WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .context("Failed to read ACP checkpoint frontier")?;
        for message in bounded_transcript_messages(messages) {
            let payload = serde_json::to_string(&message)
                .context("Failed to serialize ACP turn checkpoint event")?;
            tx.execute(
                "INSERT INTO acp_turn_checkpoint_events (session_id, payload) VALUES (?1, ?2)",
                params![session_id, payload],
            )
            .context("Failed to append ACP turn checkpoint event")?;
            frontier = tx.last_insert_rowid();
        }
        Ok(frontier)
    }

    /// Persist a seed-time trim projection. No turn checkpoint exists during
    /// restore, so this path verifies only the session identity and commits the
    /// owner-produced snapshot before its notification is forwarded.
    #[cfg(any(test, feature = "test-util"))]
    pub fn persist_retained_context_seed(
        &self,
        session_uuid: &str,
        retained_messages: &[ConversationMessage],
        breadcrumb: bool,
    ) -> Result<()> {
        let _family_guard = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let mut conn = self.legacy_connection()?;
        let session_id = Self::session_id(&conn, session_uuid)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Failed to begin retained seed context transaction")?;
        let retained = bounded_transcript_messages(retained_messages);
        let record = RetainedContextRecord {
            messages: Self::without_hidden_reasoning(&provider_safe_history(&retained)),
        };
        let payload =
            serde_json::to_string(&record).context("Failed to serialize retained seed context")?;
        tx.execute(
            "UPDATE acp_sessions
                SET retained_context_json = ?1,
                    retained_context_frontier = 0,
                    trim_breadcrumb = ?2,
                    last_activity = ?3
              WHERE id = ?4",
            params![
                payload,
                i64::from(breadcrumb),
                Utc::now().to_rfc3339(),
                session_id
            ],
        )
        .context("Failed to write retained seed context")?;
        tx.commit()
            .context("Failed to commit retained seed context")?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-util"))]
    fn without_hidden_reasoning(messages: &[ConversationMessage]) -> Vec<ConversationMessage> {
        messages
            .iter()
            .map(|message| match message {
                ConversationMessage::AssistantToolCalls {
                    text,
                    tool_calls,
                    reasoning_content: _,
                } => ConversationMessage::AssistantToolCalls {
                    text: text.clone(),
                    tool_calls: tool_calls.clone(),
                    reasoning_content: None,
                },
                other => other.clone(),
            })
            .collect()
    }

    /// Populate the legacy usage column for migration fixtures.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_token_count(&self, session_uuid: &str, token_count: u64) -> Result<()> {
        let _installation = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let conn = self.legacy_connection()?;
        let rows = conn
            .execute(
                "UPDATE acp_sessions SET token_count = ?1 WHERE session_uuid = ?2",
                params![token_count as i64, session_uuid],
            )
            .context("Failed to set token_count")?;
        if rows == 0 {
            return Err(anyhow::Error::msg(format!(
                "set_token_count: no session with uuid {session_uuid}"
            )));
        }
        Ok(())
    }

    /// Persist the session's latest TodoWrite plan as a JSON array of
    /// `PlanEntry` (whole-list replace). An empty slice stores an empty
    /// array (a cleared plan), distinct from SQL NULL (never had one).
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_plan(&self, session_uuid: &str, entries: &[PlanEntry]) -> Result<()> {
        let _installation = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let plan_json =
            serde_json::to_string(entries).context("Failed to serialize plan entries")?;
        let conn = self.legacy_connection()?;
        let rows = conn
            .execute(
                "UPDATE acp_sessions SET plan_json = ?1 WHERE session_uuid = ?2",
                params![plan_json, session_uuid],
            )
            .context("Failed to set plan_json")?;
        if rows == 0 {
            return Err(anyhow::Error::msg(format!(
                "set_plan: no session with uuid {session_uuid}"
            )));
        }
        Ok(())
    }

    /// Record a session-lifecycle event. Caller passes typed enums; the SQLite
    /// layer is the only place strings appear. Same `Action` / `EventOutcome`
    /// values are used at the matching `zeroclaw_log::record!` call site.
    #[cfg(any(test, feature = "test-util"))]
    pub fn append_event(
        &self,
        session_uuid: &str,
        action: Action,
        outcome: EventOutcome,
        payload: Option<&str>,
    ) -> Result<()> {
        let _installation = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let now = Utc::now().to_rfc3339();
        let conn = self.legacy_connection()?;
        let session_id: i64 = conn
            .query_row(
                "SELECT id FROM acp_sessions WHERE session_uuid = ?1",
                params![session_uuid],
                |row| row.get(0),
            )
            .with_context(|| format!("unknown session_uuid: {session_uuid}"))?;
        conn.execute(
            "INSERT INTO acp_session_events
               (session_id, action, outcome, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session_id, action.as_str(), outcome.as_str(), payload, now],
        )
        .context("Failed to insert session event")?;
        Ok(())
    }

    // ── per-agent cascade (agent deletion,───────────────────────────

    /// Atomically persist that an admin intentionally killed this ACP session.
    /// The transcript and any checkpoint stay durable, but runtime rehydration
    /// must not revive it.
    #[cfg(any(test, feature = "test-util"))]
    pub fn mark_session_killed_atomic(
        &self,
        session_uuid: &str,
    ) -> Result<AcpSessionKillTransition> {
        self.mark_session_killed_atomic_for_owner(session_uuid, None)
    }

    /// Tombstone only the durable row still owned by this principal. The
    /// update predicate and transition inspection share one transaction.
    #[cfg(any(test, feature = "test-util"))]
    pub fn mark_session_killed_atomic_for_owner(
        &self,
        session_uuid: &str,
        owner_principal_id: Option<&str>,
    ) -> Result<AcpSessionKillTransition> {
        let _installation = crate::session_events::installation::legacy_guard(&self.sessions_dir)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.legacy_connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Failed to begin ACP session kill transition")?;
        let rows = tx
            .execute(
                "UPDATE acp_sessions
                    SET killed_at = COALESCE(killed_at, ?1),
                        last_activity = ?1
                  WHERE session_uuid = ?2 AND killed_at IS NULL
                    AND (?3 IS NULL OR principal_id = ?3)",
                params![now, session_uuid, owner_principal_id],
            )
            .context("Failed to mark ACP session killed")?;
        let transition = if rows == 1 {
            AcpSessionKillTransition::Marked
        } else {
            let killed_at: Option<Option<String>> = tx
                .query_row(
                    "SELECT killed_at FROM acp_sessions
                     WHERE session_uuid = ?1 AND (?2 IS NULL OR principal_id = ?2)",
                    params![session_uuid, owner_principal_id],
                    |row| row.get(0),
                )
                .optional()
                .context("Failed to inspect ACP session kill transition")?;
            match killed_at {
                Some(Some(_)) => AcpSessionKillTransition::AlreadyKilled,
                Some(None) => {
                    anyhow::bail!("ACP session kill transition made no durable change")
                }
                None => AcpSessionKillTransition::Missing,
            }
        };
        tx.commit()
            .context("Failed to commit ACP session kill transition")?;
        Ok(transition)
    }

    /// Persist that an admin intentionally killed this ACP session. The
    /// transcript stays durable, but runtime rehydration must not revive it.
    /// This compatibility wrapper retains the original boolean contract for
    /// existing callers; use `mark_session_killed_atomic` when the distinction
    /// between marked, already-killed, and missing matters.
    #[cfg(any(test, feature = "test-util"))]
    pub fn mark_session_killed(&self, session_uuid: &str) -> Result<bool> {
        Ok(matches!(
            self.mark_session_killed_atomic(session_uuid)?,
            AcpSessionKillTransition::Marked | AcpSessionKillTransition::AlreadyKilled
        ))
    }

    /// Return whether this durable ACP session has been intentionally killed.
    /// Missing rows are not killed; callers can then use normal load handling
    /// to distinguish SESSION_NOT_FOUND from a terminal killed session.
    pub fn is_session_killed(&self, session_uuid: &str) -> Result<bool> {
        let conn = self.legacy_connection()?;
        let row = conn.query_row(
            "SELECT CASE WHEN killed_at IS NULL THEN 0 ELSE 1 END
             FROM acp_sessions WHERE session_uuid = ?1",
            params![session_uuid],
            |row| row.get::<_, i64>(0),
        );
        match row {
            Ok(killed) => Ok(killed != 0),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e).context("Failed to query ACP session killed marker"),
        }
    }
}

fn parse_attachments(raw: Option<String>) -> Result<Vec<AttachmentReference>> {
    raw.filter(|value| !value.is_empty())
        .map(|value| serde_json::from_str(&value).context("invalid persisted attachment list"))
        .transpose()
        .map(|attachments| attachments.unwrap_or_default())
}

fn parse_ts(s: &str, field: &'static str, session_uuid: &str) -> DateTime<Utc> {
    s.parse::<DateTime<Utc>>().unwrap_or_else(|e| {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
                ::serde_json::json!({
                    "session_uuid": session_uuid,
                    "field": field,
                    "error": e.to_string(),
                })
            ),
            "Failed to parse session timestamp"
        );
        Utc::now()
    })
}
