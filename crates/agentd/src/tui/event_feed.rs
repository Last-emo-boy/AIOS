use crate::audit::{AuditJournal, redact_summary};

use super::snapshot::{ProjectionSnapshot, ProjectionSourceSnapshot};

pub const DEFAULT_EVENT_FEED_LIMIT: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCursor {
    pub snapshot_hash: String,
    pub latest_run_id: Option<String>,
    pub offset: usize,
    pub limit: usize,
    pub total_events: usize,
    pub source_of_truth: bool,
    pub authority: &'static str,
}

impl EventCursor {
    fn from_snapshot(snapshot: &ProjectionSnapshot, total_events: usize, limit: usize) -> Self {
        let limit = limit.max(1);
        Self {
            snapshot_hash: snapshot.snapshot_hash.clone(),
            latest_run_id: snapshot.latest_run_id.clone(),
            offset: total_events.saturating_sub(limit),
            limit,
            total_events,
            source_of_truth: false,
            authority: "none; derived render cursor only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFeedItem {
    pub sequence: usize,
    pub kind: String,
    pub run_id: String,
    pub step_id: String,
    pub actor: String,
    pub summary: String,
}

impl EventFeedItem {
    fn from_line(sequence: usize, line: &str) -> Option<Self> {
        Some(Self {
            sequence,
            kind: json_string(line, "event_type")?,
            run_id: json_string(line, "run_id")?,
            step_id: json_string(line, "step_id")?,
            actor: json_string(line, "actor").unwrap_or_else(|| "-".to_string()),
            summary: redact_event_feed_text(&json_string(line, "summary")?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFeed {
    pub cursor: EventCursor,
    pub sources: Vec<ProjectionSourceSnapshot>,
    pub events: Vec<EventFeedItem>,
}

impl EventFeed {
    pub fn collect(
        snapshot: &ProjectionSnapshot,
        journal: &AuditJournal,
        limit: usize,
    ) -> Result<Self, String> {
        let audit_lines = journal
            .event_lines()
            .map_err(|error| format!("read audit journal failed: {error}"))?;
        let selected_run = snapshot.latest_run_id.as_deref();
        let mut events = audit_lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| EventFeedItem::from_line(index + 1, line))
            .filter(|event| selected_run.map_or(true, |run_id| event.run_id == run_id))
            .collect::<Vec<_>>();
        let total_events = events.len();
        let cursor = EventCursor::from_snapshot(snapshot, total_events, limit);
        events = events.into_iter().skip(cursor.offset).collect();
        Ok(Self {
            cursor,
            sources: vec![
                snapshot.runs.clone(),
                snapshot.audit.clone(),
                snapshot.approvals.clone(),
                snapshot.recovery.clone(),
                snapshot.support.clone(),
            ],
            events,
        })
    }

    pub fn degraded_sources(&self) -> Vec<&ProjectionSourceSnapshot> {
        self.sources
            .iter()
            .filter(|source| source.degraded)
            .collect()
    }

    pub fn render(&self) -> String {
        let mut lines = vec![
            "TUI Event Feed".to_string(),
            format!(
                "source=projection-snapshot+audit-journal cursor_authority=\"{}\" source_of_truth={} selected_run={} snapshot_hash={} offset={} limit={} total_events={} visible_events={} degraded_sources={}",
                self.cursor.authority,
                self.cursor.source_of_truth,
                self.cursor.latest_run_id.as_deref().unwrap_or("-"),
                self.cursor.snapshot_hash,
                self.cursor.offset,
                self.cursor.limit,
                self.cursor.total_events,
                self.events.len(),
                self.degraded_sources().len()
            ),
        ];
        lines.extend(self.sources.iter().map(|source| {
            format!(
                "source {} status={} freshness={} hash={} degraded={} authority=\"{}\" detail=\"{}\"",
                source.name,
                source.status,
                source.freshness,
                source.source_hash,
                source.degraded,
                source.authority,
                redact_event_feed_text(&source.detail)
            )
        }));
        if self.events.is_empty() {
            lines.push(
                "event[none] reason=\"no durable audit events for selected run\"".to_string(),
            );
        } else {
            lines.extend(self.events.iter().enumerate().map(|(index, event)| {
                format!(
                    "event[{}] sequence={} source=audit-journal kind={} run={} step={} actor={} summary=\"{}\"",
                    index,
                    event.sequence,
                    event.kind,
                    event.run_id,
                    event.step_id,
                    event.actor,
                    redact_event_feed_text(&event.summary)
                )
            }));
        }
        lines.join("\n")
    }
}

fn json_string(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = line.find(&pattern)? + pattern.len();
    let mut output = String::new();
    let mut escaped = false;
    for ch in line[start..].chars() {
        if escaped {
            output.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(output),
            _ => output.push(ch),
        }
    }
    None
}

fn redact_event_feed_text(value: &str) -> String {
    redact_inline_secret_assignments(&redact_summary(value))
}

fn redact_inline_secret_assignments(value: &str) -> String {
    let mut output = value.to_string();
    loop {
        let lower = output.to_ascii_lowercase();
        let found = [
            "password=",
            "token=",
            "apikey=",
            "api_key=",
            "access_token=",
            "secret=",
        ]
        .iter()
        .filter_map(|key| lower.find(key).map(|index| (index, *key)))
        .min_by_key(|(index, _)| *index);
        let Some((start, key)) = found else {
            return output;
        };
        let bytes = output.as_bytes();
        let mut end = start + key.len();
        while end < bytes.len()
            && !bytes[end].is_ascii_whitespace()
            && !matches!(bytes[end], b'"' | b'\'' | b',' | b']' | b')')
        {
            end += 1;
        }
        output.replace_range(start..end, "[REDACTED]");
    }
}
