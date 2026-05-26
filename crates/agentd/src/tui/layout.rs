use crate::audit::redact_summary;

use super::palette::CommandPreview;
use super::snapshot::ProjectionSnapshot;

pub const WIDE_LAYOUT_MIN_COLUMNS: u16 = 100;
pub const WIDE_LAYOUT_MIN_ROWS: u16 = 24;
pub const STATUS_BAR_HEIGHT: u16 = 1;
pub const TAB_STRIP_HEIGHT: u16 = 1;
pub const COMMAND_PALETTE_HEIGHT: u16 = 3;
pub const NAVIGATION_RAIL_WIDTH: u16 = 20;
pub const EVENT_FEED_WIDTH: u16 = 34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub columns: u16,
    pub rows: u16,
}

impl TerminalSize {
    pub fn new(columns: u16, rows: u16) -> Self {
        Self { columns, rows }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl PaneRect {
    fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn right(self) -> u16 {
        self.x.saturating_add(self.width)
    }

    pub fn bottom(self) -> u16 {
        self.y.saturating_add(self.height)
    }

    pub fn contains_text_width(self, value: &str) -> bool {
        value.chars().count() <= self.width as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    Wide,
    Narrow,
}

impl LayoutMode {
    pub fn as_str(self) -> &'static str {
        match self {
            LayoutMode::Wide => "wide",
            LayoutMode::Narrow => "narrow",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPanel {
    Dashboard,
    Runs,
    Approvals,
    Recovery,
    Support,
    Ecosystem,
    Release,
}

impl FocusPanel {
    pub fn as_str(self) -> &'static str {
        match self {
            FocusPanel::Dashboard => "dashboard",
            FocusPanel::Runs => "runs",
            FocusPanel::Approvals => "approvals",
            FocusPanel::Recovery => "recovery",
            FocusPanel::Support => "support",
            FocusPanel::Ecosystem => "ecosystem",
            FocusPanel::Release => "release",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneKind {
    StatusBar,
    NavigationRail,
    RunWorkspace,
    EventFeed,
    CommandPalette,
    TabStrip,
    FocusPanel,
}

impl PaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PaneKind::StatusBar => "status-bar",
            PaneKind::NavigationRail => "navigation-rail",
            PaneKind::RunWorkspace => "run-workspace",
            PaneKind::EventFeed => "event-feed",
            PaneKind::CommandPalette => "command-palette",
            PaneKind::TabStrip => "tab-strip",
            PaneKind::FocusPanel => "focus-panel",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pane {
    pub kind: PaneKind,
    pub title: String,
    pub rect: PaneRect,
}

impl Pane {
    fn new(kind: PaneKind, title: &'static str, rect: PaneRect) -> Self {
        let title = fit_label_to_width(title, rect.width);
        Self { kind, title, rect }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelLayout {
    pub terminal: TerminalSize,
    pub mode: LayoutMode,
    pub focus: FocusPanel,
    pub panes: Vec<Pane>,
}

impl PanelLayout {
    pub fn compute(terminal: TerminalSize, focus: FocusPanel) -> Self {
        if terminal.columns >= WIDE_LAYOUT_MIN_COLUMNS && terminal.rows >= WIDE_LAYOUT_MIN_ROWS {
            Self::wide(terminal, focus)
        } else {
            Self::narrow(terminal, focus)
        }
    }

    pub fn pane(&self, kind: PaneKind) -> Option<&Pane> {
        self.panes.iter().find(|pane| pane.kind == kind)
    }

    pub fn to_cli_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "TUI Layout mode={} columns={} rows={} focus={} panes={}",
            self.mode.as_str(),
            self.terminal.columns,
            self.terminal.rows,
            self.focus.as_str(),
            self.panes.len()
        )];
        lines.extend(self.panes.iter().map(|pane| {
            format!(
                "pane={} title=\"{}\" x={} y={} w={} h={}",
                pane.kind.as_str(),
                pane.title,
                pane.rect.x,
                pane.rect.y,
                pane.rect.width,
                pane.rect.height
            )
        }));
        lines
    }

    pub fn to_cli_text(&self) -> String {
        self.to_cli_lines().join("\n")
    }

    pub fn validate(&self) -> Result<(), String> {
        for pane in &self.panes {
            if pane.rect.width == 0 || pane.rect.height == 0 {
                return Err(format!("{} has zero-sized rect", pane.kind.as_str()));
            }
            if pane.rect.right() > self.terminal.columns || pane.rect.bottom() > self.terminal.rows
            {
                return Err(format!("{} exceeds terminal bounds", pane.kind.as_str()));
            }
            if !pane.rect.contains_text_width(&pane.title) {
                return Err(format!("{} title exceeds pane width", pane.kind.as_str()));
            }
        }
        for (left_index, left) in self.panes.iter().enumerate() {
            for right in self.panes.iter().skip(left_index + 1) {
                if rects_overlap(left.rect, right.rect) {
                    return Err(format!(
                        "{} overlaps {}",
                        left.kind.as_str(),
                        right.kind.as_str()
                    ));
                }
            }
        }
        Ok(())
    }

    fn wide(terminal: TerminalSize, focus: FocusPanel) -> Self {
        let body_y = STATUS_BAR_HEIGHT;
        let body_height = terminal
            .rows
            .saturating_sub(STATUS_BAR_HEIGHT + COMMAND_PALETTE_HEIGHT);
        let workspace_width = terminal
            .columns
            .saturating_sub(NAVIGATION_RAIL_WIDTH + EVENT_FEED_WIDTH);
        let command_y = terminal.rows.saturating_sub(COMMAND_PALETTE_HEIGHT);
        Self {
            terminal,
            mode: LayoutMode::Wide,
            focus,
            panes: vec![
                Pane::new(
                    PaneKind::StatusBar,
                    "Status",
                    PaneRect::new(0, 0, terminal.columns, STATUS_BAR_HEIGHT),
                ),
                Pane::new(
                    PaneKind::NavigationRail,
                    "Navigate",
                    PaneRect::new(0, body_y, NAVIGATION_RAIL_WIDTH, body_height),
                ),
                Pane::new(
                    PaneKind::RunWorkspace,
                    "Run Workspace",
                    PaneRect::new(NAVIGATION_RAIL_WIDTH, body_y, workspace_width, body_height),
                ),
                Pane::new(
                    PaneKind::EventFeed,
                    "Event Feed",
                    PaneRect::new(
                        terminal.columns.saturating_sub(EVENT_FEED_WIDTH),
                        body_y,
                        EVENT_FEED_WIDTH,
                        body_height,
                    ),
                ),
                Pane::new(
                    PaneKind::CommandPalette,
                    "Command Palette",
                    PaneRect::new(0, command_y, terminal.columns, COMMAND_PALETTE_HEIGHT),
                ),
            ],
        }
    }

    fn narrow(terminal: TerminalSize, focus: FocusPanel) -> Self {
        let command_y = terminal.rows.saturating_sub(COMMAND_PALETTE_HEIGHT);
        let focus_y = STATUS_BAR_HEIGHT + TAB_STRIP_HEIGHT;
        let focus_height = terminal
            .rows
            .saturating_sub(STATUS_BAR_HEIGHT + TAB_STRIP_HEIGHT + COMMAND_PALETTE_HEIGHT)
            .max(1);
        Self {
            terminal,
            mode: LayoutMode::Narrow,
            focus,
            panes: vec![
                Pane::new(
                    PaneKind::StatusBar,
                    "Status",
                    PaneRect::new(0, 0, terminal.columns.max(1), STATUS_BAR_HEIGHT),
                ),
                Pane::new(
                    PaneKind::TabStrip,
                    "Tabs",
                    PaneRect::new(
                        0,
                        STATUS_BAR_HEIGHT,
                        terminal.columns.max(1),
                        TAB_STRIP_HEIGHT,
                    ),
                ),
                Pane::new(
                    PaneKind::FocusPanel,
                    "Focused Panel",
                    PaneRect::new(0, focus_y, terminal.columns.max(1), focus_height),
                ),
                Pane::new(
                    PaneKind::CommandPalette,
                    "Command Palette",
                    PaneRect::new(
                        0,
                        command_y,
                        terminal.columns.max(1),
                        COMMAND_PALETTE_HEIGHT,
                    ),
                ),
            ],
        }
    }
}

pub fn render_layout_snapshot(layout: &PanelLayout, snapshot: &ProjectionSnapshot) -> String {
    let mut lines = layout.to_cli_lines();
    lines.push(format!(
        "snapshot hash={} source_of_truth={} degraded={}",
        snapshot.snapshot_hash,
        snapshot.source_of_truth,
        snapshot.has_degraded_sources()
    ));
    lines.push(format!(
        "panel status latest_run={} approvals={} recovery={} ecosystem={} release={}",
        snapshot.latest_run_id.as_deref().unwrap_or("-"),
        snapshot.approvals.status,
        snapshot.recovery.status,
        snapshot.ecosystem.status,
        snapshot.release.status
    ));
    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelSnapshot<'a> {
    pub name: &'a str,
    pub body: &'a str,
}

impl<'a> PanelSnapshot<'a> {
    pub fn new(name: &'a str, body: &'a str) -> Self {
        Self { name, body }
    }
}

pub fn render_full_screen_snapshot(
    layout: &PanelLayout,
    snapshot: &ProjectionSnapshot,
    command_preview: Option<&CommandPreview>,
    command_history: &[&str],
    panels: &[PanelSnapshot<'_>],
) -> String {
    let mut lines = vec![format!(
        "Full Screen TUI Snapshot mode={} focus={} immutable_render_input={} source_of_truth={}",
        layout.mode.as_str(),
        layout.focus.as_str(),
        snapshot.immutable_render_input,
        snapshot.source_of_truth
    )];
    lines.extend(
        render_layout_snapshot(layout, snapshot)
            .lines()
            .map(redact_tui_text),
    );
    lines.extend(
        snapshot
            .to_cli_lines()
            .into_iter()
            .map(|line| format!("projection {}", redact_tui_text(&line))),
    );
    if let Some(preview) = command_preview {
        lines.push("palette preview=present".to_string());
        lines.extend(
            preview
                .render()
                .trim_end()
                .lines()
                .map(|line| format!("palette {}", redact_tui_text(line))),
        );
    } else {
        lines.push("palette preview=none".to_string());
    }
    lines.push(format!("command_history count={}", command_history.len()));
    lines.extend(
        command_history
            .iter()
            .enumerate()
            .map(|(index, command)| format!("history[{}]=\"{}\"", index, redact_tui_text(command))),
    );
    for panel in panels {
        let panel_name = redact_tui_text(panel.name);
        lines.push(format!("panel name=\"{}\"", panel_name));
        lines.extend(
            panel
                .body
                .trim_end()
                .lines()
                .map(|line| format!("panel {} {}", panel_name, redact_tui_text(line))),
        );
    }
    lines.join("\n")
}

fn rects_overlap(left: PaneRect, right: PaneRect) -> bool {
    left.x < right.right()
        && left.right() > right.x
        && left.y < right.bottom()
        && left.bottom() > right.y
}

fn fit_label_to_width(label: &str, width: u16) -> String {
    let width = width as usize;
    if label.chars().count() <= width {
        return label.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    let mut fitted = label.chars().take(width - 3).collect::<String>();
    fitted.push_str("...");
    fitted
}

fn redact_tui_text(value: &str) -> String {
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
