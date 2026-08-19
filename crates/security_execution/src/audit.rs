use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::escape_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    IntentReceived,
    PlanFrozen,
    PolicyEvaluated,
    ApprovalBound,
    EffectPrepared,
    EffectObserved,
    CommitSealed,
    RollbackPending,
    RollbackObserved,
    RecoveryStarted,
    RecoveryCompleted,
    SandboxDenied,
}

impl AuditEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEventType::IntentReceived => "IntentReceived",
            AuditEventType::PlanFrozen => "PlanFrozen",
            AuditEventType::PolicyEvaluated => "PolicyEvaluated",
            AuditEventType::ApprovalBound => "ApprovalBound",
            AuditEventType::EffectPrepared => "EffectPrepared",
            AuditEventType::EffectObserved => "EffectObserved",
            AuditEventType::CommitSealed => "CommitSealed",
            AuditEventType::RollbackPending => "RollbackPending",
            AuditEventType::RollbackObserved => "RollbackObserved",
            AuditEventType::RecoveryStarted => "RecoveryStarted",
            AuditEventType::RecoveryCompleted => "RecoveryCompleted",
            AuditEventType::SandboxDenied => "SandboxDenied",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "IntentReceived" => Self::IntentReceived,
            "PlanFrozen" => Self::PlanFrozen,
            "PolicyEvaluated" => Self::PolicyEvaluated,
            "ApprovalBound" => Self::ApprovalBound,
            "EffectPrepared" => Self::EffectPrepared,
            "EffectObserved" => Self::EffectObserved,
            "CommitSealed" => Self::CommitSealed,
            "RollbackPending" => Self::RollbackPending,
            "RollbackObserved" => Self::RollbackObserved,
            "RecoveryStarted" => Self::RecoveryStarted,
            "RecoveryCompleted" => Self::RecoveryCompleted,
            "SandboxDenied" => Self::SandboxDenied,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub run_id: String,
    pub step_id: String,
    pub actor: String,
    pub timestamp: String,
    pub policy_version: String,
    pub tool_version: String,
    pub parameter_hash: String,
    pub parent_event: Option<String>,
    pub summary: String,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        run_id: impl Into<String>,
        step_id: impl Into<String>,
        actor: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            run_id: run_id.into(),
            step_id: step_id.into(),
            actor: actor.into(),
            timestamp: "1970-01-01T00:00:00Z".to_string(),
            policy_version: "policy-v0".to_string(),
            tool_version: "tool-v0".to_string(),
            parameter_hash: "unset".to_string(),
            parent_event: None,
            summary: redact_summary(&summary.into()),
        }
    }

    pub fn to_json_line(&self) -> String {
        let parent = self
            .parent_event
            .as_ref()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"event_type\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"actor\":\"{}\",\"timestamp\":\"{}\",\"policy_version\":\"{}\",\"tool_version\":\"{}\",\"parameter_hash\":\"{}\",\"parent_event\":{},\"summary\":\"{}\"}}",
            self.event_type.as_str(),
            escape_json(&self.run_id),
            escape_json(&self.step_id),
            escape_json(&self.actor),
            escape_json(&self.timestamp),
            escape_json(&self.policy_version),
            escape_json(&self.tool_version),
            escape_json(&self.parameter_hash),
            parent,
            escape_json(&self.summary)
        )
    }
}

#[derive(Debug, Clone)]
pub struct AuditJournal {
    path: PathBuf,
}

impl AuditJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &AuditEvent) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", event.to_json_line())?;
        file.sync_all()?;
        Ok(())
    }

    /// Group commit：把一批事件以**单次** `open + writeln×N + sync_all` 原子落盘。
    ///
    /// 相比逐事件 `append`（每事件一次 `sync_all`/fsync），N 个事件只 fsync 一次——高吞吐
    /// 场景（如多步 run loop 的 PlanFrozen→PolicyEvaluated→EffectPrepared→CommitSealed 序列）
    /// 把 N 次磁盘屏障降为 1 次，且整批原子：要么全部可见，要么全部不可见（崩溃不留下半批）。
    /// 空批为 no-op。与 `append` 写出的行格式字节一致（每行一个 JSON 事件）。
    pub fn append_batch(&self, events: &[AuditEvent]) -> std::io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        for event in events {
            writeln!(file, "{}", event.to_json_line())?;
        }
        file.sync_all()?;
        Ok(())
    }

    /// 累积型 builder：连续 `push` 事件后 `commit` 一次落盘（group commit 的人体工学入口）。
    /// `push` 只写内存；`commit` 调 `append_batch`。未 `commit` 前 push 的事件不落盘
    /// （调用方负责在耐久性边界上 commit）。
    pub fn batch(&self) -> AuditBatch<'_> {
        AuditBatch {
            journal: self,
            events: Vec::new(),
        }
    }

    pub fn event_lines(&self) -> std::io::Result<Vec<String>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        reader.lines().collect()
    }

    pub fn latest_run(&self) -> std::io::Result<Option<String>> {
        Ok(self
            .event_lines()?
            .iter()
            .rev()
            .find_map(|line| extract_json_string(line, "run_id")))
    }

    pub fn run_timeline(&self, run_id: &str) -> std::io::Result<Vec<String>> {
        Ok(self
            .event_lines()?
            .into_iter()
            .filter(|line| extract_json_string(line, "run_id").as_deref() == Some(run_id))
            .collect())
    }

    pub fn unresolved_effects(&self) -> std::io::Result<Vec<String>> {
        let lines = self.event_lines()?;
        let mut prepared = Vec::new();
        let mut sealed_steps = Vec::new();
        let mut rolled_back_steps = Vec::new();

        for line in &lines {
            let event_type = extract_json_string(line, "event_type");
            let step_id = extract_json_string(line, "step_id").unwrap_or_default();
            match event_type.as_deref() {
                Some("EffectPrepared") => prepared.push((step_id, line.clone())),
                Some("CommitSealed") => sealed_steps.push(step_id),
                Some("RollbackObserved") => rolled_back_steps.push(step_id),
                _ => {}
            }
        }

        Ok(prepared
            .into_iter()
            .filter(|(step_id, _)| {
                !sealed_steps.contains(step_id) && !rolled_back_steps.contains(step_id)
            })
            .map(|(_, line)| line)
            .collect())
    }

    pub fn project_latest_runtime_run(&self) -> std::io::Result<Option<RuntimeAuditProjection>> {
        let Some(run_id) = self.latest_run()? else {
            return Ok(None);
        };
        self.project_runtime_run(&run_id)
    }

    pub fn project_runtime_run(
        &self,
        run_id: &str,
    ) -> std::io::Result<Option<RuntimeAuditProjection>> {
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        for (index, line) in self.event_lines()?.into_iter().enumerate() {
            if extract_json_string(&line, "run_id").as_deref() != Some(run_id) {
                continue;
            }
            match RuntimeAuditEventProjection::from_line(&line) {
                Ok(event) => events.push(event),
                Err(reason) => warnings.push(format!("line {} skipped: {reason}", index + 1)),
            }
        }
        if events.is_empty() && warnings.is_empty() {
            return Ok(None);
        }
        Ok(Some(RuntimeAuditProjection::from_events(
            run_id.to_string(),
            events,
            warnings,
        )))
    }
}

/// cp-llm 阶段 R：线程安全的 `AuditJournal` 包装器。
///
/// `AuditJournal::append` 每次调用 `open + writeln + sync_all`，文件 append 模式虽保证
/// 单次 `writeln` 原子，但**多线程并发 append 不保证行间不交错**（OS 可能合并并发 write）。
/// 未来并行执行同一拓扑层级的就绪步时，多个线程会并发向 journal 写事件——这需要
/// 互斥以保证 JSON 行完整。`SyncAuditJournal` 用 `Mutex` 串行化所有写操作，`&self` 接口
/// 与 `AuditJournal` 同形（`append`/`append_batch`/`event_lines`），便于在并行调度器中
/// 透明替换。读方法（`event_lines`/`latest_run` 等）也经锁串行，避免读到半写行。
///
/// **不改变现有顺序执行路径**——`run_plan_guarded` 仍直接用 `&AuditJournal`。本类型仅
/// 供未来并行版 `run_plan_guarded_parallel` 使用。`#![forbid(unsafe_code)]` 不受影响
/// （`std::sync::Mutex` 是安全抽象）。
#[derive(Debug, Clone)]
pub struct SyncAuditJournal {
    inner: std::sync::Arc<std::sync::Mutex<AuditJournal>>,
}

impl SyncAuditJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(AuditJournal::new(path))),
        }
    }

    /// 从底层 `AuditJournal` 构造（共享同一文件路径，独立 Mutex 实例）。
    pub fn from_journal(journal: &AuditJournal) -> Self {
        Self::new(journal.path().to_path_buf())
    }

    pub fn path(&self) -> std::sync::MutexGuard<'_, AuditJournal> {
        self.inner.lock().expect("SyncAuditJournal poisoned")
    }

    pub fn append(&self, event: &AuditEvent) -> std::io::Result<()> {
        self.inner
            .lock()
            .expect("SyncAuditJournal poisoned")
            .append(event)
    }

    pub fn append_batch(&self, events: &[AuditEvent]) -> std::io::Result<()> {
        self.inner
            .lock()
            .expect("SyncAuditJournal poisoned")
            .append_batch(events)
    }

    pub fn event_lines(&self) -> std::io::Result<Vec<String>> {
        self.inner
            .lock()
            .expect("SyncAuditJournal poisoned")
            .event_lines()
    }

    pub fn latest_run(&self) -> std::io::Result<Option<String>> {
        self.inner
            .lock()
            .expect("SyncAuditJournal poisoned")
            .latest_run()
    }

    pub fn run_timeline(&self, run_id: &str) -> std::io::Result<Vec<String>> {
        self.inner
            .lock()
            .expect("SyncAuditJournal poisoned")
            .run_timeline(run_id)
    }
}

/// Group commit 累积器：`push` 写内存缓冲，`commit` 一次 `append_batch` 落盘。
///
/// 借用 `AuditJournal`（不可变），故可与其他 `&self` 读方法并发（文件 append 模式保证原子性）。
/// 未 `commit` 时缓冲事件**不落盘**——调用方须在耐久性边界（如 run loop 一步结束时）显式 commit。
/// `Drop` 时**不**自动 commit（避免静默落盘破坏 fail-closed 语义；漏 commit = 事件丢失，
/// 与逐事件 `append` 相比是显式取舍）。
#[derive(Debug)]
pub struct AuditBatch<'a> {
    journal: &'a AuditJournal,
    events: Vec<AuditEvent>,
}

impl<'a> AuditBatch<'a> {
    /// 累积一个事件到内存缓冲（不落盘）。
    pub fn push(&mut self, event: AuditEvent) -> &mut Self {
        self.events.push(event);
        self
    }

    /// 当前缓冲的事件数。
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// 缓冲是否为空。
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// 把缓冲的事件批量落盘（单次 fsync），然后清空缓冲。空缓冲为 no-op。
    pub fn commit(&mut self) -> std::io::Result<usize> {
        if self.events.is_empty() {
            return Ok(0);
        }
        let count = self.events.len();
        self.journal.append_batch(&self.events)?;
        self.events.clear();
        Ok(count)
    }
}

/// run_id 倒排索引（cp-audit-perf-2）：一次性全扫日志构建 `run_id → Vec<行号>` 映射，
/// 此后按 run_id 查询 O(1) 命中行号再按行读，免逐次全文件扫描。
///
/// `AuditJournal` 保持无状态（append-only 真相源不被缓存污染）；`RunIndex` 是独立的加速缓存，
/// 调用方在需要多次按 run_id 查询（如 TUI event feed 轮询、recovery timeline 反复查同一 run）
/// 时显式 `RunIndex::from_journal` 构建一次。日志在构建后被 append 新事件 → 索引过期，
/// 调用方须重新构建（`lines_cached()` 返回构建时的行数，可据此判断是否过期）。
#[derive(Debug, Clone)]
pub struct RunIndex {
    /// run_id → 该 run 的行号（0-based，升序）。
    runs: std::collections::BTreeMap<String, Vec<usize>>,
    /// 构建时的日志总行数（用于检测过期：当前日志行数 > 此值则索引过期）。
    lines_cached: usize,
    /// 构建时观测到的最后一个 run_id（= latest_run，O(1)）。
    last_run_id: Option<String>,
}

impl RunIndex {
    /// 从 journal 当前的全部事件行构建索引。单次全扫；之后查询 O(1)。
    pub fn from_journal(journal: &AuditJournal) -> std::io::Result<Self> {
        let lines = journal.event_lines()?;
        let mut runs: std::collections::BTreeMap<String, Vec<usize>> =
            std::collections::BTreeMap::new();
        let mut last_run_id = None;
        for (index, line) in lines.iter().enumerate() {
            if let Some(run_id) = extract_json_string(line, "run_id") {
                runs.entry(run_id.clone()).or_default().push(index);
                last_run_id = Some(run_id);
            }
        }
        Ok(Self {
            runs,
            lines_cached: lines.len(),
            last_run_id,
        })
    }

    /// 构建时缓存的日志行数。调用方可与当前 `journal.event_lines()?.len()` 比较判断索引是否过期。
    pub fn lines_cached(&self) -> usize {
        self.lines_cached
    }

    /// latest run_id（构建时观测），O(1)。无事件则 None。
    pub fn latest_run(&self) -> Option<&str> {
        self.last_run_id.as_deref()
    }

    /// 所有 run_id（按 BTreeMap 顺序，即字典序）。O(runs)。
    pub fn run_ids(&self) -> impl Iterator<Item = &str> {
        self.runs.keys().map(String::as_str)
    }

    /// 该 run 的行数。未知 run_id 返回 0。
    pub fn run_line_count(&self, run_id: &str) -> usize {
        self.runs.get(run_id).map(Vec::len).unwrap_or(0)
    }

    /// 取该 run 的全部行。需要 journal 读行（按索引跳读，而非全扫）。
    /// 未知 run_id 返回空 Vec。
    pub fn run_timeline(
        &self,
        journal: &AuditJournal,
        run_id: &str,
    ) -> std::io::Result<Vec<String>> {
        let Some(indices) = self.runs.get(run_id) else {
            return Ok(Vec::new());
        };
        if indices.is_empty() {
            return Ok(Vec::new());
        }
        // 按行号跳读：用 BufReader 按行迭代到所需行。最坏情况仍遍历到 max(indices)，
        // 但省去了对所有行做 run_id 字符串匹配 + clone（原 run_timeline 全扫 + filter）。
        let file = File::open(journal.path())?;
        let reader = BufReader::new(file);
        let mut result = Vec::with_capacity(indices.len());
        let mut wanted = indices.iter().copied();
        let mut next_wanted = wanted.next();
        for (current, line) in reader.lines().enumerate() {
            if next_wanted == Some(current) {
                result.push(line?);
                next_wanted = wanted.next();
                if next_wanted.is_none() {
                    break; // 已取到该 run 全部行
                }
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuditProjection {
    pub run_id: String,
    pub plan_id: Option<String>,
    pub plan_hash: Option<String>,
    pub planner_metadata: Option<String>,
    pub steps: Vec<RuntimeAuditStepProjection>,
    pub warnings: Vec<String>,
}

impl RuntimeAuditProjection {
    fn from_events(
        run_id: String,
        events: Vec<RuntimeAuditEventProjection>,
        warnings: Vec<String>,
    ) -> Self {
        let mut projection = Self {
            run_id,
            plan_id: None,
            plan_hash: None,
            planner_metadata: None,
            steps: Vec::new(),
            warnings,
        };
        for event in events {
            if event.event_type == AuditEventType::PlanFrozen.as_str() {
                projection.plan_id = summary_value(&event.summary, "plan_id");
                projection.plan_hash = summary_value(&event.summary, "plan_hash")
                    .or_else(|| non_empty_metadata(&event.parameter_hash));
                projection.planner_metadata = Some(event.summary.clone());
            }
            let step = projection.step_mut(&event.step_id);
            step.absorb_event(event);
        }
        projection
    }

    fn step_mut(&mut self, step_id: &str) -> &mut RuntimeAuditStepProjection {
        if let Some(index) = self.steps.iter().position(|step| step.step_id == step_id) {
            return &mut self.steps[index];
        }
        self.steps.push(RuntimeAuditStepProjection::new(step_id));
        self.steps.last_mut().expect("just pushed step")
    }

    pub fn event_count(&self) -> usize {
        self.steps.iter().map(|step| step.events.len()).sum()
    }

    pub fn to_json(&self) -> String {
        let steps = self
            .steps
            .iter()
            .map(RuntimeAuditStepProjection::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"run_id\":\"{}\",\"plan_id\":{},\"plan_hash\":{},\"planner_metadata\":{},\"event_count\":{},\"warnings\":{},\"steps\":[{}]}}",
            escape_json(&self.run_id),
            optional_json(self.plan_id.as_deref()),
            optional_json(self.plan_hash.as_deref()),
            optional_json(self.planner_metadata.as_deref()),
            self.event_count(),
            string_array_json(&self.warnings),
            steps
        )
    }

    pub fn to_cli_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "run={} plan_id={} plan_hash={} events={} warnings={}",
            self.run_id,
            self.plan_id.as_deref().unwrap_or("-"),
            self.plan_hash.as_deref().unwrap_or("-"),
            self.event_count(),
            self.warnings.len()
        )];
        lines.extend(
            self.steps
                .iter()
                .map(RuntimeAuditStepProjection::to_cli_line),
        );
        lines
    }

    pub fn to_cli_text(&self) -> String {
        self.to_cli_lines().join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuditStepProjection {
    pub step_id: String,
    pub status: String,
    pub policy_summary: Option<String>,
    pub approval_summary: Option<String>,
    pub lease_id: Option<String>,
    pub sandbox_profile_summary: Option<String>,
    pub effect_state: String,
    pub observation_summary: Option<String>,
    pub observation_source: Option<String>,
    pub observation_trust: Option<String>,
    pub verification_summary: Option<String>,
    pub rollback_summary: Option<String>,
    pub recovery_summary: Option<String>,
    pub final_summary: Option<String>,
    pub effect_prepared: bool,
    pub effect_observed: bool,
    pub commit_sealed: bool,
    pub events: Vec<RuntimeAuditEventProjection>,
}

impl RuntimeAuditStepProjection {
    fn new(step_id: &str) -> Self {
        Self {
            step_id: step_id.to_string(),
            status: "pending".to_string(),
            policy_summary: None,
            approval_summary: None,
            lease_id: None,
            sandbox_profile_summary: None,
            effect_state: "none".to_string(),
            observation_summary: None,
            observation_source: None,
            observation_trust: None,
            verification_summary: None,
            rollback_summary: None,
            recovery_summary: None,
            final_summary: None,
            effect_prepared: false,
            effect_observed: false,
            commit_sealed: false,
            events: Vec::new(),
        }
    }

    fn absorb_event(&mut self, event: RuntimeAuditEventProjection) {
        let summary = redact_summary(&event.summary);
        self.final_summary = Some(summary.clone());
        match event.event_type.as_str() {
            "IntentReceived" => {
                self.status = "accepted".to_string();
            }
            "PlanFrozen" => {
                self.status = "planned".to_string();
            }
            "PolicyEvaluated" => {
                self.policy_summary = Some(summary.clone());
                self.lease_id = self
                    .lease_id
                    .clone()
                    .or_else(|| summary_value(&summary, "lease_id"));
                if summary.contains("decision=deny") {
                    self.status = "denied".to_string();
                } else if summary.contains("pause-for-approval") {
                    self.status = "paused".to_string();
                } else {
                    self.status = "policy-evaluated".to_string();
                }
            }
            "ApprovalBound" => {
                self.approval_summary = Some(summary.clone());
                self.lease_id = self
                    .lease_id
                    .clone()
                    .or_else(|| summary_value(&summary, "lease_id"));
                if summary.contains("approval denied") {
                    self.status = "denied".to_string();
                } else {
                    self.status = "approval-bound".to_string();
                }
            }
            "EffectPrepared" => {
                self.effect_prepared = true;
                self.effect_state = "prepared".to_string();
                self.status = "prepared".to_string();
            }
            "EffectObserved" => {
                self.effect_observed = true;
                self.effect_state = "observed".to_string();
                self.status = "observed".to_string();
                self.observation_summary = Some(summary.clone());
                self.observation_source = summary_value(&summary, "source");
                self.observation_trust = summary_value(&summary, "trust");
            }
            "CommitSealed" => {
                self.commit_sealed = true;
                self.effect_state = "sealed".to_string();
                self.status = "sealed".to_string();
                self.verification_summary = Some(format!("success: {summary}"));
            }
            "RollbackPending" => {
                self.effect_state = "rollback-pending".to_string();
                self.status = "rollback-pending".to_string();
                self.rollback_summary = Some(summary.clone());
                self.verification_summary = Some(format!("failed: {summary}"));
            }
            "RollbackObserved" => {
                self.effect_state = "rolled-back".to_string();
                self.status = "rolled-back".to_string();
                self.rollback_summary = Some(summary.clone());
            }
            "RecoveryStarted" => {
                self.status = "recovering".to_string();
                self.recovery_summary = Some(format!("source=run-store+audit {summary}"));
            }
            "RecoveryCompleted" => {
                self.status = "recovered".to_string();
                self.recovery_summary = Some(format!("source=run-store+audit {summary}"));
            }
            "SandboxDenied" => {
                self.status = "denied".to_string();
                self.sandbox_profile_summary = Some(summary.clone());
            }
            _ => {}
        }
        self.events.push(event);
    }

    pub fn to_json(&self) -> String {
        let events = self
            .events
            .iter()
            .map(RuntimeAuditEventProjection::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"step_id\":\"{}\",\"status\":\"{}\",\"policy_summary\":{},\"approval_summary\":{},\"lease_id\":{},\"sandbox_profile_summary\":{},\"effect_state\":\"{}\",\"observation_summary\":{},\"observation_source\":{},\"observation_trust\":{},\"verification_summary\":{},\"rollback_summary\":{},\"recovery_summary\":{},\"final_summary\":{},\"effect_prepared\":{},\"effect_observed\":{},\"commit_sealed\":{},\"events\":[{}]}}",
            escape_json(&self.step_id),
            escape_json(&self.status),
            optional_json(self.policy_summary.as_deref()),
            optional_json(self.approval_summary.as_deref()),
            optional_json(self.lease_id.as_deref()),
            optional_json(self.sandbox_profile_summary.as_deref()),
            escape_json(&self.effect_state),
            optional_json(self.observation_summary.as_deref()),
            optional_json(self.observation_source.as_deref()),
            optional_json(self.observation_trust.as_deref()),
            optional_json(self.verification_summary.as_deref()),
            optional_json(self.rollback_summary.as_deref()),
            optional_json(self.recovery_summary.as_deref()),
            optional_json(self.final_summary.as_deref()),
            self.effect_prepared,
            self.effect_observed,
            self.commit_sealed,
            events
        )
    }

    pub fn to_cli_line(&self) -> String {
        format!(
            "step={} status={} policy={} approval={} lease={} sandbox={} effect={} observation={} verification={} recovery={} final={}",
            self.step_id,
            self.status,
            self.policy_summary.as_deref().unwrap_or("-"),
            self.approval_summary.as_deref().unwrap_or("-"),
            self.lease_id.as_deref().unwrap_or("-"),
            self.sandbox_profile_summary.as_deref().unwrap_or("-"),
            self.effect_state,
            observation_cli(self),
            self.verification_summary.as_deref().unwrap_or("-"),
            self.recovery_summary.as_deref().unwrap_or("-"),
            self.final_summary.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuditEventProjection {
    pub event_type: String,
    pub run_id: String,
    pub step_id: String,
    pub actor: String,
    pub timestamp: String,
    pub policy_version: String,
    pub tool_version: String,
    pub parameter_hash: String,
    pub parent_event: Option<String>,
    pub summary: String,
}

impl RuntimeAuditEventProjection {
    fn from_line(line: &str) -> Result<Self, String> {
        let event_type = extract_json_string(line, "event_type")
            .ok_or_else(|| "missing event_type".to_string())?;
        Ok(Self {
            event_type,
            run_id: extract_json_string(line, "run_id")
                .ok_or_else(|| "missing run_id".to_string())?,
            step_id: extract_json_string(line, "step_id")
                .ok_or_else(|| "missing step_id".to_string())?,
            actor: extract_json_string(line, "actor").unwrap_or_default(),
            timestamp: extract_json_string(line, "timestamp").unwrap_or_default(),
            policy_version: extract_json_string(line, "policy_version").unwrap_or_default(),
            tool_version: extract_json_string(line, "tool_version").unwrap_or_default(),
            parameter_hash: extract_json_string(line, "parameter_hash").unwrap_or_default(),
            parent_event: extract_json_string(line, "parent_event"),
            summary: redact_summary(
                &extract_json_string(line, "summary")
                    .ok_or_else(|| "missing summary".to_string())?,
            ),
        })
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"event_type\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"actor\":\"{}\",\"timestamp\":\"{}\",\"policy_version\":\"{}\",\"tool_version\":\"{}\",\"parameter_hash\":\"{}\",\"parent_event\":{},\"summary\":\"{}\"}}",
            escape_json(&self.event_type),
            escape_json(&self.run_id),
            escape_json(&self.step_id),
            escape_json(&self.actor),
            escape_json(&self.timestamp),
            escape_json(&self.policy_version),
            escape_json(&self.tool_version),
            escape_json(&self.parameter_hash),
            optional_json(self.parent_event.as_deref()),
            escape_json(&self.summary)
        )
    }
}

pub const REMOTE_AUDIT_MIRROR_RECORD_SCHEMA: &str = "agentos.remote-audit-mirror-record.v1";
pub const REMOTE_AUDIT_MIRROR_SOURCE: &str = "local-audit-journal";
const REMOTE_AUDIT_MIRROR_GENESIS_HASH: &str = "genesis";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteAuditFailurePolicy {
    Warn,
    Pause,
    FailClosed,
}

impl RemoteAuditFailurePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Pause => "pause",
            Self::FailClosed => "fail-closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteAuditMirrorStatus {
    Mirrored,
    Warning,
    Paused,
    FailedClosed,
}

impl RemoteAuditMirrorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mirrored => "mirrored",
            Self::Warning => "warning",
            Self::Paused => "paused",
            Self::FailedClosed => "failed-closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuditMirrorConfig {
    pub failure_policy: RemoteAuditFailurePolicy,
    pub deployment_profile: String,
}

impl RemoteAuditMirrorConfig {
    pub fn new(
        failure_policy: RemoteAuditFailurePolicy,
        deployment_profile: impl Into<String>,
    ) -> Self {
        Self {
            failure_policy,
            deployment_profile: deployment_profile.into(),
        }
    }

    pub fn local_warn() -> Self {
        Self::new(RemoteAuditFailurePolicy::Warn, "local-only")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuditMirrorRecord {
    pub sequence: usize,
    pub source: String,
    pub event_type: String,
    pub run_id: String,
    pub step_id: String,
    pub policy_version: String,
    pub tool_version: String,
    pub parameter_hash: String,
    pub summary: String,
    pub previous_hash: String,
    pub record_hash: String,
}

impl RemoteAuditMirrorRecord {
    fn from_audit_line(
        sequence: usize,
        previous_hash: impl Into<String>,
        line: &str,
    ) -> Result<Self, RemoteAuditMirrorError> {
        let previous_hash = previous_hash.into();
        let mut record = Self {
            sequence,
            source: REMOTE_AUDIT_MIRROR_SOURCE.to_string(),
            event_type: extract_json_string(line, "event_type").ok_or_else(|| {
                RemoteAuditMirrorError::MalformedAudit("missing event_type".to_string())
            })?,
            run_id: extract_json_string(line, "run_id").ok_or_else(|| {
                RemoteAuditMirrorError::MalformedAudit("missing run_id".to_string())
            })?,
            step_id: extract_json_string(line, "step_id").ok_or_else(|| {
                RemoteAuditMirrorError::MalformedAudit("missing step_id".to_string())
            })?,
            policy_version: extract_json_string(line, "policy_version").unwrap_or_default(),
            tool_version: extract_json_string(line, "tool_version").unwrap_or_default(),
            parameter_hash: extract_json_string(line, "parameter_hash").unwrap_or_default(),
            summary: redact_summary(&extract_json_string(line, "summary").unwrap_or_default()),
            previous_hash,
            record_hash: String::new(),
        };
        record.record_hash = stable_mirror_hash(&record.canonical_payload());
        Ok(record)
    }

    fn canonical_payload(&self) -> String {
        format!(
            "schema={}|sequence={}|source={}|event_type={}|run_id={}|step_id={}|policy_version={}|tool_version={}|parameter_hash={}|summary={}|previous_hash={}",
            REMOTE_AUDIT_MIRROR_RECORD_SCHEMA,
            self.sequence,
            self.source,
            self.event_type,
            self.run_id,
            self.step_id,
            self.policy_version,
            self.tool_version,
            self.parameter_hash,
            self.summary,
            self.previous_hash
        )
    }

    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"sequence\":{},\"source\":\"{}\",\"event_type\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"policy_version\":\"{}\",\"tool_version\":\"{}\",\"parameter_hash\":\"{}\",\"summary\":\"{}\",\"previous_hash\":\"{}\",\"record_hash\":\"{}\"}}",
            REMOTE_AUDIT_MIRROR_RECORD_SCHEMA,
            self.sequence,
            escape_json(&self.source),
            escape_json(&self.event_type),
            escape_json(&self.run_id),
            escape_json(&self.step_id),
            escape_json(&self.policy_version),
            escape_json(&self.tool_version),
            escape_json(&self.parameter_hash),
            escape_json(&self.summary),
            escape_json(&self.previous_hash),
            escape_json(&self.record_hash)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuditMirrorDecision {
    pub status: RemoteAuditMirrorStatus,
    pub failure_policy: RemoteAuditFailurePolicy,
    pub local_audit_authoritative: bool,
    pub mirror_authoritative_for_recovery: bool,
    pub local_diagnostics_allowed: bool,
    pub non_local_side_effects_allowed: bool,
    pub mirrored_records: usize,
    pub skipped_records: usize,
    pub next_sequence: usize,
    pub last_hash: String,
    pub mirror_path: String,
    pub warnings: Vec<String>,
}

impl RemoteAuditMirrorDecision {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"status\":\"{}\",\"failure_policy\":\"{}\",\"local_audit_authoritative\":{},\"mirror_authoritative_for_recovery\":{},\"local_diagnostics_allowed\":{},\"non_local_side_effects_allowed\":{},\"mirrored_records\":{},\"skipped_records\":{},\"next_sequence\":{},\"last_hash\":\"{}\",\"mirror_path\":\"{}\",\"warnings\":{}}}",
            self.status.as_str(),
            self.failure_policy.as_str(),
            self.local_audit_authoritative,
            self.mirror_authoritative_for_recovery,
            self.local_diagnostics_allowed,
            self.non_local_side_effects_allowed,
            self.mirrored_records,
            self.skipped_records,
            self.next_sequence,
            escape_json(&self.last_hash),
            escape_json(&self.mirror_path),
            string_array_json(&self.warnings)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAuditMirrorError {
    LocalAudit(String),
    MirrorState(String),
    MirrorWrite(String),
    MalformedAudit(String),
}

impl fmt::Display for RemoteAuditMirrorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalAudit(reason) => write!(formatter, "local audit failed: {reason}"),
            Self::MirrorState(reason) => {
                write!(formatter, "remote audit mirror state failed: {reason}")
            }
            Self::MirrorWrite(reason) => {
                write!(formatter, "remote audit mirror write failed: {reason}")
            }
            Self::MalformedAudit(reason) => {
                write!(formatter, "malformed local audit event: {reason}")
            }
        }
    }
}

impl std::error::Error for RemoteAuditMirrorError {}

#[derive(Debug)]
pub struct FileRemoteAuditMirror {
    path: PathBuf,
}

impl FileRemoteAuditMirror {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mirror_journal(
        &self,
        local_journal: &AuditJournal,
        config: &RemoteAuditMirrorConfig,
    ) -> Result<RemoteAuditMirrorDecision, RemoteAuditMirrorError> {
        let local_lines = local_journal
            .event_lines()
            .map_err(|error| RemoteAuditMirrorError::LocalAudit(error.to_string()))?;
        let mirror_state = match self.read_mirror_state() {
            Ok(state) => state,
            Err(error) => {
                return self.handle_mirror_failure(
                    local_journal,
                    config,
                    error.to_string(),
                    0,
                    REMOTE_AUDIT_MIRROR_GENESIS_HASH.to_string(),
                );
            }
        };
        if mirror_state.next_sequence > local_lines.len() {
            return self.handle_mirror_failure(
                local_journal,
                config,
                format!(
                    "mirror has {} records but local audit has {} events",
                    mirror_state.next_sequence,
                    local_lines.len()
                ),
                0,
                mirror_state.previous_hash,
            );
        }

        let mut previous_hash = mirror_state.previous_hash;
        let mut records = Vec::new();
        let mut skipped_records = 0;
        for (offset, line) in local_lines
            .iter()
            .skip(mirror_state.next_sequence)
            .enumerate()
        {
            let sequence = mirror_state.next_sequence + offset;
            match RemoteAuditMirrorRecord::from_audit_line(sequence, previous_hash.clone(), line) {
                Ok(record) => {
                    previous_hash = record.record_hash.clone();
                    records.push(record);
                }
                Err(_) => {
                    skipped_records += 1;
                }
            }
        }

        if let Err(error) = self.append_records(&records) {
            return self.handle_mirror_failure(
                local_journal,
                config,
                RemoteAuditMirrorError::MirrorWrite(error.to_string()).to_string(),
                records.len(),
                previous_hash,
            );
        }

        Ok(RemoteAuditMirrorDecision {
            status: RemoteAuditMirrorStatus::Mirrored,
            failure_policy: config.failure_policy,
            local_audit_authoritative: true,
            mirror_authoritative_for_recovery: false,
            local_diagnostics_allowed: true,
            non_local_side_effects_allowed: true,
            mirrored_records: records.len(),
            skipped_records,
            next_sequence: mirror_state.next_sequence + records.len(),
            last_hash: previous_hash,
            mirror_path: self.path.display().to_string(),
            warnings: if skipped_records == 0 {
                Vec::new()
            } else {
                vec![format!(
                    "skipped {skipped_records} malformed local audit records"
                )]
            },
        })
    }

    fn read_mirror_state(&self) -> Result<RemoteAuditMirrorState, RemoteAuditMirrorError> {
        if !self.path.exists() {
            return Ok(RemoteAuditMirrorState {
                next_sequence: 0,
                previous_hash: REMOTE_AUDIT_MIRROR_GENESIS_HASH.to_string(),
            });
        }
        let file = File::open(&self.path)
            .map_err(|error| RemoteAuditMirrorError::MirrorState(error.to_string()))?;
        let reader = BufReader::new(file);
        let mut next_sequence = 0;
        let mut previous_hash = REMOTE_AUDIT_MIRROR_GENESIS_HASH.to_string();
        for (index, line) in reader.lines().enumerate() {
            let line =
                line.map_err(|error| RemoteAuditMirrorError::MirrorState(error.to_string()))?;
            let sequence = extract_json_usize(&line, "sequence").ok_or_else(|| {
                RemoteAuditMirrorError::MirrorState(format!("line {} missing sequence", index + 1))
            })?;
            let line_previous = extract_json_string(&line, "previous_hash").ok_or_else(|| {
                RemoteAuditMirrorError::MirrorState(format!(
                    "line {} missing previous_hash",
                    index + 1
                ))
            })?;
            let record_hash = extract_json_string(&line, "record_hash").ok_or_else(|| {
                RemoteAuditMirrorError::MirrorState(format!(
                    "line {} missing record_hash",
                    index + 1
                ))
            })?;
            let expected_hash = recompute_mirror_record_hash(&line, sequence, &line_previous)?;
            if record_hash != expected_hash {
                return Err(RemoteAuditMirrorError::MirrorState(format!(
                    "line {} record hash mismatch",
                    index + 1
                )));
            }
            if sequence != next_sequence {
                return Err(RemoteAuditMirrorError::MirrorState(format!(
                    "line {} expected sequence {} got {}",
                    index + 1,
                    next_sequence,
                    sequence
                )));
            }
            if line_previous != previous_hash {
                return Err(RemoteAuditMirrorError::MirrorState(format!(
                    "line {} hash chain mismatch",
                    index + 1
                )));
            }
            previous_hash = record_hash;
            next_sequence += 1;
        }
        Ok(RemoteAuditMirrorState {
            next_sequence,
            previous_hash,
        })
    }

    fn append_records(&self, records: &[RemoteAuditMirrorRecord]) -> std::io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        for record in records {
            writeln!(file, "{}", record.to_json_line())?;
        }
        file.sync_all()
    }

    fn handle_mirror_failure(
        &self,
        local_journal: &AuditJournal,
        config: &RemoteAuditMirrorConfig,
        reason: impl Into<String>,
        attempted_records: usize,
        last_hash: String,
    ) -> Result<RemoteAuditMirrorDecision, RemoteAuditMirrorError> {
        let reason = redact_summary(&reason.into());
        let status = match config.failure_policy {
            RemoteAuditFailurePolicy::Warn => RemoteAuditMirrorStatus::Warning,
            RemoteAuditFailurePolicy::Pause => RemoteAuditMirrorStatus::Paused,
            RemoteAuditFailurePolicy::FailClosed => RemoteAuditMirrorStatus::FailedClosed,
        };
        let failure_event = AuditEvent::new(
            AuditEventType::PolicyEvaluated,
            "remote-audit-mirror",
            "mirror-failure",
            "agentos",
            format!(
                "remote-audit-mirror failure policy={} status={} profile={} attempted_records={} reason={}",
                config.failure_policy.as_str(),
                status.as_str(),
                config.deployment_profile,
                attempted_records,
                reason
            ),
        );
        local_journal
            .append(&failure_event)
            .map_err(|error| RemoteAuditMirrorError::LocalAudit(error.to_string()))?;
        Ok(RemoteAuditMirrorDecision {
            status,
            failure_policy: config.failure_policy,
            local_audit_authoritative: true,
            mirror_authoritative_for_recovery: false,
            local_diagnostics_allowed: true,
            non_local_side_effects_allowed: matches!(
                config.failure_policy,
                RemoteAuditFailurePolicy::Warn
            ),
            mirrored_records: 0,
            skipped_records: 0,
            next_sequence: 0,
            last_hash,
            mirror_path: self.path.display().to_string(),
            warnings: vec![reason],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteAuditMirrorState {
    next_sequence: usize,
    previous_hash: String,
}

pub fn redact_summary(summary: &str) -> String {
    let mut output = Vec::new();
    for token in summary.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if lower.starts_with("secret://") {
            output.push(token);
            continue;
        }
        let key = lower
            .split_once('=')
            .map(|(key, _)| key)
            .or_else(|| lower.split_once(':').map(|(key, _)| key));
        let key = key
            .map(|value| value.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_'));
        if matches!(
            key,
            Some("secret" | "password" | "token" | "apikey" | "api_key" | "access_token")
        ) {
            output.push("[REDACTED]");
        } else {
            output.push(token);
        }
    }
    output.join(" ")
}

fn observation_cli(step: &RuntimeAuditStepProjection) -> String {
    match (
        step.observation_source.as_deref(),
        step.observation_trust.as_deref(),
        step.observation_summary.as_deref(),
    ) {
        (None, None, None) => "-".to_string(),
        (source, trust, summary) => format!(
            "source={} trust={} summary={}",
            source.unwrap_or("-"),
            trust.unwrap_or("-"),
            summary.unwrap_or("-")
        ),
    }
}

fn summary_value(summary: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(|value| {
            value
                .trim_matches(|ch: char| {
                    !ch.is_ascii_alphanumeric() && !matches!(ch, ':' | '/' | '_' | '-' | '.')
                })
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

fn non_empty_metadata(value: &str) -> Option<String> {
    if value.is_empty() || value == "unset" {
        None
    } else {
        Some(value.to_string())
    }
}

fn optional_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn string_array_json(values: &[String]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn extract_json_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_json_usize(line: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let digits = rest
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    digits.parse::<usize>().ok()
}

fn stable_mirror_hash(value: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv64:{hash:016x}")
}

fn recompute_mirror_record_hash(
    line: &str,
    sequence: usize,
    previous_hash: &str,
) -> Result<String, RemoteAuditMirrorError> {
    let record = RemoteAuditMirrorRecord {
        sequence,
        source: extract_json_string(line, "source").ok_or_else(|| {
            RemoteAuditMirrorError::MirrorState("mirror record missing source".to_string())
        })?,
        event_type: extract_json_string(line, "event_type").ok_or_else(|| {
            RemoteAuditMirrorError::MirrorState("mirror record missing event_type".to_string())
        })?,
        run_id: extract_json_string(line, "run_id").ok_or_else(|| {
            RemoteAuditMirrorError::MirrorState("mirror record missing run_id".to_string())
        })?,
        step_id: extract_json_string(line, "step_id").ok_or_else(|| {
            RemoteAuditMirrorError::MirrorState("mirror record missing step_id".to_string())
        })?,
        policy_version: extract_json_string(line, "policy_version").unwrap_or_default(),
        tool_version: extract_json_string(line, "tool_version").unwrap_or_default(),
        parameter_hash: extract_json_string(line, "parameter_hash").unwrap_or_default(),
        summary: extract_json_string(line, "summary").unwrap_or_default(),
        previous_hash: previous_hash.to_string(),
        record_hash: String::new(),
    };
    Ok(stable_mirror_hash(&record.canonical_payload()))
}

pub fn extract_json_string_for_tests(line: &str, key: &str) -> Option<String> {
    extract_json_string(line, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_journal(name: &str) -> AuditJournal {
        let path = std::env::temp_dir().join(format!("agentd-{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    fn test_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "agentd-audit-runtime-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("test root");
        path
    }

    fn event(event_type: AuditEventType, run_id: &str, step_id: &str, summary: &str) -> AuditEvent {
        AuditEvent::new(event_type, run_id, step_id, "operator", summary)
    }

    #[test]
    fn appends_required_event_types_as_jsonl() {
        let journal = test_journal("append");
        let mut event = AuditEvent::new(
            AuditEventType::IntentReceived,
            "run-1",
            "step-1",
            "operator",
            "inspect service",
        );
        event.policy_version = "policy-v1".to_string();
        event.tool_version = "tool-v1".to_string();
        event.parameter_hash = "hash-1".to_string();
        journal.append(&event).expect("append event");
        let lines = journal.event_lines().expect("read lines");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event_type\":\"IntentReceived\""));
        assert!(lines[0].contains("\"policy_version\":\"policy-v1\""));
        assert!(lines[0].contains("\"parameter_hash\":\"hash-1\""));
    }

    #[test]
    fn reports_unresolved_prepared_effect_after_restart() {
        let journal = test_journal("unresolved");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-2",
                "step-2",
                "operator",
                "prepared restart",
            ))
            .expect("append prepared");

        let reopened = AuditJournal::new(journal.path().to_path_buf());
        let unresolved = reopened.unresolved_effects().expect("query unresolved");
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved[0].contains("EffectPrepared"));
    }

    #[test]
    fn sealed_effect_is_not_unresolved() {
        let journal = test_journal("sealed");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-3",
                "step-3",
                "operator",
                "prepared write",
            ))
            .expect("append prepared");
        journal
            .append(&AuditEvent::new(
                AuditEventType::CommitSealed,
                "run-3",
                "step-3",
                "operator",
                "verified and sealed",
            ))
            .expect("append sealed");
        assert!(journal.unresolved_effects().expect("query").is_empty());
    }

    #[test]
    fn redacts_secret_like_summary_tokens() {
        let event = AuditEvent::new(
            AuditEventType::EffectPrepared,
            "run-4",
            "step-4",
            "operator",
            "using password=hunter2 token=abc public-data",
        );
        let line = event.to_json_line();
        assert!(!line.contains("hunter2"));
        assert!(!line.contains("token=abc"));
        assert!(line.contains("[REDACTED]"));
        assert!(line.contains("public-data"));
    }

    #[test]
    fn redaction_does_not_hide_non_secret_words_containing_token() {
        let event = AuditEvent::new(
            AuditEventType::PolicyEvaluated,
            "run-5",
            "step-5",
            "operator",
            "approval required for token=value",
        );
        let line = event.to_json_line();
        assert!(line.contains("approval required"));
        assert!(line.contains("for"));
        assert!(!line.contains("token=value"));
        assert!(line.contains("[REDACTED]"));
    }

    #[test]
    fn projects_latest_runtime_run_with_stable_step_order() {
        let journal = test_journal("runtime-projection");
        journal
            .append(&event(
                AuditEventType::IntentReceived,
                "run-a",
                "intent",
                "intent accepted plan_id=plan-a requested_outcome=recover-nginx",
            ))
            .expect("intent");
        let mut plan = event(
            AuditEventType::PlanFrozen,
            "run-a",
            "plan",
            "plan frozen plan_id=plan-a plan_hash=hash-a",
        );
        plan.parameter_hash = "hash-a".to_string();
        journal.append(&plan).expect("plan");
        journal
            .append(&event(
                AuditEventType::PolicyEvaluated,
                "run-a",
                "inspect",
                "decision=allow tool=svc.status resource=nginx risk=read-only reason=diagnostic",
            ))
            .expect("policy");
        journal
            .append(&event(
                AuditEventType::EffectPrepared,
                "run-a",
                "inspect",
                "prepared tool=svc.status risk=read-only parameter_hash=hash-inspect",
            ))
            .expect("prepared");
        journal
            .append(&event(
                AuditEventType::EffectObserved,
                "run-a",
                "inspect",
                "observation processed source=semantic-tool trust=sandboxed-tool summary=status-active",
            ))
            .expect("observed");
        journal
            .append(&event(
                AuditEventType::CommitSealed,
                "run-a",
                "inspect",
                "commit sealed tool=svc.status commit_id=commit-1",
            ))
            .expect("sealed");

        let projection = journal
            .project_latest_runtime_run()
            .expect("projection")
            .expect("latest run");
        assert_eq!(projection.run_id, "run-a");
        assert_eq!(projection.plan_id.as_deref(), Some("plan-a"));
        assert_eq!(projection.plan_hash.as_deref(), Some("hash-a"));
        assert_eq!(projection.event_count(), 6);
        assert_eq!(projection.steps[0].step_id, "intent");
        assert_eq!(projection.steps[1].step_id, "plan");
        assert_eq!(projection.steps[2].step_id, "inspect");
        assert_eq!(projection.steps[2].status, "sealed");
        assert_eq!(
            projection.steps[2].observation_trust.as_deref(),
            Some("sandboxed-tool")
        );
        let json = projection.to_json();
        assert!(json.contains("\"effect_state\":\"sealed\""));
        assert!(json.contains("\"observation_source\":\"semantic-tool\""));
        let cli = projection.to_cli_text();
        assert!(cli.contains("run=run-a"));
        assert!(cli.contains("step=inspect status=sealed"));
    }

    #[test]
    fn projection_explains_denied_step_without_prepared_effect() {
        let journal = test_journal("runtime-denied");
        journal
            .append(&event(
                AuditEventType::PolicyEvaluated,
                "run-denied",
                "restart",
                "decision=deny tool=svc.restart resource=nginx risk=never reason=approval-missing",
            ))
            .expect("policy denied");
        journal
            .append(&event(
                AuditEventType::ApprovalBound,
                "run-denied",
                "restart",
                "approval denied reason=operator declined",
            ))
            .expect("approval denied");

        let projection = journal
            .project_runtime_run("run-denied")
            .expect("projection")
            .expect("run projection");
        assert_eq!(projection.steps.len(), 1);
        let step = &projection.steps[0];
        assert_eq!(step.status, "denied");
        assert!(!step.effect_prepared);
        assert_eq!(step.effect_state, "none");
        assert!(
            step.policy_summary
                .as_deref()
                .unwrap()
                .contains("decision=deny")
        );
        assert!(step.to_cli_line().contains("approval denied"));
    }

    #[test]
    fn projection_preserves_secret_handles_and_redacts_secret_values() {
        let journal = test_journal("runtime-redaction");
        journal
            .append(&event(
                AuditEventType::EffectObserved,
                "run-secret",
                "secret-step",
                "using secret://prod/db password=hunter2 token=abc123",
            ))
            .expect("secret observation");

        let projection = journal
            .project_runtime_run("run-secret")
            .expect("projection")
            .expect("run projection");
        let json = projection.to_json();
        assert!(json.contains("secret://prod/db"));
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("token=abc123"));
    }

    #[test]
    fn projection_records_recovery_source_and_malformed_line_warning() {
        let journal = test_journal("runtime-recovery");
        journal
            .append(&event(
                AuditEventType::RecoveryStarted,
                "run-recover",
                "restart",
                "recovery started from state=Executing",
            ))
            .expect("recovery started");
        journal
            .append(&event(
                AuditEventType::RecoveryCompleted,
                "run-recover",
                "restart",
                "recovery completed status=ReconcileEffects",
            ))
            .expect("recovery completed");
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(journal.path())
                .expect("open journal");
            writeln!(
                file,
                "{{\"run_id\":\"run-recover\",\"step_id\":\"broken\",\"summary\":\"missing event type\"}}"
            )
            .expect("write malformed line");
        }

        let projection = journal
            .project_runtime_run("run-recover")
            .expect("projection")
            .expect("run projection");
        assert_eq!(projection.steps[0].status, "recovered");
        assert!(
            projection.steps[0]
                .recovery_summary
                .as_deref()
                .unwrap()
                .contains("source=run-store+audit")
        );
        assert_eq!(projection.warnings.len(), 1);
        assert!(projection.warnings[0].contains("missing event_type"));
    }

    #[test]
    fn remote_audit_mirror_writes_redacted_hash_chain_from_local_journal() {
        let root = test_root("remote-mirror");
        let journal = AuditJournal::new(root.join("local.jsonl"));
        let mut policy_event = event(
            AuditEventType::PolicyEvaluated,
            "run-mirror",
            "step-policy",
            "decision=allow token=abc123 access_token:xyz using secret://prod/db",
        );
        policy_event.policy_version = "policy-v1".to_string();
        policy_event.tool_version = "tool-v1".to_string();
        policy_event.parameter_hash = "param-hash".to_string();
        journal.append(&policy_event).expect("append policy");
        journal
            .append(&event(
                AuditEventType::CommitSealed,
                "run-mirror",
                "step-policy",
                "commit sealed final=true",
            ))
            .expect("append commit");

        let mirror = FileRemoteAuditMirror::new(root.join("mirror.jsonl"));
        let decision = mirror
            .mirror_journal(&journal, &RemoteAuditMirrorConfig::local_warn())
            .expect("mirror");

        assert_eq!(decision.status, RemoteAuditMirrorStatus::Mirrored);
        assert_eq!(decision.mirrored_records, 2);
        assert!(decision.local_audit_authoritative);
        assert!(!decision.mirror_authoritative_for_recovery);
        assert!(decision.non_local_side_effects_allowed);

        let mirror_lines = AuditJournal::new(mirror.path().to_path_buf())
            .event_lines()
            .expect("mirror lines");
        assert_eq!(mirror_lines.len(), 2);
        assert!(mirror_lines[0].contains(REMOTE_AUDIT_MIRROR_RECORD_SCHEMA));
        assert!(mirror_lines[0].contains("\"sequence\":0"));
        assert!(mirror_lines[0].contains("\"previous_hash\":\"genesis\""));
        assert!(mirror_lines[0].contains("secret://prod/db"));
        assert!(mirror_lines[0].contains("[REDACTED]"));
        assert!(!mirror_lines[0].contains("abc123"));
        assert!(!mirror_lines[0].contains("xyz"));
        let first_hash =
            extract_json_string_for_tests(&mirror_lines[0], "record_hash").expect("hash");
        assert!(mirror_lines[1].contains(&format!("\"previous_hash\":\"{first_hash}\"")));
    }

    #[test]
    fn remote_audit_mirror_incrementally_appends_new_local_events() {
        let root = test_root("remote-incremental");
        let journal = AuditJournal::new(root.join("local.jsonl"));
        journal
            .append(&event(
                AuditEventType::PolicyEvaluated,
                "run-inc",
                "step-1",
                "decision=allow",
            ))
            .expect("append first");
        let mirror = FileRemoteAuditMirror::new(root.join("mirror.jsonl"));
        let first = mirror
            .mirror_journal(&journal, &RemoteAuditMirrorConfig::local_warn())
            .expect("first mirror");
        assert_eq!(first.mirrored_records, 1);
        assert_eq!(first.next_sequence, 1);

        journal
            .append(&event(
                AuditEventType::CommitSealed,
                "run-inc",
                "step-1",
                "commit sealed",
            ))
            .expect("append second");
        let second = mirror
            .mirror_journal(&journal, &RemoteAuditMirrorConfig::local_warn())
            .expect("second mirror");
        assert_eq!(second.mirrored_records, 1);
        assert_eq!(second.next_sequence, 2);
        assert_eq!(
            AuditJournal::new(mirror.path().to_path_buf())
                .event_lines()
                .expect("mirror lines")
                .len(),
            2
        );
    }

    #[test]
    fn remote_audit_mirror_warn_failure_keeps_local_authority_and_allows_side_effects() {
        let root = test_root("remote-warn");
        let journal = AuditJournal::new(root.join("local.jsonl"));
        journal
            .append(&event(
                AuditEventType::EffectPrepared,
                "run-warn",
                "step",
                "prepared",
            ))
            .expect("append");
        let mirror_path = root.join("mirror.jsonl");
        std::fs::write(&mirror_path, "{\"schema\":\"broken\",\"sequence\":0,\"previous_hash\":\"wrong\",\"record_hash\":\"bad\"}\n")
            .expect("seed broken mirror");

        let decision = FileRemoteAuditMirror::new(mirror_path)
            .mirror_journal(&journal, &RemoteAuditMirrorConfig::local_warn())
            .expect("warn decision");

        assert_eq!(decision.status, RemoteAuditMirrorStatus::Warning);
        assert!(decision.local_audit_authoritative);
        assert!(!decision.mirror_authoritative_for_recovery);
        assert!(decision.local_diagnostics_allowed);
        assert!(decision.non_local_side_effects_allowed);
        let local_lines = journal.event_lines().expect("local lines");
        assert!(
            local_lines
                .iter()
                .any(|line| line.contains("remote-audit-mirror failure"))
        );
    }

    #[test]
    fn remote_audit_mirror_pause_failure_blocks_non_local_side_effects_but_keeps_diagnostics() {
        let root = test_root("remote-pause");
        let journal = AuditJournal::new(root.join("local.jsonl"));
        let mirror_path = root.join("mirror.jsonl");
        std::fs::write(&mirror_path, "not-json\n").expect("seed broken mirror");
        let config = RemoteAuditMirrorConfig::new(RemoteAuditFailurePolicy::Pause, "regulated");

        let decision = FileRemoteAuditMirror::new(mirror_path)
            .mirror_journal(&journal, &config)
            .expect("pause decision");

        assert_eq!(decision.status, RemoteAuditMirrorStatus::Paused);
        assert!(decision.local_audit_authoritative);
        assert!(decision.local_diagnostics_allowed);
        assert!(!decision.non_local_side_effects_allowed);
    }

    #[test]
    fn remote_audit_mirror_fail_closed_failure_blocks_non_local_side_effects() {
        let root = test_root("remote-fail-closed");
        let journal = AuditJournal::new(root.join("local.jsonl"));
        let mirror_path = root.join("mirror.jsonl");
        std::fs::write(&mirror_path, "not-json\n").expect("seed broken mirror");
        let config =
            RemoteAuditMirrorConfig::new(RemoteAuditFailurePolicy::FailClosed, "regulated");

        let decision = FileRemoteAuditMirror::new(mirror_path)
            .mirror_journal(&journal, &config)
            .expect("fail closed decision");

        assert_eq!(decision.status, RemoteAuditMirrorStatus::FailedClosed);
        assert!(decision.local_audit_authoritative);
        assert!(!decision.mirror_authoritative_for_recovery);
        assert!(decision.local_diagnostics_allowed);
        assert!(!decision.non_local_side_effects_allowed);
        assert!(
            decision
                .to_json()
                .contains("\"failure_policy\":\"fail-closed\"")
        );
    }

    #[test]
    fn remote_audit_mirror_rejects_tampered_hash_chain() {
        let root = test_root("remote-tampered");
        let journal = AuditJournal::new(root.join("local.jsonl"));
        journal
            .append(&event(
                AuditEventType::PolicyEvaluated,
                "run-tamper",
                "step",
                "decision=allow",
            ))
            .expect("append local");
        let mirror = FileRemoteAuditMirror::new(root.join("mirror.jsonl"));
        mirror
            .mirror_journal(&journal, &RemoteAuditMirrorConfig::local_warn())
            .expect("initial mirror");
        let mut mirror_lines = AuditJournal::new(mirror.path().to_path_buf())
            .event_lines()
            .expect("mirror lines");
        mirror_lines[0] = mirror_lines[0].replace("decision=allow", "decision=deny");
        std::fs::write(mirror.path(), format!("{}\n", mirror_lines.join("\n"))).expect("tamper");

        let decision = mirror
            .mirror_journal(&journal, &RemoteAuditMirrorConfig::local_warn())
            .expect("tamper decision");

        assert_eq!(decision.status, RemoteAuditMirrorStatus::Warning);
        assert!(decision.warnings[0].contains("record hash mismatch"));
    }

    // ===== group commit（cp-audit-perf-1）：append_batch / AuditBatch =====

    #[test]
    fn append_batch_writes_all_events_in_one_fsync() {
        let journal = test_journal("batch");
        let events = vec![
            event(AuditEventType::IntentReceived, "run-b", "step-0", "intent"),
            event(AuditEventType::PlanFrozen, "run-b", "step-0", "frozen"),
            event(AuditEventType::CommitSealed, "run-b", "step-0", "sealed"),
        ];
        journal.append_batch(&events).expect("batch commit");
        let lines = journal.event_lines().expect("read");
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("IntentReceived"));
        assert!(lines[1].contains("PlanFrozen"));
        assert!(lines[2].contains("CommitSealed"));
        // 重开 journal 后仍可读全 3 行（耐久性：整批落盘）。
        let reopened = AuditJournal::new(journal.path().to_path_buf());
        assert_eq!(reopened.event_lines().unwrap().len(), 3);
    }

    #[test]
    fn append_batch_empty_is_noop() {
        let journal = test_journal("batch-empty");
        journal.append_batch(&[]).expect("empty batch");
        assert!(journal.event_lines().unwrap().is_empty());
    }

    #[test]
    fn batch_builder_commit_flushes_and_clears() {
        let journal = test_journal("batch-builder");
        let mut batch = journal.batch();
        assert!(batch.is_empty());
        batch
            .push(event(AuditEventType::IntentReceived, "run-bb", "s0", "i"))
            .push(event(AuditEventType::EffectPrepared, "run-bb", "s0", "p"));
        assert_eq!(batch.len(), 2);
        let committed = batch.commit().expect("commit");
        assert_eq!(committed, 2);
        assert!(batch.is_empty());
        assert_eq!(journal.event_lines().unwrap().len(), 2);
    }

    #[test]
    fn batch_commit_empty_is_noop() {
        let journal = test_journal("batch-empty-commit");
        let mut batch = journal.batch();
        let committed = batch.commit().expect("empty commit");
        assert_eq!(committed, 0);
        assert!(journal.event_lines().unwrap().is_empty());
    }

    /// group commit 与逐事件 append 写出的行格式字节一致（格式兼容）。
    #[test]
    fn batch_format_matches_append_line_for_line() {
        let journal_single = test_journal("batch-fmt-single");
        let journal_batch = test_journal("batch-fmt-batch");
        let events = vec![
            event(AuditEventType::PolicyEvaluated, "run-fmt", "s0", "eval"),
            event(AuditEventType::ApprovalBound, "run-fmt", "s0", "bound"),
        ];
        for ev in &events {
            journal_single.append(ev).expect("single");
        }
        journal_batch.append_batch(&events).expect("batch");
        assert_eq!(journal_single.event_lines().unwrap(), journal_batch.event_lines().unwrap());
    }

    // ===== run_id 倒排索引（cp-audit-perf-2）：RunIndex =====

    #[test]
    fn run_index_builds_and_queries_timeline_by_run_id() {
        let journal = test_journal("run-idx");
        journal
            .append(&event(AuditEventType::IntentReceived, "run-a", "s0", "a0"))
            .unwrap();
        journal
            .append(&event(AuditEventType::PlanFrozen, "run-a", "s0", "a1"))
            .unwrap();
        journal
            .append(&event(AuditEventType::IntentReceived, "run-b", "s0", "b0"))
            .unwrap();
        journal
            .append(&event(AuditEventType::CommitSealed, "run-a", "s0", "a2"))
            .unwrap();

        let index = RunIndex::from_journal(&journal).expect("build");
        // 两个 run。
        let ids: Vec<&str> = index.run_ids().collect();
        assert_eq!(ids, vec!["run-a", "run-b"]);
        // run-a 3 行，run-b 1 行。
        assert_eq!(index.run_line_count("run-a"), 3);
        assert_eq!(index.run_line_count("run-b"), 1);
        assert_eq!(index.run_line_count("run-missing"), 0);
        // latest = 最后出现的 run_id（run-a）。
        assert_eq!(index.latest_run(), Some("run-a"));
        assert_eq!(index.lines_cached(), 4);
    }

    #[test]
    fn run_index_timeline_matches_journal_run_timeline() {
        let journal = test_journal("run-idx-match");
        let events = vec![
            event(AuditEventType::IntentReceived, "run-x", "s0", "x0"),
            event(AuditEventType::PlanFrozen, "run-x", "s0", "x1"),
            event(AuditEventType::IntentReceived, "run-y", "s0", "y0"),
            event(AuditEventType::CommitSealed, "run-x", "s0", "x2"),
            event(AuditEventType::EffectObserved, "run-y", "s0", "y1"),
        ];
        journal.append_batch(&events).unwrap();

        let index = RunIndex::from_journal(&journal).expect("build");
        // 索引查询结果须与 journal.run_timeline（全扫 filter）逐行一致。
        let via_index = index.run_timeline(&journal, "run-x").expect("idx timeline");
        let via_scan = journal.run_timeline("run-x").expect("scan timeline");
        assert_eq!(via_index, via_scan);
        assert_eq!(via_index.len(), 3);

        let via_index_y = index.run_timeline(&journal, "run-y").expect("idx y");
        let via_scan_y = journal.run_timeline("run-y").expect("scan y");
        assert_eq!(via_index_y, via_scan_y);
    }

    #[test]
    fn run_index_timeline_unknown_run_is_empty() {
        let journal = test_journal("run-idx-unknown");
        journal
            .append(&event(AuditEventType::IntentReceived, "run-a", "s0", "a"))
            .unwrap();
        let index = RunIndex::from_journal(&journal).expect("build");
        let timeline = index.run_timeline(&journal, "run-missing").expect("ok");
        assert!(timeline.is_empty());
    }

    #[test]
    fn run_index_empty_journal() {
        let journal = test_journal("run-idx-empty");
        let index = RunIndex::from_journal(&journal).expect("build");
        assert_eq!(index.lines_cached(), 0);
        assert_eq!(index.latest_run(), None);
        assert!(index.run_ids().next().is_none());
    }

    // ===== 阶段 R：SyncAuditJournal =====

    #[test]
    fn sync_journal_append_and_read() {
        let path = std::env::temp_dir().join(format!(
            "agentd-sync-basic-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let sync = SyncAuditJournal::new(&path);
        sync.append(&event(AuditEventType::IntentReceived, "run-s1", "step-0", "intent"))
            .expect("append");
        let lines = sync.event_lines().expect("read");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("IntentReceived"));
    }

    #[test]
    fn sync_journal_concurrent_appends_no_interleaving() {
        use std::sync::Arc;
        use std::thread;
        let path = std::env::temp_dir().join(format!(
            "agentd-sync-concurrent-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let sync = Arc::new(SyncAuditJournal::new(&path));
        const N_THREADS: usize = 8;
        const PER_THREAD: usize = 50;
        let mut handles = Vec::new();
        for t in 0..N_THREADS {
            let sync = Arc::clone(&sync);
            handles.push(thread::spawn(move || {
                for i in 0..PER_THREAD {
                    sync.append(&event(
                        AuditEventType::EffectObserved,
                        "run-concurrent",
                        &format!("t{t}-i{i}"),
                        "observed",
                    ))
                    .expect("append");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        let lines = sync.event_lines().expect("read");
        // 无交错：每行完整 JSON，总行数 == N_THREADS * PER_THREAD。
        assert_eq!(lines.len(), N_THREADS * PER_THREAD);
        for line in &lines {
            assert!(line.contains("\"event_type\":\"EffectObserved\""), "corrupt line: {line}");
            assert!(line.starts_with('{') && line.ends_with('}'), "non-atomic line: {line}");
        }
    }

    #[test]
    fn sync_journal_append_batch_atomic() {
        let path = std::env::temp_dir().join(format!(
            "agentd-sync-batch-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let sync = SyncAuditJournal::new(&path);
        let batch = vec![
            event(AuditEventType::PlanFrozen, "run-b1", "step-0", "plan"),
            event(AuditEventType::PolicyEvaluated, "run-b1", "step-0", "policy"),
            event(AuditEventType::EffectObserved, "run-b1", "step-0", "effect"),
        ];
        sync.append_batch(&batch).expect("batch");
        assert_eq!(sync.event_lines().expect("read").len(), 3);
    }
}
