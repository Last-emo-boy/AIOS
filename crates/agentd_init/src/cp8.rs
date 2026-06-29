//! cp8 —— 真磁盘 OS 的 `fs.write.diff` 持久化 + post-crash recovery 引擎（ADR-004 cp8）。
//!
//! 纯 host 确定性逻辑：只读复用冻结 oracle（`security_execution::{rollback, audit, policy}`）
//! 的 pub API，绝不改其非测试源。本模块负责冻结 `commit()`/`rollback()` 不做的 **fsync 屏障**，
//! 把 fs.write.diff 效果真正落到 vda3 持久分区，并在崩溃后从已持久的 audit + shadow 真回滚。
//!
//! 设计不变量（synthesis interface_contracts）：
//! - WRITE ORDER + FSYNC BARRIERS：`prepare()` → Barrier1 fsync shadow → 冻结 `commit()` →
//!   Barrier2 fsync{target, target.parent(), audit dir} → verify-by-re-read。
//! - SOUNDNESS INVARIANT：previous.txt 必先于 EffectPrepared 持久（Barrier1 强制）⇒ 任一 unresolved
//!   effect 永远有可用回滚源。
//! - RECOVERY DECISION RULE：每条 `unresolved_effects()`（EffectPrepared 无 CommitSealed/RollbackObserved）
//!   一律 **roll back**（unsealed = 未被系统验证提交 ⇒ 回到 known-good base）；缺 previous.txt 或行不可
//!   解析 = fail-closed 硬错，绝不静默跳过。
//!
//! fsync 全经安全 `std::fs::File::sync_all`（文件 fd 与目录 fd 皆合法），故本模块保持
//! `#![forbid(unsafe_code)]`，platform_sys 唯一 unsafe 边界冻结不动。
#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use runtime_contracts::RiskClass;
use security_execution::audit::{
    extract_json_string_for_tests, AuditEvent, AuditEventType, AuditJournal,
};
use security_execution::policy::CapabilityLease;
use security_execution::rollback::{content_hash, RollbackHandle, WriteDiffExecutor, WriteRequest};

/// vda3 持久布局（LAYOUT 契约；`root` 为持久分区根，生产 = `/var/lib/agentos`，host 测试 = temp dir）。
#[derive(Debug, Clone)]
pub struct Layout {
    /// 持久分区根。
    pub root: PathBuf,
    /// 审计日志 `<root>/audit/journal.jsonl`（AuditJournal::append 自建 `audit/` 但只 fsync 文件不 fsync 目录）。
    pub audit: PathBuf,
    /// shadow 根 `<root>/shadow`（prepare() 自建 `shadow/<rb>/`，存 previous.txt/proposed.txt 回滚源）。
    pub shadow: PathBuf,
    /// 写目标 `<root>/state/app.conf`（冻结 commit()/rollback() 的 fs::write 不建父目录 ⇒ 须先 create_dir_all）。
    pub target: PathBuf,
}

/// 按 LAYOUT 契约从持久分区根派生 cp8 全部路径常量。
pub fn layout(root: impl AsRef<Path>) -> Layout {
    let root = root.as_ref().to_path_buf();
    Layout {
        audit: root.join("audit").join("journal.jsonl"),
        shadow: root.join("shadow"),
        target: root.join("state").join("app.conf"),
        root,
    }
}

/// 文件 fsync：`File::open(p)?.sync_all()`（= fsync(2)，纯 std，无 unsafe）。
fn fsync_file(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// 目录 fsync：`File::open(dir)?.sync_all()`（O_RDONLY 目录 fd + fsync(2)，Linux/musl 合法，刷 dirent；纯 std，无 unsafe）。
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// 构造 fs.write.diff 能力租约（tool=fs.write.diff, risk=WriteWithDiff）。
///
/// `parameter_hash` 决定 `rollback_id`（`rb-<parameter_hash>-<proposed_hash>`），故须确定性。
/// prepare() 只校验 `lease.tool == "fs.write.diff"`，其余字段随 effect 落入 audit/handle 供恢复重建。
pub fn lease_fs_write_diff(layout: &Layout, parameter_hash: &str) -> CapabilityLease {
    CapabilityLease {
        lease_id: format!("lease-fs.write.diff-{parameter_hash}"),
        actor: "agentd-init".to_string(),
        tool: "fs.write.diff".to_string(),
        resource: layout.target.display().to_string(),
        parameter_hash: parameter_hash.to_string(),
        expires_at: u64::MAX,
        policy_version: "policy-v1".to_string(),
        risk: RiskClass::WriteWithDiff,
    }
}

/// 一次正常持久写 effect 的事实（供 disk_init 串口标记 + host 测试断言）。
#[derive(Debug, Clone)]
pub struct EffectReport {
    /// 冻结 commit() 是否封存（true = EffectObserved+CommitSealed 已落）。
    pub committed: bool,
    /// 写前 base hash（读真实目标算出，缺失为 content_hash("")）。
    pub base_hash: String,
    /// commit() 回读校验后的最终 hash。
    pub final_hash: String,
    /// cp8 Barrier2 后独立 verify-by-re-read 的 hash（须 == final_hash）。
    pub reread_hash: String,
    /// rollback_id（`rb-<parameter_hash>-<proposed_hash>`）。
    pub rollback_id: String,
    /// 写目标路径。
    pub target_path: PathBuf,
}

/// NORMAL PERSIST：`prepare()` → Barrier1 → 冻结 `commit()` → Barrier2 → verify-by-re-read。
///
/// base_hash 读真实目标算出（缺失 = content_hash("")），绝不硬编码。fail-closed：commit 未封存
/// 或回读不匹配 ⇒ Err。
pub fn run_effect(
    layout: &Layout,
    run_id: &str,
    step_id: &str,
    actor: &str,
    parameter_hash: &str,
    proposed: &str,
) -> io::Result<EffectReport> {
    // 目标父目录：冻结 commit() 的 fs::write 不建父目录，否则 ENOENT。
    ensure_target_parent(layout)?;

    let lease = lease_fs_write_diff(layout, parameter_hash);
    let executor = WriteDiffExecutor::new(&layout.shadow);
    let journal = AuditJournal::new(&layout.audit);

    let base_hash = current_target_hash(&layout.target)?;
    let request = WriteRequest {
        run_id: run_id.to_string(),
        step_id: step_id.to_string(),
        actor: actor.to_string(),
        target_path: layout.target.clone(),
        proposed_content: proposed.to_string(),
        base_hash,
    };

    // prepare()：写 shadow previous.txt/proposed.txt，目标不动，不写 audit。
    let mut prepared = executor.prepare(&lease, request).map_err(write_diff_io)?;

    // Barrier1：回滚源先持久（SOUNDNESS INVARIANT —— previous.txt 必先于 EffectPrepared durable）。
    barrier1_fsync_shadow(layout, &prepared.handle)?;

    // 冻结 commit()：append EffectPrepared（AuditJournal fsync 文件）→ fs::write(target)（未 fsync）
    // → append EffectObserved + CommitSealed。
    let report = executor.commit(&journal, &mut prepared).map_err(write_diff_io)?;
    if !report.committed {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("commit not sealed final_hash={}", report.final_hash),
        ));
    }

    // Barrier2：target + target.parent() + audit dir 持久（commit 不 fsync 目标，append 不 fsync audit 目录）。
    barrier2_fsync_commit(layout)?;

    // verify-by-re-read：独立复读目标重算 hash，须 == commit 的 final_hash。
    let reread_hash = content_hash(&read_to_string_if_exists(&layout.target)?);
    if reread_hash != report.final_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "verify-by-re-read mismatch reread={reread_hash} final={}",
                report.final_hash
            ),
        ));
    }

    Ok(EffectReport {
        committed: report.committed,
        base_hash: report.base_hash,
        final_hash: report.final_hash,
        reread_hash,
        rollback_id: report.rollback_id,
        target_path: report.target_path,
    })
}

/// 崩溃装弹 effect 的事实（供跨 reboot 反假绿等式与 host 测试断言）。
#[derive(Debug, Clone)]
pub struct ArmReport {
    /// rollback_id（恢复期从 audit summary 重建 handle 的钥匙）。
    pub rollback_id: String,
    /// 崩溃前 base hash（恢复后目标须回滚到此）。
    pub base_hash: String,
    /// 半落盘 proposed hash（崩溃前已 fsync 但永无 CommitSealed）。
    pub proposed_hash: String,
    /// 写目标路径。
    pub target_path: PathBuf,
}

/// CRASH-ARM SEAM（测试/演练用）：复刻 **真 mid-commit 崩溃** 的确定性持久盘上态。
///
/// `prepare()` → Barrier1 fsync shadow → 手动 append 一条 summary 与冻结 commit()
/// （rollback.rs:246-252）**逐字一致** 的 EffectPrepared → 半落盘 fs::write(target=proposed)+sync_all
/// → fsync 父目录 → **不 append CommitSealed**（模拟写后、封存前崩溃）。
///
/// summary 逐字一致是硬约束：否则 `unresolved_effects()` 配对 + recover 的 handle 重建会解析失败。
pub fn arm_crash(
    layout: &Layout,
    run_id: &str,
    step_id: &str,
    actor: &str,
    parameter_hash: &str,
    proposed: &str,
) -> io::Result<ArmReport> {
    ensure_target_parent(layout)?;

    let lease = lease_fs_write_diff(layout, parameter_hash);
    let executor = WriteDiffExecutor::new(&layout.shadow);
    let journal = AuditJournal::new(&layout.audit);

    let base_hash = current_target_hash(&layout.target)?;
    let request = WriteRequest {
        run_id: run_id.to_string(),
        step_id: step_id.to_string(),
        actor: actor.to_string(),
        target_path: layout.target.clone(),
        proposed_content: proposed.to_string(),
        base_hash,
    };

    // prepare()：写 shadow previous.txt(=base)/proposed.txt，目标不动，不写 audit。
    let prepared = executor.prepare(&lease, request).map_err(write_diff_io)?;
    let handle = prepared.handle.clone();

    // Barrier1：回滚源先持久（previous.txt 必先于 EffectPrepared durable，否则崩溃后不可恢复）。
    barrier1_fsync_shadow(layout, &handle)?;

    // 手动 EffectPrepared —— summary 与冻结 commit() rollback.rs:246-252 逐字一致。
    let mut prepared_event = AuditEvent::new(
        AuditEventType::EffectPrepared,
        run_id,
        step_id,
        actor,
        format!(
            "prepared fs.write.diff target={} rollback_id={} base_hash={} proposed_hash={}",
            handle.target_path.display(),
            handle.rollback_id,
            handle.base_hash,
            handle.proposed_hash
        ),
    );
    prepared_event.policy_version = lease.policy_version.clone();
    prepared_event.tool_version = "fs.write.diff-v1".to_string();
    prepared_event.parameter_hash = lease.parameter_hash.clone();
    journal.append(&prepared_event)?; // append 内含 sync_all（audit 文件 durable）。
    if let Some(audit_dir) = layout.audit.parent() {
        fsync_dir(audit_dir)?; // audit dirent durable（append 不 fsync 父目录）。
    }

    // 半落盘写：fs::write(target=proposed)+sync_all + fsync 父目录（无 CommitSealed = 未解决半写）。
    {
        let mut file = File::create(&layout.target)?;
        file.write_all(proposed.as_bytes())?;
        file.sync_all()?;
    }
    if let Some(parent) = layout.target.parent() {
        fsync_dir(parent)?;
    }

    Ok(ArmReport {
        rollback_id: handle.rollback_id,
        base_hash: handle.base_hash,
        proposed_hash: handle.proposed_hash,
        target_path: handle.target_path,
    })
}

/// post-crash recovery 的事实（供 disk_init 串口标记 + host 测试断言）。
#[derive(Debug, Clone)]
pub struct RecoverReport {
    /// 真回滚的 unresolved effect 数。
    pub rolled_back: usize,
    /// 最后一次回滚后的 restored hash（== base hash）。
    pub restored_hash: String,
    /// 恢复后剩余 unresolved 数（须为 0）。
    pub unresolved_after: usize,
}

/// CRASH RECOVERY：对每条 `unresolved_effects()` 重建 RollbackHandle 真回滚（单一规则，无 live-target 分支）。
///
/// 重建 handle（ids/hashes ← summary token；parameter_hash/policy_version ← JSON 字段；
/// previous/proposed 路径 ← shadow/<rb>/{previous,proposed}.txt）→ fail-closed（previous.txt 缺失或行不可解析）
/// → 冻结 `rollback()`（从 previous.txt 全覆写 ⇒ target=base，append RollbackPending+RollbackObserved，
/// 按 step_id 解除 unresolved）→ fsync target+父目录 → 断言 restored_hash==base_hash。
pub fn recover(layout: &Layout) -> io::Result<RecoverReport> {
    let journal = AuditJournal::new(&layout.audit);
    let executor = WriteDiffExecutor::new(&layout.shadow);

    let unresolved = journal.unresolved_effects()?;
    let mut rolled_back = 0usize;
    let mut restored_hash = String::new();

    for line in &unresolved {
        let recovered = reconstruct_handle(line, &layout.shadow)?;
        let handle = recovered.handle;

        // fail-closed：回滚源缺失 = SOUNDNESS INVARIANT 被破坏，硬错（绝不静默跳过）。
        if !handle.previous_content_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "fail-closed: shadow previous.txt missing for rollback_id={}",
                    handle.rollback_id
                ),
            ));
        }

        // 冻结 rollback()：从 previous.txt 全覆写 ⇒ target=base（顺带修复撕裂半写），
        // append RollbackPending+RollbackObserved（按 step_id 解除 unresolved）。
        let report = executor
            .rollback(
                &journal,
                &handle,
                &recovered.run_id,
                &recovered.step_id,
                &recovered.actor,
            )
            .map_err(write_diff_io)?;

        // 回滚后的目标 + 父目录持久。
        fsync_file(&handle.target_path)?;
        if let Some(parent) = handle.target_path.parent() {
            fsync_dir(parent)?;
        }

        // 断言 restored_hash==base_hash（RollbackReport.restored 即此判定）；不符 = fail-closed。
        if !report.restored {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "rollback restored_hash={} != base_hash={}",
                    report.restored_hash, handle.base_hash
                ),
            ));
        }
        restored_hash = report.restored_hash;
        rolled_back += 1;
    }

    let unresolved_after = journal.unresolved_effects()?.len();
    Ok(RecoverReport {
        rolled_back,
        restored_hash,
        unresolved_after,
    })
}

/// 当前 unresolved（EffectPrepared 无 CommitSealed/RollbackObserved）effect 数。
pub fn unresolved_count(layout: &Layout) -> io::Result<usize> {
    Ok(AuditJournal::new(&layout.audit).unresolved_effects()?.len())
}

/// 从崩溃残留持久件重建的回滚上下文（内存 handle 随崩溃丢失，纯从 audit+shadow 复原）。
struct RecoveredEffect {
    handle: RollbackHandle,
    run_id: String,
    step_id: String,
    actor: String,
}

/// 创建并 fsync 目标父目录（state/）；冻结 commit()/rollback() 的 fs::write 不建父目录。
fn ensure_target_parent(layout: &Layout) -> io::Result<()> {
    if let Some(parent) = layout.target.parent() {
        fs::create_dir_all(parent)?;
        fsync_dir(parent)?;
    }
    Ok(())
}

/// Barrier1：fsync{previous.txt, proposed.txt, shadow/<rb>, shadow_root}（回滚源先持久）。
fn barrier1_fsync_shadow(layout: &Layout, handle: &RollbackHandle) -> io::Result<()> {
    fsync_file(&handle.previous_content_path)?;
    fsync_file(&handle.proposed_content_path)?;
    fsync_dir(&layout.shadow.join(&handle.rollback_id))?;
    fsync_dir(&layout.shadow)?;
    Ok(())
}

/// Barrier2：fsync{target, target.parent()=state/, audit dir}（commit 不 fsync 目标，append 不 fsync audit 目录）。
fn barrier2_fsync_commit(layout: &Layout) -> io::Result<()> {
    fsync_file(&layout.target)?;
    if let Some(parent) = layout.target.parent() {
        fsync_dir(parent)?;
    }
    if let Some(audit_dir) = layout.audit.parent() {
        fsync_dir(audit_dir)?;
    }
    Ok(())
}

/// 读目标文件；缺失返回空串（镜像冻结 read_to_string_if_exists，使首写 base_hash==content_hash("")）。
fn read_to_string_if_exists(path: &Path) -> io::Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    fs::read_to_string(path)
}

/// 读真实目标算 base hash（缺失 = content_hash("")）。
fn current_target_hash(path: &Path) -> io::Result<String> {
    Ok(content_hash(&read_to_string_if_exists(path)?))
}

/// 把冻结 WriteDiffError 收敛为 io::Error（reason 文案）。
fn write_diff_io(error: security_execution::rollback::WriteDiffError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.reason())
}

/// 从一条 EffectPrepared audit 行 + shadow 布局重建 RollbackHandle + run/step/actor。
///
/// JSON 顶层字段（run_id/step_id/actor/parameter_hash/policy_version）经
/// `extract_json_string_for_tests`；写坐标（target/rollback_id/base_hash/proposed_hash）经 summary token
/// （split_whitespace+strip_prefix）；shadow 路径按 `shadow/<rb>/{previous,proposed}.txt` 确定性约定。
fn reconstruct_handle(line: &str, shadow_root: &Path) -> io::Result<RecoveredEffect> {
    let field = |key: &str| extract_json_string_for_tests(line, key);
    let summary = field("summary").ok_or_else(|| bad_line("missing summary"))?;
    let token = |key: &str| summary_token(&summary, key);

    let rollback_id = token("rollback_id").ok_or_else(|| bad_line("missing rollback_id token"))?;
    let target_path = token("target").ok_or_else(|| bad_line("missing target token"))?;
    let base_hash = token("base_hash").ok_or_else(|| bad_line("missing base_hash token"))?;
    let proposed_hash =
        token("proposed_hash").ok_or_else(|| bad_line("missing proposed_hash token"))?;
    let step_id = field("step_id").ok_or_else(|| bad_line("missing step_id"))?;
    let run_id = field("run_id").unwrap_or_else(|| "cp8-recover".to_string());
    let actor = field("actor").unwrap_or_else(|| "agentd-init".to_string());
    let parameter_hash = field("parameter_hash").unwrap_or_default();
    let policy_version = field("policy_version").unwrap_or_default();

    let shadow_dir = shadow_root.join(&rollback_id);
    let handle = RollbackHandle {
        rollback_id,
        target_path: PathBuf::from(target_path),
        base_hash,
        proposed_hash,
        parameter_hash,
        policy_version,
        previous_content_path: shadow_dir.join("previous.txt"),
        proposed_content_path: shadow_dir.join("proposed.txt"),
        committed: false,
    };
    Ok(RecoveredEffect {
        handle,
        run_id,
        step_id,
        actor,
    })
}

/// 从空格分隔的 summary 取 `key=value` 的 value（与冻结 commit() 写入格式对偶）。
fn summary_token(summary: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(|value| value.to_string())
}

/// fail-closed：不可解析的 EffectPrepared 行（绝不静默跳过）。
fn bad_line(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("fail-closed: unparsable EffectPrepared line ({reason})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "mode=prod\nport=8080\n";
    const V2: &str = "mode=prod\nport=9090\n";

    fn temp_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("agentd-cp8-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp root");
        path
    }

    #[test]
    fn run_effect_commits_persists_and_verifies_by_reread() {
        let root = temp_root("effect");
        let l = layout(&root);

        let report =
            run_effect(&l, "cp8", "cp8-A-write", "agentd-init", "param-A", V1).expect("run_effect");

        // committed + verify-by-re-read 一致。
        assert!(report.committed);
        assert_eq!(report.final_hash, report.reread_hash);
        assert_eq!(report.final_hash, content_hash(V1));
        // 目标真落盘 == v1。
        assert_eq!(fs::read_to_string(&l.target).expect("read target"), V1);

        // audit 含三类事件。
        let lines = AuditJournal::new(&l.audit)
            .event_lines()
            .expect("event lines");
        assert!(lines.iter().any(|line| line.contains("EffectPrepared")));
        assert!(lines.iter().any(|line| line.contains("EffectObserved")));
        assert!(lines.iter().any(|line| line.contains("CommitSealed")));

        // 无残留 unresolved。
        assert_eq!(unresolved_count(&l).expect("unresolved"), 0);
    }

    #[test]
    fn arm_crash_then_recover_rolls_back_to_base() {
        let root = temp_root("recover");
        let l = layout(&root);

        // 先正常落 v1（base）。
        let effect =
            run_effect(&l, "cp8", "cp8-A-write", "agentd-init", "param-A", V1).expect("run_effect");
        let base_hash = effect.final_hash.clone();
        assert_eq!(base_hash, content_hash(V1));

        // 装弹 v1->v2（**不同 step_id** cp8-B-write，避免与 cp8-A-write 碰撞）；半落盘 v2 无 CommitSealed。
        let arm = arm_crash(&l, "cp8", "cp8-B-write", "agentd-init", "param-B", V2).expect("arm");
        assert_eq!(arm.base_hash, base_hash);
        assert_eq!(arm.proposed_hash, content_hash(V2));
        // 崩溃前盘上态：目标真被半写成 v2。
        assert_eq!(fs::read_to_string(&l.target).expect("read armed target"), V2);
        // cp8-A-write 已 sealed 被排除；cp8-B-write prepared 未 seal → unresolved=1。
        assert_eq!(unresolved_count(&l).expect("unresolved armed"), 1);

        // recover：未完成 effect 一律回滚到 base=v1。
        let rec = recover(&l).expect("recover");
        assert_eq!(rec.rolled_back, 1);
        assert_eq!(rec.unresolved_after, 0);
        assert_eq!(rec.restored_hash, base_hash);

        // 目标字节真被还原为 v1（!= 未完成的 v2）。
        assert_eq!(fs::read_to_string(&l.target).expect("read recovered target"), V1);
        assert_ne!(
            content_hash(&fs::read_to_string(&l.target).expect("read")),
            arm.proposed_hash
        );

        // RollbackObserved 已落 + 二次 recover 幂等空跑。
        let lines = AuditJournal::new(&l.audit)
            .event_lines()
            .expect("event lines");
        assert!(lines.iter().any(|line| line.contains("RollbackObserved")));
        assert_eq!(unresolved_count(&l).expect("unresolved after"), 0);
    }

    #[test]
    fn recover_is_noop_when_no_unresolved_effects() {
        let root = temp_root("noop");
        let l = layout(&root);
        run_effect(&l, "cp8", "cp8-A-write", "agentd-init", "param-A", V1).expect("run_effect");

        let rec = recover(&l).expect("recover");
        assert_eq!(rec.rolled_back, 0);
        assert_eq!(rec.unresolved_after, 0);
        // 正常 effect 不被恢复触碰。
        assert_eq!(fs::read_to_string(&l.target).expect("read target"), V1);
    }
}
