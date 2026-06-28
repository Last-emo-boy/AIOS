//! 真 write-with-diff 端到端集成测试（ADR-004 cp5 延伸 / ADR-000 受限写控制面）。
//!
//! 与合成向量不同，这里在**完整受限沙箱**（user/mount/pid/net ns + Landlock 读写授权 +
//! seccomp default-deny）内运行真实的事务写入 / 回滚 / 负面拒绝，并：
//!  - 断言 target 文件**真实字节**被改写 / 回滚；
//!  - 与冻结 `WriteDiffExecutor` 的 `rollback_id` 差分对照（real 与 oracle 同形）；
//!  - 证明陈旧 base_hash 被拒且 target 不动；
//!  - 证明越界写被**内核**（而非 DAC）拒绝；
//!  - 把事务步骤经 `agent_runtime` 真 run loop 端到端驱动到 Completed / Denied。
#![cfg(target_os = "linux")]

use agent_runtime::{AgentRuntime, RunState, StepConfiner, StepOutcome};
use security_execution::policy::CapabilityLease;
use security_execution::rollback::{content_hash, WriteDiffExecutor, WriteRequest};
use security_execution_linux::{LinuxEnforcer, RollbackObservation, WriteDiffOutcome};
use runtime_contracts::RiskClass;

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

/// 每个测试一个唯一工作目录（含 pid + 纳秒），避免并发互扰。
fn work_dir(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aios_wd_{tag}_{}_{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create work dir");
    dir
}

fn s(p: &std::path::Path) -> &str {
    p.to_str().unwrap()
}

/// 受限沙箱内真实写入：target 的真实字节必须从 "port=80\n" 改写为 "port=8080\n"。
#[test]
fn write_diff_changes_real_file_bytes() {
    let wd = work_dir("changes");
    let target = wd.join("target.conf");
    std::fs::write(&target, "port=80\n").expect("seed target");
    let shadow = wd.join("shadow");
    let out = wd.join("out.json");
    let base = content_hash("port=80\n");

    let outcome = LinuxEnforcer::new()
        .run_write_diff(
            helper(),
            s(&out),
            s(&shadow),
            s(&target),
            "port=8080\n",
            &base,
            "param-hash",
        )
        .expect("write.diff runs inside the confined sandbox");

    assert!(
        matches!(outcome, WriteDiffOutcome::Committed(_)),
        "in-scope write must commit, got {outcome:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        "port=8080\n",
        "the real target bytes must be rewritten inside the sandbox"
    );
}

/// 差分对照：同一输入下，冻结 `WriteDiffExecutor::prepare` 的 rollback_id 必须等于
/// 真 `run_write_diff` 返回的 rollback_id（证明 real 与 oracle 同形）。
#[test]
fn differential_oracle_parity() {
    let wd = work_dir("parity");
    let target = wd.join("target.conf");
    std::fs::write(&target, "port=80\n").expect("seed target");
    let base = content_hash("port=80\n");

    // 冻结 oracle：prepare 计算 rollback_id（prepare 不改 target）。
    let lease = CapabilityLease {
        lease_id: "lease-fs.write.diff".to_string(),
        actor: "operator".to_string(),
        tool: "fs.write.diff".to_string(),
        resource: s(&target).to_string(),
        parameter_hash: "param-hash".to_string(),
        expires_at: 60,
        policy_version: "policy-v1".to_string(),
        risk: RiskClass::WriteWithDiff,
    };
    let request = WriteRequest {
        run_id: "run-write".to_string(),
        step_id: "step-write".to_string(),
        actor: "operator".to_string(),
        target_path: target.clone(),
        proposed_content: "port=8080\n".to_string(),
        base_hash: base.clone(),
    };
    let oracle = WriteDiffExecutor::new(wd.join("oracle_shadow"));
    let prepared = oracle.prepare(&lease, request).expect("oracle prepare");
    let oracle_id = prepared.handle.rollback_id.clone();

    // 真实后端：run_write_diff 返回的 rollback_id。
    let out = wd.join("out.json");
    let real = LinuxEnforcer::new()
        .run_write_diff(
            helper(),
            s(&out),
            s(&wd.join("real_shadow")),
            s(&target),
            "port=8080\n",
            &base,
            "param-hash",
        )
        .expect("write.diff runs");
    let real_id = match real {
        WriteDiffOutcome::Committed(obs) => obs.rollback_id,
        other => panic!("expected Committed, got {other:?}"),
    };

    assert_eq!(
        real_id, oracle_id,
        "real rollback_id must be identical in shape to the frozen oracle's"
    );
}

/// 陈旧 base_hash：必须 BaseHashMismatch，且 target 字节**不动**（与 oracle prepare 一致）。
#[test]
fn stale_base_hash_rejected() {
    let wd = work_dir("stale");
    let target = wd.join("target.conf");
    std::fs::write(&target, "port=80\n").expect("seed target");
    let out = wd.join("out.json");

    let outcome = LinuxEnforcer::new()
        .run_write_diff(
            helper(),
            s(&out),
            s(&wd.join("shadow")),
            s(&target),
            "port=8080\n",
            "stale-deadbeef",
            "param-hash",
        )
        .expect("write.diff runs");

    assert!(
        matches!(outcome, WriteDiffOutcome::BaseHashMismatch { .. }),
        "stale base hash must be rejected, got {outcome:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        "port=80\n",
        "target must be untouched on base mismatch"
    );
}

/// 回滚恢复原字节：先 Committed 写成 "port=8080\n"，再回滚到原 "port=80\n"。
#[test]
fn rollback_restores_original_bytes() {
    let wd = work_dir("rollback");
    let target = wd.join("target.conf");
    std::fs::write(&target, "port=80\n").expect("seed target");
    let shadow = wd.join("shadow");
    let base = content_hash("port=80\n");
    let enf = LinuxEnforcer::new();

    let committed = enf
        .run_write_diff(
            helper(),
            s(&wd.join("out_diff.json")),
            s(&shadow),
            s(&target),
            "port=8080\n",
            &base,
            "param-hash",
        )
        .expect("write.diff runs");
    let rollback_id = match committed {
        WriteDiffOutcome::Committed(obs) => obs.rollback_id,
        other => panic!("expected Committed, got {other:?}"),
    };
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        "port=8080\n"
    );

    let rolled: RollbackObservation = enf
        .run_rollback(
            helper(),
            s(&wd.join("out_rb.json")),
            s(&target),
            s(&shadow),
            &rollback_id,
            &base,
        )
        .expect("rollback runs inside the confined sandbox");

    assert!(rolled.restored, "rollback must restore to base_hash");
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        "port=80\n",
        "the real target bytes must be restored to the original"
    );
}

/// 越界写被**内核**（Landlock EACCES）而非 DAC 拒绝：先确认无沙箱时 DAC 可写该路径，
/// 再在只授权 `granted` 的沙箱内写 `forbidden`，必须 KernelDenied。
#[test]
fn write_outside_landlock_denied() {
    let granted = work_dir("granted");
    let forbidden_dir = work_dir("forbidden");
    let forbidden = forbidden_dir.join("escape.txt");

    // 基线：无沙箱时该路径 DAC 可写（排除 EACCES 误判）。
    std::fs::write(&forbidden, b"baseline").expect("forbidden path is DAC-writable without sandbox");
    std::fs::remove_file(&forbidden).expect("clean baseline file");

    let out = granted.join("out.json");
    let outcome = LinuxEnforcer::new()
        .run_write_denied(
            helper(),
            s(&out),
            s(&granted),
            s(&forbidden),
            "pwned",
        )
        .expect("write.denied runs");

    assert!(
        matches!(
            outcome,
            security_execution_linux::EnforcementOutcome::KernelDenied { .. }
        ),
        "kernel (Landlock) must deny the out-of-scope write, got {outcome:?}"
    );
    assert!(
        !forbidden.exists(),
        "denied write must not have created the forbidden file"
    );
}

/// 把真实 write.diff 事务接到 run loop：Committed => Confined，其余 => KernelDenied。
struct WriteDiffConfiner {
    out: String,
    shadow: String,
    target: String,
    proposed: String,
    base_hash: String,
    parameter_hash: String,
}

impl StepConfiner for WriteDiffConfiner {
    fn confine(&self, _step_id: &str) -> std::io::Result<StepOutcome> {
        match LinuxEnforcer::new().run_write_diff(
            helper(),
            &self.out,
            &self.shadow,
            &self.target,
            &self.proposed,
            &self.base_hash,
            &self.parameter_hash,
        )? {
            WriteDiffOutcome::Committed(_) => Ok(StepOutcome::Confined),
            other => Ok(StepOutcome::KernelDenied {
                reason: format!("write.diff not committed: {other:?}"),
            }),
        }
    }
}

/// cp3 端到端：真 run loop 经 `WriteDiffConfiner` 跑一次真事务写 => Completed，
/// 且状态纯从 append-only 日志重建一致。
#[test]
fn run_loop_completes_write_diff_step() {
    let wd = work_dir("loop_ok");
    let target = wd.join("target.conf");
    std::fs::write(&target, "port=80\n").expect("seed target");
    let confiner = WriteDiffConfiner {
        out: s(&wd.join("out.json")).to_string(),
        shadow: s(&wd.join("shadow")).to_string(),
        target: s(&target).to_string(),
        proposed: "port=8080\n".to_string(),
        base_hash: content_hash("port=80\n"),
        parameter_hash: "param-hash".to_string(),
    };
    let mut rt = AgentRuntime::new();
    let state = rt.run_step("operator", "write-diff-1", &confiner);

    assert_eq!(state, RunState::Completed, "real write.diff step must complete");
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        "port=8080\n"
    );
    assert_eq!(
        AgentRuntime::rehydrate(rt.events()),
        RunState::Completed,
        "run state must rebuild purely from the append-only log"
    );
}

/// run loop 因陈旧 base 被拒：BaseHashMismatch => KernelDenied => run loop Denied。
#[test]
fn run_loop_denied_on_stale_base() {
    let wd = work_dir("loop_stale");
    let target = wd.join("target.conf");
    std::fs::write(&target, "port=80\n").expect("seed target");
    let confiner = WriteDiffConfiner {
        out: s(&wd.join("out.json")).to_string(),
        shadow: s(&wd.join("shadow")).to_string(),
        target: s(&target).to_string(),
        proposed: "port=8080\n".to_string(),
        base_hash: "stale-deadbeef".to_string(),
        parameter_hash: "param-hash".to_string(),
    };
    let mut rt = AgentRuntime::new();
    assert_eq!(
        rt.run_step("operator", "write-diff-1", &confiner),
        RunState::Denied,
        "stale base must drive the run loop to Denied"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        "port=80\n",
        "target must be untouched when the step is denied"
    );
}
