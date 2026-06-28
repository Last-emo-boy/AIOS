//! 真实工具端到端集成测试（ADR-004 cp5/cp3）。
//!
//! 与 `confined_executor.rs` 的合成向量不同，这里在**完整受限沙箱**内运行两个**真实
//! 工具**并校验回传的**真实观测**：
//!  - `fs.read <path>`：Landlock 限定到文件父目录 + seccomp default-deny 下真实读取
//!    文件字节，观测的字节长度必须等于宿主侧真实长度。
//!  - `svc.status <pid>`：受限沙箱内读 `/proc/<pid>/comm`，对 `std::process::id()`
//!    必须报告存活且 comm 非空。
//! 并把其中一个工具经 `agent_runtime` 真 run loop 端到端驱动到 `Completed`。
#![cfg(target_os = "linux")]

use agent_runtime::{AgentRuntime, RunState, StepConfiner, StepOutcome};
use security_execution_linux::LinuxEnforcer;

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

/// 每个测试用独立 (target, out) 临时文件，避免并发互扰。
fn temp_path(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aios_{tag}_{}_{nanos}", std::process::id()))
}

/// fs.read：受限沙箱内真实读取一个临时文件，回传的字节长度 == 真实长度，
/// 首行哈希为稳定的 16 位十六进制（非全零占位）。
#[test]
fn fs_read_reports_real_byte_length() {
    let target = temp_path("fsread_in");
    let out = temp_path("fsread_out");
    let content = b"first line of real content\nsecond line\nthird";
    std::fs::write(&target, content).expect("write target");

    let enf = LinuxEnforcer::new();
    let obs = enf
        .run_fs_read(helper(), out.to_str().unwrap(), target.to_str().unwrap())
        .expect("fs.read runs inside the confined sandbox");

    std::fs::remove_file(&target).ok();
    std::fs::remove_file(&out).ok();

    assert!(obs.ok, "fs.read must succeed reading an in-scope file");
    assert_eq!(
        obs.len,
        content.len(),
        "observed byte length must equal the real file length"
    );
    assert_eq!(obs.first_line_hash.len(), 16, "hash is 16 hex chars");
    assert_ne!(
        obs.first_line_hash, "0000000000000000",
        "non-empty first line must hash to a non-placeholder value"
    );
}

/// fs.read 哈希可复现：同一首行 → 同一哈希（固定种子，跨进程稳定）。
#[test]
fn fs_read_hash_is_deterministic_for_same_first_line() {
    let enf = LinuxEnforcer::new();
    let mk = |body: &[u8], tag: &str| {
        let target = temp_path(tag);
        let out = temp_path(&format!("{tag}_out"));
        std::fs::write(&target, body).unwrap();
        let obs = enf
            .run_fs_read(helper(), out.to_str().unwrap(), target.to_str().unwrap())
            .expect("fs.read runs");
        std::fs::remove_file(&target).ok();
        std::fs::remove_file(&out).ok();
        obs
    };
    // 相同首行、不同后续行 → 首行哈希一致、长度不同。
    let a = mk(b"shared header\nbody A", "hdrA");
    let b = mk(b"shared header\nbody BBBB", "hdrB");
    assert_eq!(a.first_line_hash, b.first_line_hash, "same first line → same hash");
    assert_ne!(a.len, b.len, "different bodies → different total length");
}

/// svc.status：受限沙箱内探测**自身**进程，必须报告存活且 comm 非空。
#[test]
fn svc_status_reports_self_alive() {
    let out = temp_path("svc_out");
    let me = std::process::id() as i32;

    let obs = LinuxEnforcer::new()
        .run_svc_status(helper(), out.to_str().unwrap(), me)
        .expect("svc.status runs inside the confined sandbox");

    std::fs::remove_file(&out).ok();

    assert!(obs.alive, "the running test process must be reported alive");
    assert!(
        !obs.comm.is_empty(),
        "alive process must have a non-empty comm, got {:?}",
        obs.comm
    );
}

/// svc.status：探测一个几乎必定不存在的 pid，应报告不存活（真实 /proc 缺失）。
#[test]
fn svc_status_reports_dead_pid() {
    let out = temp_path("svc_dead_out");
    // 选一个内核 pid 上限以内、几乎不可能存活的高位 pid。
    let dead = 0x3fff_fffe;

    let obs = LinuxEnforcer::new()
        .run_svc_status(helper(), out.to_str().unwrap(), dead)
        .expect("svc.status runs even for a missing pid");

    std::fs::remove_file(&out).ok();

    assert!(!obs.alive, "non-existent pid must be reported not alive");
    assert!(obs.comm.is_empty(), "dead pid has empty comm");
}

/// 把一步接到真实 `fs.read` 工具：沙箱内成功读到文件 => `StepOutcome::Confined`。
struct FsReadConfiner {
    out: String,
    file: String,
}

impl StepConfiner for FsReadConfiner {
    fn confine(&self, _step_id: &str) -> std::io::Result<StepOutcome> {
        let obs = LinuxEnforcer::new().run_fs_read(helper(), &self.out, &self.file)?;
        if obs.ok {
            Ok(StepOutcome::Confined)
        } else {
            Ok(StepOutcome::KernelDenied {
                reason: "fs.read denied/failed inside sandbox".into(),
            })
        }
    }
}

/// cp3 端到端：真 run loop 经 `FsReadConfiner` 在真沙箱里跑一次 fs.read 步骤 →
/// 内核放行 → run loop `Completed`，且状态纯从 append-only 日志重建一致。
#[test]
fn run_loop_completes_real_fs_read_step() {
    let target = temp_path("loop_in");
    let out = temp_path("loop_out");
    std::fs::write(&target, b"run-loop driven real tool read\n").expect("write target");

    let confiner = FsReadConfiner {
        out: out.to_str().unwrap().to_string(),
        file: target.to_str().unwrap().to_string(),
    };
    let mut rt = AgentRuntime::new();
    let state = rt.run_step("operator", "fs-read-1", &confiner);

    std::fs::remove_file(&target).ok();
    std::fs::remove_file(&out).ok();

    assert_eq!(state, RunState::Completed, "real fs.read step must complete");
    assert_eq!(
        AgentRuntime::rehydrate(rt.events()),
        RunState::Completed,
        "run state must rebuild purely from the append-only log"
    );
}
