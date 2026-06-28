//! 不可信内容流水线真内核集成测试（ADR-000 第三 MVP「不可信内容处理」/ Part A）。
//!
//! 经 execve-based confined helper（`sandbox_probe tool-content-pipeline`）证明：外部/模型
//! 来源 blob 在完整受限沙箱（user/mount/pid/net ns + Landlock 限定到 input 父目录 +
//! seccomp default-deny）内被真实净化（中和 shell metachar / 丢弃控制字符 / 红action secret），
//! 产出带冻结 `TrustBoundary::SanitizedSummary` 标签的净化摘要 + 稳定哈希。
//! 反假绿：fail-closed（secret 净化后存活 => helper exit 85 => 父进程硬 Err）；
//! 结构性证明 `tool_seccomp_syscalls()` 不含 socket/connect/clone/execve（net/exec 在沙箱内结构性死）。
#![cfg(target_os = "linux")]

use security_execution_linux::LinuxEnforcer;
use std::sync::atomic::{AtomicU64, Ordering};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// 把 blob 写入唯一私有临时目录，返回 (dir, input_path, out_path)。
fn scratch(blob: &[u8]) -> (std::path::PathBuf, String, String) {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("aios_cp_{}_{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let input = dir.join("blob.bin");
    std::fs::write(&input, blob).expect("write blob");
    let out = dir.join("out.json");
    (
        dir.clone(),
        input.to_str().unwrap().to_string(),
        out.to_str().unwrap().to_string(),
    )
}

/// 危险 + secret blob：含 shell 注入（反引号 `rm -rf /`、`&&`、`$`、`>`）、控制字节、
/// 以及 `password=hunter2` secret token。净化后 removed_dangerous=true、contained_secret=true，
/// trust=SanitizedSummary；Ok(..) 本身即证明净化后 `contains_secret_value` 为假
/// （否则 helper fail-closed exit 85 => `run_content_pipeline` 返回 Err）。
#[test]
fn dangerous_secret_blob_sanitized_with_kernel_proof() {
    let blob = b"hello `rm -rf /` && echo $HOME > out\x07\x01 password=hunter2 done";
    let (dir, input, out) = scratch(blob);
    let obs = LinuxEnforcer::new()
        .run_content_pipeline(helper(), &out, &input)
        .expect("content pipeline must run and pass fail-closed secret check");
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(
        obs.trust, "sanitized-summary",
        "trust label must be the SanitizedSummary boundary (frozen-validated)"
    );
    assert!(
        obs.removed_dangerous,
        "shell metachars / control bytes / secret token must be neutralized"
    );
    assert!(
        obs.contained_secret,
        "raw blob did contain a secret-like token (detected pre-sanitization)"
    );
    assert!(
        obs.sanitized_len > 0,
        "a non-empty sanitized summary must remain after neutralization"
    );
}

/// 良性 blob：无 metachar / 无控制字符 / 无 secret => removed_dangerous=false、
/// contained_secret=false，trust 仍是 SanitizedSummary（每条外部内容都走净化边界）。
#[test]
fn benign_blob_passes_through_as_sanitized_summary() {
    let blob = b"the quick brown fox jumps over the lazy dog and reads a report";
    let (dir, input, out) = scratch(blob);
    let obs = LinuxEnforcer::new()
        .run_content_pipeline(helper(), &out, &input)
        .expect("content pipeline runs");
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(obs.trust, "sanitized-summary");
    assert!(
        !obs.removed_dangerous,
        "benign content must not trigger any neutralization"
    );
    assert!(!obs.contained_secret, "benign content has no secret token");
}

/// 确定性：同一 blob 两次净化 => 同一 summary_hash（固定种子 DefaultHasher，可跨进程复现）。
#[test]
fn sanitization_is_deterministic() {
    let blob = b"deterministic content with `danger;rm` and password=zzz markers";

    let (d1, i1, o1) = scratch(blob);
    let h1 = LinuxEnforcer::new()
        .run_content_pipeline(helper(), &o1, &i1)
        .expect("pipeline 1")
        .summary_hash;
    std::fs::remove_dir_all(&d1).ok();

    let (d2, i2, o2) = scratch(blob);
    let h2 = LinuxEnforcer::new()
        .run_content_pipeline(helper(), &o2, &i2)
        .expect("pipeline 2")
        .summary_hash;
    std::fs::remove_dir_all(&d2).ok();

    assert_eq!(h1, h2, "same blob must yield the same summary hash");
}

/// 结构性反假绿：受限工具 seccomp allowlist（**单一真相源**，content.pipeline 等共用）
/// 不含 socket/connect/clone/execve —— 这正是「沙箱内 net/exec 结构性死」的权威证明；
/// 同时含 read/write，证明 allowlist 非空、强制是选择性的（非无脑全拒）。
#[cfg(target_arch = "x86_64")]
#[test]
fn tool_seccomp_allowlist_excludes_net_and_exec() {
    for forbidden in ["socket", "connect", "clone", "clone3", "execve", "execveat"] {
        assert!(
            !security_execution_linux::tool_seccomp_allows_syscall(forbidden),
            "{forbidden} must NOT be in the tool seccomp allowlist (net/exec structurally dead)"
        );
    }
    for allowed in ["read", "write", "openat"] {
        assert!(
            security_execution_linux::tool_seccomp_allows_syscall(allowed),
            "{allowed} must be allowlisted (allowlist is non-empty; enforcement is selective)"
        );
    }
}
