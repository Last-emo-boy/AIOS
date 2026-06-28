//! sandbox_probe —— 受沙箱约束的 execve 探针（ADR-004 cp5）。
//!
//! 由 `platform_sys::spawn_and_wait` 以 `fork`+`execve` 启动，在一个全新的、
//! 单线程的程序映像里 apply 沙箱、再执行探针动作，并以退出码/信号回传结果。
//! 这避免了在多线程进程 fork 出的子进程里运行可能分配的库代码（ADR-004 D1）。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn open_code(target: &str) -> i32 {
    match std::fs::File::open(target) {
        Ok(_) => 0,
        Err(e) => match e.raw_os_error() {
            Some(c) if c == libc::EACCES => 10,
            Some(c) if c == libc::ENOENT => 11,
            _ => 12,
        },
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        // 无沙箱基线：证明同 uid 本可读该文件（排除 DAC-EACCES / ENOENT 误判）。
        "baseline-open" => {
            let target = args.get(2).map(String::as_str).unwrap_or("");
            platform_sys::exit_now(open_code(target));
        }
        // Landlock：仅授权读 allowed_dir，再尝试 open target。fail-closed：未
        // FullyEnforced → 退出码 20（调用方据此硬失败）。
        "landlock-open" => {
            let allowed = args.get(2).map(String::as_str).unwrap_or("");
            let target = args.get(3).map(String::as_str).unwrap_or("");
            match platform_sys::apply_landlock_readonly(allowed) {
                Ok(true) => {}
                Ok(false) => platform_sys::exit_now(20),
                Err(_) => platform_sys::exit_now(22),
            }
            platform_sys::exit_now(open_code(target));
        }
        // seccomp default-deny allowlist（不含 getpid）：调 getpid 应被内核 SIGSYS 杀。
        "seccomp-deny-getpid" => {
            if platform_sys::apply_seccomp_allowlist(&[libc::SYS_exit_group, libc::SYS_exit])
                .is_err()
            {
                platform_sys::exit_now(21);
            }
            let _ = platform_sys::getpid(); // 不在 allowlist → KillProcess，不返回
            platform_sys::exit_now(0); // 到达=未强制
        }
        // 通用 seccomp 探针：allow_csv = 逗号分隔的 syscall 号（来自冻结 profile 编译），
        // sel = 要触发的 syscall。自动追加 exit/exit_group，否则 helper 自身 _exit 会被 SIGSYS。
        "seccomp-probe" => {
            let allow_csv = args.get(2).map(String::as_str).unwrap_or("");
            let sel = args.get(3).map(String::as_str).unwrap_or("");
            let mut allow: Vec<i64> = allow_csv
                .split(',')
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse::<i64>().ok())
                .collect();
            allow.push(libc::SYS_exit_group as i64);
            allow.push(libc::SYS_exit as i64);
            if platform_sys::apply_seccomp_allowlist(&allow).is_err() {
                platform_sys::exit_now(21);
            }
            match sel {
                "getpid" => {
                    let _ = platform_sys::getpid(); // 不在 allowlist → SIGSYS
                }
                _ => platform_sys::exit_now(2),
            }
            platform_sys::exit_now(0); // 到达 = sel 在 allowlist（放行）
        }
        // seccomp allowlist 含 getpid：调 getpid 应放行 → 正常退出 0（证明选择性）。
        "seccomp-allow-getpid" => {
            if platform_sys::apply_seccomp_allowlist(&[
                libc::SYS_getpid,
                libc::SYS_exit_group,
                libc::SYS_exit,
            ])
            .is_err()
            {
                platform_sys::exit_now(21);
            }
            let _ = platform_sys::getpid();
            platform_sys::exit_now(0);
        }
        _ => platform_sys::exit_now(2),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
