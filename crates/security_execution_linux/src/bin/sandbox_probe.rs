//! sandbox_probe —— 受沙箱约束的 execve 探针（ADR-004 cp5）。
//!
//! 由 `platform_sys::spawn_and_wait` 以 `fork`+`execve` 启动，在一个全新的、
//! 单线程的程序映像里 apply 沙箱、再执行探针动作，并以退出码/信号回传结果。
//! 全新单线程映像保证 namespace `unshare(CLONE_NEWUSER)` 不会 EINVAL，且 fork 出
//! 的子进程可安全分配（landlock/seccomp 库代码）。
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
fn arg(args: &[String], i: usize) -> &str {
    args.get(i).map(String::as_str).unwrap_or("")
}

/// 完整受限执行器序列（ADR-004 cp5 设计的正确施加顺序）。
#[cfg(target_os = "linux")]
fn run_confined(args: &[String]) -> ! {
    use platform_sys::{clone_flags as cf, ChildExit, ForkResult};

    let ns = arg(args, 2); // {user,mount,pid,net} 子集
    let seccomp_csv = arg(args, 3); // 号 csv，"" 跳过
    let landlock_dir = arg(args, 4); // 单目录，"" 跳过
    let vector = arg(args, 5); // {getpid, open, fork}
    let varg = arg(args, 6);
    let want = |k: &str| ns.split(',').any(|x| x == k);

    // ===== STAGE A：helper 主进程（execve 后单线程）=====
    if want("user") {
        // 在 unshare 之前取外层 uid/gid（unshare 之后 getuid 返回未映射的 overflow id）。
        let uid = platform_sys::getuid();
        let gid = platform_sys::getgid();
        // 1. 进入新 user namespace（获得其中的全 capability）。
        if platform_sys::unshare(cf::CLONE_NEWUSER).is_err() {
            platform_sys::exit_now(23);
        }
        // 2. setgroups=deny：best-effort。外层是 root（有 CAP_SETGID），写 gid_map
        //    不强制要求 deny；且某些（嵌套 userns）环境已锁定该文件。失败不致命。
        let _ = std::fs::write("/proc/self/setgroups", "deny");
        // 3. 写 uid/gid_map：内层 0 映射到外层真实 uid/gid。
        if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err()
            || std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_err()
        {
            platform_sys::exit_now(25);
        }
    }
    // 3. 其余 namespace（CLONE_NEWPID 仅令下一个 fork 的子进程成为 PID 1）。
    let mut nsflags = 0;
    if want("mount") {
        nsflags |= cf::CLONE_NEWNS;
    }
    if want("pid") {
        nsflags |= cf::CLONE_NEWPID;
    }
    if want("net") {
        nsflags |= cf::CLONE_NEWNET;
    }
    if nsflags != 0 && platform_sys::unshare(nsflags).is_err() {
        platform_sys::exit_now(23);
    }
    // 4. 新 mountns 后必须把 / 设为递归私有，否则 /proc 挂载 EINVAL / 泄漏回宿主。
    if want("mount") && platform_sys::make_root_private().is_err() {
        platform_sys::exit_now(24);
    }

    // ===== STAGE B：fork，child 是新 pidns 的 PID 1 =====
    match platform_sys::fork() {
        Err(_) => platform_sys::exit_now(26),
        // ===== STAGE C：parent 等待并把 child 信号上浮 =====
        Ok(ForkResult::Parent(pid)) => match platform_sys::wait_child(pid) {
            Ok(ChildExit::Exited(c)) => platform_sys::exit_now(c),
            Ok(ChildExit::KilledBySignal(s)) => platform_sys::reraise(s),
            Err(_) => platform_sys::exit_now(40),
        },
        Ok(ForkResult::Child) => {
            // child：在新 pidns 内挂载自己的 /proc（procfs 反映挂载者 pidns）。
            if want("mount") && platform_sys::mount_proc("/proc").is_err() {
                platform_sys::exit_now(24);
            }
            if platform_sys::set_no_new_privs().is_err() {
                platform_sys::exit_now(27);
            }
            // Landlock 在 seccomp 之前（其 syscall 不在 allowlist）。fail-closed。
            if !landlock_dir.is_empty() {
                match platform_sys::apply_landlock_readonly(landlock_dir) {
                    Ok(true) => {}
                    Ok(false) => platform_sys::exit_now(20),
                    Err(_) => platform_sys::exit_now(22),
                }
            }
            // seccomp **最后**：default-deny allowlist（自动含 exit/exit_group）。
            if !seccomp_csv.is_empty() {
                let mut allow: Vec<i64> = seccomp_csv
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse::<i64>().ok())
                    .collect();
                allow.push(libc::SYS_exit_group as i64);
                allow.push(libc::SYS_exit as i64);
                if platform_sys::apply_seccomp_allowlist(&allow).is_err() {
                    platform_sys::exit_now(21);
                }
            }
            // ===== 探针向量 =====
            match vector {
                "getpid" => {
                    let _ = platform_sys::getpid(); // 不在 allowlist → SIGSYS
                    platform_sys::exit_now(0); // 到达 = 放行
                }
                "open" => platform_sys::exit_now(open_code(varg)),
                "fork" => {
                    // pidns 身份：child 在新 pidns 应是 PID 1。
                    let inner = platform_sys::getpid();
                    platform_sys::exit_now(if inner == 1 { 0 } else { 50 });
                }
                _ => platform_sys::exit_now(2),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        // 完整受限执行器（namespace + landlock + seccomp 全栈）。
        "confined" => run_confined(&args),

        // 无沙箱基线：证明同 uid 本可读该文件（排除 DAC-EACCES / ENOENT 误判）。
        "baseline-open" => {
            let target = arg(&args, 2);
            platform_sys::exit_now(open_code(target));
        }
        // Landlock 单目录探针（fail-closed）。
        "landlock-open" => {
            let allowed = arg(&args, 2);
            let target = arg(&args, 3);
            match platform_sys::apply_landlock_readonly(allowed) {
                Ok(true) => {}
                Ok(false) => platform_sys::exit_now(20),
                Err(_) => platform_sys::exit_now(22),
            }
            platform_sys::exit_now(open_code(target));
        }
        // 通用 seccomp 探针：allow_csv = syscall 号；sel = 触发的 syscall。
        "seccomp-probe" => {
            let allow_csv = arg(&args, 2);
            let sel = arg(&args, 3);
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
                    let _ = platform_sys::getpid();
                }
                _ => platform_sys::exit_now(2),
            }
            platform_sys::exit_now(0);
        }
        // seccomp default-deny（不含 getpid）：getpid 应被 SIGSYS。
        "seccomp-deny-getpid" => {
            if platform_sys::apply_seccomp_allowlist(&[libc::SYS_exit_group, libc::SYS_exit])
                .is_err()
            {
                platform_sys::exit_now(21);
            }
            let _ = platform_sys::getpid();
            platform_sys::exit_now(0);
        }
        // seccomp allowlist 含 getpid：放行 → 退出 0。
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
