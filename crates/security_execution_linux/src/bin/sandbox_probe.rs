//! sandbox_probe —— 受沙箱约束的 execve 探针（ADR-004 cp5）。
//!
//! 由 `platform_sys::spawn_and_wait` 以 `fork`+`execve` 启动，在一个全新的、
//! 单线程的程序映像里 apply 沙箱、再执行探针动作，并以退出码/信号回传结果。
//! 全新单线程映像保证 namespace `unshare(CLONE_NEWUSER)` 不会 EINVAL，且 fork 出
//! 的子进程可安全分配（landlock/seccomp 库代码）。
#![forbid(unsafe_code)]

// 冻结 oracle 的稳定内容哈希：真 write-with-diff 的事务比对与 oracle 同形（同一函数）。
#[cfg(target_os = "linux")]
use security_execution::rollback::content_hash;

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

/// 施加完整受限执行栈（ADR-004 cp5 的正确顺序），**仅在受限 child 中返回**。
///
/// STAGE A（helper 主进程，execve 后单线程）：user ns→uid/gid_map→其余 ns→make
/// root private。STAGE B：fork；parent 等待并把 child 退出码/信号上浮（永不返回，
/// 经 exit_now/reraise 发散）；child 挂载自己的 /proc→no_new_privs→Landlock→seccomp
/// （**最后**，default-deny）。child 分支落空 return，把控制权交回调用者（合成向量
/// 或真实工具）在完整沙箱内运行真实动作。
#[cfg(target_os = "linux")]
fn enter_confined(ns: &str, seccomp_csv: &str, landlock_dir: &str) {
    use platform_sys::{clone_flags as cf, ChildExit, ForkResult};
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
            // child 分支落空：控制权交回调用者，在完整沙箱内运行真实动作。
        }
    }
}

/// 与 [`enter_confined`] 完全同序的读写版：唯一区别是 child 里用
/// [`platform_sys::apply_landlock`]（read+write 并集授权）替换 `apply_landlock_readonly`，
/// 以便在受限沙箱内同时读写 `reads`/`writes` 覆盖的目录（真 write-with-diff）。
/// 其余（user ns→uid/gid_map→其余 ns→make_root_private→fork→parent reraise→child
/// mount_proc→no_new_privs→seccomp LAST）逐字一致。仅在受限 child 中返回。
#[cfg(target_os = "linux")]
fn enter_confined_rw(ns: &str, seccomp_csv: &str, reads: &[&str], writes: &[&str]) {
    use platform_sys::{clone_flags as cf, ChildExit, ForkResult};
    let want = |k: &str| ns.split(',').any(|x| x == k);

    // ===== STAGE A：helper 主进程（execve 后单线程）=====
    if want("user") {
        let uid = platform_sys::getuid();
        let gid = platform_sys::getgid();
        if platform_sys::unshare(cf::CLONE_NEWUSER).is_err() {
            platform_sys::exit_now(23);
        }
        let _ = std::fs::write("/proc/self/setgroups", "deny");
        if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err()
            || std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_err()
        {
            platform_sys::exit_now(25);
        }
    }
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
    if want("mount") && platform_sys::make_root_private().is_err() {
        platform_sys::exit_now(24);
    }

    // ===== STAGE B：fork，child 是新 pidns 的 PID 1 =====
    match platform_sys::fork() {
        Err(_) => platform_sys::exit_now(26),
        Ok(ForkResult::Parent(pid)) => match platform_sys::wait_child(pid) {
            Ok(ChildExit::Exited(c)) => platform_sys::exit_now(c),
            Ok(ChildExit::KilledBySignal(s)) => platform_sys::reraise(s),
            Err(_) => platform_sys::exit_now(40),
        },
        Ok(ForkResult::Child) => {
            if want("mount") && platform_sys::mount_proc("/proc").is_err() {
                platform_sys::exit_now(24);
            }
            if platform_sys::set_no_new_privs().is_err() {
                platform_sys::exit_now(27);
            }
            // Landlock read+write 并集授权（fail-closed）。在 seccomp 之前。
            match platform_sys::apply_landlock(reads, writes) {
                Ok(true) => {}
                Ok(false) => platform_sys::exit_now(20),
                Err(_) => platform_sys::exit_now(22),
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
            // child 分支落空：控制权交回调用者，在完整沙箱内运行真实事务。
        }
    }
}

/// 完整受限执行器序列（ADR-004 cp5）：施加沙箱后运行一个**合成探针向量**。
#[cfg(target_os = "linux")]
fn run_confined(args: &[String]) -> ! {
    let ns = arg(args, 2); // {user,mount,pid,net} 子集
    let seccomp_csv = arg(args, 3); // 号 csv，"" 跳过
    let landlock_dir = arg(args, 4); // 单目录，"" 跳过
    let vector = arg(args, 5); // {getpid, open, fork}
    let varg = arg(args, 6);

    enter_confined(ns, seccomp_csv, landlock_dir);

    // ===== 仅受限 child 到达此处：合成探针向量 =====
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

/// 工具用固定 seccomp allowlist（号 csv）：default-deny 下放行真实文件 I/O 所需
/// syscall（open/read/write/stat/mmap 等），其余仍被内核 SIGSYS。覆盖 glibc 读
/// 一个文件 + 写观测文件所需集合（在本 KVM VM kernel 6.12 + glibc 上实测足够）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn tool_seccomp_csv() -> String {
    let nums: [libc::c_long; 27] = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_getrandom,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_getdents64,
        libc::SYS_clock_gettime,
        libc::SYS_getpid,
        libc::SYS_close_range,
    ];
    nums.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn tool_seccomp_csv() -> String {
    String::new()
}

/// 把观测 JSON 写入 `out`（已在沙箱施加**之前**打开的 fd —— Landlock 仅在 open 时
/// 校验路径，已打开的 fd 不受其约束；故工具产物经此 fd 真实回传给 parent）。
#[cfg(target_os = "linux")]
fn write_observation(out: std::fs::File, json: &str) -> ! {
    write_observation_code(out, json, 0)
}

/// 同 [`write_observation`]，但以指定退出码发散（真 write-with-diff 用 exit 码区分
/// committed=0 / rollback-pending=82 / base-mismatch=81，且这些路径都需先回传观测 JSON）。
#[cfg(target_os = "linux")]
fn write_observation_code(mut out: std::fs::File, json: &str, code: i32) -> ! {
    use std::io::Write;
    if out.write_all(json.as_bytes()).is_err() {
        platform_sys::exit_now(71);
    }
    let _ = out.flush();
    platform_sys::exit_now(code)
}

/// 工具 `fs.read <path>`：在完整受限栈（user/mount/pid/net ns + Landlock 限定到
/// **文件父目录** + seccomp default-deny）内真实读取文件字节，产出真实观测
/// （字节长度 + 首行哈希），经 `out` fd 回传。
#[cfg(target_os = "linux")]
fn run_tool_fs_read(args: &[String]) -> ! {
    use std::hash::Hasher;
    let out = arg(args, 2);
    let path = arg(args, 3);
    // Landlock 授权目录 = 文件父目录（只读授权恰好覆盖目标文件）。
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/");
    // 在施加沙箱**之前**打开观测 fd（侧信道，Landlock 之后仍可写）。
    let out_file = match std::fs::File::create(out) {
        Ok(f) => f,
        Err(_) => platform_sys::exit_now(70),
    };

    enter_confined("user,mount,pid,net", &tool_seccomp_csv(), parent);

    // ===== 仅受限 child 到达此处：在沙箱内真实读取文件 =====
    let json = match std::fs::read(path) {
        Ok(bytes) => {
            let len = bytes.len();
            let first_line: &[u8] = match bytes.iter().position(|&b| b == b'\n') {
                Some(i) => &bytes[..i],
                None => &bytes[..],
            };
            let mut h = std::collections::hash_map::DefaultHasher::new();
            h.write(first_line);
            let hash = h.finish();
            format!(
                "{{\"tool\":\"fs.read\",\"ok\":true,\"len\":{len},\"first_line_hash\":\"{hash:016x}\"}}"
            )
        }
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(-1);
            format!(
                "{{\"tool\":\"fs.read\",\"ok\":false,\"len\":0,\"first_line_hash\":\"0000000000000000\",\"errno\":{errno}}}"
            )
        }
    };
    write_observation(out_file, &json)
}

/// 工具 `svc.status <pid>`：在受限栈（user ns + Landlock 限定到 `/proc` 只读 +
/// seccomp default-deny；**不**进 pid/mount ns 以便看到宿主 pidns 的进程）内读取
/// `/proc/<pid>/comm`，产出真实观测（alive + comm），经 `out` fd 回传。
#[cfg(target_os = "linux")]
fn run_tool_svc_status(args: &[String]) -> ! {
    let out = arg(args, 2);
    let pid = arg(args, 3);
    let out_file = match std::fs::File::create(out) {
        Ok(f) => f,
        Err(_) => platform_sys::exit_now(70),
    };

    // 不进 pid/mount ns：保留宿主 /proc，才能查询宿主 pidns 里的真实进程。
    enter_confined("user", &tool_seccomp_csv(), "/proc");

    // ===== 仅受限 child 到达此处：在沙箱内探测真实进程 =====
    let comm_path = format!("/proc/{pid}/comm");
    let json = match std::fs::read_to_string(&comm_path) {
        Ok(s) => {
            // comm 只含进程名；剔除引号/反斜杠以保证 JSON 良构。
            let comm = s.trim().replace(['"', '\\'], "");
            format!("{{\"tool\":\"svc.status\",\"alive\":true,\"comm\":\"{comm}\"}}")
        }
        Err(_) => "{\"tool\":\"svc.status\",\"alive\":false,\"comm\":\"\"}".to_string(),
    };
    write_observation(out_file, &json)
}

/// 工具 `fs.write.diff`：在完整受限沙箱（user/mount/pid/net ns + Landlock 限定到 target
/// 父目录 + shadow 目录读写 + seccomp default-deny）内执行真 write-with-diff 事务：
/// 校验 base_hash → 暂存 previous → 写入 proposed → 回读校验 → 经 out fd 回传观测。
/// base mismatch 时在改动任何文件**之前** exit 81（保持冻结 oracle「prepare 不改 target」不变量）。
#[cfg(target_os = "linux")]
fn run_tool_write_diff(args: &[String]) -> ! {
    let out = arg(args, 2);
    let target = arg(args, 3);
    let base_hash = arg(args, 4);
    let proposed_path = arg(args, 5);
    let shadow_dir = arg(args, 6);

    // out fd 必须在沙箱施加**之前**打开（Landlock 仅在 open 时校验路径）。
    let out_file = match std::fs::File::create(out) {
        Ok(f) => f,
        Err(_) => platform_sys::exit_now(70),
    };
    // target 父目录与 shadow 目录都需读写：读 target / 读 shadow/proposed.txt、
    // 写 target / 写 shadow/previous.txt。两者同时出现在 reads 与 writes。
    let parent = std::path::Path::new(target)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/");
    let reads = [parent, shadow_dir];
    let writes = [parent, shadow_dir];

    enter_confined_rw("user,mount,pid,net", &tool_seccomp_csv(), &reads, &writes);

    // ===== 仅受限 child 到达此处：在沙箱内运行真实事务 =====
    let current = std::fs::read_to_string(target).unwrap_or_default();
    let actual_base = content_hash(&current);
    if actual_base != base_hash {
        // base 不匹配：不动 target，回传观测后 exit 81。
        let json = format!(
            "{{\"tool\":\"fs.write.diff\",\"committed\":false,\"base_mismatch\":true,\"base_hash\":\"{base_hash}\",\"actual_base\":\"{actual_base}\"}}"
        );
        write_observation_code(out_file, &json, 81);
    }
    let proposed = std::fs::read_to_string(proposed_path).unwrap_or_default();
    let proposed_hash = content_hash(&proposed);

    // 暂存原内容到 shadow（回滚依据）。
    let prev_path = format!("{shadow_dir}/previous.txt");
    if let Err(e) = std::fs::write(&prev_path, current.as_bytes()) {
        match e.raw_os_error() {
            Some(c) if c == libc::EACCES => platform_sys::exit_now(10),
            _ => platform_sys::exit_now(73),
        }
    }
    // 写入 proposed（O_TRUNC 由 Landlock V1 的 WriteFile 管、被允许）。
    if let Err(e) = std::fs::write(target, proposed.as_bytes()) {
        match e.raw_os_error() {
            Some(c) if c == libc::EACCES => platform_sys::exit_now(10),
            _ => platform_sys::exit_now(74),
        }
    }
    let final_content = std::fs::read_to_string(target).unwrap_or_default();
    let final_hash = content_hash(&final_content);
    let committed = final_hash == proposed_hash;
    let json = format!(
        "{{\"tool\":\"fs.write.diff\",\"committed\":{committed},\"base_hash\":\"{base_hash}\",\"proposed_hash\":\"{proposed_hash}\",\"final_hash\":\"{final_hash}\"}}"
    );
    write_observation_code(out_file, &json, if committed { 0 } else { 82 })
}

/// 工具 `fs.write.rollback`：在受限沙箱内把 shadow 暂存的 `previous.txt` 写回 target，
/// 回读校验后经 out fd 回传 `restored`（restored_hash == base_hash）。
#[cfg(target_os = "linux")]
fn run_tool_write_rollback(args: &[String]) -> ! {
    let out = arg(args, 2);
    let target = arg(args, 3);
    let shadow_dir = arg(args, 4);
    let base_hash = arg(args, 5);

    let out_file = match std::fs::File::create(out) {
        Ok(f) => f,
        Err(_) => platform_sys::exit_now(70),
    };
    let parent = std::path::Path::new(target)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/");
    let reads = [parent, shadow_dir];
    let writes = [parent, shadow_dir];

    enter_confined_rw("user,mount,pid,net", &tool_seccomp_csv(), &reads, &writes);

    // ===== 仅受限 child：把 shadow 暂存的原内容写回 target =====
    let prev_path = format!("{shadow_dir}/previous.txt");
    let previous = std::fs::read_to_string(&prev_path).unwrap_or_default();
    if let Err(e) = std::fs::write(target, previous.as_bytes()) {
        match e.raw_os_error() {
            Some(c) if c == libc::EACCES => platform_sys::exit_now(10),
            _ => platform_sys::exit_now(74),
        }
    }
    let restored = std::fs::read_to_string(target).unwrap_or_default();
    let restored_hash = content_hash(&restored);
    let json = format!(
        "{{\"tool\":\"fs.write.rollback\",\"restored\":{},\"restored_hash\":\"{restored_hash}\"}}",
        restored_hash == base_hash
    );
    write_observation(out_file, &json)
}

/// 工具 `fs.write.denied`（负面证明）：沙箱只授权 `granted` 读写，却尝试写沙箱外的
/// `forbidden`。内核应以 Landlock EACCES 拒绝（exit 10）。若写成功 = 逃逸（回传
/// escaped 观测、exit 0，对应测试应失败）。
#[cfg(target_os = "linux")]
fn run_tool_write_denied(args: &[String]) -> ! {
    let out = arg(args, 2);
    let granted = arg(args, 3);
    let forbidden = arg(args, 4);
    let content = arg(args, 5);

    let out_file = match std::fs::File::create(out) {
        Ok(f) => f,
        Err(_) => platform_sys::exit_now(70),
    };
    let reads = [granted];
    let writes = [granted];

    enter_confined_rw("user,mount,pid,net", &tool_seccomp_csv(), &reads, &writes);

    // ===== 仅受限 child：尝试写一个 Landlock 未授权的路径 =====
    match std::fs::write(forbidden, content.as_bytes()) {
        Err(e) => match e.raw_os_error() {
            Some(c) if c == libc::EACCES => platform_sys::exit_now(10), // 内核拒绝（期望）
            _ => platform_sys::exit_now(74),
        },
        Ok(()) => {
            // 写成功 = 沙箱逃逸（测试应失败）。
            write_observation(out_file, "{\"tool\":\"fs.write.denied\",\"escaped\":true}")
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

        // 真实工具：在完整受限沙箱内执行并把真实观测写入 out 文件（侧信道）。
        "tool-fs-read" => run_tool_fs_read(&args),
        "tool-svc-status" => run_tool_svc_status(&args),

        // 真 write-with-diff：受限沙箱内事务写、回滚、负面拒绝证明。
        "tool-write-diff" => run_tool_write_diff(&args),
        "tool-write-rollback" => run_tool_write_rollback(&args),
        "tool-write-denied" => run_tool_write_denied(&args),

        // cgroup v2 pids.max 探针：加入测试预设的 cgroup（其 pids.max 已设），连续
        // fork；子进程立即退出成 zombie 占用 pids 配额（直到 reap），超额时内核 EAGAIN。
        "cgroup-pids" => {
            use platform_sys::ForkResult;
            let cg = arg(&args, 2);
            let n: i32 = arg(&args, 3).parse().unwrap_or(0);
            if std::fs::write(
                format!("{cg}/cgroup.procs"),
                platform_sys::getpid().to_string(),
            )
            .is_err()
            {
                platform_sys::exit_now(28);
            }
            let mut kids = Vec::new();
            let mut denied = false;
            for _ in 0..n {
                match platform_sys::fork() {
                    Ok(ForkResult::Child) => platform_sys::exit_now(0), // zombie 占配额
                    Ok(ForkResult::Parent(pid)) => kids.push(pid),
                    Err(_) => {
                        denied = true; // EAGAIN = pids.max 拒绝
                        break;
                    }
                }
            }
            for pid in &kids {
                let _ = platform_sys::wait_child(*pid); // reap zombies
            }
            platform_sys::exit_now(if denied { 60 } else { 0 });
        }

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
