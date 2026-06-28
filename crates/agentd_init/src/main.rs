//! agentd_init —— 真实 PID1 / init（ADR-004 D3.2 / D5 / cp4）。
//!
//! 目标形态：最小 static-musl appliance 的唯一 PID1。
//! 职责：挂载 /proc /sys /dev（devtmpfs）→ 安装信号处理 → 永不退出地
//! reap 孤儿进程 → fork 一个受监督子进程托管 agent_runtime 运行循环。
//! 当前为骨架，真实 mount/reap/signal 经 platform_sys 在 cp4 填充。
#![forbid(unsafe_code)]

use agent_runtime::AgentRuntime;

fn main() {
    // cp4 待实现的真实 init 序列（全部经 platform_sys 安全封装）：
    //   1. mount devtmpfs/proc/sys；创建 /dev 节点
    //   2. prctl(PR_SET_NO_NEW_PRIVS)；安装 SIGCHLD/SIGTERM 处理
    //   3. pivot_root 到 ext4 rootfs 分区（D5 boot topology）
    //   4. fork 受监督子进程托管运行循环；主进程进入 reap 循环，永不退出
    let pid = platform_sys::getpid();
    let runtime = AgentRuntime::new();
    println!(
        "agentd_init skeleton: pid={pid} runtime_state={:?} (cp4 init sequence pending)",
        runtime.state()
    );
}
