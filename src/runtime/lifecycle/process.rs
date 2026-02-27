// 进程上下文检测，处理 fork 后 PID 变化时的运行时状态重建
use crate::log;

use super::super::hub;
use super::super::refresh;
use super::super::state::CoreState;
use super::proxy;

// 检测 PID 变化（fork 场景），若发生变化则恢复所有 hook 并重建运行时状态
pub(super) fn ensure_process_context(state: &mut CoreState) {
    let current_pid = unsafe { libc::getpid() as usize };
    if current_pid == 0 {
        return;
    }
    if state.process_id == current_pid {
        return;
    }
    if state.process_id == 0 {
        state.process_id = current_pid;
        return;
    }

    log::warn(format_args!(
        "process changed old_pid={} new_pid={}, rebuild runtime state",
        state.process_id, current_pid
    ));

    let _ = refresh::restore_all(state);
    state.task_slots.clear();
    state.slots.clear();
    state.single_task_targets.clear();
    state.known_modules.clear();
    state.pending_module_handles.clear();
    state.pending_module_handle_set.clear();
    state.refresh_requested = false;
    state.monitor_running = false;
    state.monitor_thread = None;
    state.process_id = current_pid;

    proxy::clear_proxy_stack();
    hub::clear_stack();
    hub::collect_retired(true);
}
