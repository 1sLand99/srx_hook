// PLT hook 调度中心（Hub）
// 每个被 hook 的 PLT slot 对应一个 Hub，管理 proxy 链表和 trampoline 入口
use crate::errno::Errno;
use crate::runtime::state::MutexPoisonRecover;
use once_cell::sync::Lazy;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod stack;
mod trampoline;

// 延迟销毁等待时间，确保仍在栈上的 trampoline 帧安全返回
const HUB_DESTROY_DELAY_SEC: u64 = 10;

// proxy 链表节点，ref_count 支持同一函数被多个 task 引用
struct ProxyNode {
    func: usize,
    ref_count: usize,
    enabled: AtomicBool,
    next: *mut ProxyNode,
}

// Hub 核心结构：orig_addr 为原始函数地址，trampo 为 trampoline 代码地址
// head 为 proxy 链表头，采用无锁读和有锁写
pub(super) struct Hub {
    pub(super) orig_addr: usize,
    pub(super) trampo: usize,
    head: AtomicPtr<ProxyNode>,
    lock: Mutex<()>,
}

// 待延迟销毁的 Hub 记录
struct RetiredHub {
    hub_ptr: usize,
    ts: u64,
}

static RETIRED_HUBS: Lazy<Mutex<Vec<RetiredHub>>> = Lazy::new(|| Mutex::new(Vec::new()));
// 全局活跃栈帧计数，非零时禁止立即回收 retired hub
static ACTIVE_STACK_FRAMES: AtomicUsize = AtomicUsize::new(0);

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[inline]
fn active_stack_frames() -> usize {
    ACTIVE_STACK_FRAMES.load(Ordering::Acquire)
}

pub(super) fn mark_stack_frame_push() {
    ACTIVE_STACK_FRAMES.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn mark_stack_frames_pop(count: usize) {
    if count == 0 {
        return;
    }
    let _ = ACTIVE_STACK_FRAMES.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_sub(count))
    });
}

// 释放 Hub 及其全部 proxy 节点和 trampoline 内存
unsafe fn destroy_hub_now(hub_ptr: *mut Hub) {
    if hub_ptr.is_null() {
        return;
    }
    let hub = unsafe { Box::from_raw(hub_ptr) };
    let mut node = hub.head.load(Ordering::Acquire);
    while !node.is_null() {
        let next = unsafe { (*node).next };
        unsafe {
            drop(Box::from_raw(node));
        }
        node = next;
    }
    if hub.trampo != 0 {
        trampoline::free_trampo(hub.trampo);
    }
}

// 回收已过期的 retired hub；force=true 时无视延迟和活跃帧计数
pub(super) fn collect_retired(force: bool) {
    let now = now_sec();
    let active_frames = active_stack_frames();
    let mut ready = Vec::new();
    {
        let mut retired = RETIRED_HUBS.lock_or_poison();
        let mut idx = 0;
        while idx < retired.len() {
            let expired = force
                || (active_frames == 0
                    && now.saturating_sub(retired[idx].ts) >= HUB_DESTROY_DELAY_SEC);
            if expired {
                let item = retired.swap_remove(idx);
                ready.push(item.hub_ptr as *mut Hub);
            } else {
                idx += 1;
            }
        }
    }
    for hub_ptr in ready {
        unsafe {
            destroy_hub_now(hub_ptr);
        }
    }
}

// 创建 Hub：分配 trampoline 并绑定 push/pop 回调
pub(super) fn create_hub(orig_addr: usize) -> Result<*mut Hub, Errno> {
    collect_retired(false);

    let hub = Box::new(Hub {
        orig_addr,
        trampo: 0,
        head: AtomicPtr::new(ptr::null_mut()),
        lock: Mutex::new(()),
    });
    let hub_ptr = Box::into_raw(hub);

    let trampo = match trampoline::alloc_trampo() {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                drop(Box::from_raw(hub_ptr));
            }
            return Err(err);
        }
    };

    let init_result = unsafe {
        trampoline::init_trampo(
            trampo,
            hub_ptr as usize,
            stack::hub_push_stack as *const () as usize,
            stack::hub_pop_stack as *const () as usize,
        )
    };
    if let Err(err) = init_result {
        trampoline::free_trampo(trampo);
        unsafe {
            drop(Box::from_raw(hub_ptr));
        }
        return Err(err);
    }

    unsafe {
        (*hub_ptr).trampo = trampo;
    }
    Ok(hub_ptr)
}

pub(super) fn destroy_hub(hub_ptr: *mut Hub, with_delay: bool) {
    if hub_ptr.is_null() {
        return;
    }

    collect_retired(false);
    if with_delay {
        let mut retired = RETIRED_HUBS.lock_or_poison();
        retired.push(RetiredHub {
            hub_ptr: hub_ptr as usize,
            ts: now_sec(),
        });
        return;
    }

    unsafe {
        destroy_hub_now(hub_ptr);
    }
}

pub(super) fn hub_trampo(hub_ptr: *mut Hub) -> usize {
    if hub_ptr.is_null() {
        return 0;
    }
    unsafe { (*hub_ptr).trampo }
}

// 向 Hub 添加 proxy 函数；已存在则增加引用计数并重新启用
pub(super) fn add_proxy(hub_ptr: *mut Hub, proxy_func: usize) -> Errno {
    if hub_ptr.is_null() || proxy_func == 0 {
        return Errno::InvalidArg;
    }

    let hub = unsafe { &*hub_ptr };
    let _guard = hub.lock.lock_or_poison();

    let mut cursor = hub.head.load(Ordering::Acquire);
    while !cursor.is_null() {
        let node = unsafe { &mut *cursor };
        if node.func == proxy_func {
            node.ref_count = node.ref_count.saturating_add(1);
            node.enabled.store(true, Ordering::SeqCst);
            return Errno::Ok;
        }
        cursor = node.next;
    }

    let node = Box::new(ProxyNode {
        func: proxy_func,
        ref_count: 1,
        enabled: AtomicBool::new(true),
        next: hub.head.load(Ordering::Acquire),
    });
    let node_ptr = Box::into_raw(node);
    hub.head.store(node_ptr, Ordering::Release);
    Errno::Ok
}

// 移除 proxy 函数；引用计数归零时标记 disabled 而非物理删除
// 返回 (操作结果, 是否仍有活跃 proxy)
pub(super) fn del_proxy(hub_ptr: *mut Hub, proxy_func: usize) -> (Errno, bool) {
    if hub_ptr.is_null() || proxy_func == 0 {
        return (Errno::InvalidArg, false);
    }

    let hub = unsafe { &*hub_ptr };
    let _guard = hub.lock.lock_or_poison();

    let mut deleted = false;

    let mut cursor = hub.head.load(Ordering::Acquire);
    while !cursor.is_null() {
        let node = unsafe { &mut *cursor };
        if node.func == proxy_func && node.enabled.load(Ordering::Acquire) {
            if node.ref_count > 1 {
                node.ref_count -= 1;
            } else {
                node.ref_count = 0;
                node.enabled.store(false, Ordering::SeqCst);
            }
            deleted = true;
            break;
        }
        cursor = node.next;
    }

    let mut have_enabled_proxy = false;
    let mut scan = hub.head.load(Ordering::Acquire);
    while !scan.is_null() {
        let node = unsafe { &*scan };
        if node.enabled.load(Ordering::Acquire) {
            have_enabled_proxy = true;
            break;
        }
        scan = node.next;
    }

    if deleted {
        return (Errno::Ok, have_enabled_proxy);
    }
    (Errno::NotFound, have_enabled_proxy)
}

pub(super) fn first_enabled(hub_ptr: *mut Hub) -> usize {
    if hub_ptr.is_null() {
        return 0;
    }
    let hub = unsafe { &*hub_ptr };
    let mut cursor = hub.head.load(Ordering::Acquire);
    while !cursor.is_null() {
        let node = unsafe { &*cursor };
        if node.enabled.load(Ordering::Acquire) {
            return node.func;
        }
        cursor = node.next;
    }
    hub.orig_addr
}

pub(super) fn get_prev_func(func: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    stack::get_prev_func(func)
}

pub(super) fn get_return_address() -> *mut std::ffi::c_void {
    stack::get_return_address()
}

pub(super) fn pop_stack(return_address: *mut std::ffi::c_void) {
    stack::pop_stack_by_return_address(return_address)
}

pub(super) fn proxy_leave(func: *mut std::ffi::c_void) {
    stack::proxy_leave(func)
}

pub(super) fn clear_stack() {
    stack::clear_stack();
}
