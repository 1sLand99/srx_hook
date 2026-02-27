// Trampoline 内存页池管理器
// 通过 mmap 分配可执行页，以位图追踪槽位占用，支持延迟回收和空闲页释放
use crate::errno::Errno;
use crate::runtime::state::MutexPoisonRecover;
use once_cell::sync::Lazy;
use std::ptr;
use std::sync::Mutex;

use super::{TRAMPO_DELAY_SEC, now_sec, trampo_size};

// 单个内存页的管理信息
struct TrampoPage {
    ptr: usize,
    // 位图标记槽位占用状态
    flags: Vec<u32>,
    // 每个槽位的释放时间戳，用于冷却期判定
    timestamps: Vec<u64>,
}

// 页池管理器
struct TrampoMgr {
    page_size: usize,
    trampo_size: usize,
    pages: Vec<TrampoPage>,
}

impl TrampoMgr {
    fn new() -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let page_size = if page_size == 0 { 4096 } else { page_size };
        let trampo_size = trampo_size();
        Self {
            page_size,
            trampo_size,
            pages: Vec::new(),
        }
    }

    fn count_per_page(&self) -> usize {
        // 每个 trampoline 独占一页，避免 RX/RW 切换影响同页的其他活跃 trampoline。
        1
    }

    // 优先复用已有页中的空闲槽位，无可用时 mmap 新页
    fn alloc(&mut self) -> Result<usize, Errno> {
        let count = self.count_per_page();
        if count == 0 {
            return Err(Errno::NewTrampo);
        }
        let now = now_sec();
        self.reclaim_idle_pages(now);

        for page in &mut self.pages {
            for idx in 0..count {
                let flags_idx = idx / 32;
                let mask = 1u32 << (idx % 32);
                if page.flags[flags_idx] & mask != 0 {
                    continue;
                }
                let ts = page.timestamps[idx];
                if ts != 0 && now.saturating_sub(ts) <= TRAMPO_DELAY_SEC {
                    continue;
                }

                let mprotect_result = unsafe {
                    libc::mprotect(
                        page.ptr as *mut libc::c_void,
                        self.page_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    )
                };
                if mprotect_result != 0 {
                    continue;
                }
                page.flags[flags_idx] |= mask;
                let addr = page.ptr + idx * self.trampo_size;
                unsafe {
                    ptr::write_bytes(addr as *mut u8, 0, self.trampo_size);
                }
                return Ok(addr);
            }
        }

        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                self.page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(Errno::NewTrampo);
        }

        let mut page = TrampoPage {
            ptr: raw as usize,
            flags: vec![0u32; count.div_ceil(32)],
            timestamps: vec![0u64; count],
        };
        page.flags[0] |= 1;
        let addr = page.ptr;
        self.pages.push(page);
        Ok(addr)
    }

    // 标记槽位为空闲并记录释放时间戳，随后尝试回收空闲页
    fn free(&mut self, trampo: usize) {
        let count = self.count_per_page();
        let now = now_sec();

        for page in &mut self.pages {
            if trampo < page.ptr || trampo >= page.ptr + self.page_size {
                continue;
            }
            let idx = (trampo - page.ptr) / self.trampo_size;
            if idx >= count {
                continue;
            }
            let flags_idx = idx / 32;
            let mask = 1u32 << (idx % 32);
            page.flags[flags_idx] &= !mask;
            page.timestamps[idx] = now;
            break;
        }

        self.reclaim_idle_pages(now);
    }

    // 回收全部槽位空闲且超过冷却期的页，至少保留一页
    fn reclaim_idle_pages(&mut self, now: u64) {
        if self.pages.len() <= 1 {
            return;
        }

        let mut idx = 0;
        while idx < self.pages.len() {
            if self.pages.len() <= 1 {
                break;
            }

            let should_remove = {
                let page = &self.pages[idx];
                if !page.flags.iter().all(|value| *value == 0) {
                    false
                } else {
                    let last_free_ts = page.timestamps.iter().copied().max().unwrap_or(0);
                    last_free_ts != 0 && now.saturating_sub(last_free_ts) > TRAMPO_DELAY_SEC
                }
            };

            if should_remove {
                let page = self.pages.swap_remove(idx);
                unsafe {
                    libc::munmap(page.ptr as *mut libc::c_void, self.page_size);
                }
                continue;
            }

            idx += 1;
        }
    }
}

static TRAMPO_MGR: Lazy<Mutex<TrampoMgr>> = Lazy::new(|| Mutex::new(TrampoMgr::new()));

pub(super) fn alloc_trampo() -> Result<usize, Errno> {
    let mut mgr = TRAMPO_MGR.lock_or_poison();
    mgr.alloc()
}

pub(super) fn free_trampo(trampo: usize) {
    let mut mgr = TRAMPO_MGR.lock_or_poison();
    mgr.free(trampo);
}
