// 内存页面保护属性的读取与修改，通过解析 /proc/self/maps 获取权限

use crate::errno::Errno;
use crate::log;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{Ordering, fence};

pub const PROT_READ_FLAG: u32 = 0x1;
pub const PROT_WRITE_FLAG: u32 = 0x2;
pub const PROT_EXEC_FLAG: u32 = 0x4;

// 查询指定地址范围的内存保护属性
// pathname 可选，用于加速 maps 行过滤；不匹配时回退纯地址查找
pub fn get_mem_protect(addr: usize, len: usize, pathname: Option<&str>) -> Result<u32, Errno> {
    if pathname.is_some()
        && let Ok(prot) = scan_maps_for_protect(addr, len, pathname)
    {
        return Ok(prot);
    }
    scan_maps_for_protect(addr, len, None)
}

// 逐行扫描 /proc/self/maps，收集覆盖 [addr, addr+len) 的所有段的权限
// 跨段时取权限交集；仅匹配私有映射（perm[3] == 'p'）
fn scan_maps_for_protect(addr: usize, len: usize, pathname: Option<&str>) -> Result<u32, Errno> {
    let mut start_addr = addr;
    let end_addr = addr.saturating_add(len);
    let mut prot: u32 = 0;
    let mut load0 = true;
    let mut found_all = false;

    let file = File::open("/proc/self/maps").map_err(|_| Errno::BadMaps)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|_| Errno::BadMaps)?;
        if let Some(path) = pathname
            && !line.contains(path)
        {
            continue;
        }

        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let perm = match parts.next() {
            Some(value) => value,
            None => continue,
        };

        if perm.len() < 4 {
            continue;
        }
        let perm_bytes = perm.as_bytes();
        if perm_bytes[3] != b'p' {
            continue;
        }

        let mut range_parts = range.split('-');
        let start_str = match range_parts.next() {
            Some(value) => value,
            None => continue,
        };
        let end_str = match range_parts.next() {
            Some(value) => value,
            None => continue,
        };
        let start = usize::from_str_radix(start_str, 16).unwrap_or(0);
        let end = usize::from_str_radix(end_str, 16).unwrap_or(0);

        if start_addr < start || start_addr >= end {
            continue;
        }

        if load0 {
            if perm_bytes[0] == b'r' {
                prot |= PROT_READ_FLAG;
            }
            if perm_bytes[1] == b'w' {
                prot |= PROT_WRITE_FLAG;
            }
            if perm_bytes[2] == b'x' {
                prot |= PROT_EXEC_FLAG;
            }
            load0 = false;
        } else {
            if perm_bytes[0] != b'r' {
                prot &= !PROT_READ_FLAG;
            }
            if perm_bytes[1] != b'w' {
                prot &= !PROT_WRITE_FLAG;
            }
            if perm_bytes[2] != b'x' {
                prot &= !PROT_EXEC_FLAG;
            }
        }

        if end_addr <= end {
            found_all = true;
            break;
        }
        start_addr = end;
    }

    if !found_all {
        return Err(Errno::SegvErr);
    }

    Ok(prot)
}

// 查询单个指针大小地址的保护属性
pub fn get_addr_protect(addr: usize, pathname: Option<&str>) -> Result<u32, Errno> {
    get_mem_protect(addr, std::mem::size_of::<usize>(), pathname)
}

// 修改指定地址所在页面的保护属性
pub fn set_addr_protect(addr: usize, prot: u32) -> Result<(), Errno> {
    let (start, len) = page_bounds(addr);
    let result = unsafe { libc::mprotect(start as *mut libc::c_void, len, prot as i32) };
    if result != 0 {
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::error(format_args!("mprotect failed: {err}"));
        return Err(Errno::Unknown);
    }
    Ok(())
}

// 单地址指令缓存刷新，仅发出内存屏障
pub fn flush_instruction_cache(addr: usize) {
    let _ = addr;
    fence(Ordering::SeqCst);
}

// 刷新指定地址范围的指令缓存
pub fn flush_instruction_cache_range(start: usize, end: usize) {
    if start >= end {
        return;
    }
    clear_cache_range(start as *mut libc::c_void, end as *mut libc::c_void);
}

// aarch64: 逐行清理 dcache 再逐行无效化 icache，最后 dsb+isb 同步
// x86_64: 硬件保证缓存一致性，仅需内存屏障
fn flush_instruction_cache_impl(start: usize, end: usize) {
    if start >= end {
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let (dcache_line, icache_line) = cache_line_size();
        let mut dcache_addr = align_down(start, dcache_line);
        while dcache_addr < end {
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) dcache_addr, options(nostack, preserves_flags));
            }
            dcache_addr = dcache_addr.saturating_add(dcache_line);
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }

        let mut icache_addr = align_down(start, icache_line);
        while icache_addr < end {
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) icache_addr, options(nostack, preserves_flags));
            }
            icache_addr = icache_addr.saturating_add(icache_line);
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
            core::arch::asm!("isb", options(nostack, preserves_flags));
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        fence(Ordering::SeqCst);
    }
}

fn clear_cache_range(start: *mut libc::c_void, end: *mut libc::c_void) {
    if start.is_null() || end.is_null() {
        return;
    }
    flush_instruction_cache_impl(start as usize, end as usize);
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

// 计算地址所在页面的起始地址和覆盖长度（页对齐）
fn page_bounds(addr: usize) -> (usize, usize) {
    let page_size = page_size();
    if page_size == 0 {
        return (addr, std::mem::size_of::<usize>());
    }
    let page_mask = !(page_size - 1);
    let start = addr & page_mask;
    let end = (addr + std::mem::size_of::<usize>() - 1) & page_mask;
    let end = end + page_size;
    (start, end - start)
}

// 读取 CTR_EL0 寄存器，返回 (dcache_line_size, icache_line_size)
#[cfg(target_arch = "aarch64")]
fn cache_line_size() -> (usize, usize) {
    let ctr_el0: usize;
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr_el0, options(nomem, nostack, preserves_flags));
    }

    let dcache_line = 4usize << ((ctr_el0 >> 16) & 0x0f);
    let icache_line = 4usize << (ctr_el0 & 0x0f);
    (dcache_line.max(4), icache_line.max(4))
}

#[cfg(target_arch = "aarch64")]
fn align_down(addr: usize, align: usize) -> usize {
    let mask = !(align.saturating_sub(1));
    addr & mask
}
