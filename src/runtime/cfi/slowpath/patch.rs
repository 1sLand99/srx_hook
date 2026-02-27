// CFI slowpath 指令级补丁，将目标地址的指令改写为 ARM64 RET
use crate::android::{memory, signal_guard};
use crate::errno::Errno;
use std::ffi::{CStr, c_void};

// ARM64 RET 指令编码 (0xd65f03c0)
const ARM64_RET_INST: u32 = 0xd65f03c0;

// 将指定地址的指令改写为 RET，使 CFI slowpath 函数立即返回
pub(super) fn patch_ret_instruction(addr: usize) -> Result<(), Errno> {
    // 已经是 RET 则无需重复 patch
    if read_ret_instruction(addr).is_some_and(|instruction| instruction == ARM64_RET_INST) {
        return Ok(());
    }

    let old_prot = memory::get_addr_protect(addr, None).map_err(|_| Errno::InitErrCfi)?;
    let writable = memory::PROT_READ_FLAG | memory::PROT_WRITE_FLAG | memory::PROT_EXEC_FLAG;
    let changed_protect = old_prot != writable;
    if changed_protect {
        memory::set_addr_protect(addr, writable).map_err(|_| Errno::InitErrCfi)?;
    }

    let write_result = signal_guard::with_guard(|| unsafe {
        std::ptr::write_volatile(addr as *mut u32, ARM64_RET_INST);
        std::ptr::read_volatile(addr as *const u32)
    });

    if changed_protect {
        let _ = memory::set_addr_protect(addr, old_prot);
    }

    let Ok(instruction) = write_result else {
        return Err(Errno::InitErrCfi);
    };
    if instruction != ARM64_RET_INST {
        return Err(Errno::InitErrCfi);
    }
    Ok(())
}

fn read_ret_instruction(addr: usize) -> Option<u32> {
    signal_guard::with_guard(|| unsafe { std::ptr::read_volatile(addr as *const u32) }).ok()
}

// 判断地址是否可能指向 CFI 运行时代码
// 通过 dladdr 检查符号名或所属库路径来启发式判断
pub(super) fn is_plausible_cfi_runtime_addr(addr: usize) -> bool {
    if addr < 0x1000 {
        return false;
    }
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(addr as *const c_void, &mut info) } == 0 || info.dli_fname.is_null() {
        return false;
    }
    if !info.dli_sname.is_null()
        && let Ok(symbol_name) = unsafe { CStr::from_ptr(info.dli_sname) }.to_str()
        && (symbol_name == "__cfi_slowpath" || symbol_name == "__cfi_slowpath_diag")
    {
        return true;
    }
    let Ok(pathname) = unsafe { CStr::from_ptr(info.dli_fname) }.to_str() else {
        return false;
    };
    pathname.contains("libdl.so")
        || pathname.contains("libc.so")
        || pathname.contains("libart.so")
        || pathname.contains("libartbase.so")
        || pathname.contains("/apex/com.android.art/")
        || pathname.ends_with("/linker")
        || pathname.ends_with("/linker64")
        || pathname.contains("/linker/")
}
