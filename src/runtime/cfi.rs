// CFI (Control Flow Integrity) 绕过模块，负责禁用 Android 的 CFI slowpath 检查
// 仅 aarch64 架构有实际实现，其他架构为空操作
use crate::elf;
use crate::errno::Errno;
use std::ffi::{CStr, c_char};
use std::sync::OnceLock;

use super::state::ModuleInfo;

// Android O (API 26) 起引入 CFI，低于此版本无需处理
const ANDROID_API_LEVEL_CFI_DISABLE: i32 = 26;
const SYSTEM_PROP_VALUE_MAX: usize = 92;
const RTLD_NEXT_FALLBACK: *mut libc::c_void = (-1isize) as *mut libc::c_void;

// 全局初始化一次的 CFI 禁用结果缓存
static CFI_DISABLE_STATUS: OnceLock<Errno> = OnceLock::new();

unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> libc::c_int;
}

#[cfg(target_arch = "aarch64")]
mod module_hook;
#[cfg(target_arch = "aarch64")]
mod slowpath;

pub(super) fn disable_slowpath() -> Errno {
    *CFI_DISABLE_STATUS.get_or_init(disable_slowpath_impl)
}

pub(super) fn refresh_slowpath_patch() -> Errno {
    refresh_slowpath_patch_impl()
}

pub(super) fn ensure_module_cfi_hook(module: &ModuleInfo, elf: &elf::Elf) -> Errno {
    ensure_module_cfi_hook_impl(module, elf)
}

pub(super) fn retain_module_cfi_hook_state(modules: &[ModuleInfo]) {
    retain_module_cfi_hook_state_impl(modules)
}

#[cfg(target_arch = "aarch64")]
fn disable_slowpath_impl() -> Errno {
    slowpath::disable_slowpath_impl()
}

#[cfg(target_arch = "aarch64")]
fn refresh_slowpath_patch_impl() -> Errno {
    slowpath::refresh_slowpath_patch_impl()
}

#[cfg(target_arch = "aarch64")]
fn ensure_module_cfi_hook_impl(module: &ModuleInfo, elf: &elf::Elf) -> Errno {
    module_hook::ensure_module_cfi_hook_impl(module, elf)
}

#[cfg(target_arch = "aarch64")]
fn retain_module_cfi_hook_state_impl(modules: &[ModuleInfo]) {
    module_hook::retain_module_cfi_hook_state_impl(modules)
}

#[cfg(not(target_arch = "aarch64"))]
fn disable_slowpath_impl() -> Errno {
    Errno::Ok
}

#[cfg(not(target_arch = "aarch64"))]
fn refresh_slowpath_patch_impl() -> Errno {
    Errno::Ok
}

#[cfg(not(target_arch = "aarch64"))]
fn ensure_module_cfi_hook_impl(_module: &ModuleInfo, _elf: &elf::Elf) -> Errno {
    Errno::Ok
}

#[cfg(not(target_arch = "aarch64"))]
fn retain_module_cfi_hook_state_impl(_modules: &[ModuleInfo]) {}

fn android_api_level() -> i32 {
    let prop_name = c"ro.build.version.sdk";
    let mut prop_value = [0 as c_char; SYSTEM_PROP_VALUE_MAX];
    let len = unsafe { __system_property_get(prop_name.as_ptr(), prop_value.as_mut_ptr()) };
    if len <= 0 {
        return 0;
    }

    let len = len as usize;
    if len >= SYSTEM_PROP_VALUE_MAX {
        return 0;
    }

    let value = unsafe { CStr::from_ptr(prop_value.as_ptr()) };
    value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .unwrap_or(0)
}
