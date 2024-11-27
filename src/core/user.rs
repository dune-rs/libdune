use std::arch::asm;
use std::ffi::c_void;
use std::alloc::{alloc, Layout};
use std::os::raw::c_ulong;

use dune_sys::DuneTf;

use crate::{dune_jump_to_user, dune_passthrough_syscall, dune_register_syscall_handler};

#[repr(C)]
pub struct UserArgs {
    arg1: c_ulong,
    arg2: c_ulong,
    arg3: c_ulong,
    arg4: c_ulong,
    arg5: c_ulong,
    arg6: c_ulong,
}

pub extern "C" fn dune_call_user(
    func: *const c_void,
    args: &UserArgs
) -> i32 {
    let ret: i32;
    let mut sp: c_ulong;
    let tf_layout = Layout::new::<DuneTf>();
    let tf_ptr = unsafe { alloc(tf_layout) as *mut DuneTf };

    if tf_ptr.is_null() {
        return -12; // -ENOMEM
    }

    unsafe {
        asm!("movq %rsp, {}", out(reg) sp, options(nostack, att_syntax));
        sp = sp - 0x10008;
        let tf = &mut *tf_ptr;
        tf.set_rip(func as c_ulong)
            .set_rsp(sp)
            .set_rflags(0x0)
            .set_rdi(args.arg1)
            .set_rsi(args.arg2)
            .set_rdx(args.arg3)
            .set_rcx(args.arg4)
            .set_r8(args.arg5)
            .set_r9(args.arg6);

        println!("entering user mode...");

        // Register syscall handler, default to passthrough
        dune_register_syscall_handler(dune_passthrough_syscall);

        // Jump to user mode
        ret = dune_jump_to_user(tf_ptr);
    }

    ret
}

pub extern "C" fn dune_call_user_main(
    func: *const c_void,
    argc: i32,
    argv: *const *const i8,
    envp: *const *const i8
) -> i32 {
    dune_call_user(func, &UserArgs {
        arg1: argc as c_ulong,
        arg2: argv as c_ulong,
        arg3: envp as c_ulong,
        arg4: 0,
        arg5: 0,
        arg6: 0,
    })
}

pub extern "C" fn dune_call_user_thread(func: *const c_void, arg: *const c_void) -> i32 {
    dune_call_user(func, &UserArgs {
        arg1: arg as c_ulong,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
        arg6: 0,
    })
}