use std::sync::{atomic::{AtomicI32, Ordering}, Once};

use libc::{cpu_set_t, sched_getaffinity, sysconf, _SC_NPROCESSORS_ONLN};
use dune_sys::Result;
use nix::errno::Errno;
use super::Percpu;

#[allow(unused)]
pub trait WithCpuset : Percpu {

    fn alloc_cpu(&self) -> i32 {
        static CURRENT_CPU: AtomicI32 = AtomicI32::new(0);
        static CPU_COUNT: AtomicI32 = AtomicI32::new(0);
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            let cpu_count = unsafe { sysconf(_SC_NPROCESSORS_ONLN) };
            let cpu_count = if cpu_count > 0 { cpu_count } else { 1 } as i32;
            CPU_COUNT.store(cpu_count, Ordering::SeqCst);
        });

        let cpu_count = CPU_COUNT.load(Ordering::SeqCst);
        let current_cpu = CURRENT_CPU.fetch_add(1, Ordering::SeqCst) % cpu_count;

        current_cpu
    }

    fn setup_cpuset(&self) -> Result<()> {
        log::info!("setup cpuset");

        let cpu = self.alloc_cpu();
        let mut cpuset: cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            let pid = libc::gettid();
            let ret = sched_getaffinity(pid, size_of::<cpu_set_t>(), &mut cpuset);;
            if ret != 0 {
                return Err(dune_sys::Error::LibcError(Errno::last()));
            }
            log::info!("Thread {} bound to CPU {}", libc::gettid(), cpu);
            log::debug!("dune: running on CPU {}", cpu);
        }

        Ok(())
    }

}