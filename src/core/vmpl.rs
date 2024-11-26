use std::ffi::{c_int, c_void};
use std::mem::{self};
use std::sync::Arc;
use libc::{mmap, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use x86_64::VirtAddr;

use dune_sys::{funcs, funcs_vec, vmpl_create_vcpu, vmpl_create_vm, vmpl_set_config, BaseDevice, BaseSystem, Device, DuneConfig, DuneRetCode, DuneTrapRegs, Error, IdtDescriptor, Result, Tptr, Tss, VcpuConfig, VmsaSeg, WithInterrupt};

use crate::globals::{GD_TSS, GD_TSS2, NR_GDT_ENTRIES, SEG_A, SEG_P, SEG_TSSA};
use crate::{log_init, DuneDebug, DuneInterrupt, DuneSignal, DuneSyscall, WithVmplFpu, XSaveArea, PGSIZE};
use crate::__dune_go_dune;
use crate::{__dune_ret, __dune_enter};
use core::arch::asm;
use crate::core::cpuset::WithCpuset;
use super::{DuneRoutine, Percpu, GDT_TEMPLATE, IDT_ENTRIES};

pub struct VmplPercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: VirtAddr,
    ufs_base: VirtAddr,
    in_usermode: u64,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
    vcpu_fd: BaseDevice,
    xsave_area: XSaveArea,
    system: Arc<VmplSystem>,
}

use crate::__dune_syscall;

#[allow(dead_code)]
fn rdfsbase() -> u64 {
    let fsbase: u64;
    unsafe {
        asm!(
            "rdfsbase {fsbase}",
            fsbase = out(reg) fsbase,
            options(nostack, preserves_flags)
        );
    }
    fsbase
}

#[allow(dead_code)]
fn wrfsbase(fsbase: u64) {
    unsafe {
        asm!(
            "wrfsbase {fsbase}",
            fsbase = in(reg) fsbase,
            options(nostack, preserves_flags)
        );
    }
}

impl VmplPercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, VirtAddr);
    funcs!(ufs_base, VirtAddr);
    funcs!(in_usermode, u64);
    funcs!(vcpu_fd, BaseDevice);
    funcs_vec!(gdt, u64);

    #[allow(dead_code)]
    fn vmpl_alloc_percpu() -> Option<*mut VmplPercpu> {
        let percpu = unsafe {
            mmap(
                std::ptr::null_mut(),
                PGSIZE as usize,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if percpu == libc::MAP_FAILED {
            return None;
        }

        let percpu = percpu as *mut VmplPercpu;
        unsafe {
            (*percpu).kfs_base = VirtAddr::new(rdfsbase());
            (*percpu).ufs_base = VirtAddr::new(rdfsbase());
            (*percpu).in_usermode = 1;
        }

        if let Err(_) = unsafe { (*percpu).setup_safe_stack() } {
            log::error!("dune: failed to setup safe stack");
            unsafe { munmap(percpu as *mut c_void, PGSIZE as usize) };
            return None;
        }

        Some(percpu)
    }

    pub fn vmpl_free_percpu(percpu: *mut VmplPercpu) {
        log::debug!("vmpl_free_percpu");
        unsafe { munmap(percpu as *mut c_void, PGSIZE as usize) };
    }

    fn set_config(&self, data: &mut VcpuConfig) -> Result<i32> {
        let fd = self.vcpu_fd.fd();
        unsafe { vmpl_set_config(fd, data as *mut VcpuConfig).map_err(|e| {
            log::error!("dune: failed to set config");
            Error::LibcError(e)
        }) }
    }

    fn setup_vmsa(&mut self) -> Result<()> {
        let mut data = Box::new(VcpuConfig::default());
        log::info!("setup vmsa");

        data.set_lstar(__dune_syscall as u64);
        let fsbase = *VmsaSeg::new().set_base(self.kfs_base.as_u64());
        let gsbase = *VmsaSeg::new().set_base(self as *const _ as u64);

        let tr = *VmsaSeg::new()
            .set_selector(GD_TSS as u16)
            .set_base(&self.tss as *const _ as u64)
            .set_limit(std::mem::size_of::<Tss>() as u32)
            .set_attrib(0x0089);

        let gdtr = *VmsaSeg::new()
            .set_base(&self.gdt as *const _ as u64)
            .set_limit((std::mem::size_of_val(&self.gdt) - 1) as u32);

        let idtr = *VmsaSeg::new()
            .set_base(self.system().get_idt().as_ptr() as u64)
            .set_limit((IDT_ENTRIES * std::mem::size_of::<IdtDescriptor>() - 1) as u32);

        data.set_fs(fsbase)
            .set_gs(gsbase)
            .set_tr(tr) // refer to linux-svsm
            .set_gdtr(gdtr)
            .set_idtr(idtr);

        self.set_config(&mut data)?;
        Ok(())
    }

    #[allow(dead_code)]
    fn serial_init() -> Result<()> {
        todo!()
    }

    fn vmpl_init_pre(&mut self) -> Result<()> {
        log::info!("vmpl_init_pre");
        // Setup CPU set for the thread
        self.setup_cpuset()?;

        // Setup GDT for hypercall
        self.setup_gdt();

        // Setup segments registers
        self.setup_vmsa()?;

        // Setup XSAVE for FPU
        self.xsave_begin();

        Ok(())
    }

    fn dump_configs(&self) {
        log::info!("dune: percpu_ptr={:x}", self.percpu_ptr);
        log::info!("dune: kfs_base={:x}", self.kfs_base.as_u64());
        log::info!("dune: ufs_base={:x}", self.ufs_base.as_u64());
        log::info!("dune: in_usermode={}", self.in_usermode);
    }

    fn vmpl_init_post(&mut self) -> Result<()> {
        // Now we are in VMPL mode
        self.set_in_usermode(0);

        // Setup XSAVE for FPU
        self.xsave_end();

        // Setup VC communication
        #[cfg(feature = "vc")]
        percpu.vc_init()?;

        // Setup hotcall
        #[cfg(feature = "hotcalls")]
        self.hotcalls_enable()?;

        // Setup serial port
        #[cfg(feature = "serial")]
        self::serial_init()?;

        Ok(())
    }

    fn __do_dune_enter(&self) -> Result<()> {
        let mut config = Box::new(DuneConfig::default());
        log::info!("dune: entering Dune mode");

        config.set_rip(__dune_ret as u64);
        config.set_rsp(0);
        config.set_rflags(0x202);

        let vcpu_fd = self.vcpu_fd.fd();
        let rc = unsafe { __dune_enter(vcpu_fd, &mut *config) };
        if rc != 0 {
            log::error!("dune: entry to Dune mode failed");
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "entry to Dune mode failed").into());
        }

        Ok(())
    }

    fn do_dune_enter(&mut self) -> Result<()> {
        self.vmpl_init_pre()?;

        // Dump configs
        self.dump_configs();

        self.__do_dune_enter()?;

        self.dune_boot()?;
        self.vmpl_init_post()?;

        Ok(())
    }

}

const SAFE_STACK_SIZE: usize = 0x1000;

impl Device for VmplPercpu {

    fn fd(&self) -> c_int {
        self.vcpu_fd.fd()
    }

    fn open(&mut self, path: &str) -> Result<i32> {
        self.vcpu_fd.open(path)
    }

    fn close(&self) -> Result<i32> {
        self.vcpu_fd.close()
    }

    fn ioctl<T>(&self, request: i32, arg: *mut T) -> Result<i32> {
        self.vcpu_fd.ioctl(request, arg)
    }
}

impl Percpu for VmplPercpu {

    type SelfType = VmplPercpu;
    type SystemType = VmplSystem;

    // fn init(&self) -> Result<&mut Self::SelfType>;

    fn prepare(&mut self) -> Result<()> {
        // Implement the prepare function
        todo!()
    }

    fn setup_safe_stack(&mut self) -> Result<()> {

        log::info!("setup safe stack");

        let safe_stack = unsafe {
            mmap(
                std::ptr::null_mut(),
                SAFE_STACK_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if safe_stack == libc::MAP_FAILED {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "failed to map safe stack").into());
        }

        let safe_stack = unsafe { safe_stack.add(SAFE_STACK_SIZE) };
        // self.tss.tss_iomb = std::mem::size_of::<Tss>() as u16;
        self.tss.set_tss_iomb(std::mem::size_of::<Tss>() as u16);

        for i in 0..7 {
            // self.tss.tss_ist[i] = safe_stack as u64;
            self.tss.set_tss_ist(i, safe_stack as u64);
        }

        self.tss.tss_rsp[0] = safe_stack as u64;

        Ok(())
    }

    fn gdtr(&self) -> Tptr {
        // Implement the gdtr function
        let mut gdtr = Tptr::default();
        let gdt = &self.gdt;
        let gdt_ptr = gdt.as_ptr();
        let size = gdt.len() * mem::size_of::<u64>() - 1;
        gdtr.set_base(gdt_ptr as u64)
            .set_limit(size as u16);
        gdtr
    }

    fn idtr(&mut self) -> Tptr {
        // Implement the idtr function
        log::info!("idtr");
        let idt = self.system().get_idt();
        let mut idtr = Tptr::default();
        idtr.set_base(idt.as_ptr().addr() as u64)
            .set_limit((idt.len() * mem::size_of::<IdtDescriptor>() - 1) as u16);
        idtr
    }

    fn system(&self) -> &Arc<Self::SystemType> {
        &self.system
    }

    fn set_system(&mut self, system: &Arc<Self::SystemType>) {
        self.system = Arc::clone(system);
    }

    fn post_dune_boot(&mut self) {
        // Implement the post_dune_boot function
        todo!()
    }

    fn setup_gdt(&mut self) {
        log::info!("setup gdt");
        let gdt = &mut self.gdt;
        let tss = &self.tss;
        gdt.copy_from_slice(&GDT_TEMPLATE);
        gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
        gdt[GD_TSS2 >> 3] = SEG_BASEHI!(tss);
    }

}

#[derive(Debug, Copy, Clone)]
pub struct VmplSystem {
    system: BaseSystem,
    dune_fd: i32,
}

impl VmplSystem {
    funcs!(system, BaseSystem);
    funcs!(dune_fd, i32);

    #[allow(dead_code)]
    pub fn new() -> Self {
        VmplSystem {
            system: BaseSystem::new(),
            dune_fd: -1,
        }
    }

    fn setup_vm(&mut self) -> Result<i32> {
        self.open("/dev/vmpl\0")?;

        let vmpl_fd = self.fd();
        let dune_fd = unsafe { vmpl_create_vm(vmpl_fd).map_err(|e| {
            log::error!("dune: failed to create vm");
            Error::LibcError(e)
        }) }?;

        unsafe { libc::close(vmpl_fd) };
        self.set_dune_fd(dune_fd);
        Ok(dune_fd)
    }

    fn create_vcpu(&mut self, data: &mut VcpuConfig) -> Result<i32> {
        let dune_fd = self.dune_fd();
        log::debug!("dune_fd={}\n", dune_fd);
        unsafe { vmpl_create_vcpu(dune_fd, data as *mut VcpuConfig).map_err(|e| {
            Error::LibcError(e)
        }) }
    }

    #[allow(dead_code)]
    fn vmpl_init_exit(&self) {
        log::info!("vmpl_init_exit");
        // self.vmpl_mm_exit();
        // self.apic_cleanup();
    }

    fn vmpl_init_stats(&self) {
        log::info!("VMPL Stats:");
        // self.vmpl_mm_stats();
    }

    fn vmpl_init_test(&self) {
        log::info!("vmpl_init_test");
    }

    fn vmpl_init_banner(&self) {
        log::info!("**********************************************");
        log::info!("*                                            *");
        log::info!("*              Welcome to VMPL!              *");
        log::info!("*                                            *");
        log::info!("**********************************************");
    }

    fn on_dune_syscall(&self, conf: &mut DuneConfig) {
        conf.set_rax(unsafe {
            libc::syscall(
                conf.status() as libc::c_long,
                conf.rdi(),
                conf.rsi(),
                conf.rdx(),
                conf.r10(),
                conf.r8(),
                conf.r9(),
            )
        });

        unsafe {
            __dune_go_dune(self.fd(), conf as *mut DuneConfig)
        };
    }

}

impl Device for VmplSystem {

    fn fd(&self) -> c_int {
        self.system.fd()
    }

    fn open(&mut self, path: &str) -> Result<i32> {
        self.system.open(path)
    }

    fn close(&self) -> Result<i32> {
        self.system.close()
    }

    fn ioctl<T>(&self, request: i32, arg: *mut T) -> Result<i32> {
        self.system.ioctl(request, arg)
    }
}

impl WithInterrupt for VmplSystem {

    fn get_idt<'a>(&self) -> &[IdtDescriptor; IDT_ENTRIES] {
        self.system.get_idt()
    }

    fn get_idt_mut<'a>(&mut self) -> &mut [IdtDescriptor; IDT_ENTRIES] {
        self.system.get_idt_mut()
    }

    fn get_trap_regs_mut<'a>(&mut self) -> &mut DuneTrapRegs {
        self.system.get_trap_regs_mut()
    }
}

impl DuneRoutine for VmplSystem {

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn dune_init(&mut self, map_full: bool) -> Result<()> {
        log_init().map_err(|e| {
            log::error!("dune: failed to initialize logger");
            Error::Unknown
        })?;
        log::info!("vmpl_init");

        // Setup VMPL without error checking
        #[cfg(feature = "signal")]
        self.setup_signals()?;
        #[cfg(feature = "hotcalls")]
        self.setup_hotcalls();
        self.setup_idt();

        self.setup_vm()?;
        #[cfg(feature = "pgtable")]
        self.setup_mm()?;
        #[cfg(feature = "seimi")]
        self.setup_seimi()?;
        #[cfg(feature = "seimi")]
        self.setup_syscall()?;
        #[cfg(feature = "pgtable")]
        self.apic_setup()?;

        Ok(())
    }

    fn dune_enter(&mut self) -> Result<()> {
        log::info!("vmpl_enter");

        let data = &mut VcpuConfig::default();
        let vcpu_fd = self.create_vcpu(data)?;

        let percpu: *mut VmplPercpu = VmplPercpu::create()?;
        let percpu = unsafe { &mut *percpu };
        percpu.set_vcpu_fd(*BaseDevice::new().set_fd(vcpu_fd));
        percpu.do_dune_enter()?;

        self.vmpl_init_test();
        self.vmpl_init_banner();
        self.vmpl_init_stats();

        Ok(())
    }

    fn on_dune_exit(&mut self, conf_: *mut DuneConfig) -> ! {
        let conf = unsafe { &mut *conf_ };
        let ret: DuneRetCode = conf.ret().into();
        match ret {
            DuneRetCode::Exit => {
                unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
            }
            DuneRetCode::Syscall => {
                self.on_dune_syscall(conf);
            }
            DuneRetCode::Interrupt => {
                #[cfg(feature = "debug")]
                self.handle_int(conf_);
                println!("dune: exit due to interrupt {}", conf.status());
            }
            DuneRetCode::Signal => {
                unsafe { __dune_go_dune(self.fd(), conf_) };
            }
            DuneRetCode::NoEnter => {
                log::warn!("dune: re-entry to Dune mode failed, status is {}", conf.status());
            }
            _ => {
                log::warn!("dune: unknown exit from Dune, ret={}, status={}", conf.ret(), conf.status());
            }
        }

        std::process::exit(libc::EXIT_FAILURE);
    }
}

impl DuneInterrupt for VmplSystem { }

impl DuneSignal for VmplSystem { }

#[cfg(feature = "debug")]
impl DuneDebug for VmplSystem { }

impl WithCpuset for VmplPercpu { }

impl WithVmplFpu for VmplPercpu {

    fn get_xsaves_area(&self) -> *mut XSaveArea {
        &self.xsave_area as *const _ as *mut XSaveArea
    }
}