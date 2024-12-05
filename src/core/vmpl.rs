use std::ffi::{c_int, c_void};
use std::mem::{self};
use std::sync::Arc;
use std::sync::Mutex;
use libc::{mmap, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use libc::{MAP_FAILED,MAP_SHARED,MAP_FIXED,MAP_POPULATE};
use x86_64::VirtAddr;
use x86_64::PhysAddr;
use x86_64::registers::model_specific::FsBase;
use x86_64::structures::paging::PageTable;
use dune_sys::PGTABLE_MMAP_BASE;
use dune_sys::vmpl_get_layout;
use dune_sys::vmpl_get_config;
use dune_sys::vmpl_get_cr3;
use dune_sys::vmpl_get_ghcb;
use dune_sys::vmpl_get_pages;
use dune_sys::GetPages;
use dune_sys::{funcs, funcs_vec, vmpl_create_vcpu, vmpl_create_vm, vmpl_set_config, BaseDevice, BaseSystem, Device, DuneConfig, DuneRetCode, DuneTrapRegs, Error, IdtDescriptor, Result, Tptr, Tss, VcpuConfig, VmsaSeg, WithInterrupt};

use crate::AddressMapping;
use crate::WithAddressTranslation;
use crate::globals::{GD_TSS, GD_TSS2, NR_GDT_ENTRIES, SEG_A, SEG_P, SEG_TSSA};
use crate::{log_init, DuneDebug, DuneInterrupt, DuneSignal, DuneSyscall, WithVmplFpu, XSaveArea, PGSIZE};
use crate::__dune_syscall;
use crate::__dune_go_dune;
use crate::{__dune_ret, __dune_enter};
use crate::core::cpuset::WithCpuset;
use crate::mm::PageManager;
use crate::mm::WithPageManager;
use crate::mm::WithPageTable;
use crate::mm::PAGE_SIZE;
use crate::mm::mark_vmpl_pages;
use crate::vc::{Ghcb, GHCB_MMAP_BASE};
use crate::vc::WithVC;
use crate::vc::WithGHCB;
use crate::vc::WithSerial;
use crate::syscall::WithHotCalls;
use crate::security::WithSeimi;
use super::{DuneRoutine, Percpu, GDT_TEMPLATE, IDT_ENTRIES};
use dune_sys::VmplLayout;

pub struct VmplPercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: u64,
    ufs_base: u64,
    in_usermode: u64,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
    ghcb: *mut Ghcb,
    vcpu_fd: BaseDevice,
    xsave_area: XSaveArea,
    system: Arc<dyn WithInterrupt>,
}

/*
 * Supervisor Private Area Format
 */
#[cfg(feature = "vmpl")]
pub mod offsets {
    use std::mem::offset_of;

    pub const TMP : usize = offset_of!(DunePercpu, tmp);
    pub const KFS_BASE: usize = offset_of!(DunePercpu, kfs_base);
    pub const UFS_BASE: usize = offset_of!(DunePercpu, ufs_base);
    pub const IN_USERMODE: usize = offset_of!(DunePercpu, in_usermode);
    pub const TRAP_STACK: usize = offset_of!(DunePercpu, tss.tss_rsp);
}

impl VmplPercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, u64);
    funcs!(ufs_base, u64);
    funcs!(in_usermode, u64);
    funcs!(ghcb, *mut Ghcb);
    funcs!(vcpu_fd, BaseDevice);
    funcs_vec!(gdt, u64);

    fn set_config(&self, data: &mut VcpuConfig) -> Result<i32> {
        let fd = self.vcpu_fd.fd();
        unsafe { vmpl_set_config(fd, data as *mut VcpuConfig).map_err(|e| {
            log::error!("dune: failed to set config");
            Error::LibcError(e)
        }) }
    }

    fn get_config(&mut self, data: &mut VcpuConfig) -> Result<i32> {
        let fd = self.vcpu_fd.fd();
        unsafe {
            vmpl_get_config(fd, data as *mut VcpuConfig).map_err(|e| {
                log::error!("dune: failed to get config");
                Error::LibcError(e)
            }) 
        }
    }

    fn create_vcpu(&mut self) -> Result<()> {
        let mut data = Box::new(VcpuConfig::default());
        log::info!("setup vcpu");

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

        data.set_lstar(__dune_syscall as u64)
            .set_fs(fsbase)
            .set_gs(gsbase)
            .set_tr(tr) // refer to linux-svsm
            .set_gdtr(gdtr)
            .set_idtr(idtr);

        self.set_config(&mut data)?;
        Ok(())
    }
}

impl Display for VmplPercpu {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VmplPercpu {{ percpu_ptr: {:x}, kfs_base: {:x}, ufs_base: {:x}, in_usermode: {:x} }}", self.percpu_ptr, self.kfs_base.as_u64(), self.ufs_base.as_u64(), self.in_usermode)
    }
}

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

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }  

    fn init(&mut self) -> Result<()> {
        log::info!("vmpl_init");
        self.setup_safe_stack(&mut self.tss)?;

        let fs_base = get_fs_base()?;
        self.set_kfs_base(fs_base)
            .set_ufs_base(fs_base)
            .set_in_usermode(1)
            .set_ghcb(ptr::null_mut());

        // Setup CPU set for the thread
        self.setup_cpuset()?;

        // Setup GDT for hypercall
        self.setup_gdt(&mut self.gdt, &mut self.tss)?;

        // Setup VCPU
        self.create_vcpu()?;

        // Setup XSAVE for FPU
        self.xsave_begin();

        Ok(())
    }

    fn enter(&mut self) -> Result<()> {
        let mut config = Box::new(DuneConfig::default());
        log::info!("dune: entering Dune mode");

        config.set_rip(__dune_ret as u64);
        config.set_rsp(0);
        config.set_rflags(0x202);

        let vcpu_fd = self.vcpu_fd.fd();
        let rc = unsafe { __dune_enter(vcpu_fd, &mut *config) };
        if rc != 0 {
            log::error!("dune: entry to Dune mode failed");
            return Err(Error::Unknown);
        }

        Ok(())
    }

    fn boot(&mut self) -> Result<()> {
        // Now we are in VMPL mode
        self.set_in_usermode(0);

        // Setup XSAVE for FPU
        self.xsave_end();

        // Setup VC communication
        #[cfg(feature = "vc")]
        self.vc_init()?;

        // Setup hotcall
        #[cfg(feature = "hotcalls")]
        self.hotcalls_enable()?;

        // Setup serial port
        #[cfg(feature = "serial")]
        self.serial_init();

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VmplSystem {
    system: BaseSystem,
    page_manager: Arc<Mutex<PageManager>>,
    layout: VmplLayout,
    dune_fd: i32,
    page_table: Option<*mut PageTable>,
}

impl VmplSystem {
    funcs!(system, BaseSystem);
    funcs!(dune_fd, i32);
    funcs_opt!(page_table, *mut PageTable);

    #[allow(dead_code)]
    pub fn new() -> Self {
        VmplSystem {
            system: BaseSystem::new(),
            layout: VmplLayout::new(),
            page_manager: Arc::new(Mutex::new(PageManager::new())),
            dune_fd: -1,
            page_table: None,
        }
    }

    fn create_vm(&mut self) -> Result<i32> {
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

    /// 清除页表指针
    pub fn clear_pgtable(&mut self) {
        // 如果页表存在,需要先解除映射
        if let Some(pt) = self.page_table {
            if !pt.is_null() {
                unsafe {
                    libc::munmap(
                        pt as *mut libc::c_void,
                        PAGE_SIZE
                    );
                }
            }
        }
        self.page_table = None;
    }

    /// 检查是否有有效的页表
    pub fn has_valid_pgtable(&self) -> bool {
        self.page_table.map_or(false, |pt| !pt.is_null())
    }
}

// 为了安全性,在 Drop 时确保页表被正确清理
impl Drop for VmplSystem {
    fn drop(&mut self) {
        self.clear_pgtable();
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

#[cfg(feature = "serial")]
impl WithSerial for VmplPercpu { }

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

    fn init(&mut self, map_full: bool) -> Result<()> {
        log_init().map_err(|e| {
            log::error!("dune: failed to initialize logger");
            Error::Unknown
        })?;
        log::info!("vmpl_init");

        // Setup VMPL without error checking
        #[cfg(feature = "signal")]
        self.setup_signals()?;

        // Setup hotcalls
        #[cfg(feature = "hotcalls")]
        self.setup_hotcalls();

        // Setup IDT
        self.setup_idt();

        // Setup address translation    
        self.setup_address_translation()?;

        // Create VM
        self.create_vm()?;

        // Setup memory management
        #[cfg(feature = "mm")]
        self.setup_mm()?;

        // Setup seimi
        #[cfg(feature = "seimi")]
        self.setup_seimi()?;

        // Setup syscall
        #[cfg(feature = "syscall")]
        self.setup_syscall()?;

        Ok(())
    }

    fn enter(&mut self) -> Result<()> {
        log::info!("vmpl_enter");

        let data = &mut VcpuConfig::default();
        let vcpu_fd = self.create_vcpu(data)?;

        // Check if this process already entered Dune before a fork...
        let percpu = get_percpu::<VmplPercpu>();
        if let Some(percpu) = percpu {
            // enter Dune mode directly        
            percpu.enter()?;
            return Ok(());
        }

        // Create a new PerCPU
        let percpu: *mut VmplPercpu = VmplPercpu::create(Arc::new(self));
        percpu.and_then(|percpu_ptr| {
            let percpu = unsafe { &mut *percpu_ptr };
            percpu.set_vcpu_fd(*BaseDevice::new().set_fd(vcpu_fd));
            percpu.init().map_err(|e| {
                log::error!("dune: failed to init percpu");
                VmplPercpu::free(percpu_ptr);
                e
            })?;
            percpu.enter().map_err(|e| {
                log::error!("dune: failed to enter Dune mode");
                VmplPercpu::free(percpu_ptr);
            })?;

            set_percpu(percpu);
        }).map_err(|e| {
            log::error!("dune: failed to create percpu");
            e
        })?;

        Ok(())
    }

    fn banner(&self) {
        log::info!("**********************************************");
        log::info!("*                                            *");
        log::info!("*              Welcome to VMPL!              *");
        log::info!("*                                            *");
        log::info!("**********************************************");
    }

    fn stats(&self) {
        log::info!("VMPL Stats:");
        // self.vmpl_mm_stats();
    }

    fn tests(&self) {
        log::info!("vmpl_test");
        #[cfg(test)]
        self.pgtable_test();
    }

    fn cleanup(&self) {
        log::info!("vmpl_cleanup");
    }

    fn on_syscall(&self, conf: &mut DuneConfig) {
        unsafe {
            let ret = libc::syscall(
                conf.status() as libc::c_long,
                conf.rdi(),
                conf.rsi(),
                conf.rdx(),
                conf.r10(),
                conf.r8(),
                conf.r9(),
            );
            conf.set_rax(ret);
        }
    }
    
    fn on_exit(&mut self, conf_: *mut DuneConfig) -> ! {
        let conf = unsafe { &mut *conf_ };
        let ret: DuneRetCode = conf.ret().into();
        match ret {
            DuneRetCode::Exit => {
                unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
            }
            DuneRetCode::Syscall => {
                self.on_syscall(conf);
                unsafe { __dune_go_dune(self.fd(), conf as *mut DuneConfig) };
            }
            DuneRetCode::Interrupt => {
                #[cfg(feature = "debug")]
                self.handle_int(conf_);
                println!("dune: exit due to interrupt {}", conf.status());
            }
            DuneRetCode::Signal => {
                // percpu signal handler
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

impl DuneSyscall for VmplSystem { }

#[cfg(feature = "debug")]
impl DuneDebug for VmplSystem { }

impl WithPageManager for VmplSystem {

    fn page_manager(&self) -> Arc<Mutex<PageManager>> {
        Arc::clone(&self.page_manager)
    }

    fn get_pages(&self, num_pages: usize) -> Result<PhysAddr> {
        let fd = self.fd();
        let mut args = GetPages::default();
        args.set_num_pages(num_pages);
        unsafe { vmpl_get_pages(fd, &mut args).map_err(|e| {
            log::error!("dune: failed to get pages");
            Error::LibcError(e)
        }) }?;
        let phys = args.phys();
        Ok(PhysAddr::new(phys))
    }
}

#[cfg(feature = "seimi")]
impl WithSeimi for VmplSystem { }

impl WithHotCalls for VmplSystem { }

impl WithAddressTranslation for VmplSystem {

    fn setup_address_translation(&mut self) -> Result<()> {
        let fd = self.fd();
        let layout = &mut self.layout;
        let ret = unsafe { vmpl_get_layout(fd, layout as *mut VmplLayout) };
        match ret {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::LibcError(e)),
        }
    }

    fn va_to_pa(&self, va: VirtAddr) -> Result<PhysAddr> {
        self.layout.va_to_pa(va)
    }

    fn pa_to_va(&self, pa: PhysAddr) -> Result<VirtAddr> {
        self.layout.pa_to_va(pa)
    }
}

impl WithCpuset for VmplPercpu { }

impl WithVmplFpu for VmplPercpu {

    fn get_xsaves_area(&self) -> *mut XSaveArea {
        &self.xsave_area as *const _ as *mut XSaveArea
    }
}

impl WithPageTable for VmplSystem {

    fn get_cr3(&self) -> Option<PhysAddr> {
        unsafe {
            let mut cr3: u64 = 0;
            let ret = vmpl_get_cr3(self.fd(), &mut cr3).map_err(|e| {
                log::error!("dune: failed to get CR3");
                Error::LibcError(e)
            }).ok()?;
            if ret < 0 {
                return None;
            }
            Some(PhysAddr::new(cr3))
        }
    }

    fn do_mapping(&self, phys: PhysAddr, len: usize) -> Result<*mut PageTable> {
        if self.page_manager().lock().unwrap().is_vmpl_page(phys) {
            log::error!("dune: page already mapped");
            return Err(Error::AlreadyMapped);
        }

        let addr = unsafe {
            mmap(
                (PGTABLE_MMAP_BASE + phys.as_u64()) as *mut _,
                len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                self.fd(),
                phys.as_u64() as i64,
            )
        };

        if addr == MAP_FAILED {
            log::error!("dune: failed to map page");
            return Err(Error::MappingFailed);
        }

        self.page_manager().lock().unwrap().mark_vmpl_pages(phys, len);

        Ok(addr as *mut PageTable)
    }

    fn get_page_table(&self) -> Result<&mut PageTable> {
        match self.page_table() {
            Some(pt) => {
                if pt.is_null() {
                    return Err(Error::NotFound);
                }
                Ok(unsafe { &mut *pt })
            }
            None => {
                let cr3 = self.get_cr3().ok_or(Error::NotFound)?;
                
                let pt = self.do_mapping(cr3, PAGE_SIZE)?;
                
                self.set_page_table(Some(pt));
                
                Ok(unsafe { &mut *pt })
            }
        }
    }
}

impl WithGHCB for VmplPercpu {

    fn ghcb(&self) -> VirtAddr {
        VirtAddr::from_ptr(self.ghcb)
    }

    fn set_ghcb(&mut self, va: VirtAddr) {
        self.ghcb = va.as_ptr();
    }

    // TODO: 需要线性映射GHCB物理页，这样就可以直接查询GHCB物理地址
    fn get_ghcb(&self) -> Option<PhysAddr>  {
        log::info!("get GHCB");
        let vcpu_fd = self.vcpu_fd.fd();
        let mut ghcb: u64 = 0;
        
        let ret = unsafe { 
            vmpl_get_ghcb(vcpu_fd, &mut ghcb).map_err(|e| {
                log::error!("dune: failed to get GHCB");
                Error::LibcError(e)
            })
        };

        match ret {
            Ok(_) => Some(PhysAddr::new(ghcb)),
            Err(_) => None
        }
    }

    fn map_ghcb(&mut self) -> Option<*mut Ghcb> {
        log::info!("map GHCB");
        let vcpu_fd = self.fd();
        
        let ghcb = unsafe {
            mmap(
                GHCB_MMAP_BASE.as_mut_ptr(),
                PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_FIXED | MAP_POPULATE,
                vcpu_fd,
                0,
            )
        };

        if ghcb == MAP_FAILED {
            log::error!("dune: failed to map GHCB");
            return None;
        }

        let ghcb_ptr = ghcb as *mut Ghcb;
        Some(ghcb_ptr)
    }
}

impl WithVC for VmplPercpu { }