use std::collections::LinkedList;
use std::sync::Mutex;
use lazy_static::lazy_static;
use dune_sys::result::{Error, Result};
use dune_sys::DuneTf;
use crate::dune_die;

lazy_static! {
    static ref SYSCALL_FILTERS: Mutex<Vec<SyscallFilter>> = Mutex::new(Vec::new());
}

#[derive(PartialEq, PartialOrd)]
pub enum FilterPriority {
    Low,
    Normal,
    Medium,
    High,
}

struct SyscallFilter {
    priority: FilterPriority,
    syscall_number: i64,
    filter: fn(&DuneTf) -> bool,
    error_handler: Option<fn(&DuneTf)>,
}

impl SyscallFilter {
    fn new(priority: FilterPriority, syscall_number: i64, filter: fn(&DuneTf) -> bool, error_handler: Option<fn(&DuneTf)>) -> Self {
        SyscallFilter {
            priority,
            syscall_number,
            filter,
            error_handler,
        }
    }
}

fn register_syscall_filter_single(new_filter: SyscallFilter) -> Result<()> {
    let mut filters = SYSCALL_FILTERS.lock().unwrap();
    let position = filters.iter().position(|f| f.priority > new_filter.priority).unwrap_or(filters.len());
    filters.insert(position, new_filter);
    Ok(())
}

fn default_error_handler(_tf: &DuneTf) {
    println!("Error: syscall filter failed");
    unsafe {dune_die()};
}

fn register_syscall_filter(filter: fn(&DuneTf) -> bool) -> Result<()> {
    let new_filter = SyscallFilter::new(
        FilterPriority::Normal,
        -1,
        filter,
        Some(default_error_handler),
    );
    register_syscall_filter_single(new_filter)
}

fn apply_syscall_filters(tf: &DuneTf) -> Result<()> {
    let filters = SYSCALL_FILTERS.lock().unwrap();
    for filter in filters.iter() {
        if filter.syscall_number != -1 && filter.syscall_number != tf.rax() as i64 {
            continue;
        }
        if !(filter.filter)(tf) {
            if let Some(handler) = filter.error_handler {
                handler(tf);
            } else {
                return Err(Error::PermissionDenied);
            }
        }
    }
    Ok(())
}

fn remove_syscall_filter(filter: fn(&DuneTf) -> bool) -> Result<()> {
    let mut filters = SYSCALL_FILTERS.lock().unwrap();
    if let Some(position) = filters.iter().position(|f| f.filter == filter) {
        filters.remove(position);
        return Ok(());
    }
    Err(Error::NotFound)
}

fn clear_syscall_filters() -> Result<()> {
    let mut filters = SYSCALL_FILTERS.lock().unwrap();
    filters.clear();
    Ok(())
}
