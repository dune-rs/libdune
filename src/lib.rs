#![feature(abi_x86_interrupt)]
#![feature(thread_local)]
#![feature(ptr_mask)]
#![feature(c_variadic)]
#![feature(trait_upcasting)]
#![allow(unused_macros)]
#![allow(unused_variables)]
#![allow(unused_comparisons)]
#![allow(unused)]
#[macro_use]
pub mod globals;
pub mod core;
pub mod mm;
#[cfg(feature = "vc")]
#[macro_use]
pub mod vc;
pub mod fpu;
#[cfg(feature = "syscall")]
pub mod syscall;
#[macro_use]
pub mod utils;
pub mod security;

pub use dune_sys::{Error, Result};

pub use crate::core::*;
pub use crate::mm::*;
pub use crate::fpu::*;
#[cfg(feature = "syscall")]
pub use crate::syscall::*;
pub use crate::utils::*;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
