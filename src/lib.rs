#![feature(thread_local)]
#![feature(ptr_mask)]
#![allow(unused_macros)]
#[macro_use]
pub mod globals;
pub mod core;
pub mod mm;
pub mod fpu;
pub mod syscall;
pub mod utils;

pub use crate::core::*;
pub use crate::mm::*;
pub use crate::fpu::*;
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
