#[macro_use]
pub mod globals;
pub mod dune;
pub mod entry;
pub mod page;
pub mod procmaps;
pub mod trap;
pub mod util;
pub mod vm;
pub mod debug;

pub use crate::dune::*;
pub use crate::entry::*;
pub use crate::trap::*;
pub use crate::util::*;
pub use crate::procmaps::*;
pub use crate::vm::*;
pub use crate::debug::*;

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
