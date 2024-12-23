use std::env;

fn get_default_page_size() -> usize {
    // 根据当前启用的 feature 返回默认值
    if cfg!(feature = "page_size_4k") {
        4096
    } else if cfg!(feature = "page_size_2k") {
        2048
    } else {
        // 默认使用 1k
        1024
    }
}

fn get_default_vmpl_va_range() -> (u64, usize) {
    (0x3fffff000000, 0x20000000)
}

fn main() {
    let default_size = get_default_page_size();

    // 从环境变量读取配置,如果没有设置则使用 feature 指定的默认值
    let vmpl_page_grow_size = env::var("VMPL_PAGE_GROW_SIZE")
        .map(|v| v.parse::<usize>().expect("Invalid VMPL_PAGE_GROW_SIZE"))
        .unwrap_or(default_size);

    let dune_page_grow_size = env::var("DUNE_PAGE_GROW_SIZE")
        .map(|v| v.parse::<usize>().expect("Invalid DUNE_PAGE_GROW_SIZE"))
        .unwrap_or(default_size);

    let (vmpl_va_start, vmpl_va_size) = env::var("VMPL_VA_RANGE")
        .map(|v| v.parse::<u64>().expect("Invalid VMPL_VA_RANGE"))
        .unwrap_or(get_default_vmpl_va_range());

    // 将配置写入编译时环境变量
    println!("cargo:rustc-env=VMPL_PAGE_GROW_SIZE={}", vmpl_page_grow_size);
    println!("cargo:rustc-env=DUNE_PAGE_GROW_SIZE={}", dune_page_grow_size);
    println!("cargo:rustc-env=VMPL_VA_START={}", vmpl_va_start);
    println!("cargo:rustc-env=VMPL_VA_SIZE={}", vmpl_va_size);

    // 重新运行条件
    println!("cargo:rerun-if-env-changed=VMPL_PAGE_GROW_SIZE");
    println!("cargo:rerun-if-env-changed=DUNE_PAGE_GROW_SIZE");
    println!("cargo:rerun-if-env-changed=VMPL_VA_RANGE");
    println!("cargo:rerun-if-changed=build.rs");
}