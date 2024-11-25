
fn main() {
    // 将编译后的目标文件链接到Rust库中
    println!("cargo:rustc-link-search=native=src");
    println!("cargo:rustc-link-lib=static=dune");
}
