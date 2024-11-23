use std::process::Command;

fn main() {
    // 编译dune.S文件，并包含src目录中的头文件
    Command::new("gcc")
        .args(&["-c", "src/dune.S", "-o", "src/dune.o", "-I", "src"])
        .status()
        .expect("Failed to compile dune.S");

    // 将编译后的目标文件链接到Rust库中
    println!("cargo:rustc-link-search=native=src");
    println!("cargo:rustc-link-lib=static=dune");
}
