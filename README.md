# libdune: Rust-based Dynamic Library for Virtualization 🚀

**libdune** is a Rust reimplementation of the library OS component of the [Stanford Dune Project](https://dune.scs.stanford.edu/). It serves as a critical interface between user-space applications and the underlying kernel module, enabling virtualization features with enhanced safety, performance, and developer ergonomics.

---

## 🌟 Features

- **Virtualization in Ring-0**: Leverage Dune's virtualization capabilities to run user-space processes at Ring-0 privilege within a VM.
- **Rust Safety**: Written in Rust, ensuring memory safety and reducing vulnerabilities common in traditional C-based implementations.
- **Flexible API**: Exposes a clean, extensible interface for advanced virtualization tasks.
- **Integration with dune-sys**: Provides seamless interaction with the `dune-sys` crate for low-level system calls.

---

## 🛠️ Getting Started

### Installation

Add **libdune** to your project by including it in your `Cargo.toml`:

```toml
[dependencies]
libdune = "0.1"
```

### Usage
Here's a simple example of using libdune in your Rust project:

```rust
use libdune::{dune_init_and_enter};
use libc::c_int;

fn main() {
    println!("hello: not running dune yet");

    let ret = dune_init_and_enter();
    if ret != 0 {
        println!("failed to initialize dune");
        return;
    }

    println!("hello: now printing from dune mode");
}
```
Check out the examples directory for more advanced use cases.

## 📚 Documentation

* API Reference: [docs.rs/libdune](docs.rs/libdune)
* Dune Project Paper: [Stanford Dune Paper](https://www.usenix.org/conference/osdi12/technical-sessions/presentation/belay)
* Getting Started with Virtualization: [Hardware and Software Support for Virtualization](https://kartikgopalan.github.io/680v/books/HSSV.pdf)

## 🌈 Contributing
We welcome contributions to make libdune better! Here's how you can help:

* Fork the repository and clone it locally.
* Check the [issues](https://github.com/dune-rs/libdune/issues) for tasks to work on.
* Submit a pull request with your improvements.
* Make sure to follow our contribution guidelines and code of conduct.

## 🧪 Testing
Run the test suite to ensure everything works as expected:

```bash
cargo test
```

If you have access to a supported virtualization environment, run integration tests:

```bash
cargo test --features=integration
```

## 📦 Roadmap

* Add support for advanced VM configurations.
* Expand API to include performance profiling tools.
* Comprehensive examples for common use cases.
* Support for additional architectures (e.g., ARM).

## 🛡️ License
This project is licensed under the MIT License.

Feel free to explore, use, and contribute to libdune. Together, let's push the boundaries of virtualization! ✨
