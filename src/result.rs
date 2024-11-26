use std::{fmt, io::ErrorKind};
use libc::c_int;
use nix::errno::Errno;

#[derive(Debug)]
pub enum Error {
    LibcError(Errno),
    Io(std::io::Error),
    InvalidInput(String),
    NotFound,
    PermissionDenied,
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LibcError(err) => write!(f, "Libc error: {}", err),
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::NotFound => write!(f, "Not found"),
            Error::PermissionDenied => write!(f, "Permission denied"),
            Error::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl From<c_int> for Error {
    fn from(err: c_int) -> Self {
        match err {
            libc::EPERM => Error::PermissionDenied,
            libc::ENOENT => Error::NotFound,
            libc::EINTR => Error::Unknown,
            libc::EIO => Error::Io(std::io::Error::from(ErrorKind::Other)),
            libc::ENOMEM => Error::InvalidInput("Out of memory".to_string()),
            libc::EACCES => Error::PermissionDenied,
            libc::EFAULT => Error::InvalidInput("Invalid pointer".to_string()),
            libc::EEXIST => Error::InvalidInput("File already exists".to_string()),
            libc::EINVAL => Error::InvalidInput("Invalid input".to_string()),
            libc::ERANGE => Error::InvalidInput("Out of range".to_string()),
            _ => Error::LibcError(Errno::from_raw(err)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
