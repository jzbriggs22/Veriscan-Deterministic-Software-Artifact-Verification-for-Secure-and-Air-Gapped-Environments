/// Filesystem utilities with security hardening.
///
/// All path operations normalize and validate to prevent directory traversal.
/// No operation blindly trusts user-supplied path components.
use crate::error::VeriError;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// Canonicalize `path` and reject any traversal attempt (e.g., `../../../etc/passwd`).
///
/// Returns the absolute, normalised path only if it stays within `base`.
/// If `base` is None, just normalise without confinement check.
pub fn safe_path(path: &Path, base: Option<&Path>) -> Result<PathBuf, VeriError> {
    let mut normalised = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // A `..` component in any user-supplied path is a traversal attempt.
                return Err(VeriError::PathTraversal {
                    path: path.display().to_string(),
                });
            }
            Component::CurDir => {} // skip `.`
            Component::Prefix(p) => normalised.push(p.as_os_str()),
            Component::RootDir => normalised.push("/"),
            Component::Normal(n) => normalised.push(n),
        }
    }

    if let Some(base) = base {
        let base_abs = base
            .canonicalize()
            .map_err(|e| VeriError::Io {
                path: base.display().to_string(),
                source: e,
            })
            .unwrap_or_else(|_| base.to_path_buf());

        let joined = base_abs.join(&normalised);

        // Attempt to canonicalize the joined path; if the file doesn't exist yet,
        // check the prefix manually.
        let resolved = if joined.exists() {
            joined.canonicalize().map_err(|e| VeriError::Io {
                path: joined.display().to_string(),
                source: e,
            })?
        } else {
            joined.clone()
        };

        if !resolved.starts_with(&base_abs) {
            return Err(VeriError::PathTraversal {
                path: path.display().to_string(),
            });
        }

        Ok(resolved)
    } else {
        Ok(normalised)
    }
}

/// Read file bytes into memory, failing with a typed error on any I/O issue.
pub fn read_bytes(path: &Path) -> Result<Vec<u8>, VeriError> {
    std::fs::read(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

/// Compute SHA-256 of a file on disk without reading the whole thing into RAM at once.
/// Reads in 64 KiB chunks.
pub fn sha256_file(path: &Path) -> Result<String, VeriError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf).map_err(|e| VeriError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Write bytes to a file atomically: write to a temp file in the same directory
/// then rename. Prevents partial writes from leaving corrupt files.
pub fn write_bytes_atomic(dest: &Path, data: &[u8]) -> Result<(), VeriError> {
    let dir = dest.parent().unwrap_or(Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| VeriError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    std::fs::write(tmp.path(), data).map_err(|e| VeriError::Io {
        path: tmp.path().display().to_string(),
        source: e,
    })?;
    tmp.persist(dest).map_err(|e| VeriError::Io {
        path: dest.display().to_string(),
        source: e.error,
    })?;
    Ok(())
}

/// Return the file size in bytes.
pub fn file_size(path: &Path) -> Result<u64, VeriError> {
    let meta = std::fs::metadata(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(meta.len())
}

/// Extract the filename component of a path as a String.
pub fn filename_str(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "<unknown>".to_string())
}
