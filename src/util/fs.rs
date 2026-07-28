/// Filesystem utilities: hashing and atomic writes.
///
/// Bundle-relative path validation (traversal rejection + containment) lives
/// in `stages::bundle::safe_bundle_path`, next to its only consumer.
use crate::error::VeriError;
use sha2::{Digest, Sha256};
use std::path::Path;

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
