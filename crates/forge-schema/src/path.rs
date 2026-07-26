//! Lossless wire representation for platform-native paths.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Encoding used to preserve a native path on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PathEncoding {
    Utf8,
    UnixBytes,
    WindowsWide,
    /// A future encoding that this binary cannot safely interpret.
    #[serde(other)]
    Unknown,
}

/// A displayable and, when needed, lossless path representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WirePath {
    pub display: String,
    pub encoding: PathEncoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_base64: Option<String>,
}

impl WirePath {
    /// Converts a native path without forcing the repository to be UTF-8.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        if let Some(utf8) = path.to_str() {
            return Self {
                display: utf8.to_owned(),
                encoding: PathEncoding::Utf8,
                raw_base64: None,
            };
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;

            return Self {
                display: path.as_os_str().to_string_lossy().into_owned(),
                encoding: PathEncoding::UnixBytes,
                raw_base64: Some(STANDARD.encode(path.as_os_str().as_bytes())),
            };
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;

            let bytes: Vec<u8> = path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect();
            return Self {
                display: path.as_os_str().to_string_lossy().into_owned(),
                encoding: PathEncoding::WindowsWide,
                raw_base64: Some(STANDARD.encode(bytes)),
            };
        }

        #[allow(unreachable_code)]
        Self {
            display: path.as_os_str().to_string_lossy().into_owned(),
            encoding: PathEncoding::Unknown,
            raw_base64: None,
        }
    }

    /// Reconstructs the native path only when this platform supports its encoding.
    pub fn to_path_buf(&self) -> Result<PathBuf, WirePathError> {
        match self.encoding {
            PathEncoding::Utf8 => {
                if self.raw_base64.is_some() {
                    return Err(WirePathError::UnexpectedRawBytes);
                }
                Ok(PathBuf::from(&self.display))
            }
            PathEncoding::UnixBytes => decode_unix_path(self.raw_base64.as_deref()),
            PathEncoding::WindowsWide => decode_windows_path(self.raw_base64.as_deref()),
            PathEncoding::Unknown => Err(WirePathError::UnsupportedEncoding),
        }
    }
}

impl From<&Path> for WirePath {
    fn from(path: &Path) -> Self {
        Self::from_path(path)
    }
}

/// Failure to reconstruct a lossless native path.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WirePathError {
    #[error("the path encoding requires raw bytes")]
    MissingRawBytes,
    #[error("a UTF-8 path must not include raw bytes")]
    UnexpectedRawBytes,
    #[error("the path raw bytes are not valid base64")]
    InvalidBase64,
    #[error("the path raw bytes have an invalid width")]
    InvalidWidth,
    #[error("the path encoding is unsupported on this platform")]
    UnsupportedEncoding,
}

fn decode_raw(raw_base64: Option<&str>) -> Result<Vec<u8>, WirePathError> {
    let encoded = raw_base64.ok_or(WirePathError::MissingRawBytes)?;
    STANDARD
        .decode(encoded)
        .map_err(|_| WirePathError::InvalidBase64)
}

#[cfg(unix)]
fn decode_unix_path(raw_base64: Option<&str>) -> Result<PathBuf, WirePathError> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    Ok(PathBuf::from(OsString::from_vec(decode_raw(raw_base64)?)))
}

#[cfg(not(unix))]
fn decode_unix_path(_raw_base64: Option<&str>) -> Result<PathBuf, WirePathError> {
    Err(WirePathError::UnsupportedEncoding)
}

#[cfg(windows)]
fn decode_windows_path(raw_base64: Option<&str>) -> Result<PathBuf, WirePathError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;

    let bytes = decode_raw(raw_base64)?;
    let mut chunks = bytes.chunks_exact(2);
    let wide: Vec<u16> = chunks
        .by_ref()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    if !chunks.remainder().is_empty() {
        return Err(WirePathError::InvalidWidth);
    }
    Ok(PathBuf::from(OsString::from_wide(&wide)))
}

#[cfg(not(windows))]
fn decode_windows_path(_raw_base64: Option<&str>) -> Result<PathBuf, WirePathError> {
    Err(WirePathError::UnsupportedEncoding)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{PathEncoding, WirePath};

    #[test]
    fn utf8_path_round_trips_without_redundant_raw_data() -> Result<(), Box<dyn std::error::Error>>
    {
        let wire = WirePath::from_path(Path::new("crates/forge-core"));

        assert_eq!(wire.encoding, PathEncoding::Utf8);
        assert_eq!(wire.raw_base64, None);
        assert_eq!(wire.to_path_buf()?, PathBuf::from("crates/forge-core"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_unix_path_round_trips_losslessly() -> Result<(), Box<dyn std::error::Error>> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let original = PathBuf::from(OsString::from_vec(b"bad-\xff-name".to_vec()));
        let wire = WirePath::from_path(&original);

        assert_eq!(wire.encoding, PathEncoding::UnixBytes);
        assert_eq!(wire.to_path_buf()?, original);
        Ok(())
    }
}
