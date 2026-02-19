use std::{fs, io::Read, path::Path};

use crate::{
    pinconstants::*,
    pinerror::{PinError, TssError},
};
use log::warn;
use std::path::PathBuf;

use crate::pinerror::PinResult;

/// Policy describing acceptable PIN characteristics.
#[derive(Debug, Clone)]
pub struct PinPolicy {
    /// Minimum allowed length (after trimming).
    pub min_length: usize,
    /// Optional maximum length.
    pub max_length: Option<usize>,
    // Maximum allowed failed attempts before lockout.
    pub max_attempts: u32,
    /// Full path to the trusted pinutil binary.
    pub pinutil_path: PathBuf,
}

impl Default for PinPolicy {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: Some(8),
            max_attempts: 3,
            pinutil_path: PathBuf::from(DEFAULT_PINUTIL_PATH),
        }
    }
}

impl PinPolicy {
    pub fn new(
        min_length: usize,
        max_length: Option<usize>,
        max_attempts: u32,
        pinutil_path: PathBuf,
    ) -> Self {
        Self {
            min_length,
            max_length,
            max_attempts,
            pinutil_path,
        }
    }
    pub fn validate(&self, pin: &str) -> PinResult<()> {
        let length = pin.len();

        // Verify PIN only contains digits and is not empty after trimming whitespace.
        let trimmed = pin.trim();
        if trimmed.is_empty() {
            return Err(PinError::PinIsEmpty);
        }
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(PinError::PinContainsNonDigits);
        }

        if length < self.min_length {
            return Err(PinError::PinTooShort {
                length,
                limit: self.min_length,
            });
        }

        if let Some(max_len) = self.max_length {
            if length > max_len {
                return Err(PinError::PinTooLong {
                    length,
                    limit: max_len,
                });
            }
        }

        Ok(())
    }
    pub fn parse_config(config: &str) -> PinResult<Self> {
        let mut min_length = 4;
        let mut max_length = Some(8);
        let mut max_attempts = 3;
        let mut pinutil_path = PathBuf::from(DEFAULT_PINUTIL_PATH);

        for part in config.split_whitespace() {
            let mut iter = part.splitn(2, '=');
            let key = iter.next().unwrap();
            let value = iter.next().ok_or_else(|| {
                PinError::from(TssError::WrapperError(
                    tss_esapi::WrapperErrorKind::ParamsMissing,
                ))
            })?;

            match key {
                "pin_min_length" => {
                    min_length = value.parse().map_err(|_| {
                        PinError::from(TssError::WrapperError(
                            tss_esapi::WrapperErrorKind::InvalidParam,
                        ))
                    })?;
                }
                "pin_max_length" => {
                    max_length = Some(value.parse().map_err(|_| {
                        PinError::from(TssError::WrapperError(
                            tss_esapi::WrapperErrorKind::InvalidParam,
                        ))
                    })?);
                }
                "pin_lockout_max_attempts" => {
                    max_attempts = value.parse().map_err(|_| {
                        PinError::from(TssError::WrapperError(
                            tss_esapi::WrapperErrorKind::InvalidParam,
                        ))
                    })?;
                }
                "pinutil_path" => {
                    let candidate = PathBuf::from(value);
                    if !candidate.is_absolute() {
                        warn!("Ignoring pinutil_path '{}': path must be absolute", value);
                        return Err(PinError::from(TssError::WrapperError(
                            tss_esapi::WrapperErrorKind::InvalidParam,
                        )));
                    }

                    match fs::metadata(&candidate) {
                        Ok(metadata) if metadata.is_file() => {
                            pinutil_path = candidate;
                        }
                        Ok(_) => {
                            warn!("Ignoring pinutil_path '{}': not a regular file", value);
                            return Err(PinError::from(TssError::WrapperError(
                                tss_esapi::WrapperErrorKind::InvalidParam,
                            )));
                        }
                        Err(err) => {
                            warn!(
                                "Ignoring pinutil_path '{}': metadata lookup failed ({})",
                                value, err
                            );
                            return Err(PinError::from(TssError::WrapperError(
                                tss_esapi::WrapperErrorKind::InvalidParam,
                            )));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(PinPolicy::new(
            min_length,
            max_length,
            max_attempts,
            pinutil_path,
        ))
    }

    /// Load the PIN policy from the standard configuration locations, falling back to defaults.
    pub fn load_from_standard_locations() -> Self {
        pub(crate) const PATHS: [&str; 1] = ["/etc/pinpam/policy"];
        for path in PATHS {
            if let Some(policy) = Self::load_from_path(path) {
                return policy;
            }
        }
        PinPolicy::default()
    }

    /// Attempt to load a PIN policy from a specific path if it passes security checks.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Option<Self> {
        let path = path.as_ref();
        let config = read_policy_if_secure(path)?;
        match PinPolicy::parse_config(&config) {
            Ok(policy) => Some(policy),
            Err(err) => {
                warn!("Failed to parse PIN policy at {}: {}", path.display(), err);
                None
            }
        }
    }
}

pub(crate) fn read_policy_if_secure(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let metadata = file
        .metadata()
        .inspect_err(|err| {
            warn!(
                "Failed to read file metadata at {}: {}",
                path.display(),
                err
            )
        })
        .ok()?;

    if !metadata.is_file() {
        warn!(
            "Ignoring PIN policy at {}: not a regular file",
            path.display()
        );
        return None;
    }

    if !metadata_is_secure(&metadata, path) {
        return None;
    }

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_) => Some(contents),
        Err(err) => {
            warn!("Failed to read PIN policy at {}: {}", path.display(), err);
            None
        }
    }
}

#[cfg(unix)]
pub(crate) fn metadata_is_secure(metadata: &fs::Metadata, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != 0 {
        warn!(
            "Ignoring PIN policy at {}: expected owner uid 0 but found {}",
            path.display(),
            metadata.uid()
        );
        return false;
    }

    let mode = metadata.mode() & 0o777;
    if (mode & 0o113) != 0 {
        warn!(
            "Ignoring PIN policy at {}: expected permissions <=0644 but found {:03o}",
            path.display(),
            mode
        );
        return false;
    }

    true
}

#[cfg(not(unix))]
pub(crate) fn metadata_is_secure(_metadata: &fs::Metadata, _path: &Path) -> bool {
    true
}
