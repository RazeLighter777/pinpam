use std::{fs, io::Read, path::Path};

use crate::{
    pinconstants::*,
    pinerror::{PinError, TssError},
    tcti::DEFAULT_TCTI_SPEC,
};
use log::warn;
use std::path::PathBuf;

use crate::pinerror::PinResult;

/// Policy describing acceptable PIN characteristics.
#[derive(Debug, Clone)]
pub struct PinPolicy {
    /// Minimum allowed length.
    pub min_length: usize,
    /// Optional maximum length.
    pub max_length: Option<usize>,
    // Maximum allowed failed attempts before lockout.
    pub max_attempts: u32,
    /// Full path to the trusted pinutil binary.
    pub pinutil_path: PathBuf,
    /// Optional TCTI spec selecting which TPM backend to use. When `None`,
    /// pinpam talks to the kernel resource manager at `/dev/tpmrm0`.
    pub tcti: Option<String>,
}

impl Default for PinPolicy {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: Some(8),
            max_attempts: 3,
            pinutil_path: PathBuf::from(DEFAULT_PINUTIL_PATH),
            tcti: None,
        }
    }
}

fn invalid_param() -> PinError {
    PinError::from(TssError::WrapperError(
        tss_esapi::WrapperErrorKind::InvalidParam,
    ))
}

fn missing_param() -> PinError {
    PinError::from(TssError::WrapperError(
        tss_esapi::WrapperErrorKind::ParamsMissing,
    ))
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
            tcti: None,
        }
    }

    /// The TCTI spec to use for talking to the TPM, falling back to the kernel
    /// resource manager device when nothing is configured.
    pub fn tcti_spec(&self) -> &str {
        self.tcti.as_deref().unwrap_or(DEFAULT_TCTI_SPEC)
    }

    /// Validate an already-normalized PIN string. Callers should use
    /// [`crate::pin::Pin::new`] rather than calling this directly so that
    /// normalization is applied consistently.
    pub fn validate(&self, pin: &str) -> PinResult<()> {
        if pin.is_empty() {
            return Err(PinError::PinIsEmpty);
        }
        if !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err(PinError::PinContainsNonDigits);
        }

        let length = pin.len();
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
        let mut policy = PinPolicy::default();

        // A `#` begins a comment that runs to the end of the line. Strip the
        // commented portion of each line before tokenizing so both full-line
        // comments (`# note`) and trailing comments (`key=value # note`) are
        // ignored.
        let uncommented = config
            .lines()
            .map(|line| line.split_once('#').map_or(line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n");

        for part in uncommented.split_whitespace() {
            let (key, value) = part.split_once('=').ok_or_else(missing_param)?;

            match key {
                "pin_min_length" => {
                    policy.min_length = value.parse().map_err(|_| invalid_param())?;
                }
                "pin_max_length" => {
                    policy.max_length = Some(value.parse().map_err(|_| invalid_param())?);
                }
                "pin_lockout_max_attempts" => {
                    policy.max_attempts = value.parse().map_err(|_| invalid_param())?;
                }
                "pinutil_path" => {
                    policy.pinutil_path = parse_pinutil_path(value)?;
                }
                "tcti" => {
                    policy.tcti = Some(parse_tcti_setting(value)?);
                }
                _ => {}
            }
        }

        Ok(policy)
    }

    /// Load the PIN policy from the standard configuration locations, falling back to defaults.
    pub fn load_from_standard_locations() -> Self {
        const PATHS: [&str; 1] = ["/etc/pinpam/policy"];
        for path in PATHS {
            if let Some(policy) = Self::load_from_path(path) {
                return policy;
            }
        }
        PinPolicy::default()
    }

    /// Process-wide cached policy. The first call loads from the standard
    /// locations; subsequent calls return the same reference.
    pub fn cached() -> &'static Self {
        static POLICY: std::sync::OnceLock<PinPolicy> = std::sync::OnceLock::new();
        POLICY.get_or_init(Self::load_from_standard_locations)
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

fn parse_tcti_setting(value: &str) -> PinResult<String> {
    if value.is_empty() {
        warn!("Ignoring empty tcti policy setting");
        return Err(invalid_param());
    }
    // Reject any spec the loader cannot interpret rather than silently falling
    // back; this surfaces typos at policy-load time instead of at TPM-open time.
    crate::tcti::parse_tcti_spec(value)?;
    Ok(value.to_owned())
}

fn parse_pinutil_path(value: &str) -> PinResult<PathBuf> {
    let candidate = PathBuf::from(value);
    if !candidate.is_absolute() {
        warn!("Ignoring pinutil_path '{}': path must be absolute", value);
        return Err(invalid_param());
    }

    match fs::metadata(&candidate) {
        Ok(metadata) if metadata.is_file() => Ok(candidate),
        Ok(_) => {
            warn!("Ignoring pinutil_path '{}': not a regular file", value);
            Err(invalid_param())
        }
        Err(err) => {
            warn!(
                "Ignoring pinutil_path '{}': metadata lookup failed ({})",
                value, err
            );
            Err(invalid_param())
        }
    }
}

fn read_policy_if_secure(path: &Path) -> Option<String> {
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
fn metadata_is_secure(metadata: &fs::Metadata, path: &Path) -> bool {
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
    // Reject anything beyond 0644: group/other write (0o020/0o002) would let a
    // non-root user rewrite `pinutil_path` and get their binary executed as root
    // during authentication; execute bits (0o100/0o010/0o001) have no business
    // on a config file. Owner write (0o200) is the only writable bit allowed.
    if (mode & 0o133) != 0 {
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
fn metadata_is_secure(_metadata: &fs::Metadata, _path: &Path) -> bool {
    true
}
