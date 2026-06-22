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
    /// When `true`, PINs may contain any printable ASCII character (0x20-0x7E)
    /// instead of only decimal digits. Off by default to preserve the
    /// historical digits-only behaviour for existing deployments.
    pub allow_alphanumeric: bool,
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
            allow_alphanumeric: false,
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
            allow_alphanumeric: false,
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
        // When alphanumeric PINs are enabled, restrict to printable ASCII
        // (0x20-0x7E): this permits letters and symbols while keeping every PIN
        // a well-defined sequence of single-byte TPM auth-value octets (no
        // control characters and no multi-byte UTF-8, so byte length always
        // equals character count). Otherwise fall back to the historical
        // digits-only rule. Stronger composition requirements (mixed case,
        // required symbols, etc.) are intentionally left to other PAM modules.
        if self.allow_alphanumeric {
            if !pin.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
                return Err(PinError::PinContainsNonPrintable);
            }
        } else if !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err(PinError::PinContainsNonDigits);
        }

        let length = pin.len();
        if length < self.min_length {
            return Err(PinError::PinTooShort {
                length,
                limit: self.min_length,
            });
        }

        // The TPM rejects an auth value longer than the NV index's name-digest
        // size, so PIN_AUTH_VALUE_MAX_LEN is a hard ceiling that applies even
        // when a policy configures a larger (or unbounded) pin_max_length.
        let max_len = self
            .max_length
            .map_or(PIN_AUTH_VALUE_MAX_LEN, |configured| {
                configured.min(PIN_AUTH_VALUE_MAX_LEN)
            });
        if length > max_len {
            return Err(PinError::PinTooLong {
                length,
                limit: max_len,
            });
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
                    let max: usize = value.parse().map_err(|_| invalid_param())?;
                    // A PIN is used directly as a TPM auth value, which the TPM
                    // bounds by the name-digest size, so a max length above that
                    // ceiling can never be honoured. Reject it at load time
                    // rather than silently clamping.
                    if max > PIN_AUTH_VALUE_MAX_LEN {
                        warn!(
                            "Ignoring pin_max_length {}: must be at most {} (the TPM auth-value digest size)",
                            max, PIN_AUTH_VALUE_MAX_LEN
                        );
                        return Err(invalid_param());
                    }
                    policy.max_length = Some(max);
                }
                "allow_alphanumeric_pins" => {
                    policy.allow_alphanumeric = value.parse().map_err(|_| invalid_param())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PinPolicy {
        PinPolicy {
            min_length: 4,
            max_length: Some(8),
            allow_alphanumeric: false,
            max_attempts: 3,
            pinutil_path: PathBuf::from("/usr/bin/true"),
            tcti: None,
        }
    }

    fn alnum_policy() -> PinPolicy {
        PinPolicy {
            allow_alphanumeric: true,
            ..policy()
        }
    }

    #[test]
    fn parses_config_without_comments() {
        let policy = PinPolicy::parse_config(
            "pin_min_length=5 pin_max_length=10 pin_lockout_max_attempts=7",
        )
        .expect("config should parse");
        assert_eq!(policy.min_length, 5);
        assert_eq!(policy.max_length, Some(10));
        assert_eq!(policy.max_attempts, 7);
    }

    #[test]
    fn ignores_full_line_comments() {
        let policy = PinPolicy::parse_config(
            "# this is a comment\npin_min_length=6\n# another comment\npin_max_length=9",
        )
        .expect("config should parse");
        assert_eq!(policy.min_length, 6);
        assert_eq!(policy.max_length, Some(9));
    }

    #[test]
    fn ignores_trailing_comments() {
        let policy = PinPolicy::parse_config(
            "pin_min_length=6 # minimum length\npin_max_length=9 # maximum length",
        )
        .expect("config should parse");
        assert_eq!(policy.min_length, 6);
        assert_eq!(policy.max_length, Some(9));
    }

    #[test]
    fn ignores_comment_immediately_after_value() {
        // No space between the value and the `#`.
        let policy = PinPolicy::parse_config("pin_min_length=6#inline comment")
            .expect("config should parse");
        assert_eq!(policy.min_length, 6);
    }

    #[test]
    fn comment_only_config_yields_defaults() {
        let policy =
            PinPolicy::parse_config("# nothing but comments\n   # indented comment")
                .expect("config should parse");
        let default = PinPolicy::default();
        assert_eq!(policy.min_length, default.min_length);
        assert_eq!(policy.max_length, default.max_length);
        assert_eq!(policy.max_attempts, default.max_attempts);
    }

    #[test]
    fn hash_disables_rest_of_line_only() {
        // The comment must not swallow settings on subsequent lines.
        let policy = PinPolicy::parse_config(
            "pin_min_length=4 # comment with key=value pin_max_length=99\npin_max_length=8",
        )
        .expect("config should parse");
        assert_eq!(policy.min_length, 4);
        assert_eq!(policy.max_length, Some(8));
    }

    // Backward compatibility: the default policy still accepts plain numeric
    // PINs exactly as before.
    #[test]
    fn numeric_pin_is_valid_by_default() {
        assert!(policy().validate("1234").is_ok());
        assert!(policy().validate("00000000").is_ok());
    }

    // Backward compatibility: alphanumeric PINs are rejected unless explicitly
    // enabled, preserving behaviour for existing deployments.
    #[test]
    fn alphanumeric_pin_is_rejected_by_default() {
        assert!(matches!(
            policy().validate("abcd"),
            Err(PinError::PinContainsNonDigits)
        ));
        assert!(matches!(
            policy().validate("12a4"),
            Err(PinError::PinContainsNonDigits)
        ));
    }

    #[test]
    fn alphanumeric_pin_is_accepted_when_enabled() {
        assert!(alnum_policy().validate("abcd").is_ok());
        assert!(alnum_policy().validate("1234").is_ok());
        assert!(alnum_policy().validate("p@55w0rd").is_ok());
        // Bounds of the printable ASCII range: space (0x20) and tilde (0x7E).
        assert!(alnum_policy().validate(" ~ ~").is_ok());
    }

    #[test]
    fn non_printable_pin_is_rejected_when_alphanumeric_enabled() {
        assert!(matches!(
            alnum_policy().validate("ab\nc"),
            Err(PinError::PinContainsNonPrintable)
        ));
        // Tab (0x09) is below the printable range.
        assert!(matches!(
            alnum_policy().validate("ab\tc"),
            Err(PinError::PinContainsNonPrintable)
        ));
        // Non-ASCII (multi-byte UTF-8).
        assert!(matches!(
            alnum_policy().validate("café"),
            Err(PinError::PinContainsNonPrintable)
        ));
        // DEL (0x7F) is just past the printable range.
        assert!(matches!(
            alnum_policy().validate("ab\x7fc"),
            Err(PinError::PinContainsNonPrintable)
        ));
    }

    #[test]
    fn empty_pin_is_rejected() {
        assert!(matches!(policy().validate(""), Err(PinError::PinIsEmpty)));
        assert!(matches!(
            alnum_policy().validate(""),
            Err(PinError::PinIsEmpty)
        ));
    }

    #[test]
    fn length_bounds_are_enforced() {
        assert!(matches!(
            policy().validate("123"),
            Err(PinError::PinTooShort { limit: 4, .. })
        ));
        assert!(matches!(
            policy().validate("123456789"),
            Err(PinError::PinTooLong { limit: 8, .. })
        ));
    }

    // The TPM digest size is a hard ceiling that applies even when a policy
    // configures a larger (or unbounded) maximum length.
    #[test]
    fn digest_size_caps_length_regardless_of_policy() {
        let at_cap = "a".repeat(PIN_AUTH_VALUE_MAX_LEN);
        let over_cap = "a".repeat(PIN_AUTH_VALUE_MAX_LEN + 1);

        let unbounded = PinPolicy {
            max_length: None,
            ..alnum_policy()
        };
        assert!(unbounded.validate(&at_cap).is_ok());
        assert!(matches!(
            unbounded.validate(&over_cap),
            Err(PinError::PinTooLong { limit, .. }) if limit == PIN_AUTH_VALUE_MAX_LEN
        ));

        let oversized = PinPolicy {
            max_length: Some(PIN_AUTH_VALUE_MAX_LEN + 100),
            ..alnum_policy()
        };
        assert!(matches!(
            oversized.validate(&over_cap),
            Err(PinError::PinTooLong { limit, .. }) if limit == PIN_AUTH_VALUE_MAX_LEN
        ));
    }

    // An alphanumeric PIN containing characters outside the printable ASCII
    // range is rejected even when alphanumeric PINs are enabled.
    #[test]
    fn alphanumeric_pin_outside_printable_range_is_rejected() {
        // Just below the printable range (0x1F) and just above it (0x7F).
        assert!(matches!(
            alnum_policy().validate("ab\x1fc"),
            Err(PinError::PinContainsNonPrintable)
        ));
        assert!(matches!(
            alnum_policy().validate("ab\x7fc"),
            Err(PinError::PinContainsNonPrintable)
        ));
        // A NUL byte, which the TPM would also strip as a trailing octet.
        assert!(matches!(
            alnum_policy().validate("ab\0c"),
            Err(PinError::PinContainsNonPrintable)
        ));
    }

    // An alphanumeric PIN longer than the TPM digest size is rejected even when
    // the policy's own max_length would otherwise permit it.
    #[test]
    fn alphanumeric_pin_exceeding_digest_size_is_rejected() {
        let over_cap = "a".repeat(PIN_AUTH_VALUE_MAX_LEN + 1);
        let unbounded = PinPolicy {
            max_length: None,
            ..alnum_policy()
        };
        assert!(matches!(
            unbounded.validate(&over_cap),
            Err(PinError::PinTooLong { limit, .. }) if limit == PIN_AUTH_VALUE_MAX_LEN
        ));
    }

    // A configured pin_max_length above the digest-size ceiling is rejected at
    // load time rather than silently clamped.
    #[test]
    fn pin_max_length_above_digest_size_is_rejected() {
        assert!(PinPolicy::parse_config("pin_max_length=33").is_err());
        assert!(PinPolicy::parse_config("pin_max_length=1000").is_err());
        // The ceiling itself is accepted.
        let at_cap = PinPolicy::parse_config("pin_max_length=32").unwrap();
        assert_eq!(at_cap.max_length, Some(PIN_AUTH_VALUE_MAX_LEN));
    }

    #[test]
    fn allow_alphanumeric_parses_from_config() {
        let enabled = PinPolicy::parse_config("allow_alphanumeric_pins=true").unwrap();
        assert!(enabled.allow_alphanumeric);

        let disabled = PinPolicy::parse_config("allow_alphanumeric_pins=false").unwrap();
        assert!(!disabled.allow_alphanumeric);

        // Defaults to off when unspecified.
        assert!(!PinPolicy::parse_config("pin_min_length=4").unwrap().allow_alphanumeric);

        // Non-boolean values are rejected.
        assert!(PinPolicy::parse_config("allow_alphanumeric_pins=yes").is_err());
    }
}
