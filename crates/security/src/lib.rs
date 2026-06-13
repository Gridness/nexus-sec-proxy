mod error;
mod external;
mod normalize;
mod osv;
mod policy;
mod severity;
mod target;
mod vulnerability;

pub use error::SecurityError;
pub use external::{ExternalScanner, ExternalScannerKind};
pub use osv::OsvClient;
pub use policy::*;
pub use severity::{Severity, SeverityParseError};
pub use target::{
	ArtifactTarget, PackageCoordinate, PackageIdentity, ScanTarget,
	default_osv_ecosystem_for_format,
};
pub use vulnerability::{Reference, Vulnerability};

#[cfg(test)]
mod tests;
